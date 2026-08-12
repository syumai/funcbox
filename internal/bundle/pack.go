package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"sort"
	"time"
)

// epoch is the fixed modification time used for every entry in a
// canonical archive.
var epoch = time.Unix(0, 0).UTC()

// Pack serializes files into a deterministic ("canonical")
// gzip-compressed tar archive. Given the same set of file contents,
// Pack always produces byte-identical output, regardless of Go map
// iteration order, the calling client, or wall-clock time:
//
//   - entries are written in sorted path order
//   - uid/gid are 0, uname/gname are empty, mode is 0644
//   - mtime is the Unix epoch
//   - the tar format is USTAR, upgrading to minimal PAX only when a
//     header field (e.g. a long path) requires it
//   - gzip compression uses a fixed level with no name, comment, or
//     modification time in its header
//
// This determinism lets the server perform content-addressed
// deduplication (sha256 of the packed bytes) across uploads,
// independent of the client archiver that originally produced the
// bundle.
func Pack(files map[string][]byte) ([]byte, error) {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for _, name := range names {
		data := files[name]
		hdr := &tar.Header{
			Name:     name,
			Typeflag: tar.TypeReg,
			Size:     int64(len(data)),
			Mode:     0644,
			Uid:      0,
			Gid:      0,
			Uname:    "",
			Gname:    "",
			ModTime:  epoch,
			// Format is left unset (FormatUnknown) so the writer
			// picks the minimal format (USTAR, upgrading to PAX only
			// when required, e.g. by a long path) automatically and
			// deterministically.
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("bundle: write tar header for %q: %w", name, err)
		}
		if _, err := tw.Write(data); err != nil {
			return nil, fmt.Errorf("bundle: write tar contents for %q: %w", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("bundle: close tar writer: %w", err)
	}

	var gzBuf bytes.Buffer
	gw, err := gzip.NewWriterLevel(&gzBuf, gzip.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("bundle: create gzip writer: %w", err)
	}
	// gzip.Header's zero values (empty Name/Comment, zero ModTime) are
	// exactly what we want: no variable metadata in the output.
	if _, err := gw.Write(tarBuf.Bytes()); err != nil {
		return nil, fmt.Errorf("bundle: write gzip contents: %w", err)
	}
	if err := gw.Close(); err != nil {
		return nil, fmt.Errorf("bundle: close gzip writer: %w", err)
	}

	return gzBuf.Bytes(), nil
}

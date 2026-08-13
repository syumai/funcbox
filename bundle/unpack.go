package bundle

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

// MaxUnpackedBytes is the maximum total size, in bytes, of all file
// contents after decompression. This is a system-wide constant (see
// in memory while hosted.
const MaxUnpackedBytes = 5 << 20 // 5 MiB

// MaxFiles is the maximum number of regular file entries allowed in a
// bundle.
const MaxFiles = 1000

// MaxPathLength is the maximum length, in bytes, of a normalized entry
// path.
const MaxPathLength = 256

var (
	// ErrTooLarge is returned when the total decompressed size of the
	// archive would exceed MaxUnpackedBytes.
	ErrTooLarge = errors.New("bundle: unpacked size exceeds limit")

	// ErrTooManyFiles is returned when the archive contains more than
	// MaxFiles regular file entries.
	ErrTooManyFiles = errors.New("bundle: too many files")

	// ErrBadPath is returned for entry paths that are absolute, escape
	// the archive root via "..", are empty, are duplicated (after
	// normalization to forward slashes), or exceed MaxPathLength.
	ErrBadPath = errors.New("bundle: invalid path")

	// ErrBadEntryType is returned for archive entries that are not
	// regular files or plain directories (symlinks, hardlinks,
	// devices, fifos, etc).
	ErrBadEntryType = errors.New("bundle: unsupported entry type")
)

// Unpack streams a gzip-compressed tar archive from r and returns its
// regular file contents as a map from normalized path to file
// contents.
//
// Limits are enforced WHILE reading, not after: the running total of
// bytes copied out of the archive is tracked continuously, and
// decoding aborts the instant that total would exceed
// MaxUnpackedBytes. Per-entry header sizes are never trusted on their
// own, so a highly compressible "gzip bomb" is rejected without ever
// decompressing more than MaxUnpackedBytes (+1 byte) of data.
//
// Plain directory entries are skipped silently. Any other
// non-regular-file entry (symlink, hardlink, device, fifo, ...) is
// rejected with ErrBadEntryType. Paths are normalized to forward
// slashes; absolute paths, ".." escapes, empty paths, duplicate
// paths, and paths longer than MaxPathLength are rejected with
// ErrBadPath. More than MaxFiles regular files is rejected with
// ErrTooManyFiles.
func Unpack(r io.Reader) (map[string][]byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("bundle: read gzip header: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	files := make(map[string][]byte)
	var total int64
	var count int

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("bundle: read tar entry: %w", err)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			// Directory entries are not represented in the result;
			// the map itself defines the file tree. Skip silently.
			continue
		case tar.TypeReg, tar.TypeRegA:
			// Handled below.
		default:
			return nil, fmt.Errorf("%w: %q (typeflag %q)", ErrBadEntryType, hdr.Name, string(hdr.Typeflag))
		}

		name, err := normalizePath(hdr.Name)
		if err != nil {
			return nil, err
		}
		if _, dup := files[name]; dup {
			return nil, fmt.Errorf("%w: duplicate path %q", ErrBadPath, name)
		}

		count++
		if count > MaxFiles {
			return nil, ErrTooManyFiles
		}

		data, n, err := readWithinBudget(tr, MaxUnpackedBytes-total)
		total += n
		if err != nil {
			return nil, err
		}

		files[name] = data
	}

	return files, nil
}

// readWithinBudget reads all of r, aborting with ErrTooLarge the
// instant more than `remaining` bytes have been read. It never
// buffers more than remaining+1 bytes, so callers can bound total
// memory use across an entire archive regardless of what any entry's
// header claims about its size.
func readWithinBudget(r io.Reader, remaining int64) ([]byte, int64, error) {
	if remaining < 0 {
		remaining = 0
	}
	// Request one byte more than the budget: if we receive it, the
	// entry (and therefore the archive) exceeds the limit.
	limited := io.LimitReader(r, remaining+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, int64(len(data)), fmt.Errorf("bundle: read entry contents: %w", err)
	}
	if int64(len(data)) > remaining {
		return nil, remaining, ErrTooLarge
	}
	return data, int64(len(data)), nil
}

// normalizePath validates and normalizes a tar entry name to a clean,
// forward-slash-separated relative path.
func normalizePath(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("%w: empty path", ErrBadPath)
	}

	norm := strings.ReplaceAll(name, "\\", "/")
	if strings.HasPrefix(norm, "/") {
		return "", fmt.Errorf("%w: absolute path %q", ErrBadPath, name)
	}

	cleaned := path.Clean(norm)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("%w: path escapes archive root %q", ErrBadPath, name)
	}
	if strings.HasPrefix(cleaned, "/") {
		return "", fmt.Errorf("%w: absolute path %q", ErrBadPath, name)
	}
	if len(cleaned) > MaxPathLength {
		return "", fmt.Errorf("%w: path too long %q", ErrBadPath, name)
	}

	return cleaned, nil
}

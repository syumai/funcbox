package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"maps"
	"testing"
)

// tarEntry describes one entry to write into a hand-crafted test
// archive. Using archive/tar directly (rather than Pack) lets tests
// construct malicious archives that Pack itself would never produce.
type tarEntry struct {
	hdr  tar.Header
	body []byte
}

func buildArchive(t *testing.T, entries []tarEntry) []byte {
	t.Helper()

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for _, e := range entries {
		hdr := e.hdr
		if hdr.Typeflag == 0 {
			hdr.Typeflag = tar.TypeReg
		}
		if hdr.Mode == 0 {
			hdr.Mode = 0644
		}
		if hdr.Typeflag == tar.TypeReg || hdr.Typeflag == tar.TypeRegA {
			hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(&hdr); err != nil {
			t.Fatalf("WriteHeader(%q): %v", hdr.Name, err)
		}
		if len(e.body) > 0 {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatalf("Write(%q): %v", hdr.Name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}

	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	if _, err := gw.Write(tarBuf.Bytes()); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	return gzBuf.Bytes()
}

func TestUnpack_TableDriven(t *testing.T) {
	tests := []struct {
		name      string
		archive   func(t *testing.T) []byte
		wantFiles map[string]string
		wantErr   error // checked with errors.Is; nil means "no error"
	}{
		{
			name: "valid multi-file archive",
			archive: func(t *testing.T) []byte {
				return buildArchive(t, []tarEntry{
					{hdr: tar.Header{Name: "index.js"}, body: []byte("export default {}")},
					{hdr: tar.Header{Name: "lib/util.js"}, body: []byte("export const x = 1")},
				})
			},
			wantFiles: map[string]string{
				"index.js":    "export default {}",
				"lib/util.js": "export const x = 1",
			},
		},
		{
			name: "directory entries are skipped silently",
			archive: func(t *testing.T) []byte {
				return buildArchive(t, []tarEntry{
					{hdr: tar.Header{Name: "lib/", Typeflag: tar.TypeDir}},
					{hdr: tar.Header{Name: "lib/util.js"}, body: []byte("ok")},
				})
			},
			wantFiles: map[string]string{"lib/util.js": "ok"},
		},
		{
			name: "backslash paths are normalized to forward slashes",
			archive: func(t *testing.T) []byte {
				return buildArchive(t, []tarEntry{
					{hdr: tar.Header{Name: `lib\util.js`}, body: []byte("ok")},
				})
			},
			wantFiles: map[string]string{"lib/util.js": "ok"},
		},
		{
			name: "absolute path is rejected",
			archive: func(t *testing.T) []byte {
				return buildArchive(t, []tarEntry{
					{hdr: tar.Header{Name: "/etc/passwd"}, body: []byte("evil")},
				})
			},
			wantErr: ErrBadPath,
		},
		{
			name: "path traversal is rejected",
			archive: func(t *testing.T) []byte {
				return buildArchive(t, []tarEntry{
					{hdr: tar.Header{Name: "../../etc/passwd"}, body: []byte("evil")},
				})
			},
			wantErr: ErrBadPath,
		},
		{
			name: "path traversal via backslash is rejected",
			archive: func(t *testing.T) []byte {
				return buildArchive(t, []tarEntry{
					{hdr: tar.Header{Name: `..\..\evil.txt`}, body: []byte("evil")},
				})
			},
			wantErr: ErrBadPath,
		},
		{
			name: "path traversal nested inside a valid-looking path is rejected",
			archive: func(t *testing.T) []byte {
				return buildArchive(t, []tarEntry{
					{hdr: tar.Header{Name: "lib/../../evil.txt"}, body: []byte("evil")},
				})
			},
			wantErr: ErrBadPath,
		},
		{
			name: "empty path is rejected",
			archive: func(t *testing.T) []byte {
				return buildArchive(t, []tarEntry{
					{hdr: tar.Header{Name: ""}, body: []byte("x")},
				})
			},
			wantErr: ErrBadPath,
		},
		{
			name: "duplicate path is rejected",
			archive: func(t *testing.T) []byte {
				return buildArchive(t, []tarEntry{
					{hdr: tar.Header{Name: "index.js"}, body: []byte("a")},
					{hdr: tar.Header{Name: "./index.js"}, body: []byte("b")},
				})
			},
			wantErr: ErrBadPath,
		},
		{
			name: "path longer than MaxPathLength is rejected",
			archive: func(t *testing.T) []byte {
				longName := ""
				for len(longName) <= MaxPathLength {
					longName += "a"
				}
				return buildArchive(t, []tarEntry{
					{hdr: tar.Header{Name: longName}, body: []byte("x")},
				})
			},
			wantErr: ErrBadPath,
		},
		{
			name: "symlink entry is rejected",
			archive: func(t *testing.T) []byte {
				return buildArchive(t, []tarEntry{
					{hdr: tar.Header{Name: "evil-link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}},
				})
			},
			wantErr: ErrBadEntryType,
		},
		{
			name: "hardlink entry is rejected",
			archive: func(t *testing.T) []byte {
				return buildArchive(t, []tarEntry{
					{hdr: tar.Header{Name: "index.js"}, body: []byte("a")},
					{hdr: tar.Header{Name: "evil-hardlink", Typeflag: tar.TypeLink, Linkname: "index.js"}},
				})
			},
			wantErr: ErrBadEntryType,
		},
		{
			name: "char device entry is rejected",
			archive: func(t *testing.T) []byte {
				return buildArchive(t, []tarEntry{
					{hdr: tar.Header{Name: "dev-entry", Typeflag: tar.TypeChar}},
				})
			},
			wantErr: ErrBadEntryType,
		},
		{
			name: "block device entry is rejected",
			archive: func(t *testing.T) []byte {
				return buildArchive(t, []tarEntry{
					{hdr: tar.Header{Name: "dev-entry", Typeflag: tar.TypeBlock}},
				})
			},
			wantErr: ErrBadEntryType,
		},
		{
			name: "fifo entry is rejected",
			archive: func(t *testing.T) []byte {
				return buildArchive(t, []tarEntry{
					{hdr: tar.Header{Name: "fifo-entry", Typeflag: tar.TypeFifo}},
				})
			},
			wantErr: ErrBadEntryType,
		},
		{
			name: "too many files is rejected",
			archive: func(t *testing.T) []byte {
				entries := make([]tarEntry, MaxFiles+1)
				for i := range entries {
					entries[i] = tarEntry{hdr: tar.Header{Name: fmtName(i)}, body: []byte("x")}
				}
				return buildArchive(t, entries)
			},
			wantErr: ErrTooManyFiles,
		},
		{
			name: "total unpacked size over the limit is rejected",
			archive: func(t *testing.T) []byte {
				return buildArchive(t, []tarEntry{
					{hdr: tar.Header{Name: "big.bin"}, body: make([]byte, MaxUnpackedBytes+1)},
				})
			},
			wantErr: ErrTooLarge,
		},
		{
			name: "total unpacked size exactly at the limit is accepted",
			archive: func(t *testing.T) []byte {
				return buildArchive(t, []tarEntry{
					{hdr: tar.Header{Name: "big.bin"}, body: make([]byte, MaxUnpackedBytes)},
				})
			},
			wantFiles: map[string]string{"big.bin": string(make([]byte, MaxUnpackedBytes))},
		},
		{
			name: "sum of multiple files over the limit is rejected",
			archive: func(t *testing.T) []byte {
				half := MaxUnpackedBytes/2 + 1
				return buildArchive(t, []tarEntry{
					{hdr: tar.Header{Name: "a.bin"}, body: make([]byte, half)},
					{hdr: tar.Header{Name: "b.bin"}, body: make([]byte, half)},
				})
			},
			wantErr: ErrTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			archive := tt.archive(t)
			files, err := Unpack(bytes.NewReader(archive))

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Unpack() error = %v, want error wrapping %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unpack() unexpected error: %v", err)
			}
			if len(files) != len(tt.wantFiles) {
				t.Fatalf("Unpack() got %d files, want %d (%v)", len(files), len(tt.wantFiles), maps.Keys(files))
			}
			for name, want := range tt.wantFiles {
				got, ok := files[name]
				if !ok {
					t.Fatalf("Unpack() missing file %q", name)
				}
				if string(got) != want {
					t.Fatalf("Unpack() file %q = %q, want %q", name, truncate(got), truncate([]byte(want)))
				}
			}
		})
	}
}

func fmtName(i int) string {
	// Simple deterministic unique names without pulling in fmt in the
	// hot loop above (fmt is already imported transitively but keep
	// this obviously cheap and side-effect free).
	digits := []byte("0123456789")
	var b []byte
	if i == 0 {
		b = []byte{'0'}
	}
	for i > 0 {
		b = append([]byte{digits[i%10]}, b...)
		i /= 10
	}
	return "file-" + string(b) + ".txt"
}

func truncate(b []byte) []byte {
	const max = 32
	if len(b) > max {
		return b[:max]
	}
	return b
}

// TestUnpack_GzipBomb proves that a highly compressible archive whose
// declared/actual decompressed size vastly exceeds MaxUnpackedBytes is
// rejected promptly, without the unpacker ever buffering the full
// decompressed payload.
func TestUnpack_GzipBomb(t *testing.T) {
	// 32 MiB of zero bytes compresses to a few KiB, but exceeds
	// MaxUnpackedBytes (5 MiB) by a wide margin.
	const bombSize = 32 << 20

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	if err := tw.WriteHeader(&tar.Header{
		Name: "bomb.bin",
		Mode: 0644,
		Size: bombSize,
	}); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	zeros := make([]byte, 1<<20) // 1 MiB chunk, reused
	written := 0
	for written < bombSize {
		n := len(zeros)
		if bombSize-written < n {
			n = bombSize - written
		}
		if _, err := tw.Write(zeros[:n]); err != nil {
			t.Fatalf("tar write: %v", err)
		}
		written += n
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}

	var gzBuf bytes.Buffer
	gw, err := gzip.NewWriterLevel(&gzBuf, gzip.BestCompression)
	if err != nil {
		t.Fatalf("gzip.NewWriterLevel: %v", err)
	}
	if _, err := gw.Write(tarBuf.Bytes()); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}

	if gzBuf.Len() >= bombSize {
		t.Fatalf("test fixture is not actually compressible: gzip size %d >= raw size %d", gzBuf.Len(), bombSize)
	}
	t.Logf("gzip bomb: %d bytes compressed -> %d bytes decompressed (ratio 1:%d)", gzBuf.Len(), bombSize, bombSize/gzBuf.Len())

	_, err = Unpack(bytes.NewReader(gzBuf.Bytes()))
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Unpack() error = %v, want ErrTooLarge", err)
	}
}

func TestUnpack_InvalidGzip(t *testing.T) {
	_, err := Unpack(bytes.NewReader([]byte("not a gzip stream")))
	if err == nil {
		t.Fatal("Unpack() expected error for invalid gzip input, got nil")
	}
}

func TestUnpack_EmptyArchive(t *testing.T) {
	archive := buildArchive(t, nil)
	files, err := Unpack(bytes.NewReader(archive))
	if err != nil {
		t.Fatalf("Unpack() unexpected error: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("Unpack() got %d files, want 0", len(files))
	}
}

func TestPack_Deterministic(t *testing.T) {
	files := map[string][]byte{
		"index.js":    []byte("export default {}"),
		"lib/util.js": []byte("export const x = 1"),
		"README.md":   []byte("# hello"),
	}

	out1, err := Pack(files)
	if err != nil {
		t.Fatalf("Pack() #1 error: %v", err)
	}
	out2, err := Pack(files)
	if err != nil {
		t.Fatalf("Pack() #2 error: %v", err)
	}
	if !bytes.Equal(out1, out2) {
		t.Fatalf("Pack() is not deterministic: got different output across two calls with identical input")
	}
}

func TestPack_RoundTrip(t *testing.T) {
	files := map[string][]byte{
		"index.js":        []byte("export default {}"),
		"lib/util.js":     []byte("export const x = 1"),
		"nested/a/b/c.js": []byte("deep"),
		"empty.txt":       {},
	}

	packed, err := Pack(files)
	if err != nil {
		t.Fatalf("Pack() error: %v", err)
	}
	got, err := Unpack(bytes.NewReader(packed))
	if err != nil {
		t.Fatalf("Unpack(Pack()) error: %v", err)
	}
	if len(got) != len(files) {
		t.Fatalf("round trip got %d files, want %d", len(got), len(files))
	}
	for name, want := range files {
		gotBody, ok := got[name]
		if !ok {
			t.Fatalf("round trip missing file %q", name)
		}
		if !bytes.Equal(gotBody, want) {
			t.Fatalf("round trip file %q = %q, want %q", name, gotBody, want)
		}
	}
}

// TestPack_HashStable pins the exact byte layout of a canonical
// archive for a fixed fixture. If this test starts failing, the
// on-disk archive format has drifted (accidentally or not) and every
// previously stored blob's content hash is now stale.
func TestPack_HashStable(t *testing.T) {
	files := map[string][]byte{
		"index.js":    []byte("export default { fetch(req) { return new Response('ok') } }\n"),
		"lib/util.js": []byte("export const add = (a, b) => a + b\n"),
	}

	packed, err := Pack(files)
	if err != nil {
		t.Fatalf("Pack() error: %v", err)
	}

	const wantHash = "dca4d9dd9dceaf16cecc1cd60f23a49669c417dcafeaacbce92a63aa16e18d89"
	sum := sha256.Sum256(packed)
	gotHash := hex.EncodeToString(sum[:])
	if gotHash != wantHash {
		t.Fatalf("Pack() sha256 = %s, want %s (canonical tar.gz format has drifted)", gotHash, wantHash)
	}
}

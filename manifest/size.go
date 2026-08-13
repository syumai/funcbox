package manifest

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrInvalidMemory is returned for a memory field that isn't a valid
// byte-size string.
var ErrInvalidMemory = errors.New("manifest: invalid memory size")

// byteUnits maps case-insensitive size suffixes to their multiplier,
// longest suffixes first so that, e.g., "MiB" is tried before "B".
var byteUnits = []struct {
	suffix     string
	multiplier int64
}{
	{"kib", 1 << 10},
	{"mib", 1 << 20},
	{"gib", 1 << 30},
	{"tib", 1 << 40},
	{"kb", 1000},
	{"mb", 1000 * 1000},
	{"gb", 1000 * 1000 * 1000},
	{"tb", 1000 * 1000 * 1000 * 1000},
	{"b", 1},
}

// parseByteSize parses a human byte-size string like "128MiB",
// "10MB", "512KiB", or a bare number of bytes ("1048576"). Units are
// case-insensitive. Binary units (KiB/MiB/GiB/TiB, base 1024) and
// decimal units (KB/MB/GB/TB, base 1000) are both accepted; a bare
// "B" or no suffix means bytes.
func parseByteSize(s string) (int64, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return 0, fmt.Errorf("%w: empty value", ErrInvalidMemory)
	}

	lower := strings.ToLower(trimmed)
	for _, u := range byteUnits {
		if strings.HasSuffix(lower, u.suffix) {
			numPart := strings.TrimSpace(trimmed[:len(trimmed)-len(u.suffix)])
			if numPart == "" {
				return 0, fmt.Errorf("%w: %q", ErrInvalidMemory, s)
			}
			n, err := strconv.ParseFloat(numPart, 64)
			if err != nil {
				return 0, fmt.Errorf("%w: %q", ErrInvalidMemory, s)
			}
			if n < 0 {
				return 0, fmt.Errorf("%w: negative size %q", ErrInvalidMemory, s)
			}
			return int64(n * float64(u.multiplier)), nil
		}
	}

	// No recognized unit suffix: must be a bare integer byte count.
	n, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%w: %q", ErrInvalidMemory, s)
	}
	return n, nil
}

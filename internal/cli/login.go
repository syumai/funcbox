package cli

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"
)

// §7.5): prompt for (or accept via stdin) an API token, verify it against
// GET /api/v1/me, and save {server, token} to the CLI config file.
func RunLogin(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(stderr)
	server := fs.String("server", "", "funcbox server URL (e.g. https://fb.example.com)")
	if _, err := parseFlagsInterspersed(fs, args); err != nil {
		return err
	}

	if *server == "" {
		existing, err := LoadConfig()
		if err == nil && existing.Server != "" {
			*server = existing.Server
		}
	}
	if *server == "" {
		return fmt.Errorf("--server is required (no existing config to fall back to)")
	}
	*server = strings.TrimSuffix(*server, "/")

	fmt.Fprint(stderr, "API token: ")
	token, err := readLine(stdin)
	if err != nil {
		return fmt.Errorf("cli: read API token: %w", err)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("API token must not be empty")
	}

	client := NewClient(Config{Server: *server, Token: token})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	me, err := client.Me(ctx)
	if err != nil {
		return fmt.Errorf("token verification failed: %w", err)
	}

	if err := SaveConfig(Config{Server: *server, Token: token}); err != nil {
		return err
	}

	path, _ := ConfigPath()
	email, _ := me["email"].(string)
	fmt.Fprintf(stdout, "Logged in as %s to %s\n", email, *server)
	fmt.Fprintf(stdout, "Config saved to %s\n", path)
	return nil
}

// readLine reads a single line from r (without requiring a real terminal,
// so a token can also be piped in non-interactively:
// `echo "$TOKEN" | funcbox login --server ...`).
func readLine(r io.Reader) (string, error) {
	reader := bufio.NewReader(r)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		if err == io.EOF {
			return "", fmt.Errorf("no input")
		}
		return "", err
	}
	return line, nil
}

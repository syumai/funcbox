// login.go implements `funcbox login` (§14.4 of
// tmp/14-auth-and-pool-improvements.md): the loopback+PKCE browser login
// flow that replaces the old paste-an-API-token prompt.
//
//  1. Generate a PKCE code_verifier/challenge pair and start a 127.0.0.1
//     listener on a random port.
//  2. Open the dashboard's CLI-login approval page in the user's browser,
//     carrying the loopback callback URL, the PKCE challenge, and this
//     device's hostname.
//  3. The user reviews and explicitly approves the request in the browser
//     (never automatic) -- see the server side's own doc comments
//     (server/internal/auth/cliauth.go, server/dashboard's
//     routes/cliAuth.tsx) for why that step can't be skipped.
//  4. The approved browser redirects back to the loopback listener with a
//     one-time authorization code, which this process exchanges (together
//     with the PKCE verifier only it ever held) for a CLI login credential
//     via the unauthenticated POST /api/v1/cli/token.
//  5. The credential is saved to the CLI config file, 0600.
package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// loginTimeout bounds how long funcbox login waits for the browser
// approval round trip to complete before giving up.
const loginTimeout = 5 * time.Minute

// RunLogin drives the loopback+PKCE browser login flow end to end and
// saves the resulting CLI credential to the config file.
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

	ctx, cancel := context.WithTimeout(context.Background(), loginTimeout)
	defer cancel()

	credential, err := loginViaBrowser(ctx, *server, stdout, stderr)
	if err != nil {
		return err
	}

	if err := SaveConfig(Config{Server: *server, Credential: credential}); err != nil {
		return err
	}

	path, _ := ConfigPath()
	fmt.Fprintf(stdout, "Logged in to %s\n", *server)
	fmt.Fprintf(stdout, "Config saved to %s\n", path)
	return nil
}

// loginViaBrowser implements this file's doc comment's steps 1-5,
// returning the freshly minted CLI credential.
func loginViaBrowser(ctx context.Context, server string, stdout, stderr io.Writer) (string, error) {
	verifier, challenge, err := generatePKCE()
	if err != nil {
		return "", err
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("cli: start loopback listener: %w", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown device"
	}

	authURL := fmt.Sprintf("%s/dashboard/cli-auth?redirect=%s&challenge=%s&name=%s",
		server, url.QueryEscape(redirect), url.QueryEscape(challenge), url.QueryEscape(hostname))

	type callbackResult struct {
		code string
		err  error
	}
	resultCh := make(chan callbackResult, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if errParam := r.URL.Query().Get("error"); errParam != "" {
			fmt.Fprint(w, loopbackFailureHTML)
			select {
			case resultCh <- callbackResult{err: fmt.Errorf("cli: login was not approved (%s)", errParam)}:
			default:
			}
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing authorization code", http.StatusBadRequest)
			select {
			case resultCh <- callbackResult{err: errors.New("cli: loopback callback missing an authorization code")}:
			default:
			}
			return
		}
		fmt.Fprint(w, loopbackSuccessHTML)
		select {
		case resultCh <- callbackResult{code: code}:
		default:
		}
	})
	httpSrv := &http.Server{Handler: mux}
	go httpSrv.Serve(listener) //nolint:errcheck // Close below always returns http.ErrServerClosed
	defer httpSrv.Close()

	fmt.Fprintf(stderr, "Opening your browser to approve this login...\n%s\n", authURL)
	if err := openBrowserHook(authURL); err != nil {
		fmt.Fprintf(stderr, "Could not open a browser automatically (%v). Open this URL manually:\n%s\n", err, authURL)
	}

	var code string
	select {
	case res := <-resultCh:
		if res.err != nil {
			return "", res.err
		}
		code = res.code
	case <-ctx.Done():
		return "", fmt.Errorf("cli: timed out waiting for browser approval; run `funcbox login` again")
	}

	client := NewClient(Config{Server: server})
	credential, err := client.ExchangeCLICode(ctx, code, verifier)
	if err != nil {
		return "", fmt.Errorf("cli: exchange authorization code: %w", err)
	}
	fmt.Fprintln(stdout, "Login approved.")
	return credential, nil
}

// generatePKCE returns a fresh RFC 7636 code_verifier and its S256
// challenge (base64url, no padding, of the verifier's SHA-256 digest).
func generatePKCE() (verifier, challenge string, err error) {
	buf := make([]byte, 32) // 256 bits of entropy
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("cli: generate PKCE verifier: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// openBrowserHook is what loginViaBrowser actually calls to "open the
// browser" -- a package variable (rather than calling openBrowser
// directly) so this file's own tests can substitute an http.Client that
// drives the loopback callback itself, exactly the way a real browser
// would after the user approves, instead of either spawning a real OS
// browser process or skipping the step entirely.
var openBrowserHook = openBrowser

// openBrowser opens url in the platform's default browser. darwin uses
// `open` (per §14.4's decision); other platforms make a best effort with
// their own equivalent. Callers must treat a non-nil error as
// non-fatal -- print url and let the user open it manually.
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}

const loopbackSuccessHTML = `<!doctype html>
<html><head><meta charset="utf-8"><title>funcbox login</title></head>
<body style="font-family:sans-serif;padding:40px;max-width:480px;margin:0 auto">
<h1>Login approved</h1>
<p>You can close this tab and return to your terminal.</p>
</body></html>`

const loopbackFailureHTML = `<!doctype html>
<html><head><meta charset="utf-8"><title>funcbox login</title></head>
<body style="font-family:sans-serif;padding:40px;max-width:480px;margin:0 auto">
<h1>Login not completed</h1>
<p>Return to your terminal; you can safely close this tab.</p>
</body></html>`

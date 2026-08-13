package auth

import "testing"

func TestIsLoopbackAddr(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:8080", true},
		{"localhost:8080", true},
		{"[::1]:8080", true},
		{":8080", false}, // all interfaces -- the exact footgun this guards against
		{"0.0.0.0:8080", false},
		{"192.168.1.5:8080", false},
		{"example.com:8080", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isLoopbackAddr(tt.addr); got != tt.want {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

func TestNew_DevModeRequiresLoopback(t *testing.T) {
	st := newTestStore(t)
	_, err := New(Config{
		Mode:          ModeDev,
		BaseURL:       "http://0.0.0.0:8080",
		ListenAddr:    "0.0.0.0:8080",
		SessionSecret: "test-secret",
	}, st)
	if err == nil {
		t.Fatal("New with dev mode on a non-loopback address should fail")
	}
}

func TestNew_DevModeAcceptsLoopback(t *testing.T) {
	st := newTestStore(t)
	a, err := New(Config{
		Mode:          ModeDev,
		BaseURL:       "http://127.0.0.1:8080",
		ListenAddr:    "127.0.0.1:8080",
		SessionSecret: "test-secret",
	}, st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.dev == nil {
		t.Fatal("dev mode Auth should have a non-nil stub identity provider")
	}
	if a.DevRoutes() == nil {
		t.Fatal("DevRoutes() should be non-nil in dev mode")
	}
}

func TestNew_GoogleModeRequiresClientCredentials(t *testing.T) {
	st := newTestStore(t)
	_, err := New(Config{
		Mode:          ModeGoogle,
		BaseURL:       "https://funcbox.example.com",
		SessionSecret: "test-secret",
	}, st)
	if err == nil {
		t.Fatal("New in google mode without client credentials should fail")
	}
}

func TestNew_GoogleModeHasNoDevRoutes(t *testing.T) {
	st := newTestStore(t)
	a, err := New(Config{
		Mode:          ModeGoogle,
		BaseURL:       "https://funcbox.example.com",
		ClientID:      "client-id",
		ClientSecret:  "client-secret",
		SessionSecret: "test-secret",
	}, st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.DevRoutes() != nil {
		t.Fatal("DevRoutes() should be nil outside dev mode")
	}
}

func TestNew_RequiresSessionSecret(t *testing.T) {
	st := newTestStore(t)
	_, err := New(Config{
		Mode:         ModeGoogle,
		BaseURL:      "https://funcbox.example.com",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}, st)
	if err == nil {
		t.Fatal("New without SessionSecret should fail")
	}
}

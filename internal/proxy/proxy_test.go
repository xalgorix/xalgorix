package proxy

import (
	"testing"
)

func TestParsePlainNoAuth(t *testing.T) {
	p, err := Parse("127.0.0.1:8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Host != "127.0.0.1" || p.Port != "8080" {
		t.Fatalf("wrong host/port: %s:%s", p.Host, p.Port)
	}
	if p.Username != "" {
		t.Fatal("expected no username")
	}
	if p.Type != ProxyTypeHTTP {
		t.Fatalf("expected HTTP, got %s", p.Type)
	}
}

func TestParsePlainWithAuth(t *testing.T) {
	p, err := Parse("192.168.1.1:3128:alice:s3cr3t")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Host != "192.168.1.1" || p.Port != "3128" {
		t.Fatalf("wrong host/port: %s:%s", p.Host, p.Port)
	}
	if p.Username != "alice" || p.Password != "s3cr3t" {
		t.Fatalf("wrong credentials: %s/%s", p.Username, p.Password)
	}
}

func TestParseSOCKS5URI(t *testing.T) {
	p, err := Parse("socks5://10.0.0.1:1080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Type != ProxyTypeSOCKS5 {
		t.Fatalf("expected SOCKS5, got %s", p.Type)
	}
	if p.Host != "10.0.0.1" || p.Port != "1080" {
		t.Fatalf("wrong host/port: %s:%s", p.Host, p.Port)
	}
}

func TestParseSOCKS5URIWithAuth(t *testing.T) {
	p, err := Parse("socks5://bob:pass123@10.0.0.2:1080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Username != "bob" || p.Password != "pass123" {
		t.Fatalf("wrong credentials: %s/%s", p.Username, p.Password)
	}
}

func TestParseHTTPURI(t *testing.T) {
	p, err := Parse("http://proxy.example.com:3128")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Type != ProxyTypeHTTP {
		t.Fatalf("expected HTTP, got %s", p.Type)
	}
}

func TestParseInvalid(t *testing.T) {
	cases := []string{
		"",
		"justhost",
		"a:b:c",
		"a:b:c:d:e",
	}
	for _, c := range cases {
		_, err := Parse(c)
		if err == nil {
			t.Errorf("expected error for %q, got nil", c)
		}
	}
}

func TestProxyURL(t *testing.T) {
	p := &Proxy{Type: ProxyTypeHTTP, Host: "127.0.0.1", Port: "8080"}
	u, err := p.URL()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.Host != "127.0.0.1:8080" {
		t.Fatalf("wrong URL: %s", u)
	}
}

func TestProxyURLPreservesEscapedCredentialsAndIPv6(t *testing.T) {
	p := &Proxy{Type: ProxyTypeHTTP, Host: "::1", Port: "8080", Username: "user@name", Password: "a b:c@d"}
	u, err := p.URL()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(u.String())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Host != p.Host || parsed.Port != p.Port || parsed.Username != p.Username || parsed.Password != p.Password {
		t.Fatalf("proxy URL round trip mismatch: host=%q port=%q user=%q", parsed.Host, parsed.Port, parsed.Username)
	}
}

func TestPoolNextRotation(t *testing.T) {
	pool := NewPool([]string{"1.1.1.1:8080", "2.2.2.2:8080", "3.3.3.3:8080"})
	if pool.Len() != 3 {
		t.Fatalf("expected 3, got %d", pool.Len())
	}
	seen := map[string]bool{}
	for i := 0; i < 9; i++ {
		p := pool.Next()
		if p == nil {
			t.Fatal("got nil from non-empty pool")
		}
		seen[p.Host] = true
	}
	if len(seen) != 3 {
		t.Fatalf("round-robin did not cycle through all proxies, seen: %v", seen)
	}
}

func TestPoolRandom(t *testing.T) {
	pool := NewPool([]string{"1.1.1.1:8080", "2.2.2.2:8080"})
	for i := 0; i < 10; i++ {
		if pool.Random() == nil {
			t.Fatal("got nil from non-empty pool")
		}
	}
}

func TestEmptyPool(t *testing.T) {
	pool := NewPool([]string{})
	if pool.Next() != nil {
		t.Fatal("expected nil from empty pool")
	}
	if pool.Random() != nil {
		t.Fatal("expected nil from empty pool")
	}
}

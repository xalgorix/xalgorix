package scanctx

import (
	"sync"
	"testing"
)

func TestCoverageStoreSharesExactPairsConcurrently(t *testing.T) {
	store := NewCoverageStore()
	const workers = 24
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store.Mark("example.test/api/users", "sqli")
		}()
	}
	wg.Wait()

	if !store.Has("example.test/api/users", "sqli") {
		t.Fatal("recorded endpoint/class pair is missing")
	}
	if !store.HasEndpoint("example.test/api/users") {
		t.Fatal("recorded endpoint should have matrix evidence")
	}
	if store.Has("example.test/api/users", "xss") {
		t.Fatal("coverage for one class must not imply another class")
	}
	if store.Has("example.test/api/admin", "sqli") {
		t.Fatal("coverage for one endpoint must not imply another endpoint")
	}
}

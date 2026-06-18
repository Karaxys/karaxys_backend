package securetoken

import "testing"

func TestGenerateAddsPrefixAndProducesDistinctValues(t *testing.T) {
	first, err := Generate("kx_test")
	if err != nil {
		t.Fatalf("generate first token: %v", err)
	}
	second, err := Generate("kx_test")
	if err != nil {
		t.Fatalf("generate second token: %v", err)
	}
	if first == second {
		t.Fatalf("expected distinct tokens")
	}
	if len(first) <= len("kx_test_") || first[:len("kx_test_")] != "kx_test_" {
		t.Fatalf("unexpected token prefix: %s", first)
	}
}

func TestHashIsStableAndDoesNotExposeToken(t *testing.T) {
	token := "kx_test_secret"
	first := Hash(token)
	second := Hash(token)
	if first != second {
		t.Fatalf("hash should be stable")
	}
	if first == token || first == "" {
		t.Fatalf("hash should not expose raw token")
	}
}

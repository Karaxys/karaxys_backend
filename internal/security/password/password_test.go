package password

import "testing"

func TestHashRejectsWeakPassword(t *testing.T) {
	if _, err := Hash("short"); err != ErrWeakPassword {
		t.Fatalf("expected weak password error, got %v", err)
	}
}

func TestHashAndVerify(t *testing.T) {
	hash, err := Hash("correct-horse-battery")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if !Verify(hash, "correct-horse-battery") {
		t.Fatalf("expected password to verify")
	}
	if Verify(hash, "wrong-password") {
		t.Fatalf("wrong password verified")
	}
}

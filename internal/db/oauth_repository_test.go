package db

import (
	"errors"
	"testing"
)

func TestDecideOAuthAction(t *testing.T) {
	cases := []struct {
		name           string
		identityExists bool
		userByEmail    bool
		emailVerified  bool
		want           oauthAction
		wantErr        error
	}{
		{name: "existing identity logs in", identityExists: true, want: oauthActionUseIdentity},
		{name: "existing identity ignores email state", identityExists: true, userByEmail: true, emailVerified: false, want: oauthActionUseIdentity},
		{name: "verified email links to existing user", userByEmail: true, emailVerified: true, want: oauthActionLinkByEmail},
		{name: "unverified email refuses linking", userByEmail: true, emailVerified: false, wantErr: ErrOAuthEmailUnverified},
		{name: "no match creates new", want: oauthActionCreateNew},
		{name: "verified email but no local user creates new", emailVerified: true, want: oauthActionCreateNew},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decideOAuthAction(tc.identityExists, tc.userByEmail, tc.emailVerified)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected error %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("decideOAuthAction = %d, want %d", got, tc.want)
			}
		})
	}
}

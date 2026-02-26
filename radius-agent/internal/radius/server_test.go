package radius

import (
	"testing"
)

func TestSplitPasswordTOTP(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantPass string
		wantTOTP string
	}{
		{
			name:     "password + 6-digit TOTP",
			input:    "MyPassword123456",
			wantPass: "MyPassword",
			wantTOTP: "123456",
		},
		{
			name:     "short password + TOTP",
			input:    "pw123456",
			wantPass: "pw",
			wantTOTP: "123456",
		},
		{
			name:     "only TOTP (6 digits)",
			input:    "123456",
			wantPass: "",
			wantTOTP: "123456",
		},
		{
			name:     "very long password + TOTP",
			input:    "ThisIsAVeryLongPassword!@#$%789012",
			wantPass: "ThisIsAVeryLongPassword!@#$%",
			wantTOTP: "789012",
		},
		{
			name:     "empty input returns empty",
			input:    "",
			wantPass: "",
			wantTOTP: "",
		},
		{
			name:     "5 chars or less treated as TOTP only",
			input:    "12345",
			wantPass: "",
			wantTOTP: "12345",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pass, totp := splitPasswordTOTP(tc.input)
			if pass != tc.wantPass {
				t.Errorf("password: expected '%s', got '%s'", tc.wantPass, pass)
			}
			if totp != tc.wantTOTP {
				t.Errorf("totp: expected '%s', got '%s'", tc.wantTOTP, totp)
			}
		})
	}
}

package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectedErr error
	}{
		{
			name:        "no authorization header",
			headers:     http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "valid ApiKey header",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key"},
			},
			expectedKey: "wrong-key",
			expectedErr: nil,
		},
		{
			name: "malformed header - wrong scheme",
			headers: http.Header{
				"Authorization": []string{"Bearer my-token"},
			},
			expectedKey: "",
			expectedErr: nil, // non-nil error, checked separately
		},
		{
			name: "malformed header - missing key value",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey: "",
			expectedErr: nil, // non-nil error, checked separately
		},
		{
			name: "malformed header - empty string",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			// Cases where we expect a specific sentinel error
			if tt.expectedErr != nil {
				if err != tt.expectedErr {
					t.Errorf("expected error %v, got %v", tt.expectedErr, err)
				}
				return
			}

			// Cases where we expect a malformed error (non-nil, non-sentinel)
			if tt.expectedKey == "" && tt.expectedErr == nil {
				if err == nil {
					t.Errorf("expected an error, got nil")
				}
				return
			}

			// Happy path
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}
		})
	}
}
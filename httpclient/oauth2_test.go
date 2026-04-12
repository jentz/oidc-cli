package httpclient

import "testing"

func TestCustomArgs_Set(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		args    CustomArgs
		input   string
		wantErr bool
		wantKey string
		wantVal string
	}{
		{
			name:    "valid key-value pair",
			args:    make(CustomArgs),
			input:   "scope=openid profile",
			wantErr: false,
			wantKey: "scope",
			wantVal: "openid profile",
		},
		{
			name:    "valid with equals in value",
			args:    make(CustomArgs),
			input:   "redirect_uri=https://example.com?param=value",
			wantErr: false,
			wantKey: "redirect_uri",
			wantVal: "https://example.com?param=value",
		},
		{
			name:    "invalid format - no equals",
			args:    make(CustomArgs),
			input:   "invalid_format",
			wantErr: true,
		},
		{
			name:    "invalid format - only key",
			args:    make(CustomArgs),
			input:   "key=",
			wantErr: false,
			wantKey: "key",
			wantVal: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.args.Set(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("CustomArgs.Set() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				got := tt.args[tt.wantKey]
				if got != tt.wantVal {
					t.Errorf("CustomArgs[%s] = %q, want %q", tt.wantKey, got, tt.wantVal)
				}
			}
		})
	}
}

func TestAuthMethod_IsValid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		method AuthMethod
		want   bool
	}{
		{"valid basic", AuthMethodBasic, true},
		{"valid post", AuthMethodPost, true},
		{"valid none", AuthMethodNone, true},
		{"invalid method", AuthMethod("invalid"), false},
		{"empty method", AuthMethod(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.method.IsValid()
			if got != tt.want {
				t.Errorf("AuthMethod.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthMethod_String(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		method AuthMethod
		want   string
	}{
		{"basic method", AuthMethodBasic, "client_secret_basic"},
		{"post method", AuthMethodPost, "client_secret_post"},
		{"none method", AuthMethodNone, "none"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.method.String()
			if got != tt.want {
				t.Errorf("AuthMethod.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAuthMethod_Set(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		value   string
		wantErr bool
		want    AuthMethod
	}{
		{
			name:    "valid basic",
			value:   "client_secret_basic",
			wantErr: false,
			want:    AuthMethodBasic,
		},
		{
			name:    "valid post",
			value:   "client_secret_post",
			wantErr: false,
			want:    AuthMethodPost,
		},
		{
			name:    "valid none",
			value:   "none",
			wantErr: false,
			want:    AuthMethodNone,
		},
		{
			name:    "invalid method",
			value:   "invalid_method",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var method AuthMethod
			err := method.Set(tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("AuthMethod.Set() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && method != tt.want {
				t.Errorf("AuthMethod.Set() = %v, want %v", method, tt.want)
			}
		})
	}
}

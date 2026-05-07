package factory

import "testing"

func TestCnRegexp_Wildcards(t *testing.T) {
	cases := []struct {
		name string
		cn   string
		want bool
	}{
		// Existing valid CNs still validate.
		{"plain hostname", "kubernetes", true},
		{"two-label FQDN", "foo.example.com", true},
		{"multi-label FQDN", "a.b.c.example.com", true},
		{"IPv4", "127.0.0.1", true},
		{"IPv6", "2001:db8::1", true},

		// New: RFC 6125 single-label leading wildcard.
		{"leading wildcard, two-label parent", "*.example.com", true},
		{"leading wildcard, multi-label parent", "*.foo.bar.example.com", true},
		{"leading wildcard, single-char label after", "*.a", true},

		// Still rejected: invalid wildcard forms.
		{"bare wildcard", "*", false},
		{"multi-label wildcard", "*.*.example.com", false},
		{"embedded wildcard", "foo*.example.com", false},
		{"prefix wildcard", "*foo.example.com", false},
		{"double leading wildcard", "**.example.com", false},
		{"trailing dot FQDN", "*.example.com.", false},
		{"empty", "", false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := cnRegexp.MatchString(tt.cn)
			if got != tt.want {
				t.Errorf("cnRegexp.MatchString(%q) = %v, want %v", tt.cn, got, tt.want)
			}
		})
	}
}

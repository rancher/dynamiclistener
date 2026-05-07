package factory

import (
	"regexp"
	"strings"
	"testing"

	v1 "k8s.io/api/core/v1"
)

var hashSuffixRe = regexp.MustCompile(`-[0-9a-f]{6}$`)

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

func TestGetAnnotationKey_EscapesWildcard(t *testing.T) {
	cases := []struct {
		name string
		cn   string
	}{
		{"two-label wildcard", "*.example.com"},
		{"multi-label wildcard", "*.foo.bar.example.com"},
		{"long wildcard hostname", "*.this-is-a-very-long-subdomain-that-makes-the-whole-thing-exceed-sixty-three.example.com"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			key := getAnnotationKey(tt.cn)

			if strings.ContainsRune(key, '*') {
				t.Errorf("getAnnotationKey(%q) = %q, contains '*' (invalid in K8s annotation keys)", tt.cn, key)
			}

			nameLen := len(strings.TrimPrefix(key, cnPrefix))
			if nameLen >= 64 {
				t.Errorf("getAnnotationKey(%q) name part is %d chars, must be < 64", tt.cn, nameLen)
			}

			if got := getAnnotationKey(tt.cn); got != key {
				t.Errorf("getAnnotationKey(%q) is not deterministic: %q vs %q", tt.cn, key, got)
			}
		})
	}
}

func TestGetAnnotationKey_IPv6AndWildcardCoexist(t *testing.T) {
	t.Run("IPv6 still escaped", func(t *testing.T) {
		ipv6 := getAnnotationKey("2001:db8::1")
		if strings.ContainsRune(ipv6, ':') {
			t.Errorf("getAnnotationKey(IPv6) = %q, contains ':'", ipv6)
		}
	})

	t.Run("wildcard and colon coexist", func(t *testing.T) {
		mixed := getAnnotationKey("*.foo:bar.example.com")
		if strings.ContainsAny(mixed, "*:") {
			t.Errorf("getAnnotationKey(mixed) = %q, contains '*' or ':'", mixed)
		}
	})
}

func TestGetAnnotationKey_LongWildcardHostname(t *testing.T) {
	cn := "*.really.long.subdomain.example.com.foo.bar.baz.thing.thing.thing"
	key := getAnnotationKey(cn)

	nameLen := len(strings.TrimPrefix(key, cnPrefix))
	if nameLen >= 64 {
		t.Errorf("name part is %d chars, must be < 64", nameLen)
	}
	if !hashSuffixRe.MatchString(key) {
		t.Errorf("expected hash suffix '-XXXXXX' (6 hex chars) at end of %q", key)
	}
	if strings.ContainsRune(key, '*') {
		t.Errorf("key %q contains '*'", key)
	}
}

func TestIsCoveredByWildcard(t *testing.T) {
	cases := []struct {
		name     string
		cn       string
		existing []string
		want     bool
	}{
		{"wildcard covers single-label match", "foo.example.com", []string{"*.example.com"}, true},
		{"wildcard covers when other entries also present", "a.example.com", []string{"foo.example.com", "*.example.com"}, true},
		{"wildcard does not cover multi-label", "a.b.example.com", []string{"*.example.com"}, false},
		{"wildcard does not cover apex", "example.com", []string{"*.example.com"}, false},
		{"no wildcard in existing", "foo.example.com", []string{"foo.example.com", "bar.example.com"}, false},
		{"wildcard cn never covered (exact wildcard)", "*.example.com", []string{"*.example.com"}, false},
		{"wildcard cn never covered (more specific)", "*.foo.example.com", []string{"*.example.com"}, false},
		{"wrong parent", "foo.evil.com", []string{"*.example.com"}, false},
		{"cn with no dot cannot be covered", "localhost", []string{"*.localhost"}, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := isCoveredByWildcard(tt.cn, tt.existing)
			if got != tt.want {
				t.Errorf("isCoveredByWildcard(%q, %v) = %v, want %v", tt.cn, tt.existing, got, tt.want)
			}
		})
	}
}

func makeSecretWithCNs(cns ...string) *v1.Secret {
	s := &v1.Secret{}
	s.Annotations = map[string]string{}
	for _, cn := range cns {
		s.Annotations[getAnnotationKey(cn)] = cn
	}
	return s
}

func TestNeedsUpdate_WildcardCovers(t *testing.T) {
	secret := makeSecretWithCNs("*.example.com")

	t.Run("subdomain covered by wildcard", func(t *testing.T) {
		if NeedsUpdate(0, secret, "foo.example.com") {
			t.Error("NeedsUpdate should be false: foo.example.com is covered by *.example.com")
		}
	})
	t.Run("multi-label not covered", func(t *testing.T) {
		if !NeedsUpdate(0, secret, "a.b.example.com") {
			t.Error("NeedsUpdate should be true: a.b.example.com is multi-label, not covered")
		}
	})
	t.Run("apex not covered", func(t *testing.T) {
		if !NeedsUpdate(0, secret, "example.com") {
			t.Error("NeedsUpdate should be true: example.com is the apex, not covered by *.example.com")
		}
	})
}

func TestNeedsUpdate_WildcardDoesNotCoverWildcard(t *testing.T) {
	secret := makeSecretWithCNs("*.example.com")

	t.Run("exact wildcard match", func(t *testing.T) {
		if NeedsUpdate(0, secret, "*.example.com") {
			t.Error("NeedsUpdate should be false: exact wildcard match")
		}
	})
	t.Run("more specific wildcard not covered", func(t *testing.T) {
		if !NeedsUpdate(0, secret, "*.foo.example.com") {
			t.Error("NeedsUpdate should be true: *.foo.example.com is a different wildcard")
		}
	})
}

func TestNeedsUpdate_WildcardCountsAsOneSAN(t *testing.T) {
	t.Run("room for one more SAN", func(t *testing.T) {
		secret := makeSecretWithCNs("a", "b", "c", "d", "e", "f", "g", "h", "i")
		if !NeedsUpdate(10, secret, "*.new.com") {
			t.Error("NeedsUpdate should be true: room for one more SAN")
		}
	})
	t.Run("MaxSANs reached", func(t *testing.T) {
		secret := makeSecretWithCNs("a", "b", "c", "d", "e", "f", "g", "h", "i", "j")
		if NeedsUpdate(10, secret, "*.new.com") {
			t.Error("NeedsUpdate should be false: MaxSANs reached")
		}
	})
}

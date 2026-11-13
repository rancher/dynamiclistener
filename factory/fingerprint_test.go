package factory

import (
	"crypto/fips140"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
)

// setFIPS overrides the mode the code under test sees. SHA-1 cannot run in a
// process that enforces fips140=only, so legacy cases skip there.
func setFIPS(t *testing.T, enabled bool) {
	t.Helper()
	if !enabled && fips140.Enforced() {
		t.Skip("SHA-1 is not available under GODEBUG=fips140=only")
	}
	prev := fipsEnabled
	fipsEnabled = func() bool { return enabled }
	t.Cleanup(func() { fipsEnabled = prev })
}

func leafDER(t *testing.T, secret *v1.Secret) []byte {
	t.Helper()
	block, _ := pem.Decode(secret.Data[v1.TLSCertKey])
	require.NotNil(t, block)
	return block.Bytes
}

func TestFingerprint_KnownAnswer(t *testing.T) {
	raw := []byte("dynamiclistener fingerprint known answer")

	t.Run("fips=false", func(t *testing.T) {
		setFIPS(t, false)
		assert.Equal(t, "SHA1=362C8A0E404BE55D7B5886D3BE683AFC17967535", fingerprint(raw))
	})
	t.Run("fips=true", func(t *testing.T) {
		setFIPS(t, true)
		assert.Equal(t, "SHA256=6721774C5AF1746F1AA67F4CC0C338E27FDCC586BF56E7FB710AC19B1B360EB0", fingerprint(raw))
	})
}

func wantFingerprint(der []byte, fips bool) string {
	if fips {
		return fmt.Sprintf("SHA256=%X", sha256.Sum256(der))
	}
	return fmt.Sprintf("SHA1=%X", sha1.Sum(der))
}

func TestGenerateCert_FingerprintFollowsMode(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("fips=%v", enabled), func(t *testing.T) {
			setFIPS(t, enabled)
			secret, _, err := newTestTLS(t).AddCN(nil, "a.example.com")
			require.NoError(t, err)

			der := leafDER(t, secret)
			assert.Equal(t, wantFingerprint(der, enabled), secret.Annotations[Fingerprint])
		})
	}
}

// Runs against the real mode, so it covers GODEBUG=fips140=on and =only.
func TestGenerateCert_FingerprintInProcessMode(t *testing.T) {
	secret, _, err := newTestTLS(t).AddCN(nil, "a.example.com")
	require.NoError(t, err)

	der := leafDER(t, secret)
	assert.Equal(t, wantFingerprint(der, fips140.Enabled()), secret.Annotations[Fingerprint])
}

// A secret written in one mode is not regenerated or relabelled when the
// process later runs in the other mode.
func TestMerge_ModeSwitchKeepsFingerprint(t *testing.T) {
	for _, from := range []bool{false, true} {
		t.Run(fmt.Sprintf("from fips=%v", from), func(t *testing.T) {
			tlsFactory := newTestTLS(t)
			setFIPS(t, from)
			existing, _, err := tlsFactory.AddCN(nil, "a.example.com")
			require.NoError(t, err)
			before := existing.Annotations[Fingerprint]
			cert := string(existing.Data[v1.TLSCertKey])

			setFIPS(t, !from)
			merged, _, err := tlsFactory.Merge(existing, existing.DeepCopy())
			require.NoError(t, err)

			assert.Equal(t, before, merged.Annotations[Fingerprint])
			assert.Equal(t, cert, string(merged.Data[v1.TLSCertKey]))
		})
	}
}

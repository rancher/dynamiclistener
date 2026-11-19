package factory

import (
	"crypto/fips140"
	"crypto/sha1"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateCert_SHA1FingerprintUnderFIPSOnly(t *testing.T) {
	if os.Getenv("FINGERPRINT_CHILD") == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestGenerateCert_SHA1FingerprintUnderFIPSOnly$")
		cmd.Env = append(os.Environ(), "FINGERPRINT_CHILD=1", "GODEBUG=fips140=only")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
		return
	}
	require.True(t, fips140.Enforced())

	secret, _, err := newTestTLS(t).AddCN(nil, "a.example.com")
	require.NoError(t, err)

	block, _ := pem.Decode(secret.Data["tls.crt"])
	require.NotNil(t, block)
	var want string
	fips140.WithoutEnforcement(func() {
		want = fmt.Sprintf("SHA1=%X", sha1.Sum(block.Bytes))
	})
	assert.Equal(t, want, secret.Annotations[Fingerprint])
}

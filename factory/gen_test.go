package factory

import (
	"crypto/x509"
	"testing"

	"github.com/rancher/dynamiclistener/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newTestTLS(t *testing.T) *TLS {
	t.Helper()
	caKey, err := NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	caCert, err := NewSelfSignedCACert(caKey, "test-ca", "test-org")
	if err != nil {
		t.Fatalf("NewSelfSignedCACert: %v", err)
	}
	return &TLS{
		CACert:       []*x509.Certificate{caCert},
		CAKey:        caKey,
		CN:           "test-cn",
		Organization: []string{"test-org"},
	}
}

// --- secretWithCNs helper for FilterExisting tests ---

// secretWithCNs returns a dynamiclistener-managed TLS secret pre-populated
// with the given CNs in its cnPrefix annotations plus real cert data.
func secretWithCNs(t *testing.T, tls *TLS, cns ...string) *v1.Secret {
	t.Helper()
	s := &v1.Secret{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{}}}
	result, _, err := tls.generateCert(s, cns...)
	require.NoError(t, err)
	return result
}

// onlyAllow returns a FilterCN that keeps only the listed CNs.
func onlyAllow(allowed ...string) func(...string) []string {
	set := make(map[string]bool, len(allowed))
	for _, cn := range allowed {
		set[cn] = true
	}
	return func(cns ...string) []string {
		var out []string
		for _, cn := range cns {
			if set[cn] {
				out = append(out, cn)
			}
		}
		return out
	}
}

// --- hasStaleCNs ---

func TestHasStaleCNs_NilFilter(t *testing.T) {
	t.Parallel()
	tls := newTestTLS(t)
	s := secretWithCNs(t, tls, "live.example.com", "dead.example.com")
	assert.False(t, tls.hasStaleCNs(s))
}

func TestHasStaleCNs_NoStale(t *testing.T) {
	t.Parallel()
	tls := newTestTLS(t)
	tls.FilterCN = onlyAllow("live.example.com")
	tls.FilterExisting = true
	s := secretWithCNs(t, tls, "live.example.com")
	assert.False(t, tls.hasStaleCNs(s), "no stale CNs expected")
}

func TestHasStaleCNs_WithStale(t *testing.T) {
	t.Parallel()
	tls := newTestTLS(t)
	tls.FilterCN = onlyAllow("live.example.com")
	tls.FilterExisting = true
	s := secretWithCNs(t, tls, "live.example.com")
	s.Annotations[getAnnotationKey("dead.example.com")] = "dead.example.com"
	assert.True(t, tls.hasStaleCNs(s), "dead.example.com should be stale")
}

// --- pruneAnnotations ---

func TestPruneAnnotations_NilFilter(t *testing.T) {
	t.Parallel()
	tls := newTestTLS(t)
	s := secretWithCNs(t, tls, "a.example.com", "b.example.com")
	before := len(cns(s))
	tls.pruneAnnotations(s)
	assert.Equal(t, before, len(cns(s)), "FilterExisting=false must not prune anything")
}

func TestPruneAnnotations_RemovesStale(t *testing.T) {
	t.Parallel()
	tls := newTestTLS(t)
	tls.FilterCN = onlyAllow("live.example.com")
	tls.FilterExisting = true
	s := secretWithCNs(t, tls, "live.example.com")
	s.Annotations[getAnnotationKey("dead.example.com")] = "dead.example.com"

	tls.pruneAnnotations(s)

	remaining := cns(s)
	assert.Len(t, remaining, 1)
	assert.Contains(t, remaining, "live.example.com")
	assert.NotContains(t, remaining, "dead.example.com")
}

func TestPruneAnnotations_PreservesNonCNAnnotations(t *testing.T) {
	t.Parallel()
	tls := newTestTLS(t)
	tls.FilterCN = onlyAllow("live.example.com")
	tls.FilterExisting = true
	s := secretWithCNs(t, tls, "live.example.com")
	s.Annotations[getAnnotationKey("dead.example.com")] = "dead.example.com"
	s.Annotations["custom/annotation"] = "preserved"

	tls.pruneAnnotations(s)

	assert.Equal(t, "preserved", s.Annotations["custom/annotation"],
		"non-CN annotations must be preserved")
}

// --- Merge with FilterExisting ---

func TestMerge_StaleInTarget_ForcesRegeneration(t *testing.T) {
	t.Parallel()
	tls := newTestTLS(t)
	tls.FilterCN = onlyAllow("live.example.com")
	tls.FilterExisting = true

	target := secretWithCNs(t, tls, "live.example.com")
	target.Annotations[getAnnotationKey("dead.example.com")] = "dead.example.com"
	additional := secretWithCNs(t, tls, "live.example.com")

	result, _, err := tls.Merge(target, additional)
	require.NoError(t, err)

	assert.NotContains(t, cns(result), "dead.example.com",
		"stale CN must be pruned by Merge")
	assert.Contains(t, cns(result), "live.example.com")
}

func TestMerge_StaleInAdditional_ForcesRegeneration(t *testing.T) {
	t.Parallel()
	tls := newTestTLS(t)
	tls.FilterCN = onlyAllow("live.example.com")
	tls.FilterExisting = true

	target := secretWithCNs(t, tls, "live.example.com")
	additional := secretWithCNs(t, tls, "live.example.com")
	additional.Annotations[getAnnotationKey("dead.example.com")] = "dead.example.com"

	result, _, err := tls.Merge(target, additional)
	require.NoError(t, err)

	assert.NotContains(t, cns(result), "dead.example.com")
	assert.Contains(t, cns(result), "live.example.com")
}

func TestMerge_NoStale_ReturnsExistingWithoutRegeneration(t *testing.T) {
	t.Parallel()
	tls := newTestTLS(t)
	tls.FilterCN = onlyAllow("a.example.com", "b.example.com")
	tls.FilterExisting = true

	target := secretWithCNs(t, tls, "a.example.com", "b.example.com")
	additional := secretWithCNs(t, tls, "a.example.com")

	result, updated, err := tls.Merge(target, additional)
	require.NoError(t, err)

	assert.False(t, updated)
	assert.Equal(t, target.Annotations[Fingerprint], result.Annotations[Fingerprint],
		"fingerprint should match target (returned without regen)")
}

func TestMerge_FilterExisting_False_BackwardsCompatible(t *testing.T) {
	t.Parallel()
	tls := newTestTLS(t)
	target := secretWithCNs(t, tls, "a.example.com", "b.example.com")
	additional := secretWithCNs(t, tls, "a.example.com")

	result, updated, err := tls.Merge(target, additional)
	require.NoError(t, err)
	assert.False(t, updated)
	assert.Equal(t, target.Annotations[Fingerprint], result.Annotations[Fingerprint],
		"target satisfies all merged CNs and has no stale → returned unchanged")
}

func TestMerge_StaticTarget_NeverModified(t *testing.T) {
	t.Parallel()
	tls := newTestTLS(t)
	tls.FilterCN = onlyAllow("live.example.com")
	tls.FilterExisting = true

	target := secretWithCNs(t, tls, "live.example.com")
	target.Annotations[Static] = "true"
	additional := secretWithCNs(t, tls, "live.example.com")

	result, updated, err := tls.Merge(target, additional)
	require.NoError(t, err)
	assert.False(t, updated, "static target must never be replaced")
	assert.Equal(t, target, result, "static target must be returned unchanged")
}

// --- Renew prunes stale CNs ---

func TestRenew_PrunesStale(t *testing.T) {
	t.Parallel()
	tls := newTestTLS(t)
	tls.FilterCN = onlyAllow("live.example.com")
	tls.FilterExisting = true

	s := secretWithCNs(t, tls, "live.example.com")
	s.Annotations[getAnnotationKey("dead.example.com")] = "dead.example.com"
	result, err := tls.Renew(s)
	require.NoError(t, err)

	assert.Contains(t, cns(result), "live.example.com")
	assert.NotContains(t, cns(result), "dead.example.com")
}

func TestRenew_NilFilter_KeepsAll(t *testing.T) {
	t.Parallel()
	tls := newTestTLS(t)
	s := secretWithCNs(t, tls, "a.example.com", "b.example.com")
	result, err := tls.Renew(s)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"a.example.com", "b.example.com"}, cns(result))
}

// --- Regenerate prunes stale CNs ---

func TestRegenerate_PrunesStale(t *testing.T) {
	t.Parallel()
	tls := newTestTLS(t)
	tls.FilterCN = onlyAllow("live.example.com")
	tls.FilterExisting = true

	s := secretWithCNs(t, tls, "live.example.com")
	s.Annotations[getAnnotationKey("dead.example.com")] = "dead.example.com"
	result, err := tls.Regenerate(s)
	require.NoError(t, err)

	assert.Contains(t, cns(result), "live.example.com")
	assert.NotContains(t, cns(result), "dead.example.com")
}

// --- AddCN: stale existing annotation is pruned when generateCert is triggered ---

func TestAddCN_PrunesStaleAnnotationOnGeneration(t *testing.T) {
	t.Parallel()
	tls := newTestTLS(t)
	tls.FilterCN = onlyAllow("live.example.com", "other.example.com")
	tls.FilterExisting = true

	s := secretWithCNs(t, tls, "live.example.com")
	// Simulate a stale CN left over from before the filter was set.
	s.Annotations[getAnnotationKey("dead.example.com")] = "dead.example.com"

	// Adding a new valid CN triggers generateCert, which prunes stale annotations.
	result, updated, err := tls.AddCN(s, "other.example.com")
	require.NoError(t, err)
	require.True(t, updated)

	assert.NotContains(t, cns(result), "dead.example.com",
		"stale CN must be pruned by pruneAnnotations during generation")
	assert.Contains(t, cns(result), "live.example.com")
	assert.Contains(t, cns(result), "other.example.com")

	certs, err := cert.ParseCertsPEM(result.Data[v1.TLSCertKey])
	require.NoError(t, err)
	require.NotEmpty(t, certs)
	for _, san := range certs[0].DNSNames {
		assert.NotEqual(t, "dead.example.com", san)
	}
}

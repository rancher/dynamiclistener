package dynamiclistener

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/rancher/dynamiclistener/factory"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	apiError "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func Test_getCertificate(t *testing.T) {
	beforeKey, beforeCert, err := newCertificate()
	assert.NoError(t, err, "Error when setting up test - unable to construct before key for test")
	beforeTLSCert, err := tls.X509KeyPair(beforeCert, beforeKey)
	assert.NoError(t, err, "Error when setting up test - unable to convert before to tls.Certificate")
	afterKey, afterCert, err := newCertificate()
	assert.NoError(t, err, "Error when setting up test - unable to construct after key for test")
	afterTLSCert, err := tls.X509KeyPair(afterCert, afterKey)
	assert.NoError(t, err, "Error when setting up test - unable to convert after to tls.Certificate")
	tests := []struct {
		// input test vars
		name          string
		secret        *v1.Secret
		secretErr     error
		cachedCert    *tls.Certificate
		cachedVersion string
		currentConn   *closeWrapper
		otherConns    map[int]*closeWrapper

		// output/result test vars
		closedConns  []int
		expectedCert *tls.Certificate
		wantError    bool
	}{
		{
			name:   "no secret found",
			secret: nil,
			secretErr: apiError.NewNotFound(schema.GroupResource{
				Group:    "",
				Resource: "Secret",
			}, "testSecret"),
			currentConn: &closeWrapper{id: 0},
			otherConns:  map[int]*closeWrapper{},

			expectedCert: nil,
			wantError:    true,
		},
		{
			name: "secret found, and is up to date",
			secret: &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					ResourceVersion: "1",
					Name:            "testSecret",
					Namespace:       "test",
				},
				Data: map[string][]byte{
					v1.TLSCertKey:       beforeCert,
					v1.TLSPrivateKeyKey: beforeKey,
				},
			},
			cachedVersion: "1",
			cachedCert:    &beforeTLSCert,
			currentConn:   &closeWrapper{id: 0},
			otherConns:    map[int]*closeWrapper{},

			expectedCert: &beforeTLSCert,
			wantError:    false,
		},
		{
			name: "secret found, is not up to date, but k8s secret is not valid",
			secret: &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					ResourceVersion: "2",
					Name:            "testSecret",
					Namespace:       "test",
				},
				Data: map[string][]byte{
					v1.TLSPrivateKeyKey: []byte("strawberry"),
				},
			},
			cachedVersion: "1",
			cachedCert:    &beforeTLSCert,
			currentConn:   &closeWrapper{id: 0},
			otherConns:    map[int]*closeWrapper{},

			expectedCert: &beforeTLSCert,
			wantError:    false,
		},
		{
			name: "secret found, but is not up to date",
			secret: &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					ResourceVersion: "2",
					Name:            "testSecret",
					Namespace:       "test",
				},
				Data: map[string][]byte{
					v1.TLSCertKey:       afterCert,
					v1.TLSPrivateKeyKey: afterKey,
				},
			},
			cachedVersion: "1",
			cachedCert:    &beforeTLSCert,
			currentConn:   &closeWrapper{id: 0},
			otherConns:    map[int]*closeWrapper{},

			expectedCert: &afterTLSCert,
			wantError:    false,
		},
		{
			name: "secret found, is not up to date, and we have conns using current cert",
			secret: &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					ResourceVersion: "2",
					Name:            "testSecret",
					Namespace:       "test",
				},
				Data: map[string][]byte{
					v1.TLSCertKey:       afterCert,
					v1.TLSPrivateKeyKey: afterKey,
				},
			},
			cachedVersion: "1",
			cachedCert:    &beforeTLSCert,
			currentConn:   &closeWrapper{id: 0},
			otherConns: map[int]*closeWrapper{
				1: {
					id:    1,
					ready: false,
					Conn:  &fakeConn{},
				},
				2: {
					id:    2,
					ready: true,
					Conn:  &fakeConn{},
				},
			},

			closedConns:  []int{2},
			expectedCert: &afterTLSCert,
			wantError:    false,
		},
	}
	for i := range tests {
		test := tests[i]
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			testConns := test.otherConns
			if testConns != nil {
				testConns[test.currentConn.id] = test.currentConn
				// make sure our conn is listed as one of the current connections
			}
			l := listener{
				cert:    test.cachedCert,
				version: test.cachedVersion,
				storage: &MockTLSStorage{
					Secret:    test.secret,
					SecretErr: test.secretErr,
				},
				conns: testConns,
			}
			for _, conn := range testConns {
				conn.l = &l
			}
			newCert, err := l.getCertificate(&tls.ClientHelloInfo{Conn: test.currentConn})
			if test.wantError {
				assert.Errorf(t, err, "expected an error but none was provdied")
			} else {
				assert.NoError(t, err, "did not expect an error but got one")
			}
			assert.Equal(t, test.expectedCert, newCert, "expected cert did not match actual cert")
			if test.expectedCert != nil && test.wantError == false && test.currentConn != nil && test.otherConns != nil {
				assert.True(t, test.currentConn.ready, "expected connection to be ready but it was not")
			} else {
				if test.currentConn != nil {
					assert.False(t, test.currentConn.ready, "did not expect connection to be ready")
				}
			}
			for _, closedConn := range test.closedConns {
				_, ok := l.conns[closedConn]
				assert.False(t, ok, "closed conns should not be found")
			}
		})
	}
}

func newCertificate() ([]byte, []byte, error) {
	cert, key, err := factory.GenCA()
	if err != nil {
		return nil, nil, err
	}

	return factory.MarshalChain(key, cert)
}

type MockTLSStorage struct {
	Secret    *v1.Secret
	SecretErr error
}

func (m *MockTLSStorage) Get() (*v1.Secret, error) {
	return m.Secret, m.SecretErr
}

func (m *MockTLSStorage) Update(secret *v1.Secret) error {
	panic("Not implemented")
}

// adapted from k8s.io/apimachinery@v0.18.8/pkg/util.proxy/ugradeaware_test.go
type fakeConn struct{}

func (f *fakeConn) Read([]byte) (int, error)        { return 0, nil }
func (f *fakeConn) Write([]byte) (int, error)       { return 0, nil }
func (f *fakeConn) Close() error                    { return nil }
func (fakeConn) LocalAddr() net.Addr                { return nil }
func (fakeConn) RemoteAddr() net.Addr               { return nil }
func (fakeConn) SetDeadline(t time.Time) error      { return nil }
func (fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (fakeConn) SetWriteDeadline(t time.Time) error { return nil }

func TestIsWildcardSAN(t *testing.T) {
	cases := []struct {
		cn   string
		want bool
	}{
		{"*.example.com", true},
		{"*.foo.bar.com", true},
		{"foo.example.com", false},
		{"*", false},
		{"foo*", false},
		{"", false},
		{"*foo.example.com", false},
	}
	for _, c := range cases {
		got := isWildcardSAN(c.cn)
		if got != c.want {
			t.Errorf("isWildcardSAN(%q) = %v, want %v", c.cn, got, c.want)
		}
	}
}

// trackingStorage counts Update calls and remembers the last secret.
// (MockTLSStorage.Update panics, so we replace rather than wrap.)
type trackingStorage struct {
	secret      *v1.Secret
	updateCalls int
}

func (s *trackingStorage) Get() (*v1.Secret, error) {
	if s.secret == nil {
		return &v1.Secret{}, nil
	}
	return s.secret, nil
}

func (s *trackingStorage) Update(secret *v1.Secret) error {
	s.updateCalls++
	s.secret = secret
	return nil
}

func newTestTLSFactory(t *testing.T) *factory.TLS {
	t.Helper()
	caCert, caKey, err := factory.GenCA()
	if err != nil {
		t.Fatalf("factory.GenCA: %v", err)
	}
	return &factory.TLS{
		CACert:       []*x509.Certificate{caCert},
		CAKey:        caKey,
		CN:           "test",
		Organization: []string{"test"},
	}
}

// fakeListener is a no-op net.Listener used to satisfy listener.Addr() in unit tests.
type fakeListener struct{}

func (fakeListener) Accept() (net.Conn, error) {
	return nil, errors.New("fakeListener: Accept not supported")
}
func (fakeListener) Close() error   { return nil }
func (fakeListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4zero, Port: 0} }

func newTestListener(t *testing.T, configSANs []string) (*listener, *trackingStorage) {
	t.Helper()
	storage := &trackingStorage{}
	l := &listener{
		Listener:  fakeListener{},
		factory:   newTestTLSFactory(t),
		storage:   storage,
		sans:      configSANs,
		certReady: make(chan struct{}),
	}
	return l, storage
}

func storedHasCN(storage *trackingStorage, cn string) bool {
	if storage.secret == nil {
		return false
	}
	for _, v := range storage.secret.Annotations {
		if v == cn {
			return true
		}
	}
	return false
}

func TestListener_RejectsWildcardFromSNI(t *testing.T) {
	l, storage := newTestListener(t, []string{"foo.example.com"})

	hello := &tls.ClientHelloInfo{ServerName: "*.evil.com"}
	_, _ = l.getCertificate(hello)

	if storage.updateCalls != 0 {
		t.Errorf("storage.Update called %d times, expected 0 (wildcard SNI should be rejected)", storage.updateCalls)
	}
}

func TestListener_AcceptsWildcardFromConfigSANs(t *testing.T) {
	l, storage := newTestListener(t, []string{"*.example.com"})

	if err := l.updateCert(l.sans...); err != nil {
		t.Fatalf("updateCert from trusted source failed: %v", err)
	}
	if storage.updateCalls == 0 {
		t.Error("expected storage.Update to be called for admin-supplied wildcard SAN")
	}
	if !storedHasCN(storage, "*.example.com") {
		t.Errorf("expected wildcard *.example.com in stored secret annotations; got %v", storage.secret.Annotations)
	}
}

func TestListener_AdminWildcardSuppressesRuntimeSubdomainRegen(t *testing.T) {
	l, storage := newTestListener(t, []string{"*.example.com"})

	if err := l.updateCert(l.sans...); err != nil {
		t.Fatalf("initial updateCert: %v", err)
	}
	updatesAfterInit := storage.updateCalls

	hello := &tls.ClientHelloInfo{ServerName: "foo.example.com"}
	_, _ = l.getCertificate(hello)

	if storage.updateCalls != updatesAfterInit {
		t.Errorf("storage.Update called again (%d -> %d), expected NO regen for covered subdomain",
			updatesAfterInit, storage.updateCalls)
	}
}

func TestListener_FilterCallbackCanReturnWildcards(t *testing.T) {
	// Documents the trust model: Config.FilterCN is integrator-controlled, and runs
	// inside updateCert AFTER the listener-layer gate. So if FilterCN returns a wildcard
	// for an input the gate already permitted, the wildcard IS accepted into the cert.
	// This is intentional, not a bug - FilterCN is part of the integrator's
	// admin-controlled trust boundary.
	tlsFactory := newTestTLSFactory(t)
	tlsFactory.FilterCN = func(cn ...string) []string {
		return []string{"*.example.com"}
	}
	storage := &trackingStorage{}
	l := &listener{
		Listener:  fakeListener{},
		factory:   tlsFactory,
		storage:   storage,
		sans:      nil,
		certReady: make(chan struct{}),
	}

	// Drive a non-wildcard SNI through the gate at getCertificate. The gate permits it
	// (not a wildcard), so updateCert is invoked; inside updateCert, Filter then
	// replaces the input with the wildcard, which reaches storage.
	hello := &tls.ClientHelloInfo{ServerName: "non-wildcard.input.com"}
	_, _ = l.getCertificate(hello)

	if !storedHasCN(storage, "*.example.com") {
		t.Errorf("expected wildcard from FilterCN to reach the cert; annotations: %v", storage.secret)
	}
}

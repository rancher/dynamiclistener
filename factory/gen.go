package factory

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/rancher/dynamiclistener/cert"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
)

const (
	cnPrefix = "listener.cattle.io/cn-"
	Static   = "listener.cattle.io/static"
	hashKey  = "listener.cattle.io/hash"
)

var (
	cnRegexp = regexp.MustCompile("^([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]$")
)

type TLS struct {
	CACert       *x509.Certificate
	CAKey        crypto.Signer
	CN           string
	Organization []string
	FilterCN     func(...string) []string
}

func cns(secret *v1.Secret) (cns []string) {
	if secret == nil {
		return nil
	}
	for k, v := range secret.Annotations {
		if strings.HasPrefix(k, cnPrefix) {
			cns = append(cns, v)
		}
	}
	return
}

func collectCNs(secret *v1.Secret) (domains []string, ips []net.IP, err error) {
	var (
		cns = cns(secret)
	)

	sort.Strings(cns)

	for _, v := range cns {
		ip := net.ParseIP(v)
		if ip == nil {
			domains = append(domains, v)
		} else {
			ips = append(ips, ip)
		}
	}

	return
}

func (t *TLS) Merge(target, additional *v1.Secret) (*v1.Secret, bool, error) {
	secret, updated, err := t.AddCN(target, cns(additional)...)
	// AddCN returns early if the CNs are the same, but we also need to handle the case
	// where the secret has been renewed with the same CNs. Since the kubernetes storage backend
	// uses Merge to detect changes, we return the second secret and note that it has been updated.
	if !updated {
		if target.Annotations[hashKey] != additional.Annotations[hashKey] {
			secret = additional
			updated = true
		}
	}
	return secret, updated, err
}

func (t *TLS) Renew(secret *v1.Secret) (*v1.Secret, error) {
	if IsStatic(secret) {
		return secret, cert.ErrStaticCert
	}
	cns := cns(secret)
	secret = secret.DeepCopy()
	secret.Annotations = map[string]string{}
	secret, _, err := t.generateCert(secret, cns...)
	return secret, err
}

func (t *TLS) Filter(cn ...string) []string {
	if len(cn) == 0 || t.FilterCN == nil {
		return cn
	}
	return t.FilterCN(cn...)
}

func (t *TLS) AddCN(secret *v1.Secret, cn ...string) (*v1.Secret, bool, error) {
	cn = t.Filter(cn...)

	if IsStatic(secret) || !NeedsUpdate(0, secret, cn...) {
		return secret, false, nil
	}
	return t.generateCert(secret, cn...)
}

func (t *TLS) generateCert(secret *v1.Secret, cn ...string) (*v1.Secret, bool, error) {
	secret = secret.DeepCopy()
	if secret == nil {
		secret = &v1.Secret{}
	}

	secret = populateCN(secret, cn...)

	privateKey, err := getPrivateKey(secret)
	if err != nil {
		return nil, false, err
	}

	domains, ips, err := collectCNs(secret)
	if err != nil {
		return nil, false, err
	}

	newCert, err := t.newCert(domains, ips, privateKey)
	if err != nil {
		return nil, false, err
	}

	certBytes, keyBytes, err := Marshal(newCert, privateKey)
	if err != nil {
		return nil, false, err
	}

	if secret.Data == nil {
		secret.Data = map[string][]byte{}
	}
	secret.Data[v1.TLSCertKey] = certBytes
	secret.Data[v1.TLSPrivateKeyKey] = keyBytes
	secret.Annotations[hashKey] = fmt.Sprintf("SHA1=%X", sha1.Sum(newCert.Raw))

	return secret, true, nil
}

func (t *TLS) newCert(domains []string, ips []net.IP, privateKey crypto.Signer) (*x509.Certificate, error) {
	return NewSignedCert(privateKey, t.CACert, t.CAKey, t.CN, t.Organization, domains, ips)
}

func populateCN(secret *v1.Secret, cn ...string) *v1.Secret {
	secret = secret.DeepCopy()
	if secret.Annotations == nil {
		secret.Annotations = map[string]string{}
	}
	for _, cn := range cn {
		if cnRegexp.MatchString(cn) {
			secret.Annotations[cnPrefix+cn] = cn
		} else {
			logrus.Errorf("dropping invalid CN: %s", cn)
		}
	}
	return secret
}

func IsStatic(secret *v1.Secret) bool {
	return secret.Annotations[Static] == "true"
}

func NeedsUpdate(maxSANs int, secret *v1.Secret, cn ...string) bool {
	if secret == nil {
		return true
	}

	for _, cn := range cn {
		if secret.Annotations[cnPrefix+cn] == "" {
			if maxSANs > 0 && len(cns(secret)) >= maxSANs {
				return false
			}
			return true
		}
	}

	return false
}

func getPrivateKey(secret *v1.Secret) (crypto.Signer, error) {
	keyBytes := secret.Data[v1.TLSPrivateKeyKey]
	if len(keyBytes) == 0 {
		return NewPrivateKey()
	}

	privateKey, err := cert.ParsePrivateKeyPEM(keyBytes)
	if signer, ok := privateKey.(crypto.Signer); ok && err == nil {
		return signer, nil
	}

	return NewPrivateKey()
}

func Marshal(x509Cert *x509.Certificate, privateKey crypto.Signer) ([]byte, []byte, error) {
	certBlock := pem.Block{
		Type:  CertificateBlockType,
		Bytes: x509Cert.Raw,
	}

	keyBytes, err := cert.MarshalPrivateKeyToPEM(privateKey)
	if err != nil {
		return nil, nil, err
	}

	return pem.EncodeToMemory(&certBlock), keyBytes, nil
}

func NewPrivateKey() (crypto.Signer, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

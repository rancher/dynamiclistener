package cert

import (
	"crypto/x509"
	"time"
)

// CalculateNotBefore calculates a NotBefore time of 1 hour in the past, or the
// NotBefore time of the optionally provided *x509.Certificate, whichever is greater.
func CalculateNotBefore(ca *x509.Certificate) time.Time {
	// Compensate for clock skew issues
	now := time.Now().UTC().Add(-time.Hour)

	// It makes no sense to return a time before the CA itself is valid.
	if ca != nil && now.Before(ca.NotBefore) {
		return ca.NotBefore
	}
	return now
}

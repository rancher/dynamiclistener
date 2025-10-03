/*
Copyright 2014 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cert

import (
	"crypto/x509"
	"testing"
	"time"

	clocktest "k8s.io/utils/clock/testing"
)

func TestCalculateNotBefore(t *testing.T) {
	baseTime := time.Date(2025, 9, 29, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		ca       *x509.Certificate
		now      time.Time
		expected time.Time
	}{
		{
			name:     "nil CA returns 1h ago",
			ca:       nil,
			now:      baseTime,
			expected: baseTime.Add(-time.Hour),
		},
		{
			name: "CA notBefore before now returns 1h ago",
			ca: &x509.Certificate{
				NotBefore: baseTime.Add(-2 * time.Hour),
			},
			now:      baseTime,
			expected: baseTime.Add(-time.Hour),
		},
		{
			name: "CA notBefore after now returns CA.NotBefore",
			ca: &x509.Certificate{
				NotBefore: baseTime.Add(2 * time.Hour),
			},
			now:      baseTime,
			expected: baseTime.Add(2 * time.Hour),
		},
		{
			name: "CA notBefore equal to now returns now",
			ca: &x509.Certificate{
				NotBefore: baseTime,
			},
			now:      baseTime,
			expected: baseTime,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock = clocktest.NewFakePassiveClock(tt.now)
			result := CalculateNotBefore(tt.ca)
			if !result.Equal(tt.expected) {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

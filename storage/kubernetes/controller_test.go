package kubernetes

import (
	"sync"
	"testing"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/util/workqueue"
)

// memoryStorage is a minimal TLSStorage backing for tests.
type memoryStorage struct {
	mu     sync.Mutex
	secret *v1.Secret
}

func (m *memoryStorage) Get() (*v1.Secret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.secret, nil
}

func (m *memoryStorage) Update(secret *v1.Secret) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secret = secret
	return nil
}

// TestUpdateQueuedSecretRace runs Update (which sets queuedSecret) concurrently
// with update (which reads it) to ensure access to queuedSecret is
// synchronized. secrets is left nil so saveInK8s short-circuits and no
// apiserver is needed. Run with -race: without the mutex this reports a data
// race on queuedSecret, with it the two paths are serialized.
func TestUpdateQueuedSecretRace(t *testing.T) {
	s := &storage{
		name:    "test",
		storage: &memoryStorage{},
		queue:   workqueue.NewTyped[string](),
	}

	const iterations = 1000
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = s.Update(&v1.Secret{})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = s.update()
		}
	}()
	wg.Wait()
}

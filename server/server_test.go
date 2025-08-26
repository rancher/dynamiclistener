package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	assertPkg "github.com/stretchr/testify/assert"
)

const (
	ignoreTLSHandErrorVal   = false
	stringTLSHandshakeError = "http: TLS handshake error"
)

type alwaysPanicHandler struct {
	msg string
}

func (z *alwaysPanicHandler) ServeHTTP(_ http.ResponseWriter, _ *http.Request) {
	panic(z.msg)
}

// safeWriter is used to allow writing to a buffer-based log in a web server
// and safely read from it in the client (i.e. this test code)
type safeWriter struct {
	writer *bytes.Buffer
	mutex  *sync.Mutex
}

func newSafeWriter(writer *bytes.Buffer, mutex *sync.Mutex) *safeWriter {
	return &safeWriter{writer: writer, mutex: mutex}
}

func (s *safeWriter) Write(p []byte) (n int, err error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.writer.Write(p)
}

func TestTlsHandshakeErrorHandling(t *testing.T) {
	assert := assertPkg.New(t)
	var buf bytes.Buffer
	var mutex sync.Mutex

	listenOpts := &ListenOpts{
		BindHost:                "127.0.0.1",
		IgnoreTLSHandshakeError: ignoreTLSHandErrorVal,
		DisplayServerLogs:       true,
	}

	go func() {
		err := ListenAndServe(context.Background(), 9013, 0, &alwaysPanicHandler{}, listenOpts)
		assert.Nil(err)
	}()

	addr := "127.0.0.1:9013"
	waitTime := 10 * time.Millisecond
	for {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(waitTime)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 5 * time.Second,
	}

	_, err := client.Get(fmt.Sprintf("https://%s/", addr))
	assert.NotNil(err)

	time.Sleep(1 * time.Second)

	mutex.Lock()
	s := buf.String()
	mutex.Unlock()

	if s != "" {
		assert.Contains(s, stringTLSHandshakeError)

		if ignoreTLSHandErrorVal {
			assert.Regexp(
				"level=debug msg=\"[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} http: TLS handshake error from [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+:[0-9]+: EOF\"",
				s,
			)
		} else {
			assert.Regexp(
				"level=error msg=\"[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} http: TLS handshake error from [0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+:[0-9]+: EOF\"",
				s,
			)
		}
	}

}

func TestHttpServerLogWithLogrus(t *testing.T) {
	assert := assertPkg.New(t)
	message := "debug-level writer"
	msg := fmt.Sprintf("panicking context: %s", message)
	var buf bytes.Buffer
	var mutex sync.Mutex
	safeWriter := newSafeWriter(&buf, &mutex)
	err := doRequest(safeWriter, message, logrus.ErrorLevel)
	assert.Nil(err)

	mutex.Lock()
	s := buf.String()
	assert.Greater(len(s), 0)
	assert.Contains(s, msg)
	assert.Contains(s, "panic serving 127.0.0.1")
	mutex.Unlock()
}

func TestHttpNoServerLogsWithLogrus(t *testing.T) {
	assert := assertPkg.New(t)

	message := "error-level writer"
	var buf bytes.Buffer
	var mutex sync.Mutex
	safeWriter := newSafeWriter(&buf, &mutex)
	err := doRequest(safeWriter, message, logrus.DebugLevel)
	assert.Nil(err)

	mutex.Lock()
	s := buf.String()
	if len(s) > 0 {
		assert.NotContains(s, message)
	}
	mutex.Unlock()
}

func doRequest(safeWriter *safeWriter, message string, logLevel logrus.Level) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	host := "127.0.0.1"
	httpPort := 9012
	httpsPort := 0
	msg := fmt.Sprintf("panicking context: %s", message)
	handler := alwaysPanicHandler{msg: msg}
	listenOpts := &ListenOpts{
		BindHost:          host,
		DisplayServerLogs: logLevel == logrus.ErrorLevel,
	}

	logrus.StandardLogger().SetOutput(safeWriter)
	if err := ListenAndServe(ctx, httpsPort, httpPort, &handler, listenOpts); err != nil {
		return err
	}
	addr := fmt.Sprintf("%s:%d", host, httpPort)
	return makeTheHttpRequest(addr)
}

func makeTheHttpRequest(addr string) error {
	url := fmt.Sprintf("%s://%s/", "http", addr)

	waitTime := 10 * time.Millisecond
	totalTime := 0 * time.Millisecond
	const maxWaitTime = 10 * time.Second
	// Waiting for server to be ready..., max of maxWaitTime
	for {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			break
		} else if totalTime > maxWaitTime {
			return fmt.Errorf("timed out waiting for the server to start after %d msec", totalTime/1e6)
		}
		time.Sleep(waitTime)
		totalTime += waitTime
		waitTime += 10 * time.Millisecond
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}
	resp, err := client.Do(req)
	if err == nil {
		return fmt.Errorf("server should have panicked on request")
	}
	if resp != nil {
		defer resp.Body.Close()
	}
	return nil
}

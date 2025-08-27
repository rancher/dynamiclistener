package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	assertPkg "github.com/stretchr/testify/assert"
)

const (
	ignoreTLSHandErrorVal = false
)

type alwaysPanicHandler struct {
	msg string
}

func (z *alwaysPanicHandler) ServeHTTP(_ http.ResponseWriter, _ *http.Request) {
	panic(z.msg)
}

type noPanicHandler struct {
	msg string
}

func (z *noPanicHandler) ServeHTTP(_ http.ResponseWriter, _ *http.Request) {
	fmt.Printf("%s", z.msg)
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

func TestTLSHandshakeErrorWriter(t *testing.T) {
	tests := []struct {
		name                    string
		ignoreTLSHandshakeError bool
		message                 string
		expectDebug             bool
		expectDefault           bool
	}{
		{
			name:                    "TLS handshake error goes to debug when ignored",
			ignoreTLSHandshakeError: true,
			message:                 "http: TLS handshake error: simulated",
			expectDebug:             true,
			expectDefault:           false,
		},
		{
			name:                    "TLS handshake error goes to default when not ignored",
			ignoreTLSHandshakeError: false,
			message:                 "http: TLS handshake error: simulated",
			expectDebug:             false,
			expectDefault:           true,
		},
		{
			name:                    "other messages always go to default",
			ignoreTLSHandshakeError: true,
			message:                 "some other error",
			expectDebug:             false,
			expectDefault:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assertPkg.New(t)

			var bufDebug, bufDefault bytes.Buffer

			var debugWriter io.Writer
			var defaultWriter io.Writer

			if tt.ignoreTLSHandshakeError {
				debugWriter = &bufDebug
				defaultWriter = &bufDefault
			} else {
				debugWriter = &bufDefault
				defaultWriter = &bufDefault
			}

			writer := &tlsHandshakeErrorWriter{
				defaultWriter: defaultWriter,
				debugWriter:   debugWriter,
			}

			n, err := writer.Write([]byte(tt.message))
			assert.Nil(err)
			assert.Equal(len(tt.message), n)

			if tt.expectDebug {
				assert.Contains(bufDebug.String(), tt.message)
			} else {
				assert.Empty(bufDebug.String())
			}

			if tt.expectDefault {
				assert.Contains(bufDefault.String(), tt.message)
			} else {
				assert.Empty(bufDefault.String())
			}
		})
	}
}

func TestTlsHandshakeErrorHandling(t *testing.T) {
	assert := assertPkg.New(t)
	var buf bytes.Buffer
	var mutex sync.Mutex
	logrus.SetOutput(&buf)
	defer logrus.SetOutput(os.Stderr)
	msg := ""
	handler := noPanicHandler{msg: msg}

	listenOpts := &ListenOpts{
		BindHost:                "127.0.0.1",
		IgnoreTLSHandshakeError: ignoreTLSHandErrorVal,
		DisplayServerLogs:       true,
	}

	go func() {
		err := ListenAndServe(context.Background(), 9013, 0, &handler, listenOpts)
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
			TLSClientConfig: &tls.Config{},
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
		if !ignoreTLSHandErrorVal {
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

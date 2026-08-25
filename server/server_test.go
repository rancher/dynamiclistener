package server

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	assertPkg "github.com/stretchr/testify/assert"
)

const (
	// logWaitTimeout bounds how long a test waits for an asynchronously
	// written server log to show up, and logPollInterval how often it looks.
	logWaitTimeout  = 10 * time.Second
	logPollInterval = 10 * time.Millisecond

	// logSettleDelay is how long a test waits before asserting that a server
	// log was never written.
	logSettleDelay = 500 * time.Millisecond
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

func TestTLSHandshakeErrorWriter(t *testing.T) {
	tests := []struct {
		name                    string
		ignoreTLSHandshakeError bool
		message                 []byte
		expectedLevel           logrus.Level
	}{
		{
			name:          "TLS handshake error is logged as debug",
			message:       []byte("http: TLS handshake error: EOF"),
			expectedLevel: logrus.DebugLevel,
		},
		{
			name:          "other errors are logged as error",
			message:       []byte("some other server error"),
			expectedLevel: logrus.ErrorLevel,
		},
	}
	var baseLogLevel = logrus.GetLevel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assertPkg.New(t)

			var buf bytes.Buffer
			logrus.SetOutput(&buf)
			logrus.SetLevel(logrus.DebugLevel)

			debugger := &TLSErrorDebugger{}
			n, err := debugger.Write(tt.message)

			assert.Nil(err)
			assert.Equal(len(tt.message), n)

			logOutput := buf.String()
			assert.Contains(logOutput, "level="+tt.expectedLevel.String())
			assert.Contains(logOutput, string(tt.message))
		})
	}
	logrus.SetLevel(baseLogLevel)
}

func TestHttpServerLogWithLogrus(t *testing.T) {
	assert := assertPkg.New(t)
	message := "debug-level writer"
	msg := fmt.Sprintf("panicking context: %s", message)
	var buf bytes.Buffer
	var mutex sync.Mutex
	safeWriter := newSafeWriter(&buf, &mutex)
	err := doRequest(safeWriter, 9012, message, logrus.ErrorLevel)
	assert.Nil(err)

	// ListenAndServe hands http.Server an ErrorLog backed by
	// logrus.Logger.WriterLevel, which is an *io.PipeWriter drained by a
	// background goroutine. The server's panic log therefore reaches the
	// logrus output some time after the client request has failed, so poll
	// for it instead of reading the buffer once.
	assert.Eventually(func() bool {
		mutex.Lock()
		defer mutex.Unlock()
		s := buf.String()
		return strings.Contains(s, msg) && strings.Contains(s, "panic serving 127.0.0.1")
	}, logWaitTimeout, logPollInterval, "server panic was never logged")
}

func TestHttpNoServerLogsWithLogrus(t *testing.T) {
	assert := assertPkg.New(t)

	message := "error-level writer"
	var buf bytes.Buffer
	var mutex sync.Mutex
	safeWriter := newSafeWriter(&buf, &mutex)
	err := doRequest(safeWriter, 9013, message, logrus.DebugLevel)
	assert.Nil(err)

	// Nothing to poll for here: give the asynchronous writer a chance to
	// emit before asserting that it never does.
	time.Sleep(logSettleDelay)

	mutex.Lock()
	s := buf.String()
	if len(s) > 0 {
		assert.NotContains(s, message)
	}
	mutex.Unlock()
}

func doRequest(safeWriter *safeWriter, httpPort int, message string, logLevel logrus.Level) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	host := "127.0.0.1"
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

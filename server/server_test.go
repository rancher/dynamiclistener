package server

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	assertPkg "github.com/stretchr/testify/assert"
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

func TestHttpServerLogWithLogrus(t *testing.T) {
	assert := assertPkg.New(t)
	message := "debug-level writer"
	msg := fmt.Sprintf("panicking context: %s", message)
	var buf bytes.Buffer
	var mutex sync.Mutex
	safeWriter := newSafeWriter(&buf, &mutex)
	doRequest(t, safeWriter, message, logrus.ErrorLevel)

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
	doRequest(t, safeWriter, message, logrus.DebugLevel)

	mutex.Lock()
	s := buf.String()
	if len(s) > 0 {
		assert.NotContains(s, message)
	}
	mutex.Unlock()
}

func doRequest(t *testing.T, safeWriter *safeWriter, message string, logLevel logrus.Level) {
	assert := assertPkg.New(t)
	ctx, cancel := context.WithCancel(context.Background())
	httpPort := 9012
	httpsPort := 0
	msg := fmt.Sprintf("panicking context: %s", message)
	handler := alwaysPanicHandler{msg: msg}
	listenOpts := &ListenOpts{
		BindHost: "127.0.0.1",
	}

	logger := logrus.StandardLogger()
	logger.SetOutput(safeWriter)
	logger.SetLevel(logrus.ErrorLevel)
	writer := logger.WriterLevel(logLevel)
	errorLog := log.New(writer, "", log.LstdFlags)

	err := listenAndServeWithLogger(ctx, httpsPort, httpPort, &handler, listenOpts, errorLog)
	assert.Nil(err)

	makeTheHttpRequest(assert, httpPort)
	cancel()
}

func makeTheHttpRequest(assert *assertPkg.Assertions, port int) {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	url := fmt.Sprintf("%s://%s/", "http", addr)

	waitTime := 10 * time.Millisecond
	for {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			break
		}
		fmt.Println("Waiting for server to be ready...")
		time.Sleep(waitTime)
		waitTime += 10 * time.Millisecond
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	resp, err := client.Do(req)
	assert.Error(err, "server should have panicked on request")
	if resp != nil {
		defer resp.Body.Close()
		fmt.Println("Response status:", resp.Status)
	}
}

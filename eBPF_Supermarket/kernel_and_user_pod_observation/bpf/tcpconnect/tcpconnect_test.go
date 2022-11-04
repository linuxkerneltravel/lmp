package tcpconnect

import (
	"testing"
	"time"
)

func TestWithTimeOut(t *testing.T) {
	timeout := 20 * time.Second
	done := make(chan bool)

	go Sample()

	select {
	case <-time.Tick(timeout):
		return
	case <-done:
	}
}

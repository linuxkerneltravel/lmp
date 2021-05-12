package mq

import (
	"fmt"
	"sync"
	"testing"
)

func TestClient(t *testing.T) {
	b := NewClient()
	b.SetConditions(100)
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		topic := fmt.Sprintf("Golang%d", i)
		payload := fmt.Sprintf("payload%d", i)
		ch, err := b.Subscribe(topic)
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)

		go func() {
			e := b.GetPayLoad(ch)
			if e != payload {
				t.Fatalf("%s expected %s but get %s", topic, payload, e)
			}

			if err := b.Unsubscribe(topic, ch); err != nil {
				t.Fatal(err)
			}

			wg.Done()
		}()

		if err := b.Publish(topic, payload); err != nil {
			t.Fatal(err)
		}
	}
}

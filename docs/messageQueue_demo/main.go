package main

import (
	"../mq"
	"fmt"
	"time"
)

var (
	topic = "Golang梦工厂"
)

func main() {
	OnceTopic()
}

func OnceTopic() {
	m := mq.NewClient()
	m.SetConditions(10)
	ch, err := m.Subscribe(topic)
	if err != nil {
		fmt.Println("subscribe failed")
		return
	}
	go OncePub(m)
	OnceSub(ch, m)
	defer m.Close()
}

func OncePub(c *mq.Client) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			err := c.Publish(topic, "haha1")
			if err != nil {
				fmt.Println("OncePub failed")
			}
		default:
		}
	}
}

func OnceSub(m <-chan interface{}, c *mq.Client) {
	for {
		val := c.GetPayLoad(m)
		fmt.Println("get message is %sn", val)
	}
}

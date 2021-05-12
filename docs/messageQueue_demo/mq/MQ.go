package mq

import (
	"errors"
	"sync"
	"time"
)

type Broker interface {
	// 消息的推送，参数是订阅的主题和要传递的消息
	publish(topic string, msg interface{}) error

	// 消息的订阅，传入订阅的主题，就可以完成订阅，并返回对应的channel用来接收数据
	subscribe(topic string) (<-chan interface{}, error)

	// 取消订阅，传入要取消订阅的主题和管道
	unsubscribe(topic string, sub <-chan interface{}) error

	// 用于关闭消息队列
	close()

	// 内部方法，作用是广播，对推送的消息进行广播，保证每一个订阅者都可以接收到
	broadcast(msg interface{}, subscribes []chan interface{})

	// 用来设置条件，条件就是消息队列的容量，用于控制消息队列的大小
	setConditions(capacity int)
}

type BrokerImpl struct {
	exit     chan bool
	capacity int
	topics   map[string][]chan interface{}
	sync.RWMutex
}

func NewBroker() *BrokerImpl {
	return &BrokerImpl{
		exit:   make(chan bool),
		topics: make(map[string][]chan interface{}),
	}
}

func (b *BrokerImpl) publish(topic string, pub interface{}) error {
	select {
	case <-b.exit:
		return errors.New("broker closed")
	default:
	}
	b.RLock()
	subscribers, ok := b.topics[topic]
	b.RUnlock()
	if !ok {
		return nil
	}
	b.broadcast(pub, subscribers)
	return nil
}

func (b *BrokerImpl) broadcast(msg interface{}, subscribers []chan interface{}) {
	count := len(subscribers)
	concurrency := 1
	switch {
	case count > 1000:
		concurrency = 3
	case count > 100:
		concurrency = 2
	default:
		concurrency = 1
	}

	pub := func(start int) {
		for j := start; j < count; j += concurrency {
			select {
			case subscribers[j] <- msg:
			case <-time.After(time.Millisecond * 5):
			case <-b.exit:
				return
			}
		}
	}

	for i := 0; i < concurrency; i++ {
		go pub(i)
	}
}

func (b *BrokerImpl) subscribe(topic string) (<-chan interface{}, error) {
	select {
	case <-b.exit:
		return nil, errors.New("broker closed")
	default:
	}

	ch := make(chan interface{}, b.capacity)
	b.RLock()
	b.topics[topic] = append(b.topics[topic], ch)
	b.RUnlock()

	return ch, nil
}

func (b *BrokerImpl) unsubscribe(topic string, sub <-chan interface{}) error {
	select {
	case <-b.exit:
		return errors.New("broker closed")
	default:
	}

	b.RLock()
	subscribers, ok := b.topics[topic]
	b.RUnlock()
	if !ok {
		return nil
	}

	var newSubs []chan interface{}
	for _, subscriber := range subscribers {
		if subscriber == sub {
			continue
		}
		newSubs = append(newSubs, subscriber)
	}

	b.RLock()
	b.topics[topic] = newSubs
	b.RUnlock()

	return nil
}

func (b *BrokerImpl) close() {
	select {
	case <-b.exit:
		return
	default:
		close(b.exit)
		b.RLock()
		b.topics = make(map[string][]chan interface{})
		b.RUnlock()
	}

	return
}

func (b *BrokerImpl) setConditions(capacity int) {
	b.capacity = capacity
}

package local_cache

import (
	"context"
	"time"
)

// sentinel 哨兵
type sentinel struct {
	// interval 间隔时间 0 不开启哨兵
	interval time.Duration
	// ctx context
	ctx context.Context
	// fn 哨兵周期执行的函数
	fn func()
}

func (s *sentinel) Start() {
	if s.interval <= 0 {
		return
	}
	tick := time.NewTicker(s.interval)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			s.fn()
		case <-s.ctx.Done():
			return
		}
	}
}

func NewSentinel(ctx context.Context, interval time.Duration, fn func()) *sentinel {
	return &sentinel{
		interval: interval,
		ctx:      ctx,
		fn:       fn,
	}
}

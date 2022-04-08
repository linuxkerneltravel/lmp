package local_cache

import (
	"github.com/songzhibin97/gkit/options"
	"time"
)

type Config struct {
	// defaultExpire 默认超时时间
	defaultExpire time.Duration

	// interval 间隔时间
	interval time.Duration
	// fn 哨兵周期执行的函数
	fn func()

	// capture 捕获删除对象时间 会返回kv值用于用户自定义处理
	capture func(k string, v interface{})

	member map[string]Iterator
}

// SetInternal 设置间隔时间
func SetInternal(interval time.Duration) options.Option {
	return func(c interface{}) {
		c.(*Config).interval = interval
	}
}

// SetDefaultExpire 设置默认的超时时间
func SetDefaultExpire(expire time.Duration) options.Option {
	return func(c interface{}) {
		c.(*Config).defaultExpire = expire
	}
}

// SetFn 设置周期的执行函数,默认(不设置)是扫描全局清除过期的k
func SetFn(fn func()) options.Option {
	return func(c interface{}) {
		c.(*Config).fn = fn
	}
}

// SetCapture 设置触发删除后的捕获函数, 数据删除后回调用设置的捕获函数
func SetCapture(capture func(k string, v interface{})) options.Option {
	return func(c interface{}) {
		c.(*Config).capture = capture
	}
}

// SetMember 设置初始化存储的成员对象
func SetMember(m map[string]Iterator) options.Option {
	return func(c interface{}) {
		c.(*Config).member = m
	}
}

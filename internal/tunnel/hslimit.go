package tunnel

import (
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// 未认证握手限速
//
// 每个新握手都要做一次 X25519 + 一次回复包，攻击者可以用伪造源地址的握手
// 洪水把服务端的 CPU 吃满（也不需要任何凭据）。这里按来源 IP 做令牌桶：
// 正常客户端/站点每 25 秒才重连一次，桶够大不会误伤；洪水则被静默丢弃。
// ---------------------------------------------------------------------------

const (
	hsBurst  = 30.0 // 每个来源允许的突发次数
	hsRateIP = 5.0  // 每秒补充的令牌数
)

type hsBucket struct {
	tokens float64
	last   time.Time
}

type hsLimiter struct {
	mu      sync.Mutex
	buckets map[string]*hsBucket
	// 被丢弃计数的日志限频
	lastLog time.Time
	dropped uint64
}

func newHSLimiter() *hsLimiter {
	return &hsLimiter{buckets: map[string]*hsBucket{}}
}

// allow 消耗一个令牌；超过速率则返回 false。
func (l *hsLimiter) allow(ip string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[ip]
	if !ok {
		// 简单清理：桶太多时丢掉一半（够用即可，避免无界增长）
		if len(l.buckets) > 4096 {
			for k := range l.buckets {
				delete(l.buckets, k)
				if len(l.buckets) < 2048 {
					break
				}
			}
		}
		b = &hsBucket{tokens: hsBurst, last: now}
		l.buckets[ip] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * hsRateIP
		if b.tokens > hsBurst {
			b.tokens = hsBurst
		}
		b.last = now
	}
	if b.tokens < 1 {
		l.dropped++
		return false
	}
	b.tokens--
	return true
}

// droppedSince returns how many handshakes were dropped since the last call
// (used for the rate-limited warning log).
func (l *hsLimiter) droppedSince() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := l.dropped
	l.dropped = 0
	return n
}

// noteHSDrop logs handshake floods at most once a minute.
func (e *Engine) noteHSDrop(ip string) {
	e.mu.Lock()
	last := e.hsLogAt
	now := time.Now()
	allow := now.Sub(last) > time.Minute
	if allow {
		e.hsLogAt = now
	}
	e.mu.Unlock()
	if !allow {
		return
	}
	n := e.hsLimiter.droppedSince()
	e.logf("握手限速：丢弃来自 %s 的握手（最近一分钟共 %d 次）—— 若这是你自己的机器，检查是否在疯狂重连", ip, n)
}

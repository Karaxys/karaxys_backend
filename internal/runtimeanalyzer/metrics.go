package runtimeanalyzer

import (
	"sync/atomic"
	"time"
)

type Metrics struct {
	consumed        atomic.Uint64
	processed       atomic.Uint64
	failed          atomic.Uint64
	retried         atomic.Uint64
	deadLettered    atomic.Uint64
	committed       atomic.Uint64
	lastLagMillis   atomic.Int64
	maxLagMillis    atomic.Int64
	lastMessageUnix atomic.Int64
}

type MetricsSnapshot struct {
	Consumed      uint64        `json:"consumed"`
	Processed     uint64        `json:"processed"`
	Failed        uint64        `json:"failed"`
	Retried       uint64        `json:"retried"`
	DeadLettered  uint64        `json:"dead_lettered"`
	Committed     uint64        `json:"committed"`
	LastLag       time.Duration `json:"last_lag"`
	MaxLag        time.Duration `json:"max_lag"`
	LastMessageAt time.Time     `json:"last_message_at,omitempty"`
}

func (m *Metrics) Snapshot() MetricsSnapshot {
	if m == nil {
		return MetricsSnapshot{}
	}
	snapshot := MetricsSnapshot{
		Consumed:     m.consumed.Load(),
		Processed:    m.processed.Load(),
		Failed:       m.failed.Load(),
		Retried:      m.retried.Load(),
		DeadLettered: m.deadLettered.Load(),
		Committed:    m.committed.Load(),
		LastLag:      time.Duration(m.lastLagMillis.Load()) * time.Millisecond,
		MaxLag:       time.Duration(m.maxLagMillis.Load()) * time.Millisecond,
	}
	if unix := m.lastMessageUnix.Load(); unix > 0 {
		snapshot.LastMessageAt = time.Unix(unix, 0).UTC()
	}
	return snapshot
}

func (m *Metrics) observeConsumed(messageTime time.Time, now time.Time) {
	if m == nil {
		return
	}
	m.consumed.Add(1)
	m.lastMessageUnix.Store(now.Unix())
	if messageTime.IsZero() {
		return
	}
	lag := now.Sub(messageTime)
	if lag < 0 {
		lag = 0
	}
	lagMillis := lag.Milliseconds()
	m.lastLagMillis.Store(lagMillis)
	for {
		current := m.maxLagMillis.Load()
		if lagMillis <= current || m.maxLagMillis.CompareAndSwap(current, lagMillis) {
			return
		}
	}
}

func (m *Metrics) observeProcessed() {
	if m != nil {
		m.processed.Add(1)
	}
}

func (m *Metrics) observeFailed() {
	if m != nil {
		m.failed.Add(1)
	}
}

func (m *Metrics) observeRetried() {
	if m != nil {
		m.retried.Add(1)
	}
}

func (m *Metrics) observeDeadLettered() {
	if m != nil {
		m.deadLettered.Add(1)
	}
}

func (m *Metrics) observeCommitted() {
	if m != nil {
		m.committed.Add(1)
	}
}

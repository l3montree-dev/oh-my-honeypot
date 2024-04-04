package store

import (
	"log/slog"
	"sync"
	"time"
)

func reverse[S ~[]E, E any](s S) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

type Timed interface {
	GetIssuedAt() time.Time
}

type timedEntry[T Timed] struct {
	msg  T
	time time.Time
}

type TimeLifo[T Timed] struct {
	msgs     []timedEntry[T]
	duration time.Duration
	msgsLock sync.Mutex
}

func (l *TimeLifo[T]) Store(msg T) error {
	l.msgsLock.Lock()
	defer l.msgsLock.Unlock()

	l.msgs = append(l.msgs, timedEntry[T]{msg, msg.GetIssuedAt()})
	return nil
}

func (l *TimeLifo[T]) Get() []T {
	l.msgsLock.Lock()
	defer l.msgsLock.Unlock()

	msgs := make([]T, len(l.msgs))
	// reverse the order
	for i, msg := range l.msgs {
		msgs[len(l.msgs)-i-1] = msg.msg
	}
	return msgs
}

func (l *TimeLifo[T]) Count() int {
	return len(l.msgs)
}

func (l *TimeLifo[T]) clean() {
	l.msgsLock.Lock()
	defer l.msgsLock.Unlock()

	now := time.Now()

	for i, msg := range l.msgs {
		if now.Sub(msg.time) < l.duration {
			// delete everything before i
			l.msgs = l.msgs[i:]
			slog.Info("cleaned messages from timeLifo", "amount", max(0, i-1))
			return
		}
	}
}

func NewTimeLifo[T Timed](duration time.Duration) Store[T] {
	timeLifoStore := &TimeLifo[T]{
		msgs:     make([]timedEntry[T], 0),
		duration: duration,
		msgsLock: sync.Mutex{},
	}
	// create a ticker which cleans the store every 10 seconds
	ticker := time.NewTicker(10 * time.Second)
	go func() {
		for range ticker.C {
			timeLifoStore.clean()
		}
	}()

	return timeLifoStore
}

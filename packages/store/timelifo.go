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

type Timefifo[T Timed] struct {
	msgs     []timedEntry[T]
	duration time.Duration
	msgsLock sync.Mutex
}

func (l *Timefifo[T]) Store(msg T) error {
	l.msgsLock.Lock()
	defer l.msgsLock.Unlock()

	l.msgs = append(l.msgs, timedEntry[T]{msg, msg.GetIssuedAt()})
	return nil
}

func (l *Timefifo[T]) Get() []T {
	l.msgsLock.Lock()
	defer l.msgsLock.Unlock()

	msgs := make([]T, len(l.msgs))
	// reverse the order
	for i, msg := range l.msgs {
		msgs[len(l.msgs)-i-1] = msg.msg
	}
	return msgs
}

func (l *Timefifo[T]) Count() int {
	return len(l.msgs)
}

func (l *Timefifo[T]) clean() {
	l.msgsLock.Lock()
	defer l.msgsLock.Unlock()

	now := time.Now()

	for i, msg := range l.msgs {
		if now.Sub(msg.time) < l.duration {
			// delete everything before i
			l.msgs = l.msgs[i:]
			slog.Info("cleaned messages from timefifo", "amount", max(0, i-1))
			return
		}
	}
}

func NewTimefifo[T Timed](duration time.Duration) Store[T] {
	timefifoStore := &Timefifo[T]{
		msgs:     make([]timedEntry[T], 0),
		duration: duration,
		msgsLock: sync.Mutex{},
	}
	// create a ticker which cleans the store every 10 seconds
	ticker := time.NewTicker(10 * time.Second)
	go func() {
		for range ticker.C {
			timefifoStore.clean()
		}
	}()

	return timefifoStore
}

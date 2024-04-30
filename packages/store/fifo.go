package store

type FIFO[T any] struct {
	msgs []T
	size int
}

func (l *FIFO[T]) Store(msg T) error {
	l.msgs = append(l.msgs, msg)
	if len(l.msgs) > l.size {
		l.msgs = l.msgs[1:]
	}
	return nil
}

func (l *FIFO[T]) Get() []T {
	return l.msgs
}

func (l *FIFO[T]) Count() int {
	return len(l.msgs)
}

func NewFIFO[T any](size int) Store[T] {
	return &FIFO[T]{
		msgs: make([]T, 0),
		size: size,
	}
}

package store

type LIFO[T any] struct {
	msgs []T
	size int
}

func (l *LIFO[T]) Store(msg T) error {
	l.msgs = append(l.msgs, msg)
	if len(l.msgs) > l.size {
		l.msgs = l.msgs[1:]
	}
	return nil
}

func (l *LIFO[T]) Get() []T {
	return l.msgs
}

func (l *LIFO[T]) Count() int {
	return len(l.msgs)
}

func NewLIFO[T any](size int) Store[T] {
	return &LIFO[T]{
		msgs: make([]T, 0),
		size: size,
	}
}

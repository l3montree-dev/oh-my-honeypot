package store

type Store[T any] interface {
	// Store a message
	Store(msg T) error
	// Get all messages
	Get() []T
	// Get the number of messages
	Count() int
}

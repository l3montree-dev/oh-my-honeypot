package store

import (
	"bufio"
	"encoding/json"
	"log/slog"
	"os"
)

type Store[T any] interface {
	// Store a message
	Store(msg T) error
	// Get all messages
	Get() []T
	// Get the number of messages
	Count() int
}

type Serializer[T any] interface {
	// Serialize the message
	Serialize(element T) ([]byte, error)
	// Deserialize the message
	Deserialize([]byte) (T, error)
}

type FileDecorator[T any] struct {
	file       *os.File
	store      Store[T]
	serializer Serializer[T]
}

func NewFileDecorator[T any](file *os.File, serializer Serializer[T], store Store[T]) Store[T] {
	middleware := FileDecorator[T]{
		file:       file,
		store:      store,
		serializer: serializer,
	}

	// read the file line by line
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		msg, err := serializer.Deserialize([]byte(scanner.Text()))
		if err != nil {
			panic(err)
		}

		if err := middleware.store.Store(msg); err != nil {
			slog.Warn("could not store into file", "err", err)
		}
	}

	return &middleware
}

func (f *FileDecorator[T]) StoreAll(msgs []T) error {
	for _, msg := range msgs {
		err := f.Store(msg)
		if err != nil {
			return err
		}
	}
	return nil
}

func (f *FileDecorator[T]) Store(msg T) error {
	// serialize the message
	serialized, err := f.serializer.Serialize(msg)
	if err != nil {
		return err
	}
	serialized = append(serialized, []byte("\n")...)
	// write the message to the file
	_, err = f.file.Write(serialized)
	if err != nil {
		return err
	}
	// store the message
	return f.store.Store(msg)
}

func (f *FileDecorator[T]) Get() []T {
	return f.store.Get()
}

func (f *FileDecorator[T]) Count() int {
	return f.store.Count()
}

type JSONSerializer[T any] struct{}

func (j JSONSerializer[T]) Serialize(element T) ([]byte, error) {
	return json.Marshal(element)
}

func (j JSONSerializer[T]) Deserialize(data []byte) (T, error) {
	var token T
	err := json.Unmarshal(data, &token)
	return token, err
}

func NewJSONSerializer[T any]() JSONSerializer[T] {
	return JSONSerializer[T]{}
}

package pipeline

import (
	"log/slog"
	"time"
)

func Drain[T any](input <-chan T) {
	go func() {
		for range input {
			// just drain it without doing anything
		}
	}()
}

func Merge[T any](inputs ...<-chan T) <-chan T {
	output := make(chan T)
	for _, input := range inputs {
		go func(input <-chan T) {
			for msg := range input {
				output <- msg
			}
		}(input)
	}
	return output
}

func Filter[T any](input <-chan T, filterFn func(input T) bool) <-chan T {
	output := make(chan T)
	go func() {
		for msg := range input {
			if filterFn(msg) {
				output <- msg
			}
		}
	}()
	return output
}

func Broadcast[T any](input <-chan T, outputs ...chan<- T) {
	go func() {
		for msg := range input {
			for _, output := range outputs {
				select {
				case output <- msg:
				default:
					// just swallow the error
					slog.Warn("could not write to channel")
				}
			}
		}
	}()
}

func Pipe[T any](input <-chan T, output chan<- T) {
	go func() {
		for msg := range input {
			select {
			case output <- msg:
			default:
				// just swallow the error
				slog.Warn("could not write to channel")
			}
		}
	}()
}

func Map[T any, R any](input <-chan T, transformFn func(input T) (R, error)) <-chan R {
	output := make(chan R)
	go func() {
		for msg := range input {
			tmp, err := transformFn(msg)
			if err != nil {
				// just swallow the error
				slog.Error("could not map", "err", err)
				continue
			}
			output <- tmp
		}
	}()
	return output
}

func Aggregate[T any](input <-chan T, aggregateTime time.Duration, aggregateFn func(acc []T) []T) <-chan T {
	output := make(chan T)
	go func() {
		buffer := make([]T, 0)
		trigger := time.NewTicker(aggregateTime)
		for {
			select {
			case msg := <-input:
				buffer = append(buffer, msg)
				if trigger == nil {
					// set a new trigger
					trigger = time.NewTicker(aggregateTime)
					continue
				}
			case <-trigger.C:
				tmp := aggregateFn(buffer)

				for _, m := range tmp {
					output <- m
				}
				buffer = make([]T, 0)

			}
		}
	}()
	return output
}

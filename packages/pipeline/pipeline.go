package pipeline

import "log"

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
					log.Println("could not write to channel")
				}
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
				log.Println(err)
				continue
			}
			output <- tmp
		}
	}()
	return output
}

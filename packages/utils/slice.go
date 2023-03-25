package utils

func Map[T any, R any](input []T, transformFn func(input T) R) []R {
	output := make([]R, len(input))
	for i, msg := range input {
		output[i] = transformFn(msg)
	}
	return output
}

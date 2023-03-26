package utils

type Comparable[T any] interface {
	Compare(T) int
}

func Map[T any, R any](input []T, transformFn func(input T) R) []R {
	output := make([]R, len(input))
	for i, msg := range input {
		output[i] = transformFn(msg)
	}
	return output
}

func BinarySearch[T Comparable[T]](a []T, x T) int {
	start, mid, end := 0, 0, len(a)-1
	for start <= end {
		mid = (start + end) >> 1
		el := a[mid]
		switch {
		case el.Compare(x) > 0:
			end = mid - 1
		case el.Compare(x) < 0:
			start = mid + 1
		default:
			return mid
		}
	}
	return -1
}

func Filter[T any](a []T, filterFn func(input T) bool) []T {
	output := make([]T, 0)
	for _, msg := range a {
		if filterFn(msg) {
			output = append(output, msg)
		}
	}
	return output
}

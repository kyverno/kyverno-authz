package events

type ringBuffer[T any] struct {
	data  []T
	size  int
	start int // index of oldest element
	count int // number of elements currently stored
}

func NewRingBuffer[T any](size int) *ringBuffer[T] {
	return &ringBuffer[T]{
		data: make([]T, size),
		size: size,
	}
}

func (r *ringBuffer[T]) Push(v T) {
	// we have enough space to store this entry.
	// will be stored at the end of the buffer
	if r.count < r.size {
		r.data[(r.start+r.count)%r.size] = v
		r.count++
		return
	}

	// overwrite oldest entry in the buffer but mark the start as the oldest + 1
	// mod r.size. because the start counter can grow infinitely
	r.data[r.start] = v
	// if start is now 1, then the buffer is essentially [2, 3, 4]
	r.start = (r.start + 1) % r.size
}

func (r *ringBuffer[T]) Values() []T {
	out := make([]T, r.count)
	for i := 0; i < r.count; i++ {
		// this will start at the middle if the middle was pushed due to exceeding capacity
		// so the last pushed element will be at the last index
		out[i] = r.data[(r.start+i)%r.size]
	}
	return out
}

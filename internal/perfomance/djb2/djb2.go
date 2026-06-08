package djb2

import (
	"encoding/binary"
	"hash"
)

const (
	size  = 8
	block = 8
	start = 5381
)

type Djb2 struct {
	sum uint64
}

func New() hash.Hash {
	return &Djb2{sum: start}
}

func (h *Djb2) BlockSize() int {
	return block
}

func (h *Djb2) Size() int {
	return size
}

func (h *Djb2) Reset() {
	h.sum = start
}

func (h *Djb2) Write(b []byte) (n int, err error) {
	for i := 0; i < len(b); i++ {
		h.sum = ((h.sum << 5) + h.sum) + uint64(b[i])
	}

	return len(b), nil
}

func (h *Djb2) Sum(b []byte) []byte {
	if len(b) > 0 {
		_, _ = h.Write(b)
	}

	v := make([]byte, size)
	binary.LittleEndian.PutUint64(v, h.sum)

	return v
}

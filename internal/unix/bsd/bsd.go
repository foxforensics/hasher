// Package bsd
package bsd

import (
	"fmt"
	"hash"
)

type BSD struct {
	sum uint16
}

func New() hash.Hash {
	return new(BSD)
}

func (h *BSD) BlockSize() int {
	return 1
}

func (h *BSD) Size() int {
	return 2
}

func (h *BSD) Reset() {
	h.sum = 0
}

func (h *BSD) Write(b []byte) (n int, err error) {
	for _, v := range b {
		h.sum = (h.sum >> 1) + ((h.sum & 1) << 15)
		h.sum += uint16(v)
	}

	return len(b), nil
}

func (h *BSD) Sum(b []byte) []byte {
	return append(b, fmt.Sprintf("%05d", h.sum)...)
}

// Package bsd
package bsd

import (
	"fmt"
	"hash"
	"log"
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
	if len(b) > 0 {
		_, err := h.Write(b)

		if err != nil {
			log.Println(err)
		}
	}

	return []byte(fmt.Sprintf("%05d", h.sum))
}

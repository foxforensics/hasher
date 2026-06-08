package sdhash

import (
	"hash"
	"strings"

	"github.com/malwarology/sdhash"
)

type Sdhash struct {
	sdbf sdhash.Sdbf
}

func New() hash.Hash {
	return new(Sdhash)
}

func (h *Sdhash) BlockSize() int {
	return 0 // stream mode
}

func (h *Sdhash) Size() int {
	return len(h.sdbf.String())
}

func (h *Sdhash) Reset() {
	h.sdbf = nil
}

func (h *Sdhash) Write(b []byte) (n int, err error) {
	f, err := sdhash.New(b)

	if err != nil {
		return 0, err
	}

	h.sdbf, err = f.Compute()

	if err != nil {
		return 0, err
	}

	return len(b), nil
}

func (h *Sdhash) Sum(_ []byte) []byte {
	return []byte(strings.TrimSpace(h.sdbf.String()))
}

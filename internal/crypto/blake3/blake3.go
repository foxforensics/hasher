package blake3

import "github.com/zeebo/blake3"

type Blake3 struct {
	blake3.Hasher
	size int
}

func New256() *Blake3 {
	return &Blake3{*blake3.New(), 32}
}

func New512() *Blake3 {
	return &Blake3{*blake3.New(), 64}
}

func (h *Blake3) Sum(b []byte) []byte {
	sum := make([]byte, h.size)
	_, _ = h.Hasher.Digest().Read(sum)

	return append(b, sum...)
}

package shake

import "crypto/sha3"

type Shake struct {
	sha3.SHAKE
	size int
}

func New128() *Shake {
	return &Shake{*sha3.NewSHAKE128(), 16}
}

func New256() *Shake {
	return &Shake{*sha3.NewSHAKE256(), 32}
}

func (h *Shake) Size() int {
	return h.size
}

func (h *Shake) Sum(b []byte) []byte {
	sum := make([]byte, h.size)
	_, _ = h.Read(sum)

	return append(b, sum...)
}

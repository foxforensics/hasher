// Package luhn source: https://github.com/theplant/luhn/blob/master/luhn.go
package luhn

import (
	"errors"
	"hash"
	"log"
	"strconv"
	"strings"
)

type Luhn struct {
	num int
}

func New() hash.Hash {
	return new(Luhn)
}

func (h *Luhn) BlockSize() int {
	return 1
}

func (h *Luhn) Size() int {
	return 1
}

func (h *Luhn) Reset() {
	h.num = 0
}

func (h *Luhn) Write(b []byte) (n int, err error) {
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))

	if err != nil {
		return 0, errors.New("could not parse number")
	}

	for i := 0; v > 0; i++ {
		cur := v % 10

		if i%2 == 0 {
			cur = cur * 2
			if cur > 9 {
				cur = cur%10 + cur/10
			}
		}

		h.num += cur
		v = v / 10
	}

	h.num %= 10

	return len(b), nil
}

func (h *Luhn) Sum(b []byte) []byte {
	if len(b) > 0 {
		_, err := h.Write(b)

		if err != nil {
			log.Println(err)
		}
	}

	if h.num == 0 {
		return []byte{'0'}
	}

	return []byte(strconv.Itoa(10 - h.num))
}

package imghash

import (
	"bytes"
	"errors"
	"hash"
	"image"

	"github.com/ajdnik/imghash/v2"
)

const (
	Average HashType = iota
	Difference
	Median
	PHash
	WHash
	MarrHildreth
	BlockMean
	PDQ
	RASH
)

type HashType int

type Hash struct {
	hsr imghash.Hasher
	sum imghash.Hash
	ht  HashType
}

func New(ht HashType) (hash.Hash, error) {
	var hsr imghash.Hasher
	var err error

	hsr, err = getHasher(ht)

	if err != nil {
		return nil, err
	}

	return &Hash{hsr: hsr, ht: ht}, nil
}

func (h *Hash) BlockSize() int {
	return 0 // individual
}

func (h *Hash) Size() int {
	return 0 // individual
}

func (h *Hash) Reset() {
	h.hsr, _ = getHasher(h.ht)
	h.sum = nil
}

func (h *Hash) Write(b []byte) (n int, err error) {
	img, _, err := image.Decode(bytes.NewReader(b))

	if err != nil {
		return 0, errors.New("invalid image format")
	}

	h.sum, err = h.hsr.Calculate(img)

	if err != nil {
		return 0, err
	}

	return len(b), nil
}

func (h *Hash) Sum(b []byte) []byte {
	if h.sum != nil {
		if sum, ok := h.sum.(imghash.Binary); ok {
			return append(b, sum...)
		}
	}

	return nil
}

func getHasher(ht HashType) (imghash.Hasher, error) {
	switch ht {
	case Average:
		return imghash.NewAverage()
	case Difference:
		return imghash.NewDifference()
	case Median:
		return imghash.NewMedian()
	case PHash:
		return imghash.NewPHash()
	case WHash:
		return imghash.NewWHash()
	case MarrHildreth:
		return imghash.NewMarrHildreth()
	case BlockMean:
		return imghash.NewBlockMean()
	case PDQ:
		return imghash.NewPDQ()
	case RASH:
		return imghash.NewRASH()
	default:
		return nil, errors.New("invalid hash type")
	}
}

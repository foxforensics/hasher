// Package hash provides general hash functions.
package hash

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"hash/fnv"
	"strings"

	"github.com/cespare/xxhash"
	"github.com/dchest/siphash"
	"github.com/glaslos/ssdeep"
	"github.com/glaslos/tlsh"
	"github.com/htruong/go-md2"
	"github.com/jzelinskie/whirlpool"
	"github.com/pedroalbanese/md6"
	"github.com/spaolacci/murmur3"
	"github.com/tjfoc/gmsm/v2/sm3"
	"github.com/zeebo/xxh3"
	"go.dw1.io/rapidhash"
	"go.foxforensics.dev/go-hash/skein"
	"go.foxforensics.dev/go-hash/streebog"
	"go.foxforensics.dev/go-krypto/has160"
	"go.foxforensics.dev/go-krypto/lsh256"
	"go.foxforensics.dev/go-krypto/lsh512"
	"go.foxforensics.dev/hasher/internal/checksum/kermit"
	"go.foxforensics.dev/hasher/internal/checksum/luhn"
	"go.foxforensics.dev/hasher/internal/crypto/blake3"
	"go.foxforensics.dev/hasher/internal/crypto/shake"
	"go.foxforensics.dev/hasher/internal/perceptual/imghash"
	"go.foxforensics.dev/hasher/internal/perfomance/djb2"
	"go.foxforensics.dev/hasher/internal/perfomance/xxh"
	"go.foxforensics.dev/hasher/internal/similarity/impfuzzy"
	"go.foxforensics.dev/hasher/internal/similarity/imphash"
	"go.foxforensics.dev/hasher/internal/similarity/sdhash"
	"go.foxforensics.dev/hasher/internal/unix/bsd"
	"go.foxforensics.dev/hasher/internal/unix/elf"
	"go.foxforensics.dev/hasher/internal/unix/sysv"
	"go.foxforensics.dev/hasher/internal/windows/lm"
	"go.foxforensics.dev/hasher/internal/windows/nt"
	"go.foxforensics.dev/hasher/internal/windows/pe"
	"go.solidsystem.no/fletcher4"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
)

// Algorithms supported
var Algorithms = []struct {
	Name string
	Type Type
}{
	{ADLER32, Checksum},
	{AVERAGE, Perceptual},
	{BLAKE2S256, Cryptographic},
	{BLAKE2B256, Cryptographic},
	{BLAKE2B384, Cryptographic},
	{BLAKE2B512, Cryptographic},
	{BLAKE3256, Cryptographic},
	{BLAKE3512, Cryptographic},
	{BLOCKMEAN, Perceptual},
	{BSD, Unix},
	{CRC16CCITT, Checksum},
	{CRC32C, Checksum},
	{CRC32K, Checksum},
	{CRC32IEEE, Checksum},
	{CRC64ECMA, Checksum},
	{CRC64ISO, Checksum},
	{DIFFERENCE, Perceptual},
	{DJB2, Performance},
	{ELF, Unix},
	{FLETCHER4, Checksum},
	{FNV1, Performance},
	{FNV1A, Performance},
	{GOST2012256, Cryptographic},
	{GOST2012512, Cryptographic},
	{HAS160, Cryptographic},
	{IMPFUZZY, Similarity},
	{IMPHASHO, Similarity},
	{IMPHASHS, Similarity},
	{LM, Windows},
	{LSH256, Cryptographic},
	{LSH512, Cryptographic},
	{LUHN, Checksum},
	{MARRHILDRETH, Perceptual},
	{MD2, Cryptographic},
	{MD4, Cryptographic},
	{MD5, Cryptographic},
	{MD6, Cryptographic},
	{MEDIAN, Perceptual},
	{MURMUR3, Performance},
	{NT, Windows},
	{PDQ, Perceptual},
	{PE, Windows},
	{PHASH, Perceptual},
	{RAPIDHASH, Performance},
	{RASH, Perceptual},
	{RIPEMD160, Cryptographic},
	{SDHASH, Similarity},
	{SHA1, Cryptographic},
	{SHA256, Cryptographic},
	{SHA512, Cryptographic},
	{SHA3, Cryptographic},
	{SHA3224, Cryptographic},
	{SHA3256, Cryptographic},
	{SHA3384, Cryptographic},
	{SHA3512, Cryptographic},
	{SHAKE128, Cryptographic},
	{SHAKE256, Cryptographic},
	{SIPHASH, Performance},
	{SKEIN224, Cryptographic},
	{SKEIN256, Cryptographic},
	{SKEIN384, Cryptographic},
	{SKEIN512, Cryptographic},
	{SM3, Cryptographic},
	{SSDEEP, Similarity},
	{STREEBOG256, Cryptographic},
	{STREEBOG512, Cryptographic},
	{SYSV, Unix},
	{TLSH, Similarity},
	{WHASH, Perceptual},
	{WHIRLPOOL, Cryptographic},
	{XXH3, Performance},
	{XXH32, Performance},
	{XXH64, Performance},
}

// NotSupported if algorithm is unknown
var NotSupported = errors.New("algorithm not supported")

// MustSum returns only the hash sum.
func MustSum(algo string, data []byte) string {
	sum, err := Sum(algo, data)

	if err != nil {
		return ""
	}

	return sum
}

// Sum returns the hash sum and any errors.
func Sum(algo string, data []byte) (string, error) {
	var h hash.Hash
	var err error

	ssdeep.Force = true

	// this list kills our cyclomatic complexity!
	switch strings.ToLower(algo) {
	case ADLER32:
		h = adler32.New()
	case AVERAGE:
		h = imghash.New(imghash.Average)
	case BLAKE2B256:
		h, err = blake2b.New256(nil)
	case BLAKE2B384:
		h, err = blake2b.New384(nil)
	case BLAKE2B512:
		h, err = blake2b.New512(nil)
	case BLAKE2S256:
		h, err = blake2s.New256(nil)
	case BLAKE3256:
		h = blake3.New256()
	case BLAKE3512:
		h = blake3.New512()
	case BLOCKMEAN:
		h = imghash.New(imghash.BlockMean)
	case BSD:
		h = bsd.New()
	case CRC16CCITT:
		h = kermit.New()
	case CRC32C:
		h = crc32.New(crc32.MakeTable(crc32.Castagnoli))
	case CRC32K:
		h = crc32.New(crc32.MakeTable(crc32.Koopman))
	case CRC32IEEE:
		h = crc32.NewIEEE()
	case CRC64ECMA:
		h = crc64.New(crc64.MakeTable(crc64.ECMA))
	case CRC64ISO:
		h = crc64.New(crc64.MakeTable(crc64.ISO))
	case DIFFERENCE:
		h = imghash.New(imghash.Difference)
	case DJB2:
		h = djb2.New()
	case ELF:
		h = elf.New()
	case FLETCHER4:
		h = fletcher4.New()
	case FNV1:
		h = fnv.New128()
	case FNV1A:
		h = fnv.New128a()
	case GOST2012256, STREEBOG256:
		h = streebog.New256()
	case GOST2012512, STREEBOG512:
		h = streebog.New512()
	case HAS160:
		h = has160.New()
	case IMPFUZZY:
		h = impfuzzy.New()
	case IMPHASHO:
		h = imphash.NewUnsorted()
	case IMPHASHS:
		h = imphash.NewSorted()
	case LM:
		h = lm.New()
	case LSH256:
		h = lsh256.New()
	case LSH512:
		h = lsh512.New()
	case LUHN:
		h = luhn.New()
	case MARRHILDRETH:
		h = imghash.New(imghash.MarrHildreth)
	case MD2:
		h = md2.New()
	case MD4:
		h = md4.New()
	case MD5:
		h = md5.New()
	case MD6:
		h = md6.New256()
	case MEDIAN:
		h = imghash.New(imghash.Median)
	case MURMUR3:
		h = murmur3.New64() // Murmur3f
	case NT:
		h = nt.New()
	case PDQ:
		h = imghash.New(imghash.PDQ)
	case PE:
		h = pe.New()
	case PHASH:
		h = imghash.New(imghash.PHash)
	case RAPIDHASH:
		h = rapidhash.New()
	case RASH:
		h = imghash.New(imghash.RASH)
	case RIPEMD160:
		h = ripemd160.New()
	case SDHASH:
		h = sdhash.New()
	case SHA1:
		h = sha1.New()
	case SHA224:
		h = sha256.New224()
	case SHA256:
		h = sha256.New()
	case SHA512:
		h = sha512.New()
	case SHA3:
		fallthrough
	case SHA3224:
		h = sha3.New224()
	case SHA3256:
		h = sha3.New256()
	case SHA3384:
		h = sha3.New384()
	case SHA3512:
		h = sha3.New512()
	case SHAKE128:
		h = shake.New128()
	case SHAKE256:
		h = shake.New256()
	case SIPHASH:
		h = siphash.New(make([]byte, 16)) // SipHash-2-4 with zero key
	case SKEIN224:
		h = skein.NewHash224()
	case SKEIN256:
		h = skein.NewHash256()
	case SKEIN384:
		h = skein.NewHash384()
	case SKEIN512:
		h = skein.NewHash512()
	case SM3:
		h = sm3.New()
	case SSDEEP:
		h = ssdeep.New()
	case SYSV:
		h = sysv.New()
	case TLSH:
		h = tlsh.New()
	case WHASH:
		h = imghash.New(imghash.WHash)
	case WHIRLPOOL:
		h = whirlpool.New()
	case XXH3:
		h = xxh3.New()
	case XXH32:
		h = xxh.New()
	case XXH64:
		h = xxhash.New()
	default:
		return "", NotSupported
	}

	if err != nil {
		return "", err
	}

	// reset is needed for some implementations
	h.Reset()

	if _, err := h.Write(data); err != nil {
		return "", err
	}

	// special formating for some hashes
	switch algo {
	case BSD, SYSV, LUHN, SDHASH, SSDEEP, IMPFUZZY:
		return fmt.Sprintf("%s", h.Sum(nil)), nil
	case TLSH:
		return fmt.Sprintf("T1%x", h.Sum(nil)), nil
	default:
		return fmt.Sprintf("%x", h.Sum(nil)), nil
	}
}

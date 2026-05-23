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
	"go.foxforensics.dev/hasher/internal/blake3"
	"go.foxforensics.dev/hasher/internal/djb2"
	"go.foxforensics.dev/hasher/internal/image"
	"go.foxforensics.dev/hasher/internal/impfuzzy"
	"go.foxforensics.dev/hasher/internal/imphash"
	"go.foxforensics.dev/hasher/internal/kermit"
	"go.foxforensics.dev/hasher/internal/lm"
	"go.foxforensics.dev/hasher/internal/nt"
	"go.foxforensics.dev/hasher/internal/pe"
	"go.foxforensics.dev/hasher/internal/shake"
	"go.foxforensics.dev/hasher/internal/xxh"
	"go.solidsystem.no/fletcher4"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
)

const (
	ADLER32      = "adler32"
	AVERAGE      = "average"
	BLAKE2S256   = "blake2s-256"
	BLAKE2B256   = "blake2b-256"
	BLAKE2B384   = "blake2b-384"
	BLAKE2B512   = "blake2b-512"
	BLAKE3256    = "blake3-256"
	BLAKE3512    = "blake3-512"
	BLOCKMEAN    = "blockmean"
	CRC16CCITT   = "crc16-ccitt"
	CRC32C       = "crc32-c"
	CRC32IEEE    = "crc32-ieee"
	CRC64ECMA    = "crc64-ecma"
	CRC64ISO     = "crc64-iso"
	DIFFERENCE   = "difference"
	DJB2         = "djb2"
	FLETCHER4    = "fletcher4"
	FNV1         = "fnv-1"
	FNV1A        = "fnv-1a"
	GOST2012256  = "gost-256"
	GOST2012512  = "gost-512"
	HAS160       = "has-160"
	IMPFUZZY     = "impfuzzy"
	IMPHASHO     = "imphasho"
	IMPHASHS     = "imphashs"
	LM           = "lm"
	LSH256       = "lsh-256"
	LSH512       = "lsh-512"
	MARRHILDRETH = "marrhildreth"
	MD2          = "md2"
	MD4          = "md4"
	MD5          = "md5"
	MD6          = "md6"
	MEDIAN       = "median"
	MURMUR3      = "murmur3"
	NT           = "nt"
	PDQ          = "pdq"
	PE           = "pe"
	PHASH        = "phash"
	RAPIDHASH    = "rapidhash"
	RASH         = "rash"
	RIPEMD160    = "ripemd-160"
	SHA1         = "sha1"
	SHA224       = "sha224"
	SHA256       = "sha256"
	SHA512       = "sha512"
	SHA3         = "sha3"
	SHA3224      = "sha3-224"
	SHA3256      = "sha3-256"
	SHA3384      = "sha3-384"
	SHA3512      = "sha3-512"
	SHAKE128     = "shake128"
	SHAKE256     = "shake256"
	SIPHASH      = "siphash"
	SKEIN224     = "skein-224"
	SKEIN256     = "skein-256"
	SKEIN384     = "skein-384"
	SKEIN512     = "skein-512"
	SM3          = "sm3"
	SSDEEP       = "ssdeep"
	STREEBOG256  = "streebog-256"
	STREEBOG512  = "streebog-512"
	TLSH         = "tlsh"
	WHASH        = "whash"
	WHIRLPOOL    = "whirlpool"
	XXH3         = "xxh3"
	XXH32        = "xxh32"
	XXH64        = "xxh64"
)

// Algorithms supported
var Algorithms = []string{
	ADLER32,
	AVERAGE,
	BLAKE2S256,
	BLAKE2B256,
	BLAKE2B384,
	BLAKE2B512,
	BLAKE3256,
	BLAKE3512,
	BLOCKMEAN,
	CRC16CCITT,
	CRC32C,
	CRC32IEEE,
	CRC64ECMA,
	CRC64ISO,
	DIFFERENCE,
	DJB2,
	FLETCHER4,
	FNV1,
	FNV1A,
	GOST2012256,
	GOST2012512,
	HAS160,
	IMPFUZZY,
	IMPHASHO,
	IMPHASHS,
	LM,
	LSH256,
	LSH512,
	MARRHILDRETH,
	MD2,
	MD4,
	MD5,
	MD6,
	MEDIAN,
	MURMUR3,
	NT,
	PDQ,
	PE,
	PHASH,
	RAPIDHASH,
	RASH,
	RIPEMD160,
	SHAKE128,
	SHAKE256,
	SHA1,
	SHA256,
	SHA512,
	SHA3,
	SHA3224,
	SHA3256,
	SHA3384,
	SHA3512,
	SIPHASH,
	SKEIN224,
	SKEIN256,
	SKEIN384,
	SKEIN512,
	SM3,
	SSDEEP,
	STREEBOG256,
	STREEBOG512,
	TLSH,
	WHASH,
	WHIRLPOOL,
	XXH3,
	XXH32,
	XXH64,
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
	ssdeep.Force = true

	var h hash.Hash

	// this list kills our cyclomatic complexity!
	switch strings.ToLower(algo) {
	case ADLER32:
		h = adler32.New()
	case AVERAGE:
		h = image.New(image.Average)
	case BLAKE2B256:
		h, _ = blake2b.New256(nil)
	case BLAKE2B384:
		h, _ = blake2b.New384(nil)
	case BLAKE2B512:
		h, _ = blake2b.New512(nil)
	case BLAKE2S256:
		h, _ = blake2s.New256(nil)
	case BLAKE3256:
		h = blake3.New256()
	case BLAKE3512:
		h = blake3.New512()
	case BLOCKMEAN:
		h = image.New(image.BlockMean)
	case CRC16CCITT:
		h = kermit.New()
	case CRC32C:
		h = crc32.New(crc32.MakeTable(crc32.Castagnoli))
	case CRC32IEEE:
		h = crc32.NewIEEE()
	case CRC64ECMA:
		h = crc64.New(crc64.MakeTable(crc64.ECMA))
	case CRC64ISO:
		h = crc64.New(crc64.MakeTable(crc64.ISO))
	case DIFFERENCE:
		h = image.New(image.Difference)
	case DJB2:
		h = djb2.New()
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
	case MARRHILDRETH:
		h = image.New(image.MarrHildreth)
	case MD2:
		h = md2.New()
	case MD4:
		h = md4.New()
	case MD5:
		h = md5.New()
	case MD6:
		h = md6.New256()
	case MEDIAN:
		h = image.New(image.Median)
	case MURMUR3:
		h = murmur3.New64() // Murmur3f
	case NT:
		h = nt.New()
	case PDQ:
		h = image.New(image.PDQ)
	case PE:
		h = pe.New()
	case PHASH:
		h = image.New(image.PHash)
	case RAPIDHASH:
		h = rapidhash.New()
	case RASH:
		h = image.New(image.RASH)
	case RIPEMD160:
		h = ripemd160.New()
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
	case TLSH:
		h = tlsh.New()
	case WHASH:
		h = image.New(image.WHash)
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

	// reset is needed for some implementations
	h.Reset()

	if _, err := h.Write(data); err != nil {
		return "", err
	}

	// special formating for some hashes
	switch algo {
	case SSDEEP, IMPFUZZY:
		return fmt.Sprintf("%s", h.Sum(nil)), nil
	case TLSH:
		return fmt.Sprintf("T1%x", h.Sum(nil)), nil
	default:
		return fmt.Sprintf("%x", h.Sum(nil)), nil
	}
}

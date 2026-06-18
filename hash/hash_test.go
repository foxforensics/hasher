package hash

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSum(t *testing.T) {
	var (
		exe = fixture("test.exe")
		jpg = fixture("test.jpg")
		txt = fixture("test.txt")
		str = []byte("password")
		num = []byte("12345678")
	)

	for _, tt := range []struct {
		data []byte
		algo string
		sum  string
	}{
		{txt, ADLER32, "77e8f18a"},
		{jpg, AVERAGE, "000000b83ab4b6ff"},
		{txt, BLAKE2S256, "66f66ee8103fa01610ade3edc5b665a26f1568555244cc60ae223a0bf3973f15"},
		{txt, BLAKE2B256, "42fc534c983953720e3242d156828a463be43f89013a3752b3e4a987bf1a64b1"},
		{txt, BLAKE2B384, "a02e216c56f11d8fb666aba6f185662c9710859a5a6a6150e86846b07eb3f1fa849606accfa4d0d63014dc42e45e4478"},
		{txt, BLAKE2B512, "c82c10d6414965e8afb9887f11fa859878b4426f76501ce1f220a1cba0cdcc2349dabe6cc549a56d693612d0645696fc76de00756297a2c160d2320b3945ed4b"},
		{txt, BLAKE3256, "84d8f3878f407a6625f560a5f8074eb26afb63e1f2fa271a895351e9dc06dad6"},
		{txt, BLAKE3512, "84d8f3878f407a6625f560a5f8074eb26afb63e1f2fa271a895351e9dc06dad65dce1e7143396f0e8e386d7178593cf0ac687bbd188446aeefbcedbcc2cb822b"},
		{jpg, BLOCKMEAN, "000000000000000000000004e10724c68e8fb08e308632c630c6fcf6faf7ffff"},
		{txt, BSD, "05453"},
		{txt, CRC16CCITT, "6684"},
		{txt, CRC32C, "6e164f51"},
		{txt, CRC32K, "e173939d"},
		{txt, CRC32IEEE, "6de95d61"},
		{txt, CRC64ECMA, "1c10bfee4250c76f"},
		{txt, CRC64ISO, "37c0210d10e905f2"},
		{jpg, DIFFERENCE, "dd9d9d9d9d93934f"},
		{txt, DJB2, "c11382ce9418f74d"},
		{txt, ELF, "ca82a10b"},
		{txt, FLETCHER4, "d5966647e82e0600402fff60c45d2e798cd6912bac405a94c516498e7b162609"},
		{txt, FNV1, "72d441840983cb43f6fa42041818a9a3"},
		{txt, FNV1A, "1486149b1886b5fc094001f35136577f"},
		{txt, GOST2012256, "cf2901c0cc7f2c921fad71154b463cdb4154ee0ff249dba7a27dd42094a69ace"},
		{txt, GOST2012512, "6d01466a29c29857ceac22e32573509f870a22c10f5bf31687a9e2356993692cdccd36df88c84becc3f9babfc9018dd020c70c68c9af6823f4c72695339dfac0"},
		{txt, HAS160, "e33a300c13e74a0c6bdedf0355bf14bea50399ac"},
		{exe, IMPFUZZY, "3:snMO/I/6l:oZ/Iil"},
		{exe, IMPHASHO, "23285270545de4353386c2c1c9ed45a4"},
		{exe, IMPHASHS, "23285270545de4353386c2c1c9ed45a4"},
		{str, LM, "e52cac67419a9a224a3b108f3fa6cb6d"},
		{txt, LSH256, "ea81e0399313b58aa11ad06b1eb6d7beb3221d8e4a3c2fb3535b554d80865680"},
		{txt, LSH512, "c2a91ed0eff71b972c7dd8bc0d0b0e2191e81c518a90796ae57f86bac382a6accb96c8c24911e1bc816cafc685ce3e118ecd2a1998bd0c912141db63b10d9e1b"},
		{num, LUHN, "2"},
		{jpg, MARRHILDRETH, "8a24ad3c465f86a569e17865e8e499e2d1c6d2687591bdd3a9d5cd472d768b0c52bb89105d41d51945a478731f2c31b95f2975e2c6782c705ac41229d45549fc874e74c155ac47b6"},
		{txt, MD2, "aceb3e20d985564d17838fc437744843"},
		{txt, MD4, "fbb9a5a610458386e0ff2bdb4dea1076"},
		{txt, MD5, "f7ebcc3119549346b871212958dbc203"},
		{txt, MD6, "7abba14b23ea4438d2009118fe9d1befed73ba7420b5b7952fa8cd3c1a6ce62a"},
		{jpg, MEDIAN, "000000f83eb6feff"},
		{txt, MURMUR3, "f0fb0f9c9956af18"},
		{str, NT, "8846f7eaee8fb117ad06bdd830b7586c"},
		{jpg, PDQ, "d9a23c5fa4c9c9f23b1bc7a0c932325f54a8f3047255332cc8d4f5a86655bb47"},
		{exe, PE, "ef780000"},
		{jpg, PHASH, "d93ea5ca3bd6c93a"},
		{txt, RAPIDHASH, "0baa2da0a5631317"},
		{jpg, RASH, "bfe01f04001f0dfe"},
		{txt, RIPEMD160, "056a6da084d6453bda9fcbe132289a46beadb47f"},
		{exe, SDHASH, "sdbf:03:1:-:1024:sha1:256:5:7ff:160:1:7:AAAAAAAAAAAAAAAAAAAAAAgAAAIAAAAAAAAAQAAAAACAACAAAAgAAAAAAAAAAAAAAAAAgAAAAAAAEAAAAAAAAAAgAABABAAAAAAAAAAAAgEAAAAAAAAAAAAAAAAgAAAAQAAAAAAAAAAAAAAAAAAiAAAAAAAAAAAAAAjAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAABAAAAIAAAAAAAAAAAAAAAAAAAAABQACAAAAAAgAAAAAAAAAAAAAAAAAAAAFAAAAIAAAAAAAAIAAAAAAAIAAAAAACAAAAAAAAAAAAAA=="},
		{txt, SHA1, "7763c40e323d9d57fc151cf9732dc4d5a07eaebf"},
		{txt, SHA224, "fda53c29697655536a36469f2aea2c3d258c52be536d1016fd352054"},
		{txt, SHA256, "61a54c7611855e09266732d923e64819273baf71b65bbb7c50249083e5b655fd"},
		{txt, SHA512, "1242372730ce347e4abeeca6903cc39f46b375ac6c123256e884040a4329e217eacae6ed5f865843ec3d98323f9d96320d97aef8b120b5443092ef8349bae6da"},
		{txt, SHA3224, "3429b00349d4dae6b707647747c8f3f9c819fb2ed8087fe435a6d126"},
		{txt, SHA3256, "96b1fbd188e128c79eb5e4c3436b47785f2894187c2545d9db1dea6580ab5679"},
		{txt, SHA3384, "273e6a839c571c724ad2d071889c23d2184387e1ed7e891d80e74a5a80b12f15393d26ec1abbe34dc85025402833de92"},
		{txt, SHA3512, "5ce1d00eaf6da7409d009a3c242597559dc3cd2a0b41d5be9d2c86ae9709b66edeff0465fbdfca0432496ad0f3d839a4d3bf1d039a4161e3910d58d39d52e930"},
		{txt, SHAKE128, "e5ac91525fd7662e0296a0bf1770d11a"},
		{txt, SHAKE256, "118916ff4882732560317a580e78582708c981b0f5b75823ead7c484653a4239"},
		{txt, SIPHASH, "f9573f48b7538cb2"},
		{txt, SKEIN224, "0a8194b97106c4dbe99e9ce6227737092d7da69c933e4e840167aaa9"},
		{txt, SKEIN256, "a5cfeeb58f1a2a725fd05d58b6a0b1b175c3907672c69da83b008596c2c85290"},
		{txt, SKEIN384, "a41b2891436da0071ee942f35f50e1ab976126183ae644ede16826db51973d1bedaa251efb1ec8cffd95913447bf44d1"},
		{txt, SKEIN512, "9f4a5de3e938308781d8d771cf444538fba5f5b88105d82b4cb6c520bf688a618b1ad6d38b0e009cfd46809272c2e5308865b15fad3a5a7896389c667e92e502"},
		{txt, SM3, "e88521a90e7ee605ac639ec20b2d4be73f134b540ce13c369da67e75ebd1ab53"},
		{txt, SSDEEP, "49152:LkD0m3lNkRAA4Ml/Mo3hdWoPPwXj3NfhrZChJl7v6ih7T87/MvwFLSMyJTszqBPh:t"},
		{txt, SYSV, "39070"},
		{txt, TLSH, "T12526a757e784133b1b620334620ea5d9f31ac43e7676ce30585ee03e2356c7996b9be8"},
		{txt, WHIRLPOOL, "a3012237694df16500e018248770b7a97db5aa2cb27560e06eea4d25e376ef56eb8295d0b4e7609931bf9ad460f036fe4e99722549d8e7ed74e6c56834a1f81c"},
		{txt, XXH3, "996653bb371ee4a1"},
		{txt, XXH32, "841e9e20"},
		{txt, XXH64, "6047f571a76ec9bb"},
	} {
		t.Run(tt.algo, func(t *testing.T) {
			sum, err := Sum(tt.algo, tt.data)

			if err != nil {
				t.Errorf("Sum: %v", err)
			}

			if strings.Compare(tt.sum, sum) != 0 {
				t.Errorf("sum mismatch: %s vs %s", tt.sum, sum)
			}
		})
	}
}

func BenchmarkSum(b *testing.B) {
	buf := []byte("The quick brown fox jumps over the lazy dog")

	for b.Loop() {
		_, _ = Sum(SHA256, buf)
	}
}

func fixture(file string) []byte {
	f, err := os.Open(filepath.Join("..", "testdata", file))

	if err != nil {
		log.Fatalf("fixture: %v", err)
	}

	defer func() {
		_ = f.Close()
	}()

	b, err := io.ReadAll(f)

	if err != nil {
		log.Fatalf("fixture: %v", err)
	}

	return b
}

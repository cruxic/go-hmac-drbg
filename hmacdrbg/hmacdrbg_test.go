package hmacdrbg

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"encoding/hex"
	"crypto/sha256"
)

func TestBasic(t *testing.T) {
	assert := assert.New(t)

	//These test vectors generated with https://github.com/fpgaminer/python-hmac-drbg
	seed48, _ := hex.DecodeString("b0a1f6d9707cc52b876d4a0ed0dd11718827f86f2c2405f7f9e068d9f5439e48531655d5b0d8170a389d9c176748f3f5")
	e1, _ := hex.DecodeString("550a8ad9e22d359c31e356efda")
	e2, _ := hex.DecodeString("16610f2eb23ccfde34fda35458cdeafc661ea67eb89c19223a28aab8353f322c7c")
	e3, _ := hex.DecodeString("e16bd5223256eab3f11ead68fa217e529307f5553ceecbfe96d8e2963d0d3f4b8588dec6d7d9410f1b4e3441c088e5a4d4441b8b74e23ad7f3c5312df3211601c79ee27a09dd0fc75f60d760b5c0ac0d72dd51161cb210703f0b5a307e62a14479d895c1ae73b8e3a694d8ec3d6655b949ea46b9ec07f3212de636ea717d6bb48ea5792534d1c42abaab79a761ef6b4f658d0b0c780f224a447ba63962c2943b721a44402fe1ffa667d3dbca7166aa356eba8d1fe1b5f5a5eed3c2d5139381b3ce12a3d11a3714e41639bf315810b3fd2ce5ab4086a1ea6827fb4c9d9680625f46858cf76d0622a4e9faf2507483208b632cd30817d459c4135d815f3c642188bee0eabd86f5c3faf622a5406873378eb6f59bd8fce24d3c17397af919f3f60d2b7f45fbccc205b477f38df6b0861bd155fbbdc11ea48dda7a1762b4133035b7a95b6becb17b4cdda86eed667c")

	rng := NewHmacDrbg(256, seed48, nil)
	
	got := make([]byte, len(e1))
	assert.True(rng.Generate(got))	
	assert.Equal(e1, got)
	
	got = make([]byte, len(e2))
	assert.True(rng.Generate(got))	
	assert.Equal(e2, got)
	
	got = make([]byte, len(e3))
	assert.True(rng.Generate(got))	
	assert.Equal(e3, got)	
	
	//With personalization string and reseed	
	seed48, _ = hex.DecodeString("c081232e6627b050e05a34cba6de97f6410a5e52739316443026cb2a40b5fe7648cea25464a79226bf97ef626a1a2579")
	pers, _ := hex.DecodeString("d5ae166c587fd664e1a9e32b29")
	reseed43, _ := hex.DecodeString("a7428e1be103930fed246c5e934a4bf5685a340e16db08c0ffef857332f1d96464f12f8da7a5ddfcb76cb6")
	e1, _ = hex.DecodeString("52292951368094b5a6c4af0346")
	e2, _ = hex.DecodeString("1371416f080b0b0471678e80f4a5c23f614a1937c45f1eb7a60b7cc13a03af4579")
	
	rng = NewHmacDrbg(256, seed48, pers)

	got = make([]byte, len(e1))
	assert.True(rng.Generate(got))	
	assert.Equal(e1, got)
	
	assert.Nil(rng.Reseed(reseed43))
	
	got = make([]byte, len(e2))
	assert.True(rng.Generate(got))	
	assert.Equal(e2, got)
}

func TestNIST1(t *testing.T) {
	assert := assert.New(t)

	//I think these are official test vectors from NIST.  I got them from:
	// https://github.com/fpgaminer/python-hmac-drbg/blob/master/HMAC_DRBG.rsp
	
	EntropyInput := "fa0ee1fe39c7c390aa94159d0de97564342b591777f3e5f6a4ba2aea342ec840"
	Nonce := "dd0820655cb2ffdb0da9e9310a67c9e5"
	PersonalizationString, _ := hex.DecodeString("f2e58fe60a3afc59dad37595415ffd318ccf69d67780f6fa0797dc9aa43e144c")
	EntropyInputReseed, _ := hex.DecodeString("e0629b6d7975ddfa96a399648740e60f1f9557dc58b3d7415f9ba9d4dbb501f6")
	ReturnedBits, _ := hex.DecodeString("f92d4cf99a535b20222a52a68db04c5af6f5ffc7b66a473a37a256bd8d298f9b4aa4af7e8d181e02367903f93bdb744c6c2f3f3472626b40ce9bd6a70e7b8f93992a16a76fab6b5f162568e08ee6c3e804aefd952ddd3acb791c50f2ad69e9a04028a06a9c01d3a62aca2aaf6efe69ed97a016213a2dd642b4886764072d9cbe")
	
	seed48, _ := hex.DecodeString(EntropyInput + Nonce)	
	rng := NewHmacDrbg(256, seed48, PersonalizationString)
		
	assert.Nil(rng.Reseed(EntropyInputReseed))
	
	got := make([]byte, len(ReturnedBits))
	assert.True(rng.Generate(got))	
	//yes, ignore the first batch of generated data
	assert.True(rng.Generate(got))
	assert.Equal(ReturnedBits, got)
}

func TestAllGenerationLengths(t *testing.T) {
	assert := assert.New(t)

	//I created this test vector with https://github.com/fpgaminer/python-hmac-drbg
	seed48 := make([]byte, 48)
	for i := range seed48 {
		seed48[i] = 97  //'a'
	}
	
	rng := NewHmacDrbg(256, seed48, nil)	
	
	h := sha256.New()
	
	//Test all valid Generate lengths
	buf := make([]byte, 0, MaxBytesPerGenerate)
	for n := 1; n <= MaxBytesPerGenerate; n++ {
		assert.True(rng.Generate(buf[0:n]))
		h.Write(buf[0:n])
	}
	
	got := h.Sum(nil)
	expect, _ := hex.DecodeString("ee5fb7498d044ad52dac5a4e6446da71a253d024985f4969dad8590e93890be3")
	assert.Equal(expect, got)
}

func TestHmacDrbgReader(t *testing.T) {
	assert := assert.New(t)

	//I created this test vector with https://github.com/fpgaminer/python-hmac-drbg
	seed48 := make([]byte, 48)
	for i := range seed48 {
		seed48[i] = 97  //'a'
	}
	
	reader := NewHmacDrbgReader(NewHmacDrbg(256, seed48, nil))
	
	h := sha256.New()
	
	//Read 3 bytes at a time
	buf := make([]byte, 3)
	
	//read total of MaxBytesPerGenerate*3 bytes
	for i := 0; i < MaxBytesPerGenerate; i++ {
		n, err := reader.Read(buf)
		if err != nil {
			t.Error(err)
			return
		}
		assert.Equal(3, n)
		h.Write(buf)
	}
		
	got := h.Sum(nil)
	expect, _ := hex.DecodeString("48dd72451290c1945261653dc11542b82b6903e458315020805d560ce125f534")
	assert.Equal(expect, got)
}

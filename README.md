Implements HMAC_DRBG in Go, as per NIST Special Publication 800-90A.

This implementation is a port of https://github.com/fpgaminer/python-hmac-drbg

The test suite has good coverage with seed length of 48 bytes.  Feel free to add more tests and submit a pull request.  I would appreciate a code-review too.

## Installing

```bash
go get github.com/cruxic/go-hmac-drbg/hmacdrbg
```

## Run unit tests
```bash
go get github.com/stretchr/testify/assert
go test github.com/cruxic/go-hmac-drbg/hmacdrbg
```

## Example Usage

```golang
package main

import (
	"log"
	"encoding/hex"
	"github.com/cruxic/go-hmac-drbg/hmacdrbg"
	"crypto/rand"
)

func main() {
	seed := make([]byte, 48)
	_, err := rand.Read(seed)
	if err != nil {
		log.Fatal(err)
	}

	//Note: security-level must be one of: 112, 128, 192, 256.
	//Initial seed length must be at least 1.5 times security-level
	//  (max is hmacdrbg.MaxEntropyBytes)
	rng := hmacdrbg.NewHmacDrbg(256, seed, nil)

	randData := make([]byte, 37)

	for i := 0; i < 10; i++ {
	
		//Note: Generate cannot do more than 
		// hmacdrbg.MaxBytesPerGenerate (937 bytes)
		if !rng.Generate(randData) {
			//Reseed is required every 10,000 calls to
			// Generate (sooner is fine)
			_, err = rand.Read(seed)
			if err != nil {
				log.Fatal(err)
			}
			err = rng.Reseed(seed)
			if err != nil {
				//only happens if seed < security-level
				log.Fatal(err)
			}
		}
		
		log.Println(hex.EncodeToString(randData))
	}
	
	//If you need a Readable use HmacDrbgReader
	reader := hmacdrbg.NewHmacDrbgReader(hmacdrbg.NewHmacDrbg(256, seed, nil))
	_, err = reader.Read(randData)
	if err != nil {
		//A reseed is necessary after ~9MB.
		//Use reader.Drbg.Reseed() if you need more.
		log.Fatal(err)
	}
	log.Println(hex.EncodeToString(randData))	
}
```




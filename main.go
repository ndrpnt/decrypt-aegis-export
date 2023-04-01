package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"

	"golang.org/x/crypto/scrypt"
)

type Vault struct {
	Version int `json:"version"`
	Header  struct {
		Slots []struct {
			Type      int    `json:"type"`
			UUID      string `json:"uuid"`
			Key       string `json:"key"`
			KeyParams struct {
				Nonce string `json:"nonce"`
				Tag   string `json:"tag"`
			} `json:"key_params"`
			N        int    `json:"n"`
			R        int    `json:"r"`
			P        int    `json:"p"`
			Salt     string `json:"salt"`
			Repaired bool   `json:"repaired"`
		} `json:"slots"`
		Params struct {
			Nonce string `json:"nonce"`
			Tag   string `json:"tag"`
		} `json:"params"`
	} `json:"header"`
	DB string `json:"db"`
}

type DB struct {
	Version int `json:"version"`
	Entries []struct {
		Type   string `json:"type"`
		Name   string `json:"name"`
		Issuer string `json:"issuer"`
		Group  string `json:"group"`
		Info   struct {
			Secret string `json:"secret"`
			Algo   string `json:"algo"`
			Digits int    `json:"digits"`
			Period int    `json:"period"`
		} `json:"info"`
	} `json:"entries"`
}

func main() {
	path := flag.String("vault", "", "Aegis vault path")
	pwd := flag.String("password", "", "Aegis vault password")
	flag.Parse()

	vaultJSON, err := ioutil.ReadFile(*path)
	if err != nil {
		panic(err)
	}

	var vault Vault
	err = json.Unmarshal(vaultJSON, &vault)
	if err != nil {
		panic(err)
	}

	var masterKey []byte
	for _, slot := range vault.Header.Slots {
		if slot.Type != 1 {
			continue
		}

		salt, err := hex.DecodeString(slot.Salt)
		if err != nil {
			panic(err)
		}

		masterKeyEnc, err := hex.DecodeString(slot.Key)
		if err != nil {
			panic(err)
		}

		nonce, err := hex.DecodeString(slot.KeyParams.Nonce)
		if err != nil {
			panic(err)
		}

		tag, err := hex.DecodeString(slot.KeyParams.Tag)
		if err != nil {
			panic(err)
		}

		key, err := scrypt.Key([]byte(*pwd), salt, slot.N, slot.R, slot.P, 32)
		if err != nil {
			panic(err)
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			panic(err)
		}

		masterKey, err = aesgcm.Open(nil, nonce, append(masterKeyEnc, tag...), nil)
		if err == nil {
			break
		}
	}

	if masterKey == nil {
		panic("failed to decrypt vault: invalid password?")
	}

	dbEnc, err := base64.StdEncoding.DecodeString(vault.DB)
	if err != nil {
		panic(err)
	}

	nonce, err := hex.DecodeString(vault.Header.Params.Nonce)
	if err != nil {
		panic(err)
	}

	tag, err := hex.DecodeString(vault.Header.Params.Tag)
	if err != nil {
		panic(err)
	}

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		panic(err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	dbJSON, err := aesgcm.Open(nil, nonce, append(dbEnc, tag...), nil)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(dbJSON))
	// var db DB
	// err = json.Unmarshal(dbJSON, &db)
	// if err != nil {
	// 	panic(err)
	// }
}

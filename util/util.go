package util

import (
	"crypto/rand"

	"golang.org/x/crypto/curve25519"
)

func RandomByte(num int) []byte {
	b := make([]byte, num)
	rand.Read(b)
	return b
}

func AsPublic(priv []byte) []byte {
	pub, _ := curve25519.X25519(priv, curve25519.Basepoint)
	return pub
}

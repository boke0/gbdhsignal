package model

import (
	"github.com/google/uuid"
	"github.com/boke0/gbdhsignal/util"
	"golang.org/x/crypto/curve25519"
)

type User struct {
	Id string
	PublicKey []byte
	PrivateKey []byte
}

func NewUser() User {
	id, _ := uuid.NewRandom()
	privKey := util.RandomByte(curve25519.ScalarSize)
	pubKey := util.AsPublic(privKey)
	return User {
		Id: id.String(),
		PrivateKey: privKey,
		PublicKey: pubKey,
	}
}

func (user User) RoomMember(private bool) RoomMember {
	if private {
		return RoomMember{
			Id: user.Id,
			PublicKey: &user.PublicKey,
			PrivateKey: &user.PrivateKey,
		}
	}else{
		return RoomMember{
			Id: user.Id,
			PublicKey: &user.PublicKey,
		}
	}
}

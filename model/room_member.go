package model

import "github.com/boke0/gbdhsignal/util"

type RoomMember struct {
	Id         string
	IsActive   bool
	PublicKey  *[]byte
	PrivateKey *[]byte
}

func (member *RoomMember) UpdatePrivateKey(key []byte) RoomMember {
	member.PrivateKey = &key
	pubKey := util.AsPublic(key)
	member.PublicKey = &pubKey
	return *member
}

func (member *RoomMember) UpdatePublicKey(key []byte) RoomMember {
	member.PublicKey = &key
	return *member
}

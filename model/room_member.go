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
	member.IsActive = true
	return *member
}

func (member *RoomMember) UpdatePublicKey(key []byte) RoomMember {
	member.PublicKey = &key
	member.IsActive = true
	return *member
}

func SortMembers(members []RoomMember) []RoomMember {
	test := true
	newMembers := members
	for test {
		test = false
		for i := 0; i+1 < len(members); i += 2 {
			if !(newMembers[i].IsActive || newMembers[i+1].IsActive) && i+3 < len(newMembers) {
				if newMembers[i+2].IsActive || newMembers[i+3].IsActive {
					t1 := newMembers[i]
					t2 := newMembers[i+1]
					newMembers[i] = newMembers[i+2]
					newMembers[i+1] = newMembers[i+3]
					newMembers[i+2] = t1
					newMembers[i+3] = t2
					test = true
				}
			}
		}
	}
	return newMembers
}

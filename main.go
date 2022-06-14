package main

import (
	"crypto/rand"
	"fmt"
	"sort"

	"golang.org/x/crypto/curve25519"
)

type Room struct {
	Members []RoomMember
}

type RoomMember struct {
	Id         int
	IsActive   bool
	PublicKey  *[]byte
	PrivateKey *[]byte
}

type KeyExchangeTreeNode struct {
	Id         int
	Active     bool
	PublicKey  *[]byte
	PrivateKey *[]byte
	Left       *KeyExchangeTreeNode
	Right      *KeyExchangeTreeNode
}

func (tree KeyExchangeTreeNode) Add(member RoomMember) KeyExchangeTreeNode {
	if tree.Left == nil || tree.Right == nil {
		return KeyExchangeTreeNode{
			Left: &tree,
			Right: &KeyExchangeTreeNode{
				Active:     member.IsActive,
				Id:         member.Id,
				PrivateKey: member.PrivateKey,
				PublicKey:  member.PublicKey,
			},
		}
	} else if tree.Left.Count() > tree.Right.Count() && (tree.Right.IsActive() || member.IsActive) {
		right := tree.Right.Add(member)
		tree.Right = &right
		return tree
	} else {
		return KeyExchangeTreeNode{
			Left: &tree,
			Right: &KeyExchangeTreeNode{
				Active:     member.IsActive,
				Id:         member.Id,
				PrivateKey: member.PrivateKey,
				PublicKey:  member.PublicKey,
			},
		}
	}
}

func (tree KeyExchangeTreeNode) Count() int {
	if tree.Right == nil || tree.Left == nil {
		return 1
	} else {
		return tree.Right.Count() + tree.Left.Count()
	}
}

func (tree KeyExchangeTreeNode) IsActive() bool {
	if tree.Right == nil && tree.Left == nil {
		return tree.Active
	} else {
		return tree.Left.IsActive() || tree.Right.IsActive()
	}
}

func (tree KeyExchangeTreeNode) IsFull() bool {
	if tree.Right == nil && tree.Left == nil {
		return true
	} else {
		return tree.Left.IsFull() && tree.Right.IsFull()
	}
}

func (tree KeyExchangeTreeNode) HasPrivate() bool {
	if tree.Right == nil && tree.Left == nil {
		return true
	} else {
		return tree.Left.HasPrivate() || tree.Right.HasPrivate()
	}
}

func (tree KeyExchangeTreeNode) GetPrivateKey() []byte {
	if tree.Right == nil && tree.Left == nil {
		return *tree.PrivateKey
	} else if tree.HasPrivate() {
		return tree.Left.GetPrivateKey()
	} else {
		return tree.Right.GetPrivateKey()
	}
}

func (tree KeyExchangeTreeNode) Exchange() []byte {
	if tree.Left == nil || tree.Right == nil {
		if tree.PrivateKey != nil {
			return *tree.PrivateKey
		}else{
			return *tree.PublicKey
		}
	}else{
		var privateKey, publicKey []byte
		if tree.Left.HasPrivate() {
			privateKey = tree.Left.Exchange()
			publicKey = tree.Right.Exchange()
		} else {
			privateKey = tree.Right.Exchange()
			publicKey = tree.Left.Exchange()
		}
		result, _ := curve25519.X25519(privateKey, publicKey)
		return result
	}
}

func randomByte(num int) []byte {
	b := make([]byte, num)
	rand.Read(b)
	return b
}

func printTree(node *KeyExchangeTreeNode, space int) {
	if node == nil {
		return
	}
	space += 10
	printTree(node.Right, space)
	println("")
	for i := 10; i < space; i++ {
		print(" ")
	}
	fmt.Printf("%d", node.Id)
	println("")
	printTree(node.Left, space)
}

func BuildKeyExchangeTree(room Room) KeyExchangeTreeNode {
	var node KeyExchangeTreeNode
	for index, member := range room.Members {
		if index == 0 {
			node.Id = index
			node.PrivateKey = member.PrivateKey
			node.PublicKey = member.PublicKey
		} else {
			node = node.Add(member)
		}
	}
	return node
}

func SortMembers(members []RoomMember) []RoomMember {
	sort.Slice(members, func(i, j int) bool { return members[i].IsActive && !members[j].IsActive })
	members_ := make([]RoomMember, len(members), len(members))
	for i := 0; i < len(members_); i += 2 {
		members_[i] = members[i/2]
	}
	for i := 1; i < len(members_); i += 2 {
		members_[i] = members[(len(members_)+i-1)/2]
	}
	return members_
}

func main() {
	room := Room{
		Members: []RoomMember{},
	}
	privKeyA := randomByte(curve25519.ScalarSize)
	pubKeyA, _ := curve25519.X25519(privKeyA, curve25519.Basepoint)
	privKeyB := randomByte(curve25519.ScalarSize)
	pubKeyB, _ := curve25519.X25519(privKeyB, curve25519.Basepoint)
	privKeyC := randomByte(curve25519.ScalarSize)
	pubKeyC, _ := curve25519.X25519(privKeyC, curve25519.Basepoint)
	privKeyD := randomByte(curve25519.ScalarSize)
	pubKeyD, _ := curve25519.X25519(privKeyD, curve25519.Basepoint)
	room.Members = append(room.Members, RoomMember{
		Id:         0,
		IsActive:   false,
		PublicKey:  &pubKeyA,
		PrivateKey: &privKeyA,
	})
	room.Members = append(room.Members, RoomMember{
		Id:         1,
		IsActive:   false,
		PublicKey:  &pubKeyB,
		PrivateKey: &privKeyB,
	})
	room.Members = append(room.Members, RoomMember{
		Id:         2,
		IsActive:   false,
		PublicKey:  &pubKeyC,
		PrivateKey: &privKeyC,
	})
	room.Members = append(room.Members, RoomMember{
		Id:         3,
		IsActive:   true,
		PublicKey:  &pubKeyD,
		PrivateKey: &privKeyD,
	})
	var tree KeyExchangeTreeNode
	for index, member := range SortMembers(room.Members) {
		if index == 0 {
			tree = KeyExchangeTreeNode{
				Id:         member.Id,
				Active:     member.IsActive,
				PublicKey:  member.PublicKey,
				PrivateKey: member.PrivateKey,
			}
		} else {
			tree = tree.Add(member)
		}
	}
	for _, member := range SortMembers(room.Members) {
		if member.IsActive {
			fmt.Printf("[%d] ", member.Id)
		} else {
			fmt.Printf("(%d) ", member.Id)
		}
	}
	printTree(&tree, 0)
	fmt.Printf("shared key is %x\n", tree.Exchange())
}

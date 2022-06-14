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
		return 0
	} else {
		result := tree.Right.Count() + tree.Left.Count()
		if result == 0 {
			return 1
		} else {
			return result
		}
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
		return tree.PrivateKey != nil
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

func (tree *KeyExchangeTreeNode) AttachKeys(keys [][]byte) {
	tree.PublicKey = &keys[0]
	if tree.Left != nil && tree.Left.Count() >= 1 {
		l := tree.Left.Count()
		tree.Left.AttachKeys(keys[1 : l+1])
	}
	if tree.Right != nil && tree.Right.Count() >= 1 {
		l := tree.Left.Count()
		tree.Right.AttachKeys(keys[l : l+tree.Right.Count()])
	}
}

func (tree KeyExchangeTreeNode) Exchange() ([]byte, [][]byte) {
	if tree.PrivateKey != nil {
		return *tree.PrivateKey, [][]byte{}
	} else if tree.PublicKey != nil && !tree.HasPrivate() {
		return *tree.PublicKey, [][]byte{}
	} else {
		var privateKey, publicKey []byte
		var nodeLeftPublicKeys, nodeRightPublicKeys [][]byte
		if tree.Left.HasPrivate() {
			privateKey, nodeLeftPublicKeys = tree.Left.Exchange()
			publicKey, nodeRightPublicKeys = tree.Right.Exchange()
		} else {
			privateKey, nodeRightPublicKeys = tree.Right.Exchange()
			publicKey, nodeLeftPublicKeys = tree.Left.Exchange()
		}
		result, _ := curve25519.X25519(privateKey, publicKey)
		nodePublicKeys := [][]byte{AsPublic(result)}
		nodePublicKeys = append(nodePublicKeys, nodeLeftPublicKeys...)
		nodePublicKeys = append(nodePublicKeys, nodeRightPublicKeys...)
		return result, nodePublicKeys
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

func AsPublic(priv []byte) []byte {
	pub, _ := curve25519.X25519(priv, curve25519.Basepoint)
	return pub
}

func main() {
	privKeyA := randomByte(curve25519.ScalarSize)
	pubKeyA, _ := curve25519.X25519(privKeyA, curve25519.Basepoint)
	privKeyB := randomByte(curve25519.ScalarSize)
	pubKeyB, _ := curve25519.X25519(privKeyB, curve25519.Basepoint)
	privKeyC := randomByte(curve25519.ScalarSize)
	pubKeyC, _ := curve25519.X25519(privKeyC, curve25519.Basepoint)
	privKeyD := randomByte(curve25519.ScalarSize)
	pubKeyD, _ := curve25519.X25519(privKeyD, curve25519.Basepoint)
	roomA := Room{
		Members: []RoomMember{
			{
				Id:         0,
				IsActive:   true,
				PublicKey:  &pubKeyA,
				PrivateKey: &privKeyA,
			},
			{
				Id:        1,
				IsActive:  false,
				PublicKey: &pubKeyB,
			},
			{
				Id:        2,
				IsActive:  false,
				PublicKey: &pubKeyC,
			},
			{
				Id:        3,
				IsActive:  false,
				PublicKey: &pubKeyD,
			},
		},
	}
	roomB := Room{
		Members: []RoomMember{
			{
				Id:        0,
				IsActive:  true,
				PublicKey: &pubKeyA,
			},
			{
				Id:         1,
				IsActive:   false,
				PublicKey:  &pubKeyB,
				PrivateKey: &privKeyB,
			},
			{
				Id:        2,
				IsActive:  false,
				PublicKey: &pubKeyC,
			},
			{
				Id:        3,
				IsActive:  false,
				PublicKey: &pubKeyD,
			},
		},
	}
	roomC := Room{
		Members: []RoomMember{
			{
				Id:        0,
				IsActive:  true,
				PublicKey: &pubKeyA,
			},
			{
				Id:        1,
				IsActive:  false,
				PublicKey: &pubKeyB,
			},
			{
				Id:         2,
				IsActive:   false,
				PublicKey:  &pubKeyC,
				PrivateKey: &privKeyC,
			},
			{
				Id:        3,
				IsActive:  false,
				PublicKey: &pubKeyD,
			},
		},
	}
	roomD := Room{
		Members: []RoomMember{
			{
				Id:        0,
				IsActive:  true,
				PublicKey: &pubKeyA,
			},
			{
				Id:        1,
				IsActive:  false,
				PublicKey: &pubKeyB,
			},
			{
				Id:         2,
				IsActive:   false,
				PublicKey:  &pubKeyC,
			},
			{
				Id:        3,
				IsActive:  false,
				PublicKey: &pubKeyD,
				PrivateKey: &privKeyD,
			},
		},
	}
	var treeA, treeB, treeC, treeD KeyExchangeTreeNode
	for index, member := range SortMembers(roomA.Members) {
		if index == 0 {
			treeA = KeyExchangeTreeNode{
				Id:         member.Id,
				Active:     member.IsActive,
				PublicKey:  member.PublicKey,
				PrivateKey: member.PrivateKey,
			}
		} else {
			treeA = treeA.Add(member)
		}
	}
	for index, member := range SortMembers(roomB.Members) {
		if index == 0 {
			treeB = KeyExchangeTreeNode{
				Id:         member.Id,
				Active:     member.IsActive,
				PublicKey:  member.PublicKey,
				PrivateKey: member.PrivateKey,
			}
		} else {
			treeB = treeB.Add(member)
		}
	}
	for index, member := range SortMembers(roomC.Members) {
		if index == 0 {
			treeC = KeyExchangeTreeNode{
				Id:         member.Id,
				Active:     member.IsActive,
				PublicKey:  member.PublicKey,
				PrivateKey: member.PrivateKey,
			}
		} else {
			treeC = treeC.Add(member)
		}
	}
	for index, member := range SortMembers(roomD.Members) {
		if index == 0 {
			treeD = KeyExchangeTreeNode{
				Id:         member.Id,
				Active:     member.IsActive,
				PublicKey:  member.PublicKey,
				PrivateKey: member.PrivateKey,
			}
		} else {
			treeD = treeD.Add(member)
		}
	}
	sharedKeyA, nodeKeysA := treeA.Exchange()
	fmt.Printf("shared key is %x\n", sharedKeyA)
	for i, nodeKey := range nodeKeysA {
		fmt.Printf("node %d key is %x\n", i, nodeKey)
	}
	printTree(&treeA, 0)
	treeB.AttachKeys(nodeKeysA)
	treeB.PublicKey = nil
	sharedKeyB, nodeKeysB := treeB.Exchange()
	fmt.Printf("shared key is %x\n", sharedKeyB)
	for i, nodeKey := range nodeKeysB {
		fmt.Printf("node %d key is %x\n", i, nodeKey)
	}
	printTree(&treeB, 0)
	treeC.AttachKeys(nodeKeysA)
	treeC.PublicKey = nil
	sharedKeyC, nodeKeysC := treeC.Exchange()
	fmt.Printf("shared key is %x\n", sharedKeyC)
	for i, nodeKey := range nodeKeysC {
		fmt.Printf("node %d key is %x\n", i, nodeKey)
	}
	printTree(&treeC, 0)
	treeD.AttachKeys(nodeKeysA)
	treeD.PublicKey = nil
	sharedKeyD, nodeKeysD := treeD.Exchange()
	fmt.Printf("shared key is %x\n", sharedKeyD)
	for i, nodeKey := range nodeKeysD {
		fmt.Printf("node %d key is %x\n", i, nodeKey)
	}
	printTree(&treeD, 0)
}

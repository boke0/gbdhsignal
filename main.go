package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type Ratchet struct {
	Id         int
	PrivateKey []byte
	PublicKey  []byte
	ChainKey   []byte
	RootKey    []byte
	Members    []RoomMember
	speaker    int
}

func (rat *Ratchet) UpdateMemberPublicKey(id int, key []byte) {
	for _, member := range rat.Members {
		if id == member.Id {
			member.UpdatePublicKey(key)
		}
	}
}

func (rat *Ratchet) UpdateKey() []byte {
	rat.PrivateKey = randomByte(curve25519.ScalarSize)
	rat.PublicKey = AsPublic(rat.PrivateKey)
	rat.UpdateMemberPublicKey(rat.Id, rat.PublicKey)
	return rat.PublicKey
}

func (rat *Ratchet) Exchange(nodePublicKeys []NodePublicKey) ([]byte, []NodePublicKey) {
	var tree KeyExchangeTreeNode
	members := SortMembers(rat.Members)
	for i := 0; i < len(rat.Members); i += 2 {
		if i == 0 {
			tree = NewKeyExchangeTreeNode(members[i], members[i+1])
		} else {
			if len(members) > i+1 {
				if members[i].IsActive || members[i+1].IsActive {
					tree = tree.AddTwo(members[i], members[i+1])
				} else {
					tree = tree.Add(members[i]).Add(members[i+1])
				}
			} else {
				tree = tree.Add(members[i])
			}
		}
	}
	if len(nodePublicKeys) > 0 {
		tree.AttachKeys(nodePublicKeys)
	}
	sharedKey, nodeKeys := tree.Exchange()
	return sharedKey, nodeKeys
}

func (rat *Ratchet) ForwardChainRatchet() []byte {
	h := hmac.New(sha512.New, []byte("CHAIN_RATCHET_KEY"))
	h.Write(rat.ChainKey)
	forwarded := h.Sum(nil)
	rat.ChainKey = forwarded[:32]
	return forwarded[32:]
}

func (rat *Ratchet) ForwardRootRatchet(key []byte) {
	forwarded := hkdf.Extract(sha512.New, rat.RootKey, key)
	rat.RootKey = forwarded[:32]
	rat.ChainKey = forwarded[32:]
}

func Pkcs7Pad(data []byte) []byte {
	length := aes.BlockSize - (len(data) % aes.BlockSize)
	trailing := bytes.Repeat([]byte{byte(length)}, length)
	return append(data, trailing...)
}

func (rat *Ratchet) Encrypt(payload string) Message {
	payloadBytes := []byte(payload)
	padded := Pkcs7Pad(payloadBytes)
	encrypted := make([]byte, len(padded)+aes.BlockSize)
	iv := encrypted[:aes.BlockSize]
	io.ReadFull(rand.Reader, iv)
	if rat.speaker != rat.Id {
		publicKey := rat.UpdateKey()
		sharedKey, nodeKeys := rat.Exchange([]NodePublicKey{})
		rat.ForwardRootRatchet(sharedKey)
		key := rat.ForwardChainRatchet()
		rat.speaker = rat.Id
		block, _ := aes.NewCipher(key)
		encrypter := cipher.NewCBCEncrypter(block, iv)
		encrypter.CryptBlocks(encrypted[aes.BlockSize:], padded)
		return Message{
			MessageHeader{
				MemberId:       rat.Id,
				PublicKey:      &publicKey,
				NodePublicKeys: &nodeKeys,
			},
			MessageBody{
				RawPayload:    payload,
				CipherPayload: encrypted,
			},
		}
	} else {
		key := rat.ForwardChainRatchet()
		block, _ := aes.NewCipher(key)
		encrypter := cipher.NewCBCEncrypter(block, iv)
		encrypter.CryptBlocks(encrypted[aes.BlockSize:], padded)
		return Message{
			MessageHeader{
				MemberId: rat.Id,
			},
			MessageBody{
				RawPayload:    payload,
				CipherPayload: encrypted,
			},
		}
	}
}

func Pkcs7Unpad(data []byte) []byte {
	dataLength := len(data)
	padLength := int(data[dataLength-1])
	return data[:dataLength-padLength]
}

func (rat *Ratchet) Decrypt(message Message) string {
	if rat.speaker != message.MessageHeader.MemberId {
		rat.UpdateMemberPublicKey(message.MessageHeader.MemberId, *message.MessageHeader.PublicKey)
		sharedKey, _ := rat.Exchange(*message.MessageHeader.NodePublicKeys)
		rat.ForwardRootRatchet(sharedKey)
	}
	rawPayload := make([]byte, len(message.MessageBody.CipherPayload)-aes.BlockSize)
	key := rat.ForwardChainRatchet()
	block, _ := aes.NewCipher(key)
	cbc := cipher.NewCBCDecrypter(block, message.MessageBody.CipherPayload[:aes.BlockSize])
	cbc.CryptBlocks(rawPayload, message.MessageBody.CipherPayload[aes.BlockSize:])
	return string(Pkcs7Unpad(rawPayload))
}

func BuildKeyExchangeTree(ratchet Ratchet) KeyExchangeTreeNode {
	var node KeyExchangeTreeNode
	for index, member := range ratchet.Members {
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

type RoomMember struct {
	Id         int
	IsActive   bool
	PublicKey  *[]byte
	PrivateKey *[]byte
}

func (member *RoomMember) UpdatePublicKey(key []byte) {
	member.PublicKey = &key
	member.IsActive = false
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

type Message struct {
	MessageHeader MessageHeader
	MessageBody   MessageBody
}

type NodePublicKey struct {
	NodeId    int
	PublicKey []byte
}

type MessageHeader struct {
	MemberId       int
	PublicKey      *[]byte
	NodePublicKeys *[]NodePublicKey
}

type MessageBody struct {
	RawPayload    string
	CipherPayload []byte
}

type KeyExchangeTreeNode struct {
	Id         int
	Active     bool
	PublicKey  *[]byte
	PrivateKey *[]byte
	Left       *KeyExchangeTreeNode
	Right      *KeyExchangeTreeNode
}

func NewKeyExchangeTreeNode(member1, member2 RoomMember) KeyExchangeTreeNode {
	return KeyExchangeTreeNode{
		Id: 100 * (member1.Id + member2.Id),
		Left: &KeyExchangeTreeNode{
			Id:         member1.Id,
			Active:     member1.IsActive,
			PublicKey:  member1.PublicKey,
			PrivateKey: member1.PrivateKey,
		},
		Right: &KeyExchangeTreeNode{
			Id:         member2.Id,
			Active:     member2.IsActive,
			PublicKey:  member2.PublicKey,
			PrivateKey: member2.PrivateKey,
		},
	}
}

func (tree KeyExchangeTreeNode) AddTwo(member1 RoomMember, member2 RoomMember) KeyExchangeTreeNode {
	return tree.Insert(member1).Insert(member2)
}

func (tree KeyExchangeTreeNode) Insert(member RoomMember) KeyExchangeTreeNode {
	if tree.Left == nil || tree.Right == nil {
		return KeyExchangeTreeNode{
			Id:   100 * (tree.Id + member.Id),
			Left: &tree,
			Right: &KeyExchangeTreeNode{
				Active:     member.IsActive,
				Id:         member.Id,
				PrivateKey: member.PrivateKey,
				PublicKey:  member.PublicKey,
			},
		}
	} else if tree.Left.Count() > tree.Right.Count() && (tree.Right.IsActive() || member.IsActive) {
		right := tree.Right.Insert(member)
		tree.Right = &right
		return tree
	} else {
		return KeyExchangeTreeNode{
			Id:   100 * (tree.Id + member.Id),
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

func (tree KeyExchangeTreeNode) Add(member RoomMember) KeyExchangeTreeNode {
	return KeyExchangeTreeNode{
		Id:   100 * (tree.Id * member.Id),
		Left: &tree,
		Right: &KeyExchangeTreeNode{
			Active:     member.IsActive,
			Id:         member.Id,
			PrivateKey: member.PrivateKey,
			PublicKey:  member.PublicKey,
		},
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

func (tree *KeyExchangeTreeNode) AttachKeys(keys []NodePublicKey) {
	for _, key := range keys {
		if key.NodeId == tree.Id {
			tree.PublicKey = &key.PublicKey
			break
		}
	}
	if tree.Left != nil && tree.Left.Count() >= 1 {
		tree.Left.AttachKeys(keys)
	}
	if tree.Right != nil && tree.Right.Count() >= 1 {
		tree.Right.AttachKeys(keys)
	}
}

func (tree KeyExchangeTreeNode) Exchange() ([]byte, []NodePublicKey) {
	if tree.PrivateKey != nil {
		return *tree.PrivateKey, []NodePublicKey{}
	} else if tree.PublicKey != nil && !tree.HasPrivate() {
		return *tree.PublicKey, []NodePublicKey{}
	} else {
		var privateKey, publicKey []byte
		var nodeLeftPublicKeys, nodeRightPublicKeys []NodePublicKey
		if tree.Left.HasPrivate() {
			privateKey, nodeLeftPublicKeys = tree.Left.Exchange()
			publicKey, nodeRightPublicKeys = tree.Right.Exchange()
		} else {
			privateKey, nodeRightPublicKeys = tree.Right.Exchange()
			publicKey, nodeLeftPublicKeys = tree.Left.Exchange()
		}
		result, _ := curve25519.X25519(privateKey, publicKey)
		nodePublicKeys := []NodePublicKey{
			{
				NodeId: tree.Id,
				PublicKey: AsPublic(result),
			},
		}
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
	space += 4
	printTree(node.Right, space)
	for i := 4; i < space; i++ {
		print(" ")
	}
	println("")
	printTree(node.Left, space)
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
	roomA := Ratchet{
		speaker: -1,
		Id:      0,
		Members: []RoomMember{
			{
				Id:         0,
				IsActive:   false,
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
	roomB := Ratchet{
		speaker: -1,
		Id:      1,
		Members: []RoomMember{
			{
				Id:        0,
				IsActive:  false,
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
	roomC := Ratchet{
		speaker: -1,
		Id:      2,
		Members: []RoomMember{
			{
				Id:        0,
				IsActive:  false,
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
	roomD := Ratchet{
		speaker: -1,
		Id:      3,
		Members: []RoomMember{
			{
				Id:        0,
				IsActive:  false,
				PublicKey: &pubKeyA,
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
				Id:         3,
				IsActive:   false,
				PublicKey:  &pubKeyD,
				PrivateKey: &privKeyD,
			},
		},
	}
	message := roomA.Encrypt("hogehogehugahugapiyopiyo")
	fmt.Printf("root key is %x\n", roomA.RootKey)
	fmt.Printf("chain key is %x\n", roomA.ChainKey)
	resultB := roomB.Decrypt(message)
	fmt.Printf("root key is %x\n", roomB.RootKey)
	fmt.Printf("chain key is %x\n", roomB.ChainKey)
	fmt.Printf("payload is %s\n", resultB)
	resultC := roomC.Decrypt(message)
	fmt.Printf("root key is %x\n", roomC.RootKey)
	fmt.Printf("chain key is %x\n", roomC.ChainKey)
	fmt.Printf("payload is %s\n", resultC)
	resultD := roomD.Decrypt(message)
	fmt.Printf("root key is %x\n", roomD.RootKey)
	fmt.Printf("chain key is %x\n", roomD.ChainKey)
	fmt.Printf("payload is %s\n", resultD)
}

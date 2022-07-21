package model

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"io"

	"github.com/boke0/gbdhsignal/util"
	"github.com/boke0/hippocampus"
	"github.com/boke0/hippocampus/engine/inmemory"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type ExchangeMethodType func(*Ratchet, map[string]NodePublicKey) ([]byte, map[string]NodePublicKey, []string)
type ExchangeEmulationMethodType func(*Ratchet) (int, int)
type ActivateMethodType func([]RoomMember, string) []RoomMember

type Ratchet struct {
	Id                      string
	Cache                   hippocampus.Hippocampus[NodePublicKey]
	PrivateKey              []byte
	PublicKey               []byte
	ChainKey                []byte
	RootKey                 []byte
	Members                 []RoomMember
	ExchangeMethod          ExchangeMethodType
	ExchangeEmulationMethod ExchangeEmulationMethodType
	ActivateMethod          ActivateMethodType
	speaker                 *string
}

func NewRatchet(id string, exchangeMethod ExchangeMethodType, exchangeEmulationMethod ExchangeEmulationMethodType, activateMethod ActivateMethodType, members []RoomMember) Ratchet {
	return Ratchet{
		speaker:        nil,
		Id:             id,
		Cache:          hippocampus.NewHippocampus[NodePublicKey](inmemory.NewInmemoryEngine[NodePublicKey]()),
		ExchangeMethod: exchangeMethod,
		ExchangeEmulationMethod: exchangeEmulationMethod,
		ActivateMethod: activateMethod,
		Members:        members,
	}
}

func (rat *Ratchet) UpdateMemberPrivateKey(id string, key []byte) {
	for i, member := range rat.Members {
		if id == member.Id {
			rat.Members[i] = member.UpdatePrivateKey(key)
		}
	}
}

func (rat *Ratchet) UpdateMemberPublicKey(id string, key []byte) {
	for i, member := range rat.Members {
		if id == member.Id {
			rat.Members[i] = member.UpdatePublicKey(key)
		}
	}
}

func (rat *Ratchet) UpdateKey() []byte {
	rat.PrivateKey = util.RandomByte(curve25519.ScalarSize)
	rat.PublicKey = util.AsPublic(rat.PrivateKey)
	rat.UpdateMemberPrivateKey(rat.Id, rat.PrivateKey)
	return rat.PublicKey
}

func (rat *Ratchet) Exchange(nodePublicKey map[string]NodePublicKey) ([]byte, map[string]NodePublicKey, []string) {
	sharedKey, nodeKeys, nodes := rat.ExchangeMethod(rat, nodePublicKey)
	return sharedKey, nodeKeys, nodes
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

func (rat *Ratchet) Activate(id string) {
	rat.Members = rat.ActivateMethod(rat.Members, id)
}

func (rat *Ratchet) EmulateBytes() (int, int) {
	return rat.ExchangeEmulationMethod(rat)
}

func (rat *Ratchet) Encrypt(payload string) (Message, []string) {
	payloadBytes := []byte(payload)
	padded := Pkcs7Pad(payloadBytes)
	encrypted := make([]byte, len(padded)+aes.BlockSize)
	iv := encrypted[:aes.BlockSize]
	io.ReadFull(rand.Reader, iv)
	//if rat.speaker != &rat.Id {
	publicKey := rat.UpdateKey()
	rat.Members = rat.ActivateMethod(rat.Members, rat.Id)
	sharedKey, nodeKeys, nodes := rat.Exchange(make(map[string]NodePublicKey))
	//rat.ForwardRootRatchet(sharedKey)
	//key := rat.ForwardChainRatchet()
	//rat.speaker = &rat.Id
	//block, _ := aes.NewCipher(key)
	block, _ := aes.NewCipher(sharedKey)
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
	}, nodes
	/*} else {
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
	}*/
}

func Pkcs7Unpad(data []byte) []byte {
	dataLength := len(data)
	padLength := int(data[dataLength-1])
	return data[:dataLength-padLength]
}

func (rat *Ratchet) Decrypt(message Message) (string, []string) {
	if rat.speaker != &message.MessageHeader.MemberId {
		rat.UpdateMemberPublicKey(message.MessageHeader.MemberId, *message.MessageHeader.PublicKey)
		//sharedKey, _ := rat.Exchange(*message.MessageHeader.NodePublicKeys)
		//rat.ForwardRootRatchet(sharedKey)
	}
	rat.Members = rat.ActivateMethod(rat.Members, message.MessageHeader.MemberId)
	key, _, tree := rat.Exchange(*message.MessageHeader.NodePublicKeys)
	rawPayload := make([]byte, len(message.MessageBody.CipherPayload)-aes.BlockSize)
	//key := rat.ForwardChainRatchet()
	block, _ := aes.NewCipher(key)
	cbc := cipher.NewCBCDecrypter(block, message.MessageBody.CipherPayload[:aes.BlockSize])
	cbc.CryptBlocks(rawPayload, message.MessageBody.CipherPayload[aes.BlockSize:])
	return string(Pkcs7Unpad(rawPayload)), tree
}

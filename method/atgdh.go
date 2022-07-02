package method

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	. "github.com/boke0/gbdhsignal/model"
	. "github.com/boke0/gbdhsignal/util"
	"github.com/boke0/hippocampus"
	"golang.org/x/crypto/curve25519"
)

type KeyExchangeTreeNode struct {
	Id         string
	Active     bool
	PublicKey  *[]byte
	PrivateKey *[]byte
	Left       *KeyExchangeTreeNode
	Right      *KeyExchangeTreeNode
}

func BuildKeyExchangeTree(ratchet Ratchet) KeyExchangeTreeNode {
	var node KeyExchangeTreeNode
	for index, member := range ratchet.Members {
		if index == 0 {
			node.Id = ""
			node.PrivateKey = member.PrivateKey
			node.PublicKey = member.PublicKey
		} else {
			node = node.Add(member)
		}
	}
	return node
}

func NewKeyExchangeTreeNode(member1, member2 RoomMember) KeyExchangeTreeNode {
	id := sha256.Sum256([]byte(member1.Id + member2.Id))
	return KeyExchangeTreeNode{
		Id: hex.EncodeToString(id[:]),
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
		id := sha256.Sum256([]byte(tree.Id + member.Id))
		return KeyExchangeTreeNode{
			Id: hex.EncodeToString(id[:]),
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
		id := sha256.Sum256([]byte(tree.Id + member.Id))
		return KeyExchangeTreeNode{
			Id: hex.EncodeToString(id[:]),
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
	id := sha256.Sum256([]byte(tree.Id + member.Id))
	return KeyExchangeTreeNode{
		Id: hex.EncodeToString(id[:]),
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

func (tree *KeyExchangeTreeNode) AttachKeys(keys hippocampus.Hippocampus[NodePublicKey]) {
	if cached, exists := keys.Get(tree.Id); exists {
		key := cached
		tree.PublicKey = &key.PublicKey
	}
	if tree.Left != nil && tree.Left.Count() >= 1 {
		tree.Left.AttachKeys(keys)
	}
	if tree.Right != nil && tree.Right.Count() >= 1 {
		tree.Right.AttachKeys(keys)
	}
}

func (tree *KeyExchangeTreeNode) Exists(key string) bool {
	if tree.Id == key {
		return true
	}else{
		return tree.Left.Exists(key) || tree.Right.Exists(key)
	}
}

func (tree KeyExchangeTreeNode) Exchange() ([]byte, map[string]NodePublicKey) {
	if tree.PrivateKey != nil {
		return *tree.PrivateKey, make(map[string]NodePublicKey)
	} else if tree.PublicKey != nil && !tree.HasPrivate() {
		return *tree.PublicKey, make(map[string]NodePublicKey)
	} else {
		var privateKey, publicKey []byte
		var nodeLeftPublicKeys, nodeRightPublicKeys map[string]NodePublicKey
		if tree.Left.HasPrivate() {
			privateKey, nodeLeftPublicKeys = tree.Left.Exchange()
			publicKey, nodeRightPublicKeys = tree.Right.Exchange()
		} else {
			privateKey, nodeRightPublicKeys = tree.Right.Exchange()
			publicKey, nodeLeftPublicKeys = tree.Left.Exchange()
		}
		result, _ := curve25519.X25519(privateKey, publicKey)
		key := sha256.Sum256(result)
		nodePublicKeys := map[string]NodePublicKey{
			tree.Id: {
				NodeId: tree.Id,
				PublicKey: AsPublic(key[:]),
			},
		}
		nodePublicKeys = merge(nodePublicKeys, nodeLeftPublicKeys)
		nodePublicKeys = merge(nodePublicKeys, nodeRightPublicKeys)
		return key[:], nodePublicKeys
	}
}

func merge(m ...map[string]NodePublicKey) map[string]NodePublicKey {
    ans := make(map[string]NodePublicKey, 0)

    for _, c := range m {
        for k, v := range c {
            ans[k] = v
        }
    }
    return ans
}

func ATGDHExchange(rat *Ratchet, nodePublicKeys map[string]NodePublicKey) ([]byte, map[string]NodePublicKey) {
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
		for k, v := range nodePublicKeys {
			rat.Cache.Set(k, v)
		}
	}
	tree.AttachKeys(rat.Cache)
	sharedKey, nodeKeys := tree.Exchange()
	return sharedKey, nodeKeys
}

func printTree(node *KeyExchangeTreeNode, space int) {
	if node == nil {
		return
	}
	space += 2
	printTree(node.Right, space)
	for i := 0; i < space; i++ {
		print(" ")
	}
	if node.PublicKey != nil {
		fmt.Printf("%s %x\n", node.Id[:8], (*node.PublicKey)[:8])
	}else{
		fmt.Printf("%s\n", node.Id[:8])
	}
	println("")
	printTree(node.Left, space)
}

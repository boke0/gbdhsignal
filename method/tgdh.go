package method

import (
	. "github.com/boke0/gbdhsignal/model"
)

func ActivateTGDHMembers(members []RoomMember, sendorId string) []RoomMember {
	for i, member := range members {
		if member.Id == sendorId {
			member.IsActive = true
		}else{
			member.IsActive = false
		}
		members[i] = member
	}
	return members
}

func tgdhSortMembers(members []RoomMember) []RoomMember {
	test := true
	newMembers := members
	for test {
		test = false
		for i := 0; i+1 < len(members); i ++ {
			if !newMembers[i].IsActive && i+2 < len(newMembers) {
				if newMembers[i+1].IsActive {
					t1 := newMembers[i]
					newMembers[i] = newMembers[i+1]
					newMembers[i+1] = t1
					test = true
				}
			}
		}
	}
	return newMembers
}

func TGDHExchange(rat *Ratchet, nodePublicKeys map[string]NodePublicKey) ([]byte, map[string]NodePublicKey, []string) {
	var tree KeyExchangeTreeNode
	members := tgdhSortMembers(rat.Members)
	for i := 0; i < len(rat.Members); i += 2 {
		if i == 0 {
			tree = NewKeyExchangeTreeNode(members[i], members[i+1])
		} else {
			if len(members) > i+1 {
				tree = tree.Add(members[i]).Add(members[i+1])
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
	return sharedKey, nodeKeys, tree.NodeIds()
}

func TGDHEmulation(rat *Ratchet) (int, int) {
	var tree KeyExchangeTreeNode
	members := tgdhSortMembers(rat.Members)
	for i := 0; i < len(rat.Members); i += 2 {
		if i == 0 {
			tree = NewKeyExchangeTreeNode(members[i], members[i+1])
		} else {
			if len(members) > i+1 {
				tree = tree.Add(members[i]).Add(members[i+1])
			} else {
				tree = tree.Add(members[i])
			}
		}
	}
	return tree.EmulateSendBytes(), tree.EmulateCacheBytes()
}

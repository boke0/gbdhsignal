package main

import (
	"fmt"
	"os"
	"path"
	"time"

	. "github.com/boke0/gbdhsignal/method"
	. "github.com/boke0/gbdhsignal/model"
	. "github.com/boke0/hippocampus/engine/inmemory"
)

func main() {
	var users []User
	var ratchets []Ratchet
	for i := 0; i < 500; i++ {
		users = append(users, NewUser())
	}
	for _, user := range users {
		var members []RoomMember
		for _, user_ := range users {
			members = append(members, user_.RoomMember(user.Id == user_.Id))
		}
		ratchet := NewRatchet(user.Id, ATGDHExchange, members)
		ratchets = append(ratchets, ratchet)
	}
	fmt.Printf("count, enc_ticks")
	fmt.Fprintf(os.Stderr, "count, enc_ticks")
	for i := 0; i < 500; i++ {
		fmt.Printf(", %s", ratchets[i].Id)
		fmt.Fprintf(os.Stderr, ", %s", ratchets[i].Id)
	}
	fmt.Println("")
	fmt.Fprintln(os.Stderr, "")
	cwd, _ := os.Getwd()
	for i := 0; i < 5000; i++ {
		if cacheExists(path.Join(cwd, "./.cache/"+ratchets[i%500].Id+".json")) {
			engine, _ := ratchets[i%500].Cache.Engine.(InmemoryEngine[NodePublicKey])
			engine.Import("./.cache/" + ratchets[i%500].Id + ".json")
			ratchets[i%500].Cache.Engine = engine
		}
		enc_start := time.Now()
		message, tree := ratchets[i%500].Encrypt("hogehogehugahugapiyopiyo")
		enc_ticks := time.Since(enc_start).Microseconds()
		fmt.Printf("%d, %d", i, enc_ticks)
		fmt.Fprintf(os.Stderr, "%d, %d", i, enc_ticks)
		{
			engine, _ := ratchets[i%500].Cache.Engine.(InmemoryEngine[NodePublicKey])
			engine_ := NewInmemoryEngine[NodePublicKey]()
			for _, id := range tree {
				if value := engine.Get(id); value != nil {
					engine_.Set(id, *value)
				}
			}
			engine_.Export("./.cache/" + ratchets[i%500].Id + ".json")
			ratchets[i%500].Cache.Engine = engine_
		}
		for j := 0; j < 500; j++ {
			if (i % 500) != j {
				if cacheExists(path.Join(cwd, "./.cache/"+ratchets[j].Id+".json")) {
					engine, _ := ratchets[j].Cache.Engine.(InmemoryEngine[NodePublicKey])
					engine.Import("./.cache/" + ratchets[j].Id + ".json")
					ratchets[j].Cache.Engine = engine
				}
				dec_start := time.Now()
				ratchets[j].Decrypt(message)
				dec_tick := time.Since(dec_start).Microseconds()
				fmt.Printf(", %d", dec_tick)
				fmt.Fprintf(os.Stderr, ", %d", dec_tick)
				engine, _ := ratchets[j].Cache.Engine.(InmemoryEngine[NodePublicKey])
				engine_ := NewInmemoryEngine[NodePublicKey]()
				for _, id := range tree {
					if value := engine.Get(id); value != nil {
						engine_.Set(id, *value)
					}
				}
				engine_.Export("./.cache/" + ratchets[j].Id + ".json")
				ratchets[j].Cache.Engine = engine_
			} else {
				fmt.Printf(", ")
				fmt.Fprintf(os.Stderr, ", ")
			}
		}
		fmt.Printf("\n")
		fmt.Fprintf(os.Stderr, "\n")
	}
}

func cacheExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

package main

import (
	"fmt"
	"time"

	. "github.com/boke0/gbdhsignal/method"
	. "github.com/boke0/gbdhsignal/model"
)

func main() {
	var users []User
	var ratchets []Ratchet
	for i := 0; i<1000; i++ {
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
	fmt.Printf("count, enc_ticks, average_dec_ticks, max_ticks, min_ticks\n")
	for i := 0; i<10000; i++ {
		enc_start := time.Now()
		message := ratchets[i % 1000].Encrypt("hogehogehugahugapiyopiyo")
		enc_ticks := time.Since(enc_start).Microseconds()
		fmt.Printf("%d, %d, ", i, enc_ticks)
		var dec_a int64 = 0
		var min int64 = 10000000000
		var max int64 = 0
		for j := 0; j<1000; j++ {
			if (i % 1000) != j {
				dec_start := time.Now()
				ratchets[j].Decrypt(message)
				dec_tick := time.Since(dec_start).Microseconds()
				dec_a += dec_tick
				if min > dec_tick {
					min = dec_tick
				}
				if max < dec_tick {
					max = dec_tick
				}
			}
		}
		fmt.Printf("%d, %d, %d\n", dec_a / 999, max, min)
	}
}

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
	for i := 0; i<100; i++ {
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
	fmt.Printf("count, enc_ticks,\n")
	for i := 0; i<1000; i++ {
		enc_start := time.Now()
		message := ratchets[i % 100].Encrypt("hogehogehugahugapiyopiyo")
		enc_ticks := time.Since(enc_start).Microseconds()
		fmt.Printf("%d, %d", i, enc_ticks)
		for j := 0; j<100; j++ {
			if (i % 100) != j {
				dec_start := time.Now()
				ratchets[j].Decrypt(message)
				dec_tick := time.Since(dec_start).Microseconds()
				fmt.Printf(", %d", dec_tick)
			}
		}
		fmt.Printf("\n")
	}
}

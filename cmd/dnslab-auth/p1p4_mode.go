package main

import "github.com/hazyhaar/c2blue55/internal/dnslab"

// ServeP1P4Packet traite un datagramme de question DNS en mode P1..P4 et poignée de main iodine sans état (0 B/op).
func ServeP1P4Packet(question []byte, seed uint64, response []byte) (int, dnslab.Decision, error) {
	return dnslab.BuildLabResponseP1P4(question, seed, response)
}

//go:build linux

package probes

import "golang.org/x/sys/unix"

// BuildFilterDNSICMP retourne le programme cBPF classique qui n'admet que le
// trafic IPv4 suivant : UDP de ou vers le port 53, et ICMP de type 8 ou 0.
// Le décalage X est recalculé par BPF_MSH afin de couvrir les options IP.
func BuildFilterDNSICMP() []unix.SockFilter {
	return []unix.SockFilter{
		// 0 : charge l'EtherType.
		{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_ABS, K: 12},
		// 1 : IPv4 seulement, sinon rejet direct (15).
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 13, K: 0x0800},
		// 2 : charge le protocole IP (offset Ethernet 14 + IP 9).
		{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: 23},
		// 3 : UDP vers le bloc 4, sinon contrôle ICMP (9).
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 5, K: 17},
		// 4 : X = IHL*4.
		{Code: unix.BPF_LDX | unix.BPF_B | unix.BPF_MSH, K: 14},
		// 5 : port source UDP.
		{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_IND, K: 14},
		// 6 : source 53, acceptation (14), sinon destination (7).
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 7, Jf: 0, K: 53},
		// 7 : port destination UDP.
		{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_IND, K: 16},
		// 8 : destination 53, acceptation (14), sinon rejet (15).
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 5, Jf: 6, K: 53},
		// 9 : protocole ICMP vers 10, sinon rejet (15).
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 5, K: 1},
		// 10 : X = IHL*4.
		{Code: unix.BPF_LDX | unix.BPF_B | unix.BPF_MSH, K: 14},
		// 11 : type ICMP.
		{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_IND, K: 14},
		// 12 : type 8 (Echo Request), acceptation (14), sinon test type 0.
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, Jf: 0, K: 8},
		// 13 : type 0 (Echo Reply), acceptation (14), sinon rejet (15).
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 1, K: 0},
		// 14 : acceptation totale.
		{Code: unix.BPF_RET | unix.BPF_K, K: 0xFFFFFFFF},
		// 15 : rejet.
		{Code: unix.BPF_RET | unix.BPF_K, K: 0},
	}
}

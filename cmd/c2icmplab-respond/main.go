package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hazyhaar/c2blue55/internal/icmplab"
)

func extraireEnteteEtTrameICMP(paquet []byte, repli [4]byte) ([4]byte, []byte, bool) {
	if len(paquet) < 28 {
		return [4]byte{}, nil, false
	}
	if paquet[0]>>4 == 4 {
		longueurEntete := int(paquet[0]&0x0F) * 4
		if longueurEntete < 20 || len(paquet) < longueurEntete+8 {
			return [4]byte{}, nil, false
		}
		ipSource := [4]byte{paquet[12], paquet[13], paquet[14], paquet[15]}
		return ipSource, paquet[longueurEntete:], true
	}
	return repli, paquet, true
}

func main() {
	drapeauInterface := flag.String("iface", "wg0", "interface réseau d'écoute")
	drapeauCle := flag.Uint64("key", 0, "clé de transformation FNV-1a")
	drapeauMagique := flag.String("magic", "c2il", "préfixe de charge utile")
	drapeauMaxParSeconde := flag.Int("max-per-second", 50, "cadence maximale de réponses par seconde")
	flag.Parse()

	if *drapeauMaxParSeconde <= 0 {
		fmt.Fprintln(os.Stderr, "max-per-second invalide")
		os.Exit(2)
	}
	octetsMagiques := []byte(*drapeauMagique)

	descripteur, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ouverture socket brut: %v\n", err)
		os.Exit(1)
	}
	defer syscall.Close(descripteur)

	if *drapeauInterface != "" {
		if err := syscall.BindToDevice(descripteur, *drapeauInterface); err != nil {
			fmt.Fprintf(os.Stderr, "liaison interface %s: %v\n", *drapeauInterface, err)
			os.Exit(1)
		}
	}

	delaiLecture := syscall.Timeval{Sec: 0, Usec: 200000}
	if err := syscall.SetsockoptTimeval(descripteur, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &delaiLecture); err != nil {
		fmt.Fprintf(os.Stderr, "configuration délai réception: %v\n", err)
		os.Exit(1)
	}

	canalSignaux := make(chan os.Signal, 1)
	signal.Notify(canalSignaux, syscall.SIGTERM, syscall.SIGINT)

	var tamponReception [2048]byte
	var tamponTransformation [1400]byte
	var tamponEmission [1500]byte
	var vue icmplab.EchoView

	var secondeCourante int64
	var reponsesSeconde int

	for {
		select {
		case <-canalSignaux:
			return
		default:
		}

		nbLus, origine, err := syscall.Recvfrom(descripteur, tamponReception[:], 0)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
				continue
			}
			fmt.Fprintf(os.Stderr, "lecture socket: %v\n", err)
			return
		}

		adresseV4, ok := origine.(*syscall.SockaddrInet4)
		if !ok {
			continue
		}

		ipSource, trameICMP, ok := extraireEnteteEtTrameICMP(tamponReception[:nbLus], adresseV4.Addr)
		if !ok {
			continue
		}
		if !icmplab.SourceAutoriseeLaboratoire(ipSource) {
			fmt.Fprintf(
				os.Stderr,
				"source refusée src=%d.%d.%d.%d\n",
				ipSource[0], ipSource[1], ipSource[2], ipSource[3],
			)
			continue
		}
		if err := icmplab.ParseEcho(trameICMP, &vue); err != nil {
			continue
		}
		if vue.Type != 8 || !vue.ChecksumOK {
			continue
		}
		if len(vue.Payload) < len(octetsMagiques) || len(vue.Payload) > len(tamponTransformation) {
			continue
		}
		if !bytes.Equal(vue.Payload[:len(octetsMagiques)], octetsMagiques) {
			continue
		}

		instant := time.Now()
		seconde := instant.Unix()
		if seconde != secondeCourante {
			secondeCourante = seconde
			reponsesSeconde = 0
		}
		if reponsesSeconde >= *drapeauMaxParSeconde {
			continue
		}

		longueurCharge := len(vue.Payload)
		icmplab.TransformPayload(*drapeauCle, vue.Payload, tamponTransformation[:longueurCharge])
		longueurEmission, err := icmplab.BuildEcho(0, vue.ID, vue.Seq, tamponTransformation[:longueurCharge], tamponEmission[:])
		if err != nil {
			continue
		}
		if err := syscall.Sendto(descripteur, tamponEmission[:longueurEmission], 0, adresseV4); err != nil {
			continue
		}
		reponsesSeconde++
		fmt.Fprintf(
			os.Stderr,
			"ts=%d src=%d.%d.%d.%d id=%d seq=%d longueur=%d\n",
			instant.UnixNano(),
			adresseV4.Addr[0], adresseV4.Addr[1], adresseV4.Addr[2], adresseV4.Addr[3],
			vue.ID, vue.Seq, longueurCharge,
		)
	}
}

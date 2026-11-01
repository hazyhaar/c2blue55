package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/hazyhaar/c2blue55/internal/icmplab"
)

const (
	fnvBase64    uint64 = 14695981039346656037
	fnvPremier64 uint64 = 1099511628211
	prefixeLabo         = "c2il"
)

func analyserCibleLabo(chaineIP string) ([4]byte, error) {
	var adresse [4]byte
	ip := net.ParseIP(chaineIP)
	if ip == nil {
		return adresse, errors.New("adresse IP invalide")
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return adresse, errors.New("adresse IPv4 requise")
	}
	copy(adresse[:], ip4)
	if adresse[0] != 10 || adresse[1] != 55 || adresse[2] != 0 {
		return adresse, errors.New("cible hors du sous-réseau 10.55.0.0/24")
	}
	return adresse, nil
}

func remplirTrancheFNV1a(graine uint64, indice int, sortie []byte) {
	etat := fnvBase64
	for decalage := 0; decalage < 64; decalage += 8 {
		etat ^= (graine >> decalage) & 0xFF
		etat *= fnvPremier64
	}
	compteur := uint64(indice)
	for decalage := 0; decalage < 64; decalage += 8 {
		etat ^= (compteur >> decalage) & 0xFF
		etat *= fnvPremier64
	}
	for pos := range sortie {
		etat ^= uint64(byte(pos))
		etat *= fnvPremier64
		sortie[pos] = byte(etat ^ (etat >> 32))
	}
}

func extraireTrameICMP(paquet []byte) ([]byte, bool) {
	if len(paquet) < 28 {
		return nil, false
	}
	if paquet[0]>>4 == 4 {
		longueurEntete := int(paquet[0]&0x0F) * 4
		if longueurEntete < 20 || len(paquet) < longueurEntete+8 {
			return nil, false
		}
		return paquet[longueurEntete:], true
	}
	return paquet, true
}

func main() {
	drapeauCible := flag.String("target", "10.55.0.1", "adresse IPv4 cible dans 10.55.0.0/24")
	drapeauNombre := flag.Int("count", 10, "nombre de requêtes Echo (<= 1000)")
	drapeauParSeconde := flag.Int("per-second", 5, "cadence d'émission par seconde (<= 20)")
	drapeauGraine := flag.Uint64("seed", 1, "graine FNV-1a de génération de charge")
	drapeauTranche := flag.Int("chunk", 32, "octets de charge après préfixe et compteur (<= 1392)")
	drapeauID := flag.Uint("id", 0x101, "identifiant ICMP Echo (16 bits)")
	flag.Parse()

	adresseCible, err := analyserCibleLabo(*drapeauCible)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cible invalide: %v\n", err)
		os.Exit(2)
	}
	if *drapeauNombre < 0 || *drapeauNombre > 1000 {
		fmt.Fprintln(os.Stderr, "paramètre -count hors bornes (0..1000)")
		os.Exit(2)
	}
	if *drapeauParSeconde <= 0 || *drapeauParSeconde > 20 {
		fmt.Fprintln(os.Stderr, "paramètre -per-second hors bornes (1..20)")
		os.Exit(2)
	}
	if *drapeauTranche < 0 || *drapeauTranche > 1392 {
		fmt.Fprintln(os.Stderr, "paramètre -chunk hors bornes (0..1392)")
		os.Exit(2)
	}
	if *drapeauID > 0xFFFF {
		fmt.Fprintln(os.Stderr, "paramètre -id hors bornes (0..65535)")
		os.Exit(2)
	}

	descripteur, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ouverture socket brut: %v\n", err)
		os.Exit(1)
	}
	defer syscall.Close(descripteur)

	var empreintesEmises [1000]uint64
	var tamponCharge [1400]byte
	var tamponEmission [1500]byte
	var tamponReception [2048]byte
	var vue icmplab.EchoView

	idEcho := uint16(*drapeauID)
	longueurCharge := 8 + *drapeauTranche
	copy(tamponCharge[0:4], prefixeLabo)
	intervalle := time.Second / time.Duration(*drapeauParSeconde)
	destination := &syscall.SockaddrInet4{Addr: adresseCible}

	nbEnvoyes := 0
	nbReponses := 0
	nbTransformees := 0

	lireReponsesJusqua := func(echeance time.Time) {
		for {
			restant := time.Until(echeance)
			if restant <= 0 {
				return
			}
			usec := max(restant.Microseconds(), 1000)
			delai := syscall.Timeval{
				Sec:  usec / 1000000,
				Usec: usec % 1000000,
			}
			if err := syscall.SetsockoptTimeval(descripteur, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &delai); err != nil {
				return
			}
			nbLus, origine, err := syscall.Recvfrom(descripteur, tamponReception[:], 0)
			if err != nil {
				if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
					if time.Now().Before(echeance) {
						continue
					}
				}
				return
			}
			adresseV4, ok := origine.(*syscall.SockaddrInet4)
			if !ok || adresseV4.Addr != adresseCible {
				continue
			}
			trameICMP, ok := extraireTrameICMP(tamponReception[:nbLus])
			if !ok {
				continue
			}
			if err := icmplab.ParseEcho(trameICMP, &vue); err != nil {
				continue
			}
			if vue.Type != 0 || !vue.ChecksumOK || vue.ID != idEcho {
				continue
			}
			if int(vue.Seq) >= nbEnvoyes {
				continue
			}
			empreinteRecue := icmplab.FNV1aPayload(vue.Payload)
			natureEmpreinte := "identique"
			if empreinteRecue != empreintesEmises[vue.Seq] {
				natureEmpreinte = "transformée"
				nbTransformees++
			}
			nbReponses++
			fmt.Printf("id=%d seq=%d longueur=%d empreinte=%s\n", vue.ID, vue.Seq, len(vue.Payload), natureEmpreinte)
		}
	}

	for indice := 0; indice < *drapeauNombre; indice++ {
		debutPas := time.Now()
		binary.BigEndian.PutUint32(tamponCharge[4:8], uint32(indice))
		remplirTrancheFNV1a(*drapeauGraine, indice, tamponCharge[8:longueurCharge])
		chargeCourante := tamponCharge[:longueurCharge]
		empreintesEmises[indice] = icmplab.FNV1aPayload(chargeCourante)

		longueurPaquet, err := icmplab.BuildEcho(8, idEcho, uint16(indice), chargeCourante, tamponEmission[:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "assemblage requête %d: %v\n", indice, err)
			os.Exit(1)
		}
		if err := syscall.Sendto(descripteur, tamponEmission[:longueurPaquet], 0, destination); err != nil {
			fmt.Fprintf(os.Stderr, "envoi requête %d: %v\n", indice, err)
			os.Exit(1)
		}
		nbEnvoyes++

		if indice+1 < *drapeauNombre {
			lireReponsesJusqua(debutPas.Add(intervalle))
		}
	}

	lireReponsesJusqua(time.Now().Add(2 * time.Second))
	fmt.Printf("sent=%d replies=%d transformed=%d\n", nbEnvoyes, nbReponses, nbTransformees)
}

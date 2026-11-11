// Package main — l1_bilan_ecoute_test.go
// Test d'acceptation de la ligne L-1 (EXG-21) sur le bilan d'écoute de c2agent :
// après une écoute UDP passive recevant trois datagrammes invalides puis une
// question DNS valide de type A, et après arrêt par SIGTERM, la sortie standard
// doit contenir le bilan exact des compteurs et le code de sortie doit être 0.
package main

import (
	"bytes"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// l1Tampon collecte la sortie standard du processus et signale l'annonce d'écoute.
type l1Tampon struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	pret    chan struct{}
	unefois sync.Once
}

func (t *l1Tampon) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf.Write(p)
	if bytes.Contains(t.buf.Bytes(), []byte("Écoute active")) {
		t.unefois.Do(func() { close(t.pret) })
	}
	return len(p), nil
}

func (t *l1Tampon) texte() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.buf.String()
}

// l1CompteErreursAnalyse compte les lignes « [ERREUR ANALYSE] » déjà collectées.
func (t *l1Tampon) compteErreursAnalyse() int {
	n := 0
	for _, ligne := range strings.Split(t.texte(), "\n") {
		if strings.HasPrefix(ligne, "[ERREUR ANALYSE]") {
			n++
		}
	}
	return n
}

// l1QuestionA construit une question DNS valide de type A (QCLASS IN) pour nom.
func l1QuestionA(nom string) []byte {
	var b bytes.Buffer
	// En-tête de 12 octets : identifiant 0x1234, drapeau RD, QDCOUNT=1, autres comptes à 0.
	b.Write([]byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	for _, label := range strings.Split(nom, ".") {
		b.WriteByte(byte(len(label)))
		b.WriteString(label)
	}
	b.WriteByte(0)
	// QTYPE=1 (A), QCLASS=1 (IN).
	b.Write([]byte{0x00, 0x01, 0x00, 0x01})
	return b.Bytes()
}

// TestL1_BilanEcoute exécute c2agent en écoute passive et contrôle son bilan à l'arrêt.
func TestL1_BilanEcoute(t *testing.T) {
	t.Run("L1-01", func(t *testing.T) {
		bin := filepath.Join(t.TempDir(), "c2agent")
		build := exec.CommandContext(t.Context(), "go", "build", "-o", bin, ".")
		if sortieBuild, err := build.CombinedOutput(); err != nil {
			t.Fatalf("construction de c2agent : %v\n%s", err, sortieBuild)
		}

		// Port UDP libre : ouverture puis fermeture d'une écoute éphémère sur la boucle locale.
		libre, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			t.Fatalf("recherche d'un port UDP libre : %v", err)
		}
		adresse := libre.LocalAddr().String()
		if err := libre.Close(); err != nil {
			t.Fatalf("fermeture de l'écoute de recherche : %v", err)
		}

		journal := filepath.Join(t.TempDir(), "journal.jsonl")
		sortie := &l1Tampon{pret: make(chan struct{})}
		cmd := exec.CommandContext(t.Context(), bin, "-v", "-listen", adresse, "-log", journal)
		cmd.Stdout = sortie
		cmd.Stderr = sortie
		if err := cmd.Start(); err != nil {
			t.Fatalf("lancement de c2agent : %v", err)
		}
		attente := make(chan error, 1)
		go func() { attente <- cmd.Wait() }()

		annonce := time.NewTimer(30 * time.Second)
		defer annonce.Stop()
		select {
		case <-sortie.pret:
		case err := <-attente:
			t.Fatalf("c2agent terminé avant l'annonce d'écoute : %v\n%s", err, sortie.texte())
		case <-annonce.C:
			_ = cmd.Process.Kill()
			t.Fatalf("annonce « Écoute active » absente après 30 s\n%s", sortie.texte())
		}

		conn, err := net.Dial("udp", adresse)
		if err != nil {
			t.Fatalf("ouverture de l'émetteur UDP : %v", err)
		}
		defer conn.Close()
		// Ordre d'émission : d'abord la question DNS valide, puis les trois datagrammes
		// invalides. Les datagrammes d'une même socket sur la boucle locale sont traités
		// dans l'ordre d'émission.
		if _, err := conn.Write(l1QuestionA("www.example.com")); err != nil {
			t.Fatalf("émission de la question DNS valide : %v", err)
		}
		invalides := [][]byte{
			{0xde, 0xad, 0xbe, 0xef, 0x00},
			{0x01, 0x02, 0x03, 0x04, 0x05},
			{0xff, 0xff, 0xff, 0xff, 0xff},
		}
		for _, d := range invalides {
			if _, err := conn.Write(d); err != nil {
				t.Fatalf("émission d'un datagramme invalide : %v", err)
			}
		}

		// Scrutation bornée à 5 secondes : attendre trois lignes « [ERREUR ANALYSE] »
		// (une par datagramme invalide en mode -v). Sur la tête de base ces lignes
		// n'existent pas : la boucle expire sans échouer ici, et le test poursuit
		// jusqu'à l'assertion du bilan.
		scrutation := time.NewTimer(5 * time.Second)
		defer scrutation.Stop()
		pas := time.NewTicker(20 * time.Millisecond)
		defer pas.Stop()
	attenteErreurs:
		for sortie.compteErreursAnalyse() < len(invalides) {
			select {
			case <-pas.C:
			case <-scrutation.C:
				break attenteErreurs
			}
		}

		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatalf("envoi de SIGTERM : %v", err)
		}
		arret := time.NewTimer(20 * time.Second)
		defer arret.Stop()
		var errFin error
		select {
		case errFin = <-attente:
		case <-arret.C:
			_ = cmd.Process.Kill()
			t.Fatalf("c2agent non terminé dans la borne de 20 secondes\n%s", sortie.texte())
		}

		if errFin != nil {
			t.Errorf("code de sortie : %v ; attendu 0", errFin)
		}

		bilanAttendu := "[c2agent] bilan: passes=1 refus=0 escalades=0 erreurs_analyse=3 escalades_rejetees=0"
		trouve := false
		for _, ligne := range strings.Split(sortie.texte(), "\n") {
			if strings.TrimRight(ligne, "\r") == bilanAttendu {
				trouve = true
				break
			}
		}
		if !trouve {
			t.Errorf("ligne de bilan absente de la sortie standard\n  attendu : %q\n  sortie :\n%s", bilanAttendu, sortie.texte())
		}
	})
}

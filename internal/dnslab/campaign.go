package dnslab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ErrCampaignContract signale une campagne hors contrat (cible hors maillage,
// nom hors zone, cadence > 50, durée hors [1 s, 1 h], outil inconnu).
var ErrCampaignContract = errors.New("dnslab: campagne hors contrat")

const CanaryPassword = "canari-lab-pound2pound"

// Campaign décrit une campagne étiquetée du laboratoire.
type Campaign struct {
	RunID      string
	Family     string
	Tool       string
	Server     string
	ServerPort uint16
	Zone       string
	Duration   time.Duration
	MaxQPS     uint32
	Names      []string
	Recursive  bool
	QType      uint16
}

// ServerAddr rend l'adresse UDP du résolveur cible ; le port 53 est la valeur
// par défaut quand ServerPort est nul.
func (c *Campaign) ServerAddr() *net.UDPAddr {
	port := c.ServerPort
	if port == 0 {
		port = 53
	}
	return &net.UDPAddr{IP: net.ParseIP(c.Server), Port: int(port)}
}

// CampaignReport est le résultat mesuré d'une campagne.
type CampaignReport struct {
	RunID      string
	Start      time.Time
	End        time.Time
	Sent       uint32
	Dropped    uint32
	Errors     uint32
	Tool       string
	ExitCode   int
	Diagnostic string
}

// Validate oppose les bornes du laboratoire : RunID sans '/', Family et Tool
// dans l'ontologie fermée, Server dans 10.55.0.0/24, Zone apex valide,
// Duration dans [1 s, 1 h], MaxQPS dans [1, 50], Names en zone pour replay.
func (c *Campaign) Validate() error {
	if c == nil || c.RunID == "" || c.RunID == "." || c.RunID == ".." || strings.ContainsAny(c.RunID, "/\\\x00") || c.Duration < time.Second || c.Duration > time.Hour || c.MaxQPS < 1 || c.MaxQPS > 50 {
		return ErrCampaignContract
	}
	if (c.Family != "redhost-iodine" || c.Tool != "iodine") && (c.Family != "redhost-dns2tcp" || c.Tool != "dns2tcp") && (c.Family != "redhost-replay" || c.Tool != "replay") && (c.Family != "redhost-negative-soa" || c.Tool != "replay") {
		return ErrCampaignContract
	}
	if c.QType != 0 && c.QType != 1 && c.QType != 16 && c.QType != 28 {
		return fmt.Errorf("%w: type de question %d hors {0, 1, 16, 28}", ErrCampaignContract, c.QType)
	}
	labPrefix, _ := netip.ParsePrefix("10.55.0.0/24")
	address, err := netip.ParseAddr(c.Server)
	if err != nil {
		return ErrCampaignContract
	}
	if !labPrefix.Contains(address) && !(c.Family == "redhost-negative-soa" && address.IsLoopback()) {
		return ErrCampaignContract
	}
	if _, err := NewZone(c.Zone, [4]byte{}, "", 0); err != nil {
		return fmt.Errorf("%w: zone: %v", ErrCampaignContract, err)
	}
	if c.Tool == "replay" && len(c.Names) == 0 {
		return ErrCampaignContract
	}
	for _, name := range c.Names {
		if !strings.HasSuffix(name, "."+c.Zone) {
			return ErrCampaignContract
		}
		var query [512]byte
		if _, err := BuildQuery(1, []byte(name), c.typeQuestionEffectif(), query[:]); err != nil {
			return ErrCampaignContract
		}
	}
	return nil
}

// RunReplay envoie Names en boucle sous la zone, à MaxQPS par seau à un jeton,
// jusqu'à Duration ou l'annulation du contexte, sans lire de réponse.
func RunReplay(ctx context.Context, conn net.PacketConn, serverAddr net.Addr, c *Campaign, now func() time.Time) (CampaignReport, error) {
	if err := c.Validate(); err != nil || c.Tool != "replay" || conn == nil || serverAddr == nil || now == nil {
		return CampaignReport{}, ErrCampaignContract
	}
	report := CampaignReport{RunID: c.RunID, Tool: c.Tool, Start: now()}
	interval := time.Second / time.Duration(c.MaxQPS)
	due := report.Start
	previous := report.Start
	stalled := 0
	var query [512]byte
	first := true
	for {
		select {
		case <-ctx.Done():
			report.End = now()
			return report, nil
		default:
		}
		instant := report.Start
		if first {
			first = false
		} else {
			instant = now()
			if !instant.After(previous) {
				stalled++
				if stalled >= 1000 {
					report.End = instant
					return report, fmt.Errorf("%w: horloge figee", ErrCampaignContract)
				}
			} else {
				stalled = 0
			}
			previous = instant
		}
		if instant.Sub(report.Start) >= c.Duration {
			report.End = instant
			return report, nil
		}
		// Le jeton ne se reconstitue qu'une fois depuis le dernier envoi :
		// un WriteTo lent ne crée jamais de crédit à rattraper.
		if instant.Before(due) {
			wait := min(due.Sub(instant), 10*time.Millisecond)
			// Sleep cède seulement le processeur ; now décide seul de la cadence.
			time.Sleep(wait)
			continue
		}
		length, err := BuildQuery(uint16(report.Sent+1), []byte(c.Names[int(report.Sent)%len(c.Names)]), c.typeQuestionEffectif(), query[:])
		if err != nil {
			report.Errors++
			report.End = instant
			return report, err
		}
		if c.Recursive {
			query[2] |= 0x01
		}
		if _, err := conn.WriteTo(query[:length], serverAddr); err != nil {
			report.Errors++
			report.End = instant
			return report, err
		}
		report.Sent++
		due = instant.Add(interval)
	}
}

// RunTool lance l'outil public de la campagne par launch et l'arrête à
// Duration ; l'échec de poignée de main de l'outil n'est pas une erreur, seul
// un lancement impossible l'est.
func RunTool(ctx context.Context, c *Campaign, launch func(ctx context.Context, name string, args ...string) (exitCode int, err error)) (CampaignReport, error) {
	if err := c.Validate(); err != nil || c.Tool == "replay" || launch == nil {
		return CampaignReport{}, ErrCampaignContract
	}
	report := CampaignReport{RunID: c.RunID, Tool: c.Tool, Start: time.Now(), ExitCode: -1}
	limited, cancel := context.WithTimeout(ctx, c.Duration)
	defer cancel()
	var exitCode int
	var err error
	if c.Tool == "iodine" {
		exitCode, err = launch(limited, "iodine", "-f", "-r", "-T", "NULL", "-P", CanaryPassword, c.Server, c.Zone)
	} else {
		exitCode, err = launch(limited, "dns2tcpc", "-z", c.Zone, "-r", "canari", c.Server)
	}
	report.End = time.Now()
	if err != nil {
		report.Errors = 1
		return report, err
	}
	report.ExitCode = exitCode
	return report, nil
}

// WriteRunManifest écrit <dir>/<RunID>.manifest.json de façon atomique au
// format RedhostLabManifest étendu et rend son chemin.
func WriteRunManifest(dir string, c *Campaign, rep CampaignReport, host string) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	manifest := struct {
		RunID          string   `json:"run_id"`
		Host           string   `json:"host"`
		Interface      string   `json:"interface"`
		Filter         string   `json:"filter"`
		Resolver       string   `json:"resolver"`
		Start          string   `json:"start"`
		End            string   `json:"end"`
		QueriedDomains []string `json:"queried_domains"`
		Label          string   `json:"label"`
		Note           string   `json:"note"`
		Family         string   `json:"family"`
		Tool           string   `json:"tool"`
		Emitter        string   `json:"emitter"`
		Server         string   `json:"server"`
	}{c.RunID, host, "wg0", "udp port 53 or tcp port 53", c.Server, rep.Start.UTC().Format(time.RFC3339Nano), rep.End.UTC().Format(time.RFC3339Nano), []string{c.Zone}, c.Family, fmt.Sprintf("Sent=%d Dropped=%d Errors=%d ExitCode=%d%s", rep.Sent, rep.Dropped, rep.Errors, rep.ExitCode, diagnosticNote(rep.Diagnostic)), c.Family, c.Tool, "c2dnslab-emit", c.Server}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, c.RunID+".manifest.json")
	staging := filepath.Join(dir, "."+c.RunID+".manifest.json.tmp")
	file, err := os.OpenFile(staging, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	defer os.Remove(staging)
	_, writeErr := file.Write(encoded)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		return "", writeErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if err := os.Rename(staging, path); err != nil {
		return "", err
	}
	return path, nil
}

func (c *Campaign) typeQuestionEffectif() uint16 {
	if c.QType == 0 {
		return 16
	}
	return c.QType
}

func diagnosticNote(diagnostic string) string {
	if diagnostic == "" {
		return ""
	}
	return " Diagnostic=" + diagnostic
}

package socagent

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hazyhaar/c2blue55"
)

func TestAuditSequenceUUIDComplete(t *testing.T) {
	uuidSeqZero := ComposeV7(1_700_000_000_000, 0x0000, 42)
	uuidSeqHaute := ComposeV7(1_700_000_000_000, 0x1000, 42)
	if uuidSeqZero == uuidSeqHaute {
		t.Fatalf("deux sequences 16 bits distinctes (0x0000 vs 0x1000) produisent le meme UUIDv7: %s", uuidSeqZero)
	}
}

func TestAuditRemediationExigeUnFait(t *testing.T) {
	var evenement c2blue55.Event
	evenement.Subsystem = c2blue55.SubProc
	evenement.Action = c2blue55.ActRead
	copy(evenement.Payload[:], "lecture benigne")

	remediations := RemediationFor(nil, []c2blue55.Event{evenement})
	if len(remediations) != 0 {
		t.Fatalf("une lecture processus sans aucun fait produit une remediation non vide: %v", remediations)
	}
}

func TestAuditIncidentJSONUTF8(t *testing.T) {
	var evenement c2blue55.Event
	evenement.Subsystem = c2blue55.SubFile
	evenement.Action = c2blue55.ActWrite
	evenement.Flags = c2blue55.FlagBlocked
	copy(evenement.Payload[:], []byte{'/', 0xff, '/', 'A', 'G', 'E', 'N', 'T', 'S', '.', 'm', 'd'})

	dossier, err := AdmitAt([]c2blue55.Event{evenement}, ScoreThreshold, 0, time.Unix(1, 0), 1)
	if err != nil {
		t.Fatalf("AdmitAt: %v", err)
	}
	serialise := AppendJSON(nil, dossier)
	if !json.Valid(serialise) {
		t.Fatalf("l'incident admis est serialise en JSON invalide: %q", serialise)
	}
}

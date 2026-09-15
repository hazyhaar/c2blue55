package socagent

import (
	"code.hazyhaar.fr/devhoros/pkg/c2blue55"
	"testing"
)

func TestFileObservationRejectThenBlockedWrite(t *testing.T) {
	for _, path := range []string{"/tmp/innocent.txt", "/devhoros/AGENTS.md.bak", "/devhoros/AGENTS.md"} {
		ev := doctrineEvent(7, path)
		ev.Action = c2blue55.ActRead
		if facts := Translate([]c2blue55.Event{ev}); len(facts) != 0 {
			t.Fatalf("read became write: %+v", facts)
		}
		if actions := RemediationFor(nil, []c2blue55.Event{ev}); len(actions) != 0 {
			t.Fatalf("read produced remediation: %v", actions)
		}
	}
	ev := doctrineEvent(7, "/devhoros/AGENTS.md")
	ev.Flags = 0
	if len(Translate([]c2blue55.Event{ev})) != 0 {
		t.Fatal("unblocked write called unauthorized")
	}
	ev.Flags = c2blue55.FlagBlocked
	facts := Translate([]c2blue55.Event{ev})
	if len(facts) != 1 || facts[0].Confidence != 0 {
		t.Fatalf("blocked observation recovery: %+v", facts)
	}
}

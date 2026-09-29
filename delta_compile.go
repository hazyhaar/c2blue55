package c2blue55

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55/internal/engine"
)

// DeltaDescription est la description JSON d'un catalogue de dispenses, que
// CompileDeltaDescription traduit en règles .c2delta.
type DeltaDescription struct {
	Rules []DeltaRuleDescription `json:"rules"`
}

// DeltaRuleDescription décrit une règle de dispense par l'état qu'elle vise,
// exprimé dans les champs d'un instantané, au lieu d'un motif de 512 bits.
// Preset et State s'excluent : un préréglage fournit l'état, les champs
// fixés, le rayon et les échelles, ces trois derniers restant surchargeables.
type DeltaRuleDescription struct {
	ID        uint32                 `json:"id"`
	Label     string                 `json:"label"`
	Preset    string                 `json:"preset,omitempty"`
	NotBefore string                 `json:"not_before"`       // RFC 3339, inclus
	NotAfter  string                 `json:"not_after"`        // RFC 3339, inclus
	Days      []string               `json:"days,omitempty"`   // sun..sat ou dim..sam, UTC ; vide = tous
	Hours     string                 `json:"hours,omitempty"`  // « HH:MM-HH:MM » UTC, fin exclue ; vide = journée entière
	Scales    []string               `json:"scales,omitempty"` // 4h, 12h, 24h, 7d, 30d, 120d, 365d
	Radius    *uint16                `json:"radius,omitempty"` // distance de Hamming admise sur les bits fixés
	State     *DeltaStateDescription `json:"state,omitempty"`  // état visé
	Match     []string               `json:"match,omitempty"`  // champs fixés ; la sévérité l'est toujours
}

// DeltaStateDescription décrit l'état visé dans les termes de ParseLogLine.
type DeltaStateDescription struct {
	Subsystem   uint16 `json:"subsystem"`
	Action      uint16 `json:"action"`
	Severity    uint16 `json:"severity"`
	HealthScore uint16 `json:"health_score"`
	Correlated  uint16 `json:"correlated"`
	EntropyQ8   uint32 `json:"entropy_q8"`
	Entity      string `json:"entity,omitempty"`    // acteur du journal (« sshd », « dpkg »…), haché par LogActorID comme ParseLogLine
	EntityID    uint64 `json:"entity_id,omitempty"` // identifiant brut, exclusif de Entity
	Time        string `json:"time,omitempty"`      // « HH:MM » UTC, requis si le créneau est fixé
	Payload     string `json:"payload,omitempty"`   // charge textuelle, tronquée à 96 octets
}

// ErrDeltaDescription signale une description de catalogue invalide.
var ErrDeltaDescription = errors.New("c2delta: description invalide")

// deltaPreset est un préréglage de règle de maintenance.
type deltaPreset struct {
	state  DeltaStateDescription
	match  []string
	radius uint16
	scales []string
}

// deltaPresets sont les états que ParseLogLine produit pendant une maintenance
// ordinaire, et que seule une fenêtre datée doit dispenser :
//   - apt-maintenance : ligne dpkg ou apt « half-installed » ou « error »,
//     sous-système stockage, mutation de fichier, Medium, score 800 ;
//   - kernel-warn-maintenance : avertissement noyau (« warn », « tainted »),
//     par exemple au rechargement d'un module, Medium, score 700.
var deltaPresets = map[string]deltaPreset{
	"apt-maintenance": {
		state: DeltaStateDescription{Subsystem: engine.OracleSubStorage, Action: engine.OracleActFileMutate,
			Severity: engine.SeverityMedium, HealthScore: 800, Correlated: 1},
		match:  []string{"subsystem", "action", "correlated", "score"},
		radius: 4,
		scales: []string{"24h", "7d", "30d", "120d", "365d"},
	},
	"kernel-warn-maintenance": {
		state: DeltaStateDescription{Subsystem: engine.OracleSubKernel, Action: engine.OracleActStateNominal,
			Severity: engine.SeverityMedium, HealthScore: 700, Correlated: 1},
		match:  []string{"subsystem", "action", "correlated", "score"},
		radius: 4,
		scales: []string{"24h", "7d", "30d", "120d", "365d"},
	},
}

var deltaMatchNames = map[string]engine.DeltaMatchField{
	"subsystem":  engine.DeltaMatchSubsystem,
	"action":     engine.DeltaMatchAction,
	"severity":   0,
	"correlated": engine.DeltaMatchCorrelated,
	"score":      engine.DeltaMatchScore,
	"entropy":    engine.DeltaMatchEntropy,
	"slot":       engine.DeltaMatchSlot,
	"entity":     engine.DeltaMatchEntity,
	"payload":    engine.DeltaMatchPayload,
}

var deltaDayNames = map[string]uint{
	"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6,
	"dim": 0, "lun": 1, "mar": 2, "mer": 3, "jeu": 4, "ven": 5, "sam": 6,
}

// CompileDeltaDescription lit une description JSON (champs inconnus refusés)
// et rend ses règles, chacune validée par engine.ValidateDeltaRule.
func CompileDeltaDescription(r io.Reader) ([]engine.DeltaRule, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var desc DeltaDescription
	if err := dec.Decode(&desc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDeltaDescription, err)
	}
	if len(desc.Rules) == 0 {
		return nil, fmt.Errorf("%w: aucune regle", ErrDeltaDescription)
	}
	rules := make([]engine.DeltaRule, 0, len(desc.Rules))
	for i := range desc.Rules {
		rule, err := compileDeltaRule(&desc.Rules[i])
		if err != nil {
			return nil, fmt.Errorf("regle %d (%q): %w", i, desc.Rules[i].Label, err)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func compileDeltaRule(d *DeltaRuleDescription) (engine.DeltaRule, error) {
	var r engine.DeltaRule
	state, match, scales := d.State, d.Match, d.Scales
	radius := d.Radius
	if d.Preset != "" {
		p, ok := deltaPresets[d.Preset]
		if !ok {
			return r, fmt.Errorf("%w: preset %q inconnu", ErrDeltaDescription, d.Preset)
		}
		if state != nil {
			return r, fmt.Errorf("%w: preset et state s'excluent", ErrDeltaDescription)
		}
		st := p.state
		state = &st
		if match == nil {
			match = p.match
		}
		if scales == nil {
			scales = p.scales
		}
		if radius == nil {
			radius = &p.radius
		}
	}
	if state == nil {
		return r, fmt.Errorf("%w: ni state ni preset", ErrDeltaDescription)
	}
	if radius == nil {
		return r, fmt.Errorf("%w: rayon absent", ErrDeltaDescription)
	}
	if len(d.Label) == 0 || len(d.Label) > len(r.Label) {
		return r, fmt.Errorf("%w: libelle vide ou de plus de %d octets", ErrDeltaDescription, len(r.Label))
	}
	nb, err := time.Parse(time.RFC3339, d.NotBefore)
	if err != nil {
		return r, fmt.Errorf("%w: not_before: %v", ErrDeltaDescription, err)
	}
	na, err := time.Parse(time.RFC3339, d.NotAfter)
	if err != nil {
		return r, fmt.Errorf("%w: not_after: %v", ErrDeltaDescription, err)
	}
	if nb.Unix() < 0 || na.Unix() < 0 {
		return r, fmt.Errorf("%w: date anterieure a 1970", ErrDeltaDescription)
	}

	var fields engine.DeltaMatchField
	for _, m := range match {
		f, ok := deltaMatchNames[m]
		if !ok {
			return r, fmt.Errorf("%w: champ %q inconnu", ErrDeltaDescription, m)
		}
		fields |= f
	}
	snap, err := deltaSnapshot(state, fields&engine.DeltaMatchSlot != 0)
	if err != nil {
		return r, err
	}
	for _, sc := range scales {
		bit, ok := ParsePyramidHorizon(sc)
		if !ok {
			return r, fmt.Errorf("%w: echelle %q inconnue", ErrDeltaDescription, sc)
		}
		r.ScaleMask |= bit
	}
	r.DaysOfWeekMask = engine.DeltaAllDays
	if len(d.Days) > 0 {
		r.DaysOfWeekMask = 0
		for _, day := range d.Days {
			n, ok := deltaDayNames[strings.ToLower(day)]
			if !ok {
				return r, fmt.Errorf("%w: jour %q inconnu", ErrDeltaDescription, day)
			}
			r.DaysOfWeekMask |= 1 << n
		}
	}
	r.TimeSlotMin, r.TimeSlotMax = 0, engine.DeltaSlotsPerDay-1
	if d.Hours != "" {
		if r.TimeSlotMin, r.TimeSlotMax, err = deltaHoursToSlots(d.Hours); err != nil {
			return r, err
		}
	}

	r.Pattern, r.Mask = engine.DeltaPatternFromSnapshot(&snap, fields)
	r.NotBeforeSec, r.NotAfterSec = uint64(nb.Unix()), uint64(na.Unix())
	r.RuleID = d.ID
	r.MaxRadius = *radius
	copy(r.Label[:], d.Label)
	if err := engine.ValidateDeltaRule(&r); err != nil {
		return r, err
	}
	return r, nil
}

// deltaSnapshot construit l'instantané visé ; l'heure n'est exigée que si le
// créneau est fixé.
func deltaSnapshot(st *DeltaStateDescription, needSlot bool) (engine.ServerHealthSnapshot, error) {
	var s engine.ServerHealthSnapshot
	s.Subsystem, s.Action, s.Severity = st.Subsystem, st.Action, st.Severity
	s.HealthScore, s.CorrelatedCount, s.EntropyQ8 = st.HealthScore, st.Correlated, st.EntropyQ8
	if st.Severity > engine.SeverityCritical {
		return s, fmt.Errorf("%w: severite %d", ErrDeltaDescription, st.Severity)
	}
	switch {
	case st.Entity != "" && st.EntityID != 0:
		return s, fmt.Errorf("%w: entity et entity_id s'excluent", ErrDeltaDescription)
	case st.Entity != "":
		s.EntityID = LogActorID(st.Entity)
	default:
		s.EntityID = st.EntityID
	}
	copy(s.RawPayload[:], st.Payload)
	if st.Time != "" {
		sec, err := deltaClock(st.Time, false)
		if err != nil {
			return s, err
		}
		s.TimestampSec = uint64(sec)
	} else if needSlot {
		return s, fmt.Errorf("%w: champ slot fixe sans state.time", ErrDeltaDescription)
	}
	return s, nil
}

// deltaHoursToSlots traduit « HH:MM-HH:MM » (UTC, fin exclue) en créneaux de
// 22,5 minutes. Une plage qui franchit minuit se décrit en deux règles.
func deltaHoursToSlots(h string) (uint8, uint8, error) {
	from, to, ok := strings.Cut(h, "-")
	if !ok {
		return 0, 0, fmt.Errorf("%w: plage horaire %q", ErrDeltaDescription, h)
	}
	a, err := deltaClock(from, false)
	if err != nil {
		return 0, 0, err
	}
	b, err := deltaClock(to, true)
	if err != nil {
		return 0, 0, err
	}
	if b <= a {
		return 0, 0, fmt.Errorf("%w: plage horaire %q vide ou franchissant minuit", ErrDeltaDescription, h)
	}
	return uint8(a * engine.DeltaSlotsPerDay / 86400), uint8((b - 1) * engine.DeltaSlotsPerDay / 86400), nil
}

// deltaClock lit « HH:MM » en secondes depuis minuit ; « 24:00 » n'est admis
// qu'en fin de plage.
func deltaClock(s string, end bool) (int, error) {
	var hh, mm int
	if n, err := fmt.Sscanf(s, "%d:%d", &hh, &mm); err != nil || n != 2 || len(s) != 5 ||
		mm < 0 || mm > 59 || hh < 0 || hh > 24 || (hh == 24 && (mm != 0 || !end)) {
		return 0, fmt.Errorf("%w: heure %q", ErrDeltaDescription, s)
	}
	return hh*3600 + mm*60, nil
}

// Package engine — forensic_proof.go
// Dossier de preuve forensique rejouable et opposable signé Ed25519 (crypto/ed25519).
// Permet au jury du tournoi de sécurité de vérifier cryptographiquement l'intégrité
// d'un veto ou d'une décision d'interdiction contre la clé publique hôte racine,
// de vérifier le hachage cryptographique de la charge et de rejouer l'évaluation bit-à-bit sur le moteur.
package engine

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
	"unsafe"

	"github.com/hazyhaar/c2pkg/c2archtsim"
)

// Magic binaire de la preuve forensique.
var ProofMagic = [8]byte{'C', '2', 'P', 'R', 'O', 'O', 'F', '1'}

// proofCanonicalSize est la taille de la projection signée : Magic(8) + SeqID(8)
// + Ts(8) + Event(128) + FloppyFamily(2) + FloppyCRC(4) + Hamming(2) + Stage(1)
// + Action(1) + Conf(2) + PayloadHash(32) + PubKey(32) + OntoSubject(1) +
// OntoContext(1) = 230 octets.
const proofCanonicalSize = 230

// ForensicProof représente un dossier opposable et rejouable complet.
//
// Payload embarque la charge exacte que la cascade a évaluée (jusqu'à 4096
// octets). Elle n'entre pas telle quelle dans la projection signée : son
// empreinte SHA-256 (PayloadHash) y figure, et la vérification recalcule cette
// empreinte. Le rejeu évalue donc la charge scellée, indépendamment de l'état
// de l'arène au moment du rejeu.
type ForensicProof struct {
	Magic         [8]byte
	SeqID         uint64
	TimestampNs   uint64
	Event         Probe_event_t
	FloppyFamily  uint16
	FloppyCRC32   uint32
	HammingDist   uint16
	DecisionStage uint8
	VerdictAction uint8
	ConfidenceQ8  uint16
	OntoSubject   uint8
	OntoContext   uint8
	PayloadHash   [32]byte
	SignerPubKey  [32]byte
	Signature     [64]byte
	Payload       []byte
}

// Erreurs de liaison entre la charge et le descripteur de l'événement.
var (
	errProofPayloadShort = errors.New("charge courte différente du contenu de l'événement")
	errProofPayloadLong  = errors.New("charge longue incompatible avec le descripteur d'arène de l'événement")
)

// CanonicalBytes extrait la projection binaire déterministe des champs à signer.
func (p *ForensicProof) CanonicalBytes() []byte {
	buf := make([]byte, proofCanonicalSize)
	copy(buf[0:8], p.Magic[:])
	binary.LittleEndian.PutUint64(buf[8:16], p.SeqID)
	binary.LittleEndian.PutUint64(buf[16:24], p.TimestampNs)

	// Sérialisation de l'événement (128 octets)
	evBytes := (*[128]byte)(unsafe.Pointer(&p.Event))[:]
	copy(buf[24:152], evBytes)

	binary.LittleEndian.PutUint16(buf[152:154], p.FloppyFamily)
	binary.LittleEndian.PutUint32(buf[154:158], p.FloppyCRC32)
	binary.LittleEndian.PutUint16(buf[158:160], p.HammingDist)
	buf[160] = p.DecisionStage
	buf[161] = p.VerdictAction
	binary.LittleEndian.PutUint16(buf[162:164], p.ConfidenceQ8)
	copy(buf[164:196], p.PayloadHash[:])
	copy(buf[196:228], p.SignerPubKey[:])
	buf[228] = p.OntoSubject
	buf[229] = p.OntoContext

	return buf
}

// bindPayloadToEvent vérifie que payload est bien la charge portée par ev :
// égalité stricte pour une charge courte ; pour une charge longue, égalité du
// préfixe de 80 octets, de la longueur et du CRC32-C de page scellés dans le
// descripteur d'arène.
func bindPayloadToEvent(ev *Probe_event_t, payload []byte) error {
	if ev.Flags&FlagLongPayload == 0 {
		if !bytes.Equal(payload, ev.Payload[:payloadUsed(ev.Payload[:])]) {
			return errProofPayloadShort
		}
		return nil
	}
	length := int(binary.LittleEndian.Uint16(ev.Payload[metaOffsetLen:metaOffsetCRC]))
	if len(payload) != length || length <= 96 || length > PageSize {
		return errProofPayloadLong
	}
	if !bytes.Equal(payload[:metaOffsetPageIdx], ev.Payload[:metaOffsetPageIdx]) {
		return errProofPayloadLong
	}
	var img [PageSize]byte
	copy(img[:], payload)
	if c2archtsim.C2archtsim_page4k_crc32c(img[:]) != binary.LittleEndian.Uint32(ev.Payload[metaOffsetCRC:metaOffsetEpoch]) {
		return errProofPayloadLong
	}
	return nil
}

// SignForensicProof construit et signe un dossier de preuve forensique avec la clé privée de l'hôte.
// payload doit être la charge exacte que la cascade a évaluée pour ev ; elle
// est liée au descripteur de l'événement puis copiée dans la preuve.
func SignForensicProof(privKey ed25519.PrivateKey, seqID uint64, ev *Probe_event_t, payload []byte, v CascadeVerdict, floppyFamily uint16, floppyCRC uint32) (*ForensicProof, error) {
	if len(privKey) != ed25519.PrivateKeySize || ev == nil {
		return nil, errors.New("paramètres de signature invalides")
	}
	if v.Flags&FlagArenaInvalid != 0 {
		return nil, errors.New("verdict rendu sans charge lisible dans l'arène : aucune charge à sceller")
	}
	if err := bindPayloadToEvent(ev, payload); err != nil {
		return nil, fmt.Errorf("charge non liée à l'événement : %w", err)
	}

	proof := &ForensicProof{
		Magic:         ProofMagic,
		SeqID:         seqID,
		TimestampNs:   ev.Ts_ns,
		Event:         *ev,
		FloppyFamily:  floppyFamily,
		FloppyCRC32:   floppyCRC,
		HammingDist:   uint16(v.HammingDist),
		DecisionStage: v.Stage,
		VerdictAction: v.Action,
		ConfidenceQ8:  v.ConfidenceQ8,
		OntoSubject:   v.OntoSubject,
		OntoContext:   v.OntoContext,
		Payload:       bytes.Clone(payload),
	}
	proof.PayloadHash = sha256.Sum256(proof.Payload)

	pubKey := privKey.Public().(ed25519.PublicKey)
	copy(proof.SignerPubKey[:], pubKey)

	canonical := proof.CanonicalBytes()
	sig := ed25519.Sign(privKey, canonical)
	copy(proof.Signature[:], sig)

	return proof, nil
}

// VerifyForensicProof vérifie l'authenticité et l'intégrité de la preuve contre
// la clé publique racine de confiance. La clé est obligatoire : une clé nulle
// ou de taille incorrecte est refusée, et la signature est vérifiée contre la
// clé de confiance elle-même, jamais contre la clé déclarée par la preuve. La
// charge embarquée doit reproduire PayloadHash.
func VerifyForensicProof(trustedPubKey ed25519.PublicKey, proof *ForensicProof) bool {
	if len(trustedPubKey) != ed25519.PublicKeySize {
		return false
	}
	if proof == nil || proof.Magic != ProofMagic {
		return false
	}
	if subtle.ConstantTimeCompare(proof.SignerPubKey[:], trustedPubKey) != 1 {
		return false
	}
	payloadHash := sha256.Sum256(proof.Payload)
	if subtle.ConstantTimeCompare(payloadHash[:], proof.PayloadHash[:]) != 1 {
		return false
	}
	return ed25519.Verify(trustedPubKey, proof.CanonicalBytes(), proof.Signature[:])
}

// ReplayForensicProof rejoue l'événement contre la cascade active pour prouver
// la reproductibilité bit-à-bit. Le rejeu évalue la charge embarquée dans la
// preuve, après avoir vérifié sa signature, son empreinte SHA-256 et sa liaison
// au descripteur de l'événement ; il ne relit jamais l'arène, qui a pu être
// recyclée depuis.
func ReplayForensicProof(trustedPubKey ed25519.PublicKey, proof *ForensicProof, cascade *CascadeEngine) (reproduced bool, diff string) {
	if proof == nil || cascade == nil {
		return false, "entrée de rejeu invalide"
	}
	if !VerifyForensicProof(trustedPubKey, proof) {
		return false, "preuve refusée : clé racine absente ou non approuvée, signature Ed25519 invalide ou empreinte de charge discordante"
	}
	if err := bindPayloadToEvent(&proof.Event, proof.Payload); err != nil {
		return false, fmt.Sprintf("charge scellée non liée à l'événement : %v", err)
	}

	// Parité de la disquette : celle que le sous-système de l'événement
	// sollicite doit être celle que la preuve a scellée.
	disk := cascade.diskFor(proof.Event.Subsystem)
	if disk == nil {
		if proof.FloppyFamily != 0 {
			return false, fmt.Sprintf("disquette famille %d non montée pour le rejeu", proof.FloppyFamily)
		}
	} else {
		if disk.Header.FamilyID != proof.FloppyFamily {
			return false, fmt.Sprintf("famille de disquette divergente : preuve %d, active %d", proof.FloppyFamily, disk.Header.FamilyID)
		}
		if disk.Header.CRC32C != proof.FloppyCRC32 {
			return false, fmt.Sprintf("discordance CRC32 disquette famille %d : attendu 0x%08X, actif 0x%08X",
				proof.FloppyFamily, proof.FloppyCRC32, disk.Header.CRC32C)
		}
	}

	// Rejeu de l'événement exact, sur la charge scellée et sous le contexte scellé.
	ev := proof.Event
	cctx := CascadeContext{Subject: proof.OntoSubject, Context: proof.OntoContext}
	v := cascade.evaluateResolved(&ev, proof.Payload, cctx, disk, time.Now().UnixNano())

	if v.Action != proof.VerdictAction {
		return false, fmt.Sprintf("action divergente au rejeu : attendu %d, obtenu %d", proof.VerdictAction, v.Action)
	}
	if v.Stage != proof.DecisionStage {
		return false, fmt.Sprintf("étage divergent au rejeu : attendu L%d, obtenu L%d", proof.DecisionStage, v.Stage)
	}
	if uint16(v.HammingDist) != proof.HammingDist || v.ConfidenceQ8 != proof.ConfidenceQ8 {
		return false, fmt.Sprintf("mesures divergentes au rejeu : Hamming %d/%d, confiance %d/%d",
			proof.HammingDist, v.HammingDist, proof.ConfidenceQ8, v.ConfidenceQ8)
	}

	return true, "rejeu déterministe parfait : conformité bit-à-bit validée"
}

package dnslab

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
)

// GenerateNegativeNames engendre nameCount noms inexistants « nx-<16 hex> » sous la
// zone, déterministes par graine : deux graines donnent deux ensembles disjoints.
func GenerateNegativeNames(seed uint64, zone string, nameCount int) ([]string, error) {
	if nameCount < 1 || nameCount > 200 {
		return nil, ErrCampaignContract
	}
	if _, err := NewZone(zone, [4]byte{}, "", 0); err != nil {
		return nil, fmt.Errorf("%w: zone: %v", ErrCampaignContract, err)
	}
	names := make([]string, 0, nameCount)
	var material [16]byte
	for i := range nameCount {
		binary.BigEndian.PutUint64(material[0:8], seed)
		binary.BigEndian.PutUint64(material[8:16], uint64(i))
		hasher := fnv.New64a()
		_, _ = hasher.Write(material[:])
		names = append(names, fmt.Sprintf("nx-%016x.%s", hasher.Sum64(), zone))
	}
	return names, nil
}

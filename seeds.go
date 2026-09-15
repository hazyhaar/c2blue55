// Package c2blue55 provides legacy, unverified local reputation policies.
// No publication, capture, date or digest authenticates these entries.
package c2blue55

import "sync"

var (
	defaultSeedOnce sync.Once
	defaultSeedSnap []byte
)

// DefaultBuildEntries is a legacy local policy, NOT certified threat intelligence.
// Names containing test/attacker/beacon are unverified examples, not attested IOCs.
// Deployment must replace this policy with reviewed, sourced entries. Exported
// configuration must not be mutated concurrently with compilation/synchronization.
var DefaultBuildEntries = []BuildEntry{
	// 1. Unverified vendor policy; the pipeline still inspects shape and volume.
	{Domain: "sophosxl.com", Classification: RepClassAllowVendor, MatchKind: MatchSubtree},
	{Domain: "sophosxl.net", Classification: RepClassAllowVendor, MatchKind: MatchSubtree},
	{Domain: "avts.mcafee.com", Classification: RepClassAllowVendor, MatchKind: MatchSubtree},
	{Domain: "mcafee.com", Classification: RepClassAllowVendor, MatchKind: MatchSubtree},
	{Domain: "rep.trendmicro.com", Classification: RepClassAllowVendor, MatchKind: MatchSubtree},
	{Domain: "trendmicro.com", Classification: RepClassAllowVendor, MatchKind: MatchSubtree},
	{Domain: "barracudabrts.com", Classification: RepClassAllowVendor, MatchKind: MatchSubtree},
	{Domain: "spamexperts.com", Classification: RepClassAllowVendor, MatchKind: MatchSubtree},
	{Domain: "appsechcl.com", Classification: RepClassAllowVendor, MatchKind: MatchSubtree},
	{Domain: "zen.spamhaus.org", Classification: RepClassAllowVendor, MatchKind: MatchSubtree},
	{Domain: "dnsbl.sorbs.net", Classification: RepClassAllowVendor, MatchKind: MatchSubtree},

	// 2. Infrastructures CDN, Cloud et Top Domaines Tranco (Allowlist - MatchSubtree)
	{Domain: "google.com", Classification: RepClassAllowTranco, MatchKind: MatchSubtree},
	{Domain: "googleapis.com", Classification: RepClassAllowTranco, MatchKind: MatchExact},
	{Domain: "1e100.net", Classification: RepClassAllowTranco, MatchKind: MatchSubtree},
	{Domain: "microsoft.com", Classification: RepClassAllowTranco, MatchKind: MatchSubtree},
	{Domain: "azure.com", Classification: RepClassAllowTranco, MatchKind: MatchExact},
	{Domain: "trafficmanager.net", Classification: RepClassAllowTranco, MatchKind: MatchExact},
	{Domain: "cloudflare.com", Classification: RepClassAllowTranco, MatchKind: MatchSubtree},
	{Domain: "cloudflare.net", Classification: RepClassAllowTranco, MatchKind: MatchSubtree},
	{Domain: "akamai.net", Classification: RepClassAllowTranco, MatchKind: MatchExact},
	{Domain: "akamaiedge.net", Classification: RepClassAllowTranco, MatchKind: MatchExact},
	{Domain: "github.com", Classification: RepClassAllowTranco, MatchKind: MatchSubtree},
	{Domain: "githubusercontent.com", Classification: RepClassAllowTranco, MatchKind: MatchExact},
	{Domain: "amazon.com", Classification: RepClassAllowTranco, MatchKind: MatchSubtree},
	{Domain: "amazonaws.com", Classification: RepClassAllowTranco, MatchKind: MatchExact},
	{Domain: "cloudfront.net", Classification: RepClassAllowTranco, MatchKind: MatchExact},
	{Domain: "apple.com", Classification: RepClassAllowTranco, MatchKind: MatchSubtree},
	{Domain: "icloud.com", Classification: RepClassAllowTranco, MatchKind: MatchSubtree},

	// 3. Historical deny policies without source evidence. Not attack attribution.
	{Domain: "dnscat2.net", Classification: RepClassBlockC2, MatchKind: MatchSubtree},
	{Domain: "tunnel.dnscat2.org", Classification: RepClassBlockC2, MatchKind: MatchSubtree},
	{Domain: "iodine.test-c2.org", Classification: RepClassBlockC2, MatchKind: MatchSubtree},
	{Domain: "dns2tcp.attacker.org", Classification: RepClassBlockC2, MatchKind: MatchSubtree},
	{Domain: "almacommunicator.net", Classification: RepClassBlockC2, MatchKind: MatchSubtree},
	{Domain: "decoydog.tunnel.org", Classification: RepClassBlockC2, MatchKind: MatchSubtree},
	{Domain: "c2-beacon.threatfox.ch", Classification: RepClassBlockC2, MatchKind: MatchSubtree},
	{Domain: "bad-exfil-test.xyz", Classification: RepClassBlockC2, MatchKind: MatchSubtree},
	{Domain: "sliver-c2-dns.net", Classification: RepClassBlockC2, MatchKind: MatchSubtree},
}

// GetDefaultReputationTable retourne l'instance globale de réputation précompilée pour le runtime.
func GetDefaultReputationTable() (*ReputationTable, error) {
	defaultSeedOnce.Do(func() {
		snap, err := CompileReputationSnapshot(DefaultBuildEntries)
		if err == nil {
			defaultSeedSnap = snap
		}
	})
	if defaultSeedSnap == nil {
		return nil, ErrCorruptSnapshot
	}
	return NewReputationTable(defaultSeedSnap)
}

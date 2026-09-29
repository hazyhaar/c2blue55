package engine

// FlawsReentrancy : catalogue de quinze anti-patterns de cohérence d'état, de
// réentrance et de gestion de fonds natifs relevés dans les contrats Solidity et
// les ponts inter-chaînes (Celer sgn-v2-contracts, Arbitrum bridge). Chaque
// définition porte une fenêtre canonique de moins de 96 octets terminée par des
// NUL, le sous-système et la sévérité. L'encodage RaBitQ 512D réemploie
// FeatureExtractor.ExtractTo puis Encode512 par la voie commune EncodeMotif,
// sans nouvelle voie de calcul.
//
// Les motifs de code vulnérable vont de ThreatID 0x4001 à 0x400F. Le vocabulaire
// de sous-systèmes, d'actions et de sévérités provient de motifs_croises_05.go et
// codebook.go : MotifDef, mustMotifWindow, motifSubProc, motifSubNet,
// motifActExec, motifActConnect et les constantes Severity* y sont déjà
// déclarés et sont réemployés tels quels.

// FlawsReentrancy rend le catalogue complet des quinze motifs. L'ordre est
// stable et suit la numérotation croissante des identifiants de menace.
func FlawsReentrancy() []MotifDef {
	return []MotifDef{
		{
			ThreatID:  0x4001,
			Name:      "solidity-reentrancy-state-update-after-call",
			Source:    "Solidity; envoi natif avant mise à jour de balance",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow(`(bool ok, ) = msg.sender.call{value: amt}(""); balances[msg.sender] -= amt;`),
		},
		{
			ThreatID:  0x4002,
			Name:      "celer-fee-on-transfer-unverified-delta",
			Source:    "Celer sgn-v2-contracts; CELER-VULN-06; jeton à prélèvement",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow(`token.transferFrom(user, address(this), amt); deposit[user] += amt; // CELER-VULN-06`),
		},
		{
			ThreatID:  0x4003,
			Name:      "raw-call-unchecked-boolean-return",
			Source:    "Solidity; adresse.call sans require(success)",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow(`target.call(data); // absence de require(success) sur transfert de fonds`),
		},
		{
			ThreatID:  0x4004,
			Name:      "tx-origin-authorization-phishing",
			Source:    "Solidity; tx.origin comme contrôle d'accès",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow(`require(tx.origin == owner); // usurpation via contrat intermédiaire`),
		},
		{
			ThreatID:  0x4005,
			Name:      "read-only-reentrancy-curve-price-oracle",
			Source:    "DeFi; lecture de prix Curve avant synchronisation des soldes",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow(`price := pool.get_virtual_price(); // lecture prix avant sync des soldes`),
		},
		{
			ThreatID:  0x4006,
			Name:      "celer-native-currency-trap-in-retry",
			Source:    "Celer sgn-v2-contracts; CELER-VULN-04; retry sans remboursement",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow(`if (status == Retry) { msg.value transmis sans remboursement; CELER-VULN-04 }`),
		},
		{
			ThreatID:  0x4007,
			Name:      "cross-function-reentrancy-shared-state",
			Source:    "Solidity; garde nonReentrant partielle sur état partagé",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow(`function transfer() external nonReentrant { ... } function withdraw() sans guard`),
		},
		{
			ThreatID:  0x4008,
			Name:      "eip-150-gas-griefing-63-64-rule",
			Source:    "Celer sgn-v2-contracts; CELER-VULN-03; EIP-150 règle 63/64",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow(`target.call{gas: gasleft()}(data); // CELER-VULN-03 EIP-150 fail status force`),
		},
		{
			ThreatID:  0x4009,
			Name:      "unprotected-selfdestruct-or-delegatecall",
			Source:    "Solidity; delegatecall sur msg.data sans garde",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow(`(bool ok, ) = lib.delegatecall(msg.data); // prise de contrôle du stockage`),
		},
		{
			ThreatID:  0x400A,
			Name:      "uninitialized-proxy-implementation-logic",
			Source:    "Solidity; initialize public sans modificateur initializer",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow(`function initialize(address _owner) public { owner = _owner; } // sans initializer`),
		},
		{
			ThreatID:  0x400B,
			Name:      "erc20-approve-frontrunning-race",
			Source:    "ERC-20; approve sans remise à zéro intermédiaire",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityMedium,
			Window:    mustMotifWindow(`token.approve(spender, newAmount); // sans remise à zéro intermédiaire`),
		},
		{
			ThreatID:  0x400C,
			Name:      "block-timestamp-manipulation-miner",
			Source:    "Solidity; logique de verrou dépendante de block.timestamp",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityMedium,
			Window:    mustMotifWindow(`if (block.timestamp >= unlockTime) // manipulation timestamp validateur`),
		},
		{
			ThreatID:  0x400D,
			Name:      "celer-delayed-transfer-permanent-lock",
			Source:    "Celer sgn-v2-contracts; CELER-VULN-05; échec de transfert sans annulation",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow(`receiver.call{value: amt}(""); if revert, fonds bloqués sans cancel; CELER-VULN-05`),
		},
		{
			ThreatID:  0x400E,
			Name:      "arbitrary-from-in-transferfrom",
			Source:    "Arbitrum bridge; transferFrom sur paramètre from non contrôlé",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow(`token.transferFrom(from, to, amount); // from contrôlé sans check allowance`),
		},
		{
			ThreatID:  0x400F,
			Name:      "hash-collision-abi-encodepacked-multiple-arrays",
			Source:    "Solidity; keccak256 sur abi.encodePacked de types dynamiques",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow(`keccak256(abi.encodePacked(a, b)); // collision si a et b sont de types dynamiques`),
		},
	}
}

// BuildFlawsReentrancyCodebook encode le catalogue complet et rend un codebook
// contigu, prêt pour la recherche par distance de Hamming.
func BuildFlawsReentrancyCodebook() (*Codebook, error) {
	defs := FlawsReentrancy()
	entries := make([]CodebookEntry, 0, len(defs))
	for i := range defs {
		entry, _, _, err := EncodeMotif(&defs[i])
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return NewCodebook(entries), nil
}

// SaveFlawsReentrancyCodebook écrit le catalogue encodé au format .c2book.
func SaveFlawsReentrancyCodebook(path string) error {
	cb, err := BuildFlawsReentrancyCodebook()
	if err != nil {
		return err
	}
	return SaveCodebook(path, cb.entries)
}

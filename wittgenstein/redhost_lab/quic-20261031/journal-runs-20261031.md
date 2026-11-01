# Journal des runs du 2026-10-31 (UTC) — tunnels DNS réels, clair puis chiffrés

Serveurs : redhost (10.55.0.1, tunnel 10.55.0.10 ; dnsproxy DoQ 853 / DoH3 8443 devant 10.55.0.10:53 ; second dnsproxy DoQ 8853 / DoH3 8444 devant dnslab-auth 10.55.0.1:53), redbo (10.55.0.2 ; Unbound 1.13.1 sur 53 et 5335 ; stub dnsproxy 127.0.0.1:53 vers quic:// ou h3://).
Captures redhost : dnslab-capture.service wg0 udp/53 (dnslab-20261031T15Z.pcap) ; cap-quic wg0 ports 853/8443 (wg0-quic.pcap jusqu'à 15:38, puis wg0-quic-b.pcap avec 8853/8444) ; cap-clear lo 'udp port 53 and host 10.55.0.10' (lo-clear.pcap).
Blob transféré : 300 000 octets, SHA-256 f1330dabfabb847c1bc5… (identique à chaque réception).

| Run | Transport résolveur | Fenêtre UTC | Résultat |
|---|---|---|---|
| iodine clair, essai 1 | UDP/53 via Unbound | 15:19:59 – 15:22:42 | tunnel établi, HTTP bloqué par ufw (port 8080 sur dns0), client arrêté « no downstream data » |
| iodine clair, essai 2 | UDP/53 via Unbound | 15:23:23 – 15:23:34 | 300 000 octets en 0,795 s ; 1 264 paquets host 10.55.0.10 ; codec amont Base128 |
| dns2tcp clair | UDP/53 via Unbound | 15:25:18 – 15:25:21 | 300 000 octets en 0,445 s ; 2 323 paquets ; TXT |
| iodine DoQ | quic://10.55.0.1:853 | 15:34:5x – 15:34:58 | 300 000 octets en 0,387 s ; fragment aval 1522 |
| dns2tcp DoQ | quic://10.55.0.1:853 | 15:35:2x – 15:35:25 | 300 000 octets en 1,045 s |
| dns2tcp DoH3, essai 1 | h3://10.55.0.1:8443 | 15:36:04 – 15:36:10 | échec http=000 (délai client 3 s, premières requêtes en 20 s côté serveur) |
| iodine DoH3 | h3://10.55.0.1:8443 | 15:36:5x – 15:36:55 | 300 000 octets en 0,490 s |
| dns2tcp DoH3, essai 2 | h3://10.55.0.1:8443, -t 10 | 15:37:4x – 15:37:48 | 300 000 octets en 1,226 s |
| bénin DoQ | quic://10.55.0.1:8853 → dnslab-auth | voir sortie b6ta72n8h | 200 AAAA, 5 noms répétés |
| bénin DoH3 | h3://10.55.0.1:8444 → dnslab-auth | voir sortie b6ta72n8h | 200 AAAA |

Évaluations faites (lab-eval, disquettes apprises sur netrack, zone de labo jamais vue) :
- clair : dns2tcp 1 162 questions → TP 819, QuarantaineHostile 343, FN 0, AUC 0,71 ; iodine 657 questions dont 246 rejetées (étiquettes Base128 hors charset), 411 jugées → TP 290, QH 103, FN 18, AUC 0,70 ; bénin local-dns 69 questions → FP 20, TN 49.

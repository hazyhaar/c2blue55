# Tranches de transit chiffré (wg0 de redhost, 2026-10-31)

Capture `tcpdump -i wg0 -nn -s 0 -U` sur redhost, filtre `udp port 853 or udp port 8443 or tcp port 8443 or udp port 8853 or udp port 8444 or tcp port 8444`, découpée par fenêtre horaire UTC puis filtrée par port. Côté client, un stub `dnsproxy` sur redbo (127.0.0.1:53) relaie vers `quic://10.55.0.1:853`, `h3://10.55.0.1:8443/dns-query` (serveur devant le serveur de tunnel 10.55.0.10:53), `quic://10.55.0.1:8853` ou `h3://10.55.0.1:8444/dns-query` (serveur devant `dnslab-auth` 10.55.0.1:53, trafic bénin). Certificat auto-signé `CN=doq.lab.pound2pound.fr`, validation désactivée côté stub. Aucun paquet fabriqué.

| Fichier | Transport | Contenu transporté | Fenêtre UTC | Paquets |
|---|---|---|---|---|
| `wg0-iodine-doq.pcap` | DNS over QUIC, UDP 853 | tunnel iodine, 300 000 octets HTTP | 15:34:50 – 15:35:00 | 1 257 |
| `wg0-dns2tcp-doq.pcap` | DNS over QUIC, UDP 853 | tunnel dns2tcp, 300 000 octets HTTP | 15:35:18 – 15:35:30 | 4 633 |
| `wg0-iodine-doh3.pcap` | DNS over HTTPS/3, UDP 8443 | tunnel iodine, 300 000 octets HTTP | 15:36:40 – 15:37:00 | 1 269 |
| `wg0-dns2tcp-doh3.pcap` | DNS over HTTPS/3, UDP 8443 | tunnel dns2tcp, 300 000 octets HTTP | 15:37:40 – 15:37:50 | 4 657 |
| `wg0-benin-doq.pcap` | DNS over QUIC, UDP 8853 | 200 questions AAAA bénignes (5 noms de la zone) à 5/s | 15:38:44 – 15:39:32 | 1 025 |
| `wg0-benin-doh3.pcap` | DNS over HTTPS/3, UDP 8444 | 200 questions AAAA bénignes à 5/s | 15:39:30 – 15:40:19 | 1 027 |

Les tranches homologues de la jambe terminale en clair (dnsproxy 10.55.0.1 → 10.55.0.10:53, interface `lo` de redhost) sont dans `../terminal/` avec leurs manifestes au format du banc. Les tranches homologues en clair sans chiffrement de transport (Unbound → serveur de tunnel, UDP 53) sont dans `../../tunnels-20261031/`.

Lecture par le lecteur PCAP du détecteur (`IngestRedhostLabRun`) sur chacune des six tranches de transit : `UDPQuestions = 0`, `Accepted = 0`, tous les enregistrements comptés en `OtherPackets`. Le détecteur est aveugle en transit par construction (port 53 attendu), ce qui est l'objet de la mesure.

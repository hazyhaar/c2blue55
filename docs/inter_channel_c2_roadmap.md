# Feuille de route architecturale — Familles C2 Inter-Canaux (hors DNS)

Ce document consigne l'architecture de détection en `0 B/op`, les invariants géométriques et le protocole de banc d'émission des **6 familles de canaux de commande et contrôle (C2) hors DNS**, complétant les **17 motifs DNS (`M-01..M-04` + `P1..P13`)** homologués dans `c2blue55`.

Chaque famille inter-canal a vocation à constituer une disquette `.c2book` dédiée, scellée par HMAC-SHA256 au même titre que `floppy_lolbas.c2book`, `floppy_dns_c2.c2book` et `floppy_agent_mcp.c2book`.

---

## 1. Famille `IC-01` : Tunnel ICMP (`floppy_icmp_c2.c2book`)

### 1.1 Outils représentatifs et mécanique offensive
- **Outils** : `icmptunnel`, `ptunnel`, `icmpsh`, `hans`, `pingtunnel`.
- **Principe** : encapsulation bidirectionnelle de flux IP/TCP ou de commandes shell dans la charge utile (*Data Payload*) des paquets `ICMP Echo Request` (`Type=8, Code=0`) et `ICMP Echo Reply` (`Type=0, Code=0`), contournant les pare-feux qui n'inspectent que TCP/UDP.

### 1.2 Invariants physiques en `0 B/op`
1. **Asymétrie et non-parité de la charge Echo (`EchoPayloadMismatch`)** : RFC 792 exige que les octets de données d'un `Echo Reply` (`Type=0`) soient la copie bit à bit de la charge de l'`Echo Request` (`Type=8`) portant le même couple `(Identifier, SequenceNumber)`. Toute divergence de hash FNV-1a 64 bits entre la requête et la réponse appariées sur `(SrcIP, DstIP, ID, Seq)` signe immédiatement un canal C2 descendant (`icmpsh` / `ptunnel`).
2. **Déviation du gabarit d'octets de remplissage OS (`OSPadPatternAnomaly`)** :
   - Linux (`iputils-ping`) émet $56$ octets de charge utile : $8$ octets de timestamp suivis de la séquence déterministe `0x10 0x11 ... 0x37`.
   - Windows (`ping.exe`) émet $32$ octets répétant `abcdefghijklmnopqrstuvwabcdefghi`.
   - Un tunnel ICMP présente une entropie de Shannon $H > 4{,}20\text{ bits/octet}$ ou une taille de payload $> 128$ octets avec renouvellement continu du contenu à chaque numéro de séquence.
3. **Invariance ou réinitialisation anormale du `SequenceNumber`** : certains implants (`icmpsh`) figent `Identifier == 0` ou `SequenceNumber == 0` sur des centaines d'échanges consécutifs.

---

## 2. Famille `IC-02` : Balise HTTP/HTTPS Malléable avec Jitter (`floppy_http_beacon.c2book`)

### 2.1 Outils représentatifs et mécanique offensive
- **Outils** : Cobalt Strike (*Malleable C2 Profiles*), Sliver, Havoc, Mythic, Brute Ratel C4.
- **Principe** : requêtes périodiques `HTTP/1.1` ou `HTTP/2` avec gigue temporelle (*jitter* de $10\text{ \%}$ à $35\text{ \%}$) et profils malléables dissimulant les métadonnées de session dans les cookies, en-têtes HTTP (`Authorization`, `X-Forwarded-For`, `Accept-Language`) ou chemins d'URI imitant un CDN.

### 2.2 Invariants physiques en `0 B/op`
1. **Spectre d'intervalle à support borné sous Jitter uniforme (`BoundedJitterBoxDetector`)** : une balise configurée avec $(T_0, j)$ tire ses intervalles dans $[T_0(1-j), T_0(1+j)]$. Alors que le trafic web humain suit une loi parétienne à queue lourde ($\text{Kurtosis} \gg 3$, $\text{Skewness} > 2$), une balise à jitter uniforme présente un aplatissement négatif ($\text{Excess Kurtosis} \approx -1{,}2$) et un support strictement borné $[\Delta t_{\min}, \Delta t_{\max}]$ sur l'accumulateur de Welford d'ordre 4.
2. **Discordance JA3/JA4 TLS vs `User-Agent` / Ordre des en-têtes HTTP** : la pile TLS de l'implant (`wininet`, `winhttp`, `Go crypto/tls`) produit une empreinte `ClientHello` distincte du navigateur déclaré dans le profil malléable.
3. **Asymétrie d'entropie Cookie/URI à chemin statique** : requêtes répétées vers les mêmes 2 ou 3 chemins URI dont la valeur de cookie change à 100 % des requêtes avec $H \ge 4{,}30\text{ bits/octet}$.

---

## 3. Famille `IC-03` : Tunnel NTP (`floppy_ntp_c2.c2book`)

### 3.1 Outils représentatifs et mécanique offensive
- **Outils** : implants APT personnalisés sur UDP/123, `ntptunnel`.
- **Principe** : dissimulation de 8 à 24 octets par paquet dans les champs d'horodatage 64 bits (`Originate Timestamp`, `Receive Timestamp`, `Transmit Timestamp`) ou dans les champs d'extension NTPv4.

### 3.2 Invariants physiques en `0 B/op`
1. **Violation de causalité chronologique RFC 5905 (`TimestampCausalityViolation`)** : dans une synchronisation NTP légitime, le `Originate Timestamp` ($T_1$) de la réponse serveur (`Mode=4`) doit égaler bit à bit le `Transmit Timestamp` de la requête client (`Mode=3`), et l'écart $|T_{\text{transmit}} - T_{\text{wallclock}}|$ est borné. Un tunnel NTP injectant de la donnée dans les 32 bits de poids fort (secondes) ou de poids faible (fraction) viole l'égalité $T_1 == T_{\text{req}}$ ou dérive de l'horloge murale de $> 3600\text{ s}$.
2. **Cadence de polling hors enveloppe `MinPoll`/`MaxPoll`** : RFC 5905 impose un intervalle de polling entre $2^4 = 16\text{ s}$ (`MinPoll=4`) et $2^{17} = 36\text{ h}$. Un flux UDP/123 dépassant $1\text{ req/s}$ depuis un poste client est intrinsèquement anormal.

---

## 4. Famille `IC-04` : Mouvement Latéral SMB / WMI / WinRM (`floppy_lateral_smb.c2book`)

### 4.1 Outils représentatifs et mécanique offensive
- **Outils** : Impacket (`psexec.py`, `wmiexec.py`, `smbexec.py`), CrackMapExec / NetExec, Cobalt Strike `jump psexec_psh` / `winrm`, tubes nommés SMB (`\PIPE\atsvc`, `\PIPE\svcctl`, `\PIPE\wkssvc`).
- **Principe** : exécution distante de commandes et relais de balises C2 en pair-à-pair (*SMB Named Pipe Beaconing*) sur les ports TCP/445, TCP/135 (RPC Endpoint Mapper) et TCP/5985–5986 (WinRM).

### 4.2 Invariants physiques en `0 B/op`
1. **Séquence transactionnelle `IPC$` $\to$ `ADMIN$` $\to$ `svcctl` (`PsExecTriadSignature`)** : ouverture en moins de $2\text{ s}$ d'un partage `ADMIN$` ou `C$` suivie d'une écriture de binaire et d'un appel RPC `CreateServiceW` / `StartServiceW` sur `\PIPE\svcctl`.
2. **Tubes nommés SMB à préfixe pseudo-aléatoire (`NamedPipeEntropy`)** : détection des pipes de balises C2 (`\PIPE\msagent_xx`, `\PIPE\postex_xxxx`, `\PIPE\status_xx`) par déviation vis-à-vis du catalogue fermé des tubes RPC Windows légitimes.

---

## 5. Famille `IC-05` : C2 Locale & Évasion Intra-Hôte (`floppy_local_ipc.c2book`)

### 5.1 Mécanique offensive et sondes `internal/probes` existantes
- **Techniques** : communication inter-processus locale (tubes nommés, ports `ALPC`, segments de mémoire partagée `/dev/shm` ou `memfd_create`), *Process Hollowing*, *DLL Sideloading*.
- **Ancrage dans `c2blue55`** : directement observable par les sondes noyau déjà présentes dans `internal/probes` (`fanotify`, `cnproc`, audit d'exécution sans fichier).

### 5.2 Invariants physiques en `0 B/op`
1. **Exécution depuis un descripteur anonyme ou mémoire partagée (`MemfdShmExec`)** : événement `fanotify` / `execve` dont le chemin résolu pointe vers `/memfd:`, `/dev/shm/`, `/tmp/` ou un inode supprimé `(deleted)`.
2. **Discordance d'arbre de filiation `cnproc` (`ParentChildLineageAnomaly`)** : création d'un processus interpréteur (`sh`, `bash`, `python`, `powershell`) ou chargement d'une bibliothèque hors `/usr/lib` par un démon réseau ou bureautique, corrélée en `0 B/op` par le moteur pyramidal de `c2blue55`.

---

## 6. Famille `IC-06` : Canaux Émergents MQTT/CoAP (IoT) et QUIC/TLS Brut (`floppy_emerging_c2.c2book`)

### 6.1 Mécanique offensive
- **MQTT / CoAP** : utilisation de courtiers MQTT publics ou internes (TCP/1883, TLS/8883) et d'échanges CoAP (UDP/5683) comme bus de commande pub/sub asynchrone.
- **QUIC / HTTP/3 (UDP/443)** : transport de balises C2 dans des flux QUIC multiplexés (`Sliver` HTTP/3, tunnels QUIC personnalisés).

### 6.2 Invariants physiques en `0 B/op`
1. **Topologie de sujets MQTT à haute entropie (`MQTTTopicCardinality`)** : dans l'IoT légitime, les sujets (`sensors/temp/room1`) suivent une hiérarchie statique à faible cardinalité et charges courtes ($< 64\text{ octets}$). Un C2 sur MQTT publie des charges chiffrées à taille variable sur des topics dynamiques ou alterne publication/acquittement sur un couple de topics symétriques `(cmd/<id>, res/<id>)`.
2. **Empreinte d'initialisation QUIC (`QUICInitialPacketProfile`)** : inspection en `0 B/op` du paquet `QUIC Initial` (version, longueur des `Connection ID`, paramètres de transport TLS 1.3 en clair dans le `ClientHello` QUIC) et détection du maintien de session UDP/443 bidirectionnelle à cadence régulière hors navigation web.

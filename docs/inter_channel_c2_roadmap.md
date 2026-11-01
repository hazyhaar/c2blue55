# Feuille de route architecturale — Familles C2 Inter-Canaux (hors DNS)

Ce document décrit comment le moteur d'inspection de `c2blue55` s'étend au-delà du canal DNS vers **six autres familles de canaux de commande et contrôle (C2)**. Pour chaque famille, la progression suit trois paliers explicites : le **phénomène opérationnel** observé par l'exploitant réseau ou système, le **mécanisme d'ingénierie** permettant de séparer le canal caché du trafic normal sans allocation dynamique de mémoire sur le chemin critique (`0 B/op`, `0 allocs/op`), puis les **invariants exacts et seuils mesurables** destinés aux tests contradictoires.

## Périmètre actuel (`v8.2`) et cible de réalisation

Dans l'état livré de `c2blue55` (`v8.2`), quatre briques couvrent déjà le DNS et l'amorce multi-canaux :
- **Inspection filaire DNS en clair (`M-01..M-04` et `P1..P15`)** : quatre détecteurs de rafales et d'encodages de requêtes (`M-01..M-04`) combinés à quinze règles d'état et de grammaire protocolaire sur les requêtes et réponses DNS (`P1..P15`, couvrant notamment les charges cachées dans des réponses négatives `NXDOMAIN` et le renouvellement continu des réponses `SRV`/`TXT`/`MX`/`NS`/`CAA`), validés sur le catalogue de banc fermé à 29 profils de trafic (`PatternCatalog29`).
- **Classification cinétique sans clé des résolveurs chiffrés (`encrypted-eval -hote`)** : distinction entre requêtes récursives ordinaires, navigation web massive et tunnels bidirectionnels sur DNS-over-QUIC (`DoQ`, port UDP/853) et DNS-over-HTTPS (`DoH2` sur TCP, `DoH3` sur QUIC/UDP) par agrégation des volumes et cadences par hôte client.
- **Télémétrie cinétique par processus Linux (`internal/cinetique`)** : calcul en virgule fixe de **12 quotients comportementaux par processus**, dont `part_resolveur_permille` (fraction en millièmes du trafic réseau d'un processus dirigée exclusivement vers des résolveurs DNS/DoQ/DoH, qui démasque un binaire C2 autonome même lorsque son flux réseau partage une infrastructure chiffrée, hors cas d'un tunnel exécuté à l'intérieur d'un navigateur web légitime).
- **Sondes hôtes et laboratoire ICMP existants** : les paquets `internal/probes` (événements noyau Linux `fanotify` et `cn_proc`) et `internal/icmplab` (suivi de parité des paquets `ICMP Echo` et émetteurs/répondeurs de banc `cmd/c2icmplab-emit` / `cmd/c2icmplab-respond`) fournissent dès aujourd'hui les capteurs de base des familles `IC-01` et `IC-05`.

Chaque famille inter-canal ci-dessous a vocation à compiler ses vecteurs de référence et ses mots-clés dans une **disquette de connaissances `.c2book`** dédiée — un fichier binaire immuable projeté directement en mémoire vive en lecture seule (`mmap`) et scellé cryptographiquement par `HMAC-SHA256`, sur le même modèle que les trois disquettes déjà livrées (`floppy_lolbas.c2book` pour les lignes de commande, `floppy_dns_c2.c2book` pour le DNS et `floppy_agent_mcp.c2book` pour les appels d'outils d'agents).

---

## 1. Famille `IC-01` : Tunnel ICMP (`floppy_icmp_c2.c2book`)

### 1.1 Phénomène opérationnel et outils représentatifs
- **Problème concret** : de nombreux réseaux d'entreprise filtrent les ports TCP et UDP sortants mais laissent passer les messages de diagnostic `ping` (`ICMP Echo Request` et `ICMP Echo Reply`) pour la supervision réseau. Des outils offensifs comme `icmptunnel`, `ptunnel`, `icmpsh`, `hans` ou `pingtunnel` en profitent pour glisser un flux interactif de commandes ou un tunnel IP complet dans la zone de données utiles (*Data Payload*) des paquets `ping`.
- **État dans le dépôt** : les suiveurs de parité et de réponses non sollicitées sont déjà implémentés et testés dans `internal/icmplab` ; la compilation d'une disquette dédiée `floppy_icmp_c2.c2book` constitue l'étape d'intégration suivante.

### 1.2 Mécanisme d'ingénierie et invariants physiques en `0 B/op`
Un diagnostic `ping` légitime obéit à une symétrie stricte imposée par le standard RFC 792 : à chaque `Echo Request` correspond un `Echo Reply` recopiant à l'identique les octets reçus dans la requête. Un tunnel C2 bidirectionnel brise cette symétrie soit en modifiant la charge utile de la réponse (*piggybacking*), soit en ouvrant deux flux indépendants d'`Echo Request` sans réponse symétrique.

1. **Rupture de symétrie requête/réponse (`EchoPayloadMismatch`) et asymétrie d'initiation (`UnsolicitedOrOrphanEcho`)** : pour chaque requête `Echo Request` (`Type=8, Code=0`), le capteur calcule à la volée une empreinte rapide 64 bits sans allocation (`FNV-1a` sur 64 bits) indexée par le quadruplet `(IP source, IP destination, Identifiant ICMP, Numéro de séquence)`. Lorsque la réponse `Echo Reply` (`Type=0, Code=0`) revient avec le même identifiant et le même numéro de séquence mais une empreinte différente, un canal descendant caché par *piggybacking* (`ptunnel`) est caractérisé dès le premier échange asymétrique ; lorsqu'un outil (`icmpsh`, `icmptunnel` selon le mode) émet des `Echo Reply` non sollicités ou deux flux croisés d'`Echo Request` sans appariement `Request`/`Reply`, les compteurs de parité d'initiation (`internal/icmplab`) isolent le déséquilibre.
2. **Déviation vis-à-vis des gabarits de remplissage des systèmes d'exploitation (`OSPadPatternAnomaly`)** :
   - Sur Linux 64 bits (`x86_64`), l'utilitaire standard `iputils-ping` émet par défaut $56$ octets utiles composés de $16$ octets d'horodatage (`struct timeval` 64 bits) suivis des $40$ octets de la suite arithmétique fixe `0x10 0x11 ... 0x37` ($16 + 40 = 56$).
   - Sur Windows, `ping.exe` émet $32$ octets répétant l'alphabet ASCII `abcdefghijklmnopqrstuvwabcdefghi`.
   - Un tunnel chiffré ou compressé présente au contraire une entropie de Shannon (mesure du désordre statistique des octets) $H > 4{,}20\text{ bits/octet}$, ou des charges dépassant $128$ octets dont le contenu change à chaque numéro de séquence.
3. **Figement anormal des compteurs (`SequenceNumber` / `Identifier` invariants)** : plusieurs implants minimalistes (`icmpsh`) laissent `Identifier == 0` ou `SequenceNumber == 0` constants sur des centaines d'échanges consécutifs, au lieu d'incrémenter le numéro de séquence à chaque paquet.

---

## 2. Famille `IC-02` : Balise HTTP/HTTPS Malléable avec Gigue Temporelle (`floppy_http_beacon.c2book`)

### 2.1 Phénomène opérationnel et outils représentatifs
- **Problème concret** : les frameworks de post-exploitation modernes (Cobalt Strike et ses *Malleable C2 Profiles*, Sliver, Havoc, Mythic, Brute Ratel C4) imitent le trafic web HTTPS ordinaire vers des réseaux de diffusion de contenu (CDN). Pour déjouer les détecteurs de périodicité fixe, l'implant introduit une **gigue temporelle** (*jitter* aléatoire de $10\text{ \%}$ à $35\text{ \%}$ autour de l'intervalle de rappel $T_0$) et dissimule ses ordres dans des cookies, des en-têtes HTTP (`Authorization`, `X-Forwarded-For`, `Accept-Language`) ou des chemins d'URL d'apparence banale.
- **État dans le dépôt** : famille au stade de spécification architecturale (non câblée dans `encrypted-eval` en `v8.2`).

### 2.2 Mécanisme d'ingénierie et invariants physiques en `0 B/op`
Même lorsqu'un implant brouille son horloge avec un tirage aléatoire uniforme, la statistique de ses intervalles reste mathématiquement étrangère à celle d'un utilisateur humain naviguant sur le Web : l'humain clique par rafales suivies de longs silences imprévisibles (distribution à queue lourde), tandis que l'implant reste enfermé dans une boîte temporelle rigide $[T_0(1-j), T_0(1+j)]$.

1. **Détection de boîte temporelle bornée par moments glissants (`BoundedJitterBoxDetector`)** : un accumulateur en ligne de Welford d'ordre 4 (qui met à jour moyenne, variance, asymétrie et aplatissement en quelques opérations flottantes sans stocker l'historique des paquets) mesure l'aplatissement centré (*Excess Kurtosis*). Une navigation web humaine présente un aplatissement fortement positif ($\text{Kurtosis} \gg 3$, asymétrie $\text{Skewness} > 2$), alors qu'une balise à gigue uniforme converge vers un aplatissement négatif caractéristique ($\text{Excess Kurtosis} \approx -1{,}2$) à l'intérieur d'un support strictement borné $[\Delta t_{\min}, \Delta t_{\max}]$.
2. **Discordance entre l'empreinte cryptographique TLS (`JA4`) et le navigateur déclaré (`User-Agent`)** : lorsqu'une terminaison TLS ou un proxy inverse est présent, un implant compilé en Go (`crypto/tls`) ou utilisant les bibliothèques système Windows (`wininet`, `winhttp`) négocie le chiffrement TLS avec une liste de suites et d'extensions (`ClientHello` résumé par l'empreinte `JA4`) incompatible avec le navigateur Chrome ou Firefox proclamé dans son en-tête `User-Agent`.
3. **Asymétrie d'entropie sur chemin HTTP fixe** : lorsque le trafic est observé en clair derrière un répartiteur TLS, un client qui interroge indéfiniment les 2 ou 3 mêmes chemins d'URI mais présente à $100\text{ \%}$ des requêtes un cookie de session entièrement renouvelé à forte entropie ($H \ge 4{,}30\text{ bits/octet}$) trahit le passage de messages chiffrés dans l'en-tête HTTP.

---

## 3. Famille `IC-03` : Tunnel NTP (`floppy_ntp_c2.c2book`)

### 3.1 Phénomène opérationnel et outils représentatifs
- **Problème concret** : le protocole de synchronisation d'horloge NTP (`UDP/123`) est quasi systématiquement ouvert sur les serveurs internes. Des implants spécialisés et outils tels que `ntptunnel` détournent les champs d'horodatage sur 64 bits (`Originate Timestamp`, `Receive Timestamp`, `Transmit Timestamp`) ou les extensions NTPv4 pour transférer discrètement 8 à 24 octets par paquet.
- **État dans le dépôt** : famille au stade de spécification architecturale.

### 3.2 Mécanisme d'ingénierie et invariants physiques en `0 B/op`
Le protocole NTP (RFC 5905) repose sur un chaînage causal d'horodatages vérifiable sans état lourd : la réponse du serveur doit obligatoirement recopier à l'identique l'heure d'émission annoncée par le client, et une horloge système réelle ne consulte son serveur de temps qu'à basse fréquence.

1. **Violation de causalité chronologique RFC 5905 (`TimestampCausalityViolation`)** : dans un échange NTP valide, le champ `Originate Timestamp` ($T_1$) de la réponse serveur (`Mode=4`) doit être la copie bit à bit du `Transmit Timestamp` ($T_{\text{req}}$) envoyé par le client (`Mode=3`), et l'écart $|T_{\text{transmit}} - T_{\text{wallclock}}|$ avec l'horloge réelle reste borné. Dès qu'un tunnel remplace les bits de secondes entières ou rompt la recopie serveur, soit l'égalité $T_1 == T_{\text{req}}$ est violée, soit l'horodatage diverge de plus de $3\,600\text{ s}$ de l'heure courante.
2. **Cadence d'interrogation hors enveloppe protocolaire (`MinPoll` / `MaxPoll`) et stéganographie des bits fractionnaires** : le standard RFC 5905 borne l'intervalle normal entre deux requêtes NTP entre $2^4 = 16\text{ s}$ (`MinPoll=4`) et $2^{17} \approx 36\text{ h}$. Un poste ou serveur émettant plus de $1\text{ requête/s}$ sur `UDP/123` sort immédiatement du régime de synchronisation d'horloge. Pour le cas limite d'un canal stéganographique basse cadence qui ne modifie que les bits fractionnaires de poids faible de $T_{\text{req}}$ (fidèlement recopiés dans $T_1$ par le serveur et maintenus sous `MinPoll`), la détection combine le contrôle statistique des bits fractionnaires avec le confinement par processus sur l'hôte Linux (seul le démon système autorisé `chronyd`, `systemd-timesyncd` ou `ntpd` est légitime à émettre sur `UDP/123`).

---

## 4. Famille `IC-04` : Mouvement Latéral SMB / WMI / WinRM (`floppy_lateral_smb.c2book`)

### 4.1 Phénomène opérationnel et outils représentatifs
- **Problème concret** : une fois un premier poste compromis, un attaquant évite que chaque machine interne communique directement vers Internet. Il relie ses implants internes entre eux en pair-à-pair via les partages et tubes nommés Windows (`SMB` sur `TCP/445`), l'infrastructure d'administration `RPC/WMI` (`TCP/135`) ou `WinRM` (`TCP/5985–5986`), à l'aide d'outils tels qu'Impacket (`psexec.py`, `wmiexec.py`, `smbexec.py`), NetExec ou les balises SMB de Cobalt Strike (`\PIPE\atsvc`, `\PIPE\svcctl`, `\PIPE\wkssvc`).
- **État dans le dépôt** : famille au stade de spécification architecturale.

### 4.2 Mécanisme d'ingénierie et invariants physiques en `0 B/op`
L'exécution distante automatisée enchaîne en quelques centaines de millisecondes trois opérations SMB/RPC distinctes rarement groupées ainsi par un administrateur humain, ou crée des tubes nommés dont le nom suit un gabarit pseudo-aléatoire.

1. **Triade transactionnelle d'exécution distante (`PsExecTriadSignature`)** : détection sans allocation sur automate à 3 états de l'ouverture successive, en moins de $2\text{ s}$ depuis une même source, du partage d'énumération `IPC$`, puis d'un partage administratif d'écriture (`ADMIN$` ou `C$`) accompagnée d'un dépôt de binaire, suivie immédiatement d'un appel RPC de création ou démarrage de service (`CreateServiceW` / `StartServiceW`) sur `\PIPE\svcctl`.
2. **Déviation lexicale des tubes nommés SMB (`NamedPipeEntropy`)** : les services légitimes de Windows utilisent un ensemble restreint et stable de noms de tubes RPC (`lsarpc`, `samr`, `netlogon`, `srvsvc`, `wkssvc`). Les balises C2 relaient leurs flux sur des tubes générés par gabarit ou suffixe hexadécimal (`\PIPE\msagent_xx`, `\PIPE\postex_xxxx`, `\PIPE\status_xx`), isolables en temps constant contre la table blanche compilée dans `.c2book` et par mesure de densité hexadécimale.

---

## 5. Famille `IC-05` : Relais Locaux Intra-Hôte & Exécution sans Fichier (`floppy_local_ipc.c2book`)

### 5.1 Phénomène opérationnel et ancrage dans les sondes existantes
- **Problème concret** : sur un serveur compromis, un implant cherche à éviter toute écriture sur le disque dur (où un antivirus classique pourrait scanner le binaire) et fait communiquer un processus exposé au réseau avec un second processus local via des canaux inter-processus internes : tubes nommés locaux, ports Windows `ALPC` (*Asynchronous Local Procedure Call*), segments de mémoire partagée POSIX (`/dev/shm`) ou fichiers anonymes résidant uniquement en RAM (`memfd_create` sous Linux), couplés à du remplacement d'image mémoire (*Process Hollowing*) ou du chargement détourné de bibliothèques (*DLL Sideloading*).
- **État dans le dépôt** : les capteurs noyau Linux correspondants sont déjà opérationnels dans `internal/probes` (`fanotify` pour l'accès aux fichiers exécutés, `cn_proc` pour les filiations `fork`/`exec`/`exit`, et l'inspection ontologique de chemins temporaires ou supprimés dans `internal/engine`).

### 5.2 Mécanisme d'ingénierie et invariants physiques en `0 B/op`
1. **Exécution directe depuis la mémoire vive ou un inode effacé (`MemfdShmExec`)** : lors d'un événement d'exécution (`execve` / `fanotify`), tout chemin résolu dans `/proc/<pid>/exe` débutant par `/memfd:`, `/dev/shm/`, `/tmp/`, `/var/tmp/` ou portant le suffixe noyau `(deleted)` (binaire supprimé du système de fichiers immédiatement après son lancement) déclenche l'indicateur matériel d'exécution furtive sans aucune allocation sur le tas.
2. **Rupture d'arbre de filiation `cn_proc` (`ParentChildLineageAnomaly`)** : maintien en table fixe par identifiant de processus (`PID`) du couple `(exécutable parent, exécutable enfant)`. Lorsqu'un démon frontal réseau ou bureautique engendre directement un interpréteur interactif (`sh`, `bash`, `python`, `powershell`) ou charge une bibliothèque partagée depuis un répertoire inscriptible hors `/usr/lib`, l'événement est corrélé en `0 B/op` avec la cascade vectorielle à trois étages `L0/L1a/L1b` (`L0` : filtre réflexe de signatures exactes ; `L1a` : sonde binaire conforme à 512 bits par instruction `POPCNT` ; `L1b` : hyperplan linéaire quantifié `INT8` et veto par rayon de centroïde hostile).

---

## 6. Famille `IC-06` : Bus IoT (`MQTT` / `CoAP`) et Tunnels `QUIC` / TLS Génériques (`floppy_emerging_c2.c2book`)

### 6.1 Phénomène opérationnel et outils représentatifs
- **Problème concret** : deux vecteurs non conventionnels gagnent du terrain :
  1. Le détournement de courtiers de messagerie **MQTT** (`TCP/1883`, `TLS/8883`) ou d'échanges **CoAP** (`UDP/5683`), présents dans les environnements industriels et objets connectés (IoT), comme boîtes aux lettres asynchrones de commande et contrôle.
  2. L'encapsulation de balises C2 génériques directement dans **QUIC / HTTP/3** (`UDP/443`, par exemple les implants HTTP/3 de `Sliver` ou des tunnels QUIC sur mesure hors DNS).
- **État dans le dépôt** : le décodeur d'en-têtes `QUIC Initial` sans allocation et l'évaluateur cinétique bidirectionnel sur `DoQ`/`DoH3`/`H3` sont déjà opérationnels dans `encrypted_wire_decode.go`, `encrypted_wire_eval.go` et `encrypted_wire_hote.go` ; la partie `MQTT`/`CoAP` et le déchiffrement déterministe RFC 9001 des trames `CRYPTO` relèvent de la feuille de route.

### 6.2 Mécanisme d'ingénierie et invariants physiques en `0 B/op`
1. **Cardinalité et entropie anormales des sujets `MQTT` (`MQTTTopicCardinality`)** : un capteur IoT légitime publie de courts messages télémétriques ($< 64\text{ octets}$) sur une arborescence de sujets (*topics*) fixe et lisible (`sensors/temp/room1`). Un canal C2 sur MQTT se distingue soit par des sujets contenant des identifiants dynamiques à forte entropie, soit par l'alternance serrée publication/réponse d'objets chiffrés volumineux sur une paire symétrique de sujets `(cmd/<id>, res/<id>)`.
2. **Profilage `QUIC Initial` et persistance bidirectionnelle hors navigation (`QUICInitialPacketProfile`)** : sans aucune clé privée TLS du serveur, l'analyseur inspecte en `0 B/op` l'en-tête en clair du premier datagramme `QUIC Initial` (version QUIC, longueurs des identifiants de connexion `DCID`/`SCID`), dérive de manière déterministe les clés publiques RFC 9001 §5.2 à partir du `DCID` et du sel fixe du standard lorsqu'il doit lire le protocole applicatif `ALPN` annoncé dans le `ClientHello` TLS 1.3, puis suit la persistance bidirectionnelle du flux UDP. Un tunnel interactif maintient un échange soutenu dans les deux sens ($\min(V_\uparrow, V_\downarrow)$ élevé), contrairement à un téléchargement HTTP/3 ordinaire fortement asymétrique vers le client — sous la réserve physique documentée qu'un tunnel multiplexé à l'intérieur de la même connexion QUIC qu'un téléchargement HTTP/3 massif masque le flux sur le fil et requiert sur l'hôte Linux l'attribution par processus (`part_resolveur_permille`, qui démasque un binaire C2 dédié hors exécution intra-navigateur).

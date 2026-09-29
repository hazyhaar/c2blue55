// SPDX-License-Identifier: Apache-2.0 OR MIT

package c2archtsim

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
)

var castagnoliTable = crc32.MakeTable(crc32.Castagnoli)

// C2archtsim_page4k_is_zero vérifie par uint64 (512 blocs) si la page de 4096 octets est à zéro.
// Retourne 1 si tout est nul, sinon 0.
func C2archtsim_page4k_is_zero(page []byte) uint32 {
	if len(page) < 4096 {
		return 0
	}
	p := page[:4096]
	for i := 0; i < 4096; i += 8 {
		if binary.LittleEndian.Uint64(p[i:i+8]) != 0 {
			return 0
		}
	}
	return 1
}

// C2archtsim_page4k_is_zero_avx2 est l'équivalent fonctionnel du noyau vectorisé AVX2.
func C2archtsim_page4k_is_zero_avx2(page []byte) uint32 {
	return C2archtsim_page4k_is_zero(page)
}

// C2archtsim_page4k_diff_mask compare 64 lignes de 64 octets et positionne le bit i si la ligne diverge.
func C2archtsim_page4k_diff_mask(oldPage []byte, newPage []byte) uint64 {
	if len(oldPage) < 4096 || len(newPage) < 4096 {
		return 0
	}
	oldP := oldPage[:4096]
	newP := newPage[:4096]
	var mask uint64
	for i := 0; i < 64; i++ {
		start := i * 64
		if !bytes.Equal(oldP[start:start+64], newP[start:start+64]) {
			mask |= (uint64(1) << i)
		}
	}
	return mask
}

// C2archtsim_page4k_diff_mask_avx2 est l'équivalent fonctionnel du masque vectorisé AVX2.
func C2archtsim_page4k_diff_mask_avx2(oldPage []byte, newPage []byte) uint64 {
	return C2archtsim_page4k_diff_mask(oldPage, newPage)
}

// C2archtsim_page4k_crc32c calcule le CRC32-C Castagnoli pur sur 4096 octets.
func C2archtsim_page4k_crc32c(page []byte) uint32 {
	if len(page) < 4096 {
		return 0
	}
	return crc32.Checksum(page[:4096], castagnoliTable)
}

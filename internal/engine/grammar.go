package engine

import "strings"

const C2BT_MAX_MCP_TOOLS = 32

type C2bt_grammar_profile_t struct {
	Tool_name         [32]byte
	Q_dist            [256]byte
	Char_mask_allowed uint32
	Threshold_djs_q8  uint16
	Sample_count      uint16
	Flags             uint32
}

type C2bt_grammar_table_t struct {
	Tools [C2BT_MAX_MCP_TOOLS]C2bt_grammar_profile_t
	Count uint32
}

func C2bt_grammar_init(table *C2bt_grammar_table_t) {
	if table == nil {
		return
	}
	*table = C2bt_grammar_table_t{}
}

func C2bt_grammar_register_tool(table *C2bt_grammar_table_t, name string, sample []byte, charMask uint32, thresholdQ8 uint16) int {
	if table == nil || name == "" || len(name) >= 32 || strings.IndexByte(name, 0) >= 0 || len(sample) == 0 {
		return -1
	}
	idx := grammarFindTool(table, name)
	if idx < 0 {
		if table.Count >= C2BT_MAX_MCP_TOOLS {
			return -2
		}
		idx = int(table.Count)
		table.Count++
		table.Tools[idx] = C2bt_grammar_profile_t{}
	}
	slot := &table.Tools[idx]
	slot.Tool_name = [32]byte{}
	copy(slot.Tool_name[:], name)
	if histNormalize256(sample, slot.Q_dist[:]) != 0 {
		return -1
	}
	slot.Char_mask_allowed = charMask
	slot.Threshold_djs_q8 = thresholdQ8
	if slot.Sample_count < 0xFFFF {
		slot.Sample_count++
	}
	slot.Flags = 0
	return 0
}

func C2bt_grammar_eval(table *C2bt_grammar_table_t, toolName string, args []byte, outDjsQ8 *uint32, outFlags *uint32) int {
	if outDjsQ8 == nil || outFlags == nil {
		return -1
	}
	*outDjsQ8 = 0
	*outFlags = 0
	if table == nil || toolName == "" {
		return -1
	}
	idx := grammarFindTool(table, toolName)
	if idx < 0 {
		return -1
	}
	slot := &table.Tools[idx]
	if len(args) == 0 {
		return 0
	}
	for i := 0; i < len(args); i++ {
		cls := uint32(archtime_char_class[args[i]])
		if cls&slot.Char_mask_allowed == 0 {
			*outDjsQ8 = 256
			*outFlags = 0x0004 | 0x0400
			return 1
		}
	}
	var pDist [256]byte
	if histNormalize256(args, pDist[:]) != 0 {
		return -1
	}
	djs := C2bt_calc_djs_q8(&pDist, &slot.Q_dist)
	*outDjsQ8 = djs
	if djs > uint32(slot.Threshold_djs_q8) {
		*outFlags = 0x0004 | 0x0400
		return 1
	}
	return 0
}

func C2bt_calc_djs_q8(p *[256]byte, q *[256]byte) uint32 {
	if p == nil || q == nil {
		return 0
	}
	return (klPmQ8(p, q) + klPmQ8(q, p)) / 2
}

func grammarFindTool(table *C2bt_grammar_table_t, name string) int {
	if table == nil || name == "" || len(name) >= 32 {
		return -1
	}
	n := len(name)
	for i := uint32(0); i < table.Count; i++ {
		stored := table.Tools[i].Tool_name
		match := true
		for j := 0; j < n; j++ {
			if stored[j] != name[j] {
				match = false
				break
			}
		}
		if match && stored[n] == 0 {
			return int(i)
		}
	}
	return -1
}

func histNormalize256(data []byte, out []byte) int {
	if len(data) == 0 || len(out) < 256 {
		return -1
	}
	var freq [256]uint32
	var raw [256]uint32
	off := 0
	for off+7 < len(data) {
		freq[data[off]]++
		freq[data[off+1]]++
		freq[data[off+2]]++
		freq[data[off+3]]++
		freq[data[off+4]]++
		freq[data[off+5]]++
		freq[data[off+6]]++
		freq[data[off+7]]++
		off += 8
	}
	for ; off < len(data); off++ {
		freq[data[off]]++
	}
	sum := uint32(0)
	maxF := uint32(0)
	maxI := 0
	n := uint64(len(data))
	for i := 0; i < 256; i++ {
		v := uint32((uint64(freq[i]) * 256) / n)
		if v > 255 {
			v = 255
		}
		raw[i] = v
		sum += v
		if freq[i] > maxF {
			maxF = freq[i]
			maxI = i
		}
	}
	if sum < 256 {
		rem := 256 - sum
		room := 255 - raw[maxI]
		add := rem
		if add > room {
			add = room
		}
		raw[maxI] += add
		rem -= add
		for i := 0; rem > 0 && i < 256; i++ {
			if raw[i] < 255 {
				raw[i]++
				rem--
			}
		}
	}
	for i := 0; i < 256; i++ {
		out[i] = byte(raw[i])
	}
	return 0
}

func log2SymQ8(c uint32) uint32 {
	if c <= 1 {
		return 0
	}
	if c <= 256 {
		return c_log2_c_table[c] / c
	}
	return Arch_log2_q8_8(uint64(c))
}

func klTermDiffQ8(pi, mi uint32) int32 {
	return int32(log2SymQ8(pi)) - int32(log2SymQ8(mi)) + 256
}

func klPmQ8(p *[256]byte, q *[256]byte) uint32 {
	acc := int64(0)
	for i := 0; i < 256; i++ {
		pi := uint32(p[i])
		if pi == 0 {
			continue
		}
		mi := uint32(p[i]) + uint32(q[i])
		if mi == 0 {
			continue
		}
		acc += int64(pi) * int64(klTermDiffQ8(pi, mi))
	}
	if acc < 0 {
		return 0
	}
	return uint32(uint64(acc) / 256)
}

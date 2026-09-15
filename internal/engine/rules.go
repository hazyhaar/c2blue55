// Native Go rules. This file is not generated and does not claim C parity or SIMD.
package engine

import "bytes"

func Check_lolbas_comm(comm []byte) int {
	start := 0
	for start < len(comm) && (comm[start] == ' ' || comm[start] == '\t') {
		start++
	}
	end := start
	for end < len(comm) && comm[end] != 0 && comm[end] != ' ' && comm[end] != '\t' && comm[end] != '\r' && comm[end] != '\n' {
		end++
	}
	word := comm[start:end]
	if slash := bytes.LastIndexByte(word, '/'); slash >= 0 {
		word = word[slash+1:]
	}
	switch string(word) {
	case "curl", "wget", "nc", "ncat", "netcat", "socat", "base64", "perl", "ruby", "sh", "bash", "zsh", "dash", "ash":
		return 1
	}
	for _, prefix := range [...]string{"python", "php", "lua"} {
		if bytes.HasPrefix(word, []byte(prefix)) {
			return 1
		}
	}
	return 0
}

func C2bt_eval_rules_batch(inEvents, outEvents []Probe_event_t, count int) int {
	count = min(count, len(inEvents), len(outEvents))
	if count <= 0 {
		return 0
	}
	for i := 0; i < count; i++ {
		ev := inEvents[i]
		payload := ev.Payload[:]
		if end := bytes.IndexByte(payload, 0); end >= 0 {
			payload = payload[:end]
		}
		has := func(text string) bool { return bytes.Contains(payload, []byte(text)) }
		switch ev.Subsystem {
		case 1:
			if ev.Action == 1 && Check_lolbas_comm(payload) != 0 {
				ev.Flags |= 12
			}
		case 4:
			if ev.Action == 4 {
				piped := (has("curl") || has("wget")) && (has("| sh") || has("| bash") || has("|sh") || has("|bash"))
				if piped || has("rm -rf") || has("rm -r ") || has("chmod 777") || has("mkfs") || has("dd if=") || has(".claude") || has("CLAUDE.md") || has("AGENTS.md") || ev.Flags&0x100 != 0 {
					ev.Flags |= 6
				}
			}
		case 6:
			class := uint32(ev.Src >> 32)
			switch {
			case class == 4 || uint32(ev.Src) >= 0x780 || ev.Flags&0x100 != 0:
				ev.Flags |= 0x106
			case class == 3 || ev.Flags&0x80 != 0:
				ev.Flags |= 0x84
			case class == 2 || ev.Flags&0x40 != 0:
				ev.Flags |= 0x44
			}
		case 2:
			// A read/open does not attest a forbidden modification.
			if ev.Action == 6 && (has(".claude") || has("CLAUDE.md") || has("AGENTS.md")) {
				ev.Flags |= 6
			}
		}
		if ev.Flags&6 != 0 {
			ev.Flags &^= 1
		} else {
			ev.Flags |= 1
		}
		outEvents[i] = ev
	}
	return count
}

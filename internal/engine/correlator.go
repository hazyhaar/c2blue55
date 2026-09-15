// Native Go correlation policy, not a transpiled C artifact.
package engine

func C2bt_tracker_init(table *C2bt_tracker_table_t) {
	if table != nil {
		*table = C2bt_tracker_table_t{}
	}
}

func C2bt_tracker_reset_entry(entry *C2bt_process_tracker_t, pid uint32, tsNS uint64) {
	if entry != nil {
		*entry = C2bt_process_tracker_t{Pid: pid, Last_ts_ns: tsNS}
	}
}

// Last_ts_ns anchors a fixed window, not a sliding inactivity timeout.
// Only the first suspicious signal from each subsystem contributes 50 points.
// The score is a policy counter, not a probability or proof of interdiction.
func C2bt_correlate_event(table *C2bt_tracker_table_t, ev *Probe_event_t, outFlags *uint32, windowNS uint64) int {
	if table == nil || ev == nil || outFlags == nil {
		return -1
	}
	*outFlags = ev.Flags &^ 0x200
	// No stable process identity is available when PID is zero.
	if ev.Pid == 0 {
		return 0
	}
	if windowNS == 0 {
		windowNS = 1000000000
	}
	entry := &table.Entries[ev.Pid&1023]
	if entry.Event_count == 0 || entry.Pid != ev.Pid || ev.Ts_ns < entry.Last_ts_ns || ev.Ts_ns-entry.Last_ts_ns >= windowNS {
		C2bt_tracker_reset_entry(entry, ev.Pid, ev.Ts_ns)
	}
	if entry.Event_count < 65535 {
		entry.Event_count++
	}
	entry.Last_action = ev.Action
	hostile := false
	switch ev.Subsystem {
	case 1:
		hostile = ev.Action == 1 && ev.Flags&8 != 0
	case 2:
		hostile = ev.Action == 6 && ev.Flags&6 == 6
	case 3:
		hostile = ev.Flags&0x10 != 0
	case 4:
		hostile = ev.Action == 4 && (ev.Flags&0x400 != 0 || ev.Flags&6 == 6)
	case 5:
		hostile = ev.Flags&0x20 != 0
	case 6:
		hostile = ev.Flags&0x100 != 0
	}
	if !hostile {
		return 0
	}
	bit := uint32(1) << ev.Subsystem
	if entry.Subsystems_mask&bit == 0 {
		entry.Subsystems_mask |= bit
		entry.Accumulated_score += 50
	}
	if entry.Accumulated_score >= 100 {
		*outFlags = (ev.Flags | 0x204) &^ 1
	}
	return 0
}

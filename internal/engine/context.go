// Native Go lifecycle for injected observations. No operating-system probes
// or interception backend are connected by this implementation.
package engine

func C2bt_init_inplace(ctx *C2bt_ctx_t, cfg *C2bt_config_t) int {
	if ctx == nil {
		return -1
	}
	*ctx = C2bt_ctx_t{Sealed_mem_fd: -1, Fanotify_fd: -1, Mcp_proxy_fd: -1}
	if cfg != nil {
		ctx.Config = *cfg
	}
	return 0
}

func C2bt_start(ctx *C2bt_ctx_t) int {
	if ctx == nil {
		return -1
	}
	cfg := &ctx.Config
	if cfg.Enable_proc != 0 || cfg.Enable_file != 0 || cfg.Enable_net != 0 || cfg.Enable_mcp != 0 || cfg.Enable_entropy != 0 || cfg.Enable_gpu != 0 || cfg.Enforce_mode != 0 || cfg.Fail_safe_policy != 0 || len(cfg.Mcp_socket_path) != 0 || len(cfg.Harness_dir) != 0 {
		return -2
	}
	ctx.Running = 1
	return 0
}

func C2bt_stop(ctx *C2bt_ctx_t) int {
	if ctx == nil {
		return -1
	}
	ctx.Running = 0
	return 0
}

func C2bt_poll_batch(ctx *C2bt_ctx_t, out []Probe_event_t, maxEvents int) int {
	if ctx == nil || ctx.Running == 0 {
		return 0
	}
	maxEvents = min(maxEvents, len(out))
	count := 0
	channels := [...]*Probe_channel_t{&ctx.Chan_proc, &ctx.Chan_file, &ctx.Chan_net, &ctx.Chan_mcp}
	for count < maxEvents {
		before := count
		for _, ch := range channels {
			if count < maxEvents && C2bt_channel_read(ch, &out[count]) == 1 {
				count++
			}
		}
		if count == before {
			break
		}
	}
	C2bt_eval_rules_batch(out, out, count)
	for i := 0; i < count; i++ {
		var flags uint32
		C2bt_correlate_event(&ctx.Tracker_table, &out[i], &flags, 1000000000)
		out[i].Flags = flags
	}
	return count
}

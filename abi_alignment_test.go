package c2blue55

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"testing"
	"unsafe"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55/internal/engine"
)

// This checks the real Go transport against the module-local C layout, not
// the different, mutable external c2blueteam.h ABI (which is not supported).
func TestABIAlignment_Layout(t *testing.T) {
	var ev Event
	var channel engine.Probe_channel_t
	var wrapper Channel
	if unsafe.Sizeof(wrapper) != unsafe.Sizeof(channel) {
		t.Fatal("channel wrapper layout differs")
	}
	want := []uintptr{
		unsafe.Sizeof(ev), unsafe.Alignof(ev), unsafe.Offsetof(ev.Ts_ns), unsafe.Offsetof(ev.Pid), unsafe.Offsetof(ev.Tid), unsafe.Offsetof(ev.Subsystem), unsafe.Offsetof(ev.Action), unsafe.Offsetof(ev.Flags), unsafe.Offsetof(ev.Src), unsafe.Offsetof(ev.Payload),
		unsafe.Sizeof(channel), unsafe.Alignof(channel), unsafe.Offsetof(channel.Slots), unsafe.Offsetof(channel.Head), unsafe.Offsetof(channel.Drops), unsafe.Offsetof(channel.Pad1), unsafe.Offsetof(channel.Tail), unsafe.Offsetof(channel.Pad2),
	}
	bin := filepath.Join(t.TempDir(), "abi-oracle")
	if out, err := exec.Command("gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "internal/engine/testdata/abi_oracle.c", "-o", bin).CombinedOutput(); err != nil {
		t.Fatalf("gcc: %v: %s", err, out)
	}
	out, err := exec.Command(bin).Output()
	if err != nil {
		t.Fatal(err)
	}
	var got [18]uintptr
	n, err := fmt.Sscan(string(out), &got[0], &got[1], &got[2], &got[3], &got[4], &got[5], &got[6], &got[7], &got[8], &got[9], &got[10], &got[11], &got[12], &got[13], &got[14], &got[15], &got[16], &got[17])
	if err != nil || n != len(want) {
		t.Fatalf("oracle output %q: %v", out, err)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("layout field %d: C=%d Go=%d", i, got[i], want[i])
		}
	}
}

/* Independent, module-local transport layout. Not a generation source.
 * This is the supported Go channel layout, not the external cached-head ABI.
 * Config and Context contain Go slices and are NOT a C ABI.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef struct {
    uint64_t ts_ns;
    uint32_t pid, tid;
    uint16_t subsystem, action;
    uint32_t flags;
    uint64_t src;
    unsigned char payload[96];
} event;

typedef struct {
    event slots[1024];
    uint64_t head, drops;
    unsigned char pad1[48];
    uint64_t tail;
    unsigned char pad2[56];
} channel;

_Static_assert(sizeof(event) == 128, "event size");
_Static_assert(sizeof(channel) == 131200, "channel size");
_Static_assert(offsetof(channel, tail) == 131136, "tail offset");

int main(void) {
    printf("%zu %zu %zu %zu %zu %zu %zu %zu %zu %zu "
           "%zu %zu %zu %zu %zu %zu %zu %zu\n",
           sizeof(event), _Alignof(event), offsetof(event, ts_ns),
           offsetof(event, pid), offsetof(event, tid), offsetof(event, subsystem),
           offsetof(event, action), offsetof(event, flags), offsetof(event, src),
           offsetof(event, payload), sizeof(channel), _Alignof(channel),
           offsetof(channel, slots), offsetof(channel, head), offsetof(channel, drops),
           offsetof(channel, pad1), offsetof(channel, tail), offsetof(channel, pad2));
    return 0;
}

#include <uapi/linux/ptrace.h>

struct lpm_key {
    u32 prefixlen;
    u32 addr;
};

struct value_t {
    u32 value;
};

BPF_LPM_TRIE(route_trie, struct lpm_key, struct value_t, 128);

int test_prog(struct pt_regs *ctx) {
    return 0;
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Poptrie-backed BPF LPM trie map (BPF_MAP_TYPE_LPM_TRIE)
 *
 * Drop-in replacement for the kernel's lpm_trie.c.  All external ABI
 * is preserved.
 *
 * =========================================================================
 * Algorithm: O(N log N) rebuild via per-bucket sparse route scan
 * =========================================================================
 *
 * Previous (dense ctab) approach and why it failed:
 *   An earlier version precomputed a "coverage table" for each of the 4096
 *   direct-pointing buckets (POPTRIE_S = 12).  Each ctab was a dense array
 *   of 2^(32-s+1)-1 = 2,097,151 cells.  Building it required:
 *     Pass 1: propagate 2^20 ≈ 1M cells at the deepest level per bucket.
 *     Pass 2: 2M-cell bottom-up has_deeper scan per bucket.
 *     kvcalloc(2M, 4) ≈ 8 MB allocation per bucket.
 *   Total: 4096 * (2M writes + 2M writes + 8 MB alloc) ≈ 16 billion writes
 *   and 32 GB of memory bandwidth.  This caused the soft-lockup watchdog
 *   to fire and the kernel to kill the process.
 *
 * Current approach: zero-allocation bucket context (struct bucket_ctx).
 *   For each bucket we initialise a lightweight context that holds a pointer
 *   into the sorted flat[] RIB array and the inherited best_fib from prefixes
 *   shorter than s_bits.  No memory is allocated; no propagation pass runs.
 *
 *   bctx_query(ctx, abs_depth, addr, &best_fib, &has_deeper):
 *     Scans the bucket's slice of flat[] once.  Per-entry cost: one mask
 *     and one compare.  Cost: O(routes_in_bucket).
 *
 *   bctx_init(ctx, flat, flat_n, bucket_addr, s_bits):
 *     Binary search to locate the slice + linear scan for inherited match.
 *     Cost: O(log N + short_prefix_count).
 *
 *   build_node() issues at most fanout=64 queries per node.  The recursion
 *   depth is at most ceil((32-s)/k) = ceil(20/6) = 4 levels.  For a dense
 *   bucket with R routes, the node count is O(R) and total queries ≈ R*64*4.
 *   With avg R ≈ 230 routes/bucket: 4096 * 230 * 64 * 4 ≈ 240M comparisons.
 *   Each comparison is a cheap integer mask + compare — completes in seconds.
 *
 *   Total rebuild: O(N log N) sort + O(N) bctx_init × 4096 + O(N * nodes * 64)
 *                ≈ O(N * nodes * 64), linear in practice for BGP tables.
 *
 * =========================================================================
 * Locking model
 * =========================================================================
 *
 *   update_mutex  – mutex serialising all RIB mutations and rebuild.
 *                   Sleepable: prevents watchdog firing on long rebuilds.
 *
 *   snap_lock     – spinlock protecting only the live snapshot swap.
 *                   Held for nanoseconds; never during rebuild.
 *
 * =========================================================================
 * Bulk-load protocol
 * =========================================================================
 *
 *   Write key.prefixlen = POPTRIE_BULK_SENTINEL   to enter bulk mode.
 *   Write key.prefixlen = POPTRIE_COMMIT_SENTINEL to exit and rebuild.
 *
 * =========================================================================
 * Limitations
 * =========================================================================
 *   IPv4 only (data_size == 4).
 *
 * =========================================================================
 * Fixes applied vs. original
 * =========================================================================
 *   1. trie_mem_usage: was dereferencing __rcu * with '.' instead of '->'.
 *      Now uses rcu_dereference_raw() then -> accessors.
 *
 *   2. poptrie_rebuild: flat[] was never sorted before the binary partition
 *      search, so flat_lo_s was always 0 (rb_first() yields longest-prefix-
 *      first because route_cmp puts longer prefixes on the left subtree).
 *      Added sort(flat, flat_n, rib_flat_cmp) immediately after filling
 *      flat[], before the partition binary search.  Without this sort,
 *      bucket_inherit was never populated and all /0-/11 routes were silently
 *      ignored.
 *
 *   3. bctx_query: has_deeper detection only inspected entries[end-1] and
 *      could miss interior entries with plen > next_depth.  Replaced with a
 *      full linear scan of [start, end).
 *
 *   4. trie_update_elem: old value was freed via synchronize_rcu()+kfree()
 *      before the new snapshot was installed, creating a window where live
 *      XDP readers could dereference freed memory.  Old value is now freed
 *      after poptrie_rebuild() (which calls synchronize_rcu() only after the
 *      new snapshot is live), or after an explicit synchronize_rcu() in bulk
 *      mode.
 *
 *   5. trie_delete_elem: same use-after-free pattern as #4.  synchronize_rcu()
 *      and kfree() moved to after poptrie_rebuild() / explicit grace period.
 *
 *   6. ensure_nodes / ensure_leaves / ensure_fib: used ksize() to probe
 *      capacity, which is unreliable for vmalloc-backed memory (kvcalloc falls
 *      back to vmalloc above ~4 MB, which happens for a full BGP FIB).  All
 *      three helpers now track capacity explicitly with _cap fields in
 *      poptrie_snapshot.
 */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/err.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/rbtree.h>
#include <linux/sort.h>
#include <linux/bitops.h>
#include <uapi/linux/btf.h>


/* -------------------------------------------------------------------------
 * Tunables
 * ------------------------------------------------------------------------- */
#ifndef POPTRIE_K
#define POPTRIE_K 6
#endif
#ifndef POPTRIE_S
#define POPTRIE_S 12
#endif

#define KEYLENGTH 32

#define POPTRIE_BULK_SENTINEL   0xFFFFFFFEU
#define POPTRIE_COMMIT_SENTINEL 0xFFFFFFFFU

/* -------------------------------------------------------------------------
 * Bit helpers
 * ------------------------------------------------------------------------- */

static inline u64 low_mask64(unsigned int n)
{
	return (n >= 64) ? ~0ULL : (1ULL << n) - 1ULL;
}

static inline u32 extract32(u32 a, unsigned int s, unsigned int n)
{
	if (n == 0) return 0;
	if (s + n > 32) n = 32 - s;
	return (a >> (32 - (s + n))) & ((1U << n) - 1U);
}

/* -------------------------------------------------------------------------
 * Poptrie snapshot structures
 * ------------------------------------------------------------------------- */

struct poptrie_node {
	u64 vector;
	u64 leafvec;
	u32 base0;
	u32 base1;
};

typedef u32 poptrie_leaf_t;

struct poptrie_fib_entry {
	void *value;
};

struct poptrie_snapshot {
	struct poptrie_node      *nodes;
	poptrie_leaf_t           *leaves;
	u32                      *dir;
	u32 nodes_used;
	u32 nodes_cap;   /* FIX #6: explicit capacity tracked here, not via ksize() */
	u32 leaves_used;
	u32 leaves_cap;  /* FIX #6 */
	u32 fib_used;
	u32 fib_cap;     /* FIX #6 */
	struct poptrie_fib_entry *fib;
	u32 s;
	u32 k;
	u32 dir_sz;
};

/* -------------------------------------------------------------------------
 * RIB structures
 * ------------------------------------------------------------------------- */

struct poptrie_route {
	struct rb_node rb;
	u32 addr;
	u32 prefixlen;
	void *value;
	u32 fib_idx;
};

static inline int route_cmp(u32 a_addr, u32 a_plen, u32 b_addr, u32 b_plen)
{
	if (a_plen != b_plen) return (a_plen > b_plen) ? -1 : 1;
	if (a_addr < b_addr)  return -1;
	if (a_addr > b_addr)  return  1;
	return 0;
}

/*
 * Flat RIB entry for the sorted array used during rebuild.
 * Sorted prefixlen ascending, addr ascending.
 */
struct rib_flat_entry {
	u32 addr;
	u32 prefixlen;
	u32 fib_idx;
};

static int rib_flat_cmp(const void *a, const void *b)
{
	const struct rib_flat_entry *ea = a, *eb = b;
	if (ea->prefixlen != eb->prefixlen)
		return (ea->prefixlen < eb->prefixlen) ? -1 : 1;
	if (ea->addr < eb->addr) return -1;
	if (ea->addr > eb->addr) return  1;
	return 0;
}

/*
 * rib_bucket_cmp - secondary sort for the above-s_bits portion of flat[].
 *
 * Sorts by (bucket_index, prefixlen, addr) so that each direct-pointing
 * bucket's routes form one contiguous run.  Applied only to entries with
 * prefixlen >= POPTRIE_S; the below-s portion stays (prefixlen, addr)-sorted
 * so the inherited-best-fib computation stays correct.
 *
 * bucket_index = addr >> (32 - POPTRIE_S).  For routes with prefixlen >= S,
 * addr is already masked to the route length, so the top S bits uniquely
 * identify the /S bucket that contains the route.
 */
static int rib_bucket_cmp(const void *a, const void *b)
{
	const struct rib_flat_entry *ea = a, *eb = b;
	if (ea->addr < eb->addr) return -1;
	if (ea->addr > eb->addr) return  1;
	if (ea->prefixlen != eb->prefixlen)
		return (ea->prefixlen < eb->prefixlen) ? -1 : 1;
	return 0;
}

/* -------------------------------------------------------------------------
 * Bucket context
 *
 * A lightweight struct that points into a pre-partitioned slice of the
 * flat RIB array.  Before the main rebuild loop, poptrie_rebuild() re-sorts
 * flat[flat_lo_s..flat_n] by (bucket_idx, prefixlen, addr) using
 * rib_bucket_cmp(), so each bucket's routes form one contiguous run.
 * Binary search then finds [lo, hi) for each bucket in O(log N).
 *
 * bctx_query() scans only the bucket's own entries (~230 on average for a
 * full BGP table, vs. 941K if the whole flat[] is scanned).  This reduces
 * the total work from O(N^2) to O(N * nodes * 64) which is linear and fast.
 *
 * inherit: best_fib from routes with prefixlen < s_bits.  These cover
 * multiple buckets; they are precomputed into bucket_inherit[dir_sz] once
 * before the bucket loop and stored here per bucket.
 * ------------------------------------------------------------------------- */

struct bucket_ctx {
	const struct rib_flat_entry *entries; /* bucket's own routes only */
	u32  count;                           /* number of entries */
	u32  inherit;                         /* best_fib from prefixlen < s_bits */
	u32  s_bits;                          /* the s_bits boundary */
};

/*
 * bctx_query - answer (best_fib, has_deeper) for a subspace within a bucket.
 *
 * Scans ctx->entries[0..count) -- the routes belonging to this bucket only.
 * Cost: O(routes_in_bucket), not O(N).
 *
 * FIX #3: has_deeper detection previously only checked entries[end-1], which
 * could miss interior entries.  Now scans all entries in [start, end).
 */
static void bctx_query(const struct bucket_ctx *ctx,
		       u32 next_depth, u32 sub_addr,
		       u32 *best_fib, bool *has_deeper)
{
	u32 best = ctx->inherit;
	bool deep = false;
	u32 low_addr = sub_addr;
	u32 high_addr = (next_depth == 32) ? sub_addr : (sub_addr | (~0U >> next_depth));
	u32 blo, bhi, mid, start, end, i;
	int p;

	/* 1. Find if there are deeper routes.
	 * Find range [start, end) of routes whose addr is in [low_addr, high_addr].
	 */
	blo = 0; bhi = ctx->count;
	while (blo < bhi) {
		mid = blo + (bhi - blo) / 2;
		if (ctx->entries[mid].addr < low_addr) blo = mid + 1;
		else bhi = mid;
	}
	start = blo;

	bhi = ctx->count;
	while (blo < bhi) {
		mid = blo + (bhi - blo) / 2;
		if (ctx->entries[mid].addr <= high_addr) blo = mid + 1;
		else bhi = mid;
	}
	end = blo;

	/*
	 * FIX #3: Scan all entries in [start, end).  An entry signals
	 * has_deeper if it either:
	 *   (a) has addr > sub_addr  — it is a distinct longer prefix inside
	 *       this subspace, OR
	 *   (b) has addr == sub_addr and plen > next_depth — it is an exact
	 *       match at a deeper prefix length.
	 * The original code only checked entries[end-1] and could miss entries
	 * earlier in the range that satisfy (b) when a wider-addr entry
	 * happened to land at end-1.
	 */
	for (i = start; i < end; i++) {
		if (ctx->entries[i].addr > sub_addr ||
		    ctx->entries[i].prefixlen > next_depth) {
			deep = true;
			break;
		}
	}

	/* 2. Find longest matching prefix <= next_depth.
	 * Routes inside ctx have plen >= s_bits, so search down to s_bits.
	 */
	for (p = next_depth; p >= (int)ctx->s_bits; p--) {
		u32 mask = (p == 0) ? 0u : (~0U << (32 - p));
		u32 target = sub_addr & mask;
		u32 l = 0, r = ctx->count;
		bool found = false;

		while (l < r) {
			u32 m = l + (r - l) / 2;
			if (ctx->entries[m].addr < target) {
				l = m + 1;
			} else if (ctx->entries[m].addr > target) {
				r = m;
			} else {
				/* Found matching addr. Check surrounding prefixlens. */
				u32 idx = m;
				while (idx > 0 && ctx->entries[idx - 1].addr == target)
					idx--;
				while (idx < ctx->count && ctx->entries[idx].addr == target) {
					if (ctx->entries[idx].prefixlen == p) {
						best = ctx->entries[idx].fib_idx;
						found = true;
						break;
					}
					if (ctx->entries[idx].prefixlen > p)
						break; /* sorted by plen, can stop early */
					idx++;
				}
				break;
			}
		}
		if (found)
			break;
	}

	*best_fib = best;
	*has_deeper = deep;
}

/* -------------------------------------------------------------------------
 * Map wrapper
 * ------------------------------------------------------------------------- */

struct lpm_trie {
	struct bpf_map map;
	struct mutex   update_mutex;

	u32 data_size;
	u32 max_prefixlen;
	size_t n_entries;
	bool bulk_loading;
	struct rb_root routes;

	/* RCU pointer to the active snapshot */
	struct poptrie_snapshot __rcu *snap;
};

/* -------------------------------------------------------------------------
 * RIB rbtree ops
 * ------------------------------------------------------------------------- */

static struct poptrie_route *route_find(struct lpm_trie *trie,
					u32 addr, u32 prefixlen)
{
	struct rb_node *n = trie->routes.rb_node;
	while (n) {
		struct poptrie_route *r = rb_entry(n, struct poptrie_route, rb);
		int c = route_cmp(addr, prefixlen, r->addr, r->prefixlen);
		if      (c < 0) n = n->rb_left;
		else if (c > 0) n = n->rb_right;
		else            return r;
	}
	return NULL;
}

static int route_insert(struct lpm_trie *trie, struct poptrie_route *nr)
{
	struct rb_node **link = &trie->routes.rb_node, *parent = NULL;
	while (*link) {
		struct poptrie_route *r = rb_entry(*link, struct poptrie_route, rb);
		int c = route_cmp(nr->addr, nr->prefixlen, r->addr, r->prefixlen);
		parent = *link;
		if      (c < 0) link = &(*link)->rb_left;
		else if (c > 0) link = &(*link)->rb_right;
		else            return -EEXIST;
	}
	rb_link_node(&nr->rb, parent, link);
	rb_insert_color(&nr->rb, &trie->routes);
	return 0;
}

/* -------------------------------------------------------------------------
 * Snapshot array helpers
 *
 * FIX #6: All three helpers previously used ksize() to probe whether a
 * reallocation was needed.  ksize() is only valid for pure kmalloc-backed
 * memory; kvcalloc silently falls back to vmalloc for allocations above
 * ~4 MB (KMALLOC_MAX_SIZE).  For a full BGP FIB the fib[] array alone is
 * ~900K * 8 bytes = ~7 MB, so ksize() would return the requested size or
 * 0 depending on kernel version, making the capacity check unpredictable
 * and potentially skipping needed reallocations (silent OOB writes).
 *
 * Capacity is now tracked explicitly via nodes_cap / leaves_cap / fib_cap
 * fields added to struct poptrie_snapshot.
 * ------------------------------------------------------------------------- */

static int ensure_nodes(struct poptrie_snapshot *s, u32 need)
{
	struct poptrie_node *nn;
	u32 newcap;

	if (need <= s->nodes_cap) return 0;

	newcap = max_t(u32, 1024, roundup_pow_of_two(need));
	nn = kvrealloc(s->nodes, newcap * sizeof(*nn), GFP_KERNEL | __GFP_NOWARN);
	if (!nn) return -ENOMEM;

	/* Zero only the newly added portion */
	if (newcap > s->nodes_cap)
		memset(nn + s->nodes_cap, 0,
		       (newcap - s->nodes_cap) * sizeof(*nn));

	s->nodes     = nn;
	s->nodes_cap = newcap;
	return 0;
}

static int ensure_leaves(struct poptrie_snapshot *s, u32 need)
{
	poptrie_leaf_t *nl;
	u32 newcap;

	if (need <= s->leaves_cap) return 0;

	newcap = max_t(u32, 1024, roundup_pow_of_two(need));
	nl = kvrealloc(s->leaves, newcap * sizeof(*nl), GFP_KERNEL | __GFP_NOWARN);
	if (!nl) return -ENOMEM;

	if (newcap > s->leaves_cap)
		memset(nl + s->leaves_cap, 0,
		       (newcap - s->leaves_cap) * sizeof(*nl));

	s->leaves     = nl;
	s->leaves_cap = newcap;
	return 0;
}

static int ensure_fib(struct poptrie_snapshot *s, u32 need)
{
	struct poptrie_fib_entry *nf;
	u32 newcap;

	if (need <= s->fib_cap) return 0;

	newcap = max_t(u32, 64, roundup_pow_of_two(need));
	nf = kvrealloc(s->fib, newcap * sizeof(*nf), GFP_KERNEL | __GFP_NOWARN);
	if (!nf) return -ENOMEM;

	if (newcap > s->fib_cap)
		memset(nf + s->fib_cap, 0,
		       (newcap - s->fib_cap) * sizeof(*nf));

	s->fib     = nf;
	s->fib_cap = newcap;
	return 0;
}

static void snapshot_free_arrays(struct poptrie_snapshot *s)
{
	kvfree(s->nodes);  s->nodes  = NULL; s->nodes_cap  = 0;
	kvfree(s->leaves); s->leaves = NULL; s->leaves_cap = 0;
	kvfree(s->dir);    s->dir    = NULL;
	kvfree(s->fib);    s->fib    = NULL; s->fib_cap    = 0;
}

/* -------------------------------------------------------------------------
 * Poptrie node builder
 *
 * Takes a bucket_ctx instead of a flat RIB array.
 * Every slot query is an O(routes_in_bucket) bctx_query() scan.
 * ------------------------------------------------------------------------- */
static int build_node(const struct bucket_ctx *bctx,
		      struct poptrie_snapshot *s,
		      u32 node_idx, u32 prefix_addr, u32 depth)
{
	const u32 k        = s->k;
	const u32 fanout   = 1U << k;
	const u32 rem      = (depth >= KEYLENGTH) ? 0u : (KEYLENGTH - depth);
	const u32 use_bits = min(k, rem);
	const u32 pad      = k - use_bits;

	u64 vector = 0, leafvec = 0;
	u32 base1, base0;
	u32 internal_cnt = 0, leaf_cnt = 0;

	bool internal_child[64];
	u32  child_prefix[64];
	u32  child_depth_arr[64];
	u32  leaf_fib[64];
	u32  n;

	if (fanout > 64)
		return -EINVAL;

	memset(internal_child, 0, sizeof(internal_child));

	for (n = 0; n < fanout; n++) {
		u32 r              = pad ? (n >> pad) : n;
		bool is_group_base = pad ? (n == (r << pad)) : true;
		u32 next_depth     = min(depth + use_bits, (u32)KEYLENGTH);
		u32 sub_addr;
		u32 best;
		bool deeper;

		if (!is_group_base) {
			internal_child[n] = false;
			leaf_fib[n]       = 0;
			continue;
		}

		sub_addr = prefix_addr;
		if (use_bits) {
			u32 chunk_bits = r & ((1U << use_bits) - 1u);
			sub_addr |= chunk_bits << (32 - (depth + use_bits));
		}
		child_prefix[n]    = sub_addr;
		child_depth_arr[n] = next_depth;

		/* O(routes_in_bucket) scan -- no dense array needed. */
		bctx_query(bctx, next_depth, sub_addr, &best, &deeper);

		if (next_depth < KEYLENGTH && deeper) {
			internal_child[n] = true;
			internal_cnt++;
			vector |= (1ULL << n);
		} else {
			internal_child[n] = false;
			leaf_fib[n] = best;
			leaf_cnt++;
			leafvec |= (1ULL << n);
		}
	}

	base1 = s->nodes_used;
	base0 = s->leaves_used;

	if (ensure_nodes(s, s->nodes_used + internal_cnt + 1))
		return -ENOMEM;
	if (ensure_leaves(s, s->leaves_used + leaf_cnt + 1))
		return -ENOMEM;

	s->nodes_used  += internal_cnt;
	s->leaves_used += leaf_cnt;

	{
		u32 icur = 0, lcur = 0;
		for (n = 0; n < fanout; n++) {
			u32 r              = pad ? (n >> pad) : n;
			bool is_group_base = pad ? (n == (r << pad)) : true;

			if (!is_group_base) continue;

			if (internal_child[n]) {
				u32 child_idx = base1 + icur++;
				int err;

				memset(&s->nodes[child_idx], 0,
				       sizeof(struct poptrie_node));
				err = build_node(bctx, s, child_idx,
						 child_prefix[n],
						 child_depth_arr[n]);
				if (err) return err;
			} else {
				s->leaves[base0 + lcur++] = leaf_fib[n];
			}
		}
	}

	s->nodes[node_idx].vector  = vector;
	s->nodes[node_idx].leafvec = leafvec;
	s->nodes[node_idx].base0   = base0;
	s->nodes[node_idx].base1   = base1;

	return 0;
}

/* -------------------------------------------------------------------------
 * poptrie_rebuild
 * ------------------------------------------------------------------------- */
static int poptrie_rebuild(struct lpm_trie *trie)
{
	struct poptrie_snapshot *staging, *old;
	struct rib_flat_entry *flat = NULL;
	u32 *bucket_inherit = NULL;
	size_t flat_n = trie->n_entries;
	struct rb_node *n;
	u32 i = 0, d, flat_lo_s = 0;
	u32 s_bits, dir_sz;
	int err = 0;

	/* 1. Allocate the NEW snapshot container */
	staging = kvzalloc(sizeof(*staging), GFP_KERNEL);
	if (!staging) return -ENOMEM;

	/* Fetch current parameters from the old snapshot */
	old = rcu_dereference_protected(trie->snap, lockdep_is_held(&trie->update_mutex));
	staging->k = old ? old->k : POPTRIE_K;
	staging->s = old ? old->s : POPTRIE_S;
	staging->dir_sz = old ? old->dir_sz : ((POPTRIE_S == 0) ? 1U : (1U << POPTRIE_S));

	s_bits = staging->s;
	dir_sz = staging->dir_sz;

	/* 2. Prepare the Flat RIB */
	flat = kvmalloc_array(flat_n, sizeof(*flat), GFP_KERNEL);
	if (!flat && flat_n > 0) {
		err = -ENOMEM;
		goto err_staging_struct;
	}

	for (n = rb_first(&trie->routes); n; n = rb_next(n)) {
		struct poptrie_route *r = rb_entry(n, struct poptrie_route, rb);
		flat[i].addr      = r->addr;
		flat[i].prefixlen = r->prefixlen;
		r->fib_idx        = i + 1;
		flat[i].fib_idx   = r->fib_idx;
		i++;
	}

	/*
	 * FIX #2: Sort flat[] by (prefixlen ascending, addr ascending) BEFORE
	 * the partition binary search.
	 *
	 * rb_first() yields routes in the order imposed by route_cmp(), which
	 * sorts longer prefixes as "smaller" (left subtree), so rb_first()
	 * produces longest-prefix-first order (plen descending).  The binary
	 * search below assumes ascending plen; without this sort, flat_lo_s was
	 * always 0, the bucket_inherit loop body never executed, and all
	 * coverage from prefixes shorter than s_bits (/0 through /11 for the
	 * default S=12) was silently dropped — meaning default routes and all
	 * short aggregate prefixes were never matched.
	 */
	if (flat_n > 0)
		sort(flat, flat_n, sizeof(*flat), rib_flat_cmp, NULL);

	/* Sort and partition logic */
	if (flat_n > 0 && s_bits > 0) {
		u32 lo = 0, hi = flat_n, bshift = 32 - s_bits;
		/* Binary search for first entry with prefixlen >= s_bits.
		 * flat[] is now sorted ascending by prefixlen, so this is correct. */
		while (lo < hi) {
			u32 mid = lo + (hi - lo) / 2;
			if (flat[mid].prefixlen < s_bits) lo = mid + 1;
			else hi = mid;
		}
		flat_lo_s = lo;

		bucket_inherit = kvzalloc(dir_sz * sizeof(u32), GFP_KERNEL);
		if (!bucket_inherit) { err = -ENOMEM; goto err_flat; }

		/*
		 * Propagate short-prefix coverage into bucket_inherit[].
		 * Iterating shortest-to-longest means each successive write
		 * correctly overwrites a shorter match with a longer one,
		 * preserving LPM semantics.  This is only correct because
		 * flat[0..flat_lo_s) is now sorted by ascending prefixlen.
		 */
		for (i = 0; i < flat_lo_s; i++) {
			u32 plen = flat[i].prefixlen;
			u32 fb   = flat[i].addr >> bshift;
			u32 nb   = 1U << (s_bits - plen);
			u32 j, end = min(fb + nb, dir_sz);
			for (j = fb; j < end; j++)
				bucket_inherit[j] = flat[i].fib_idx;
		}
		if (flat_n > flat_lo_s)
			sort(flat + flat_lo_s, flat_n - flat_lo_s,
			     sizeof(*flat), rib_bucket_cmp, NULL);
	}

	/* Allocate staging arrays */
	if (ensure_fib(staging, flat_n + 2)) { err = -ENOMEM; goto err_flat; }
	staging->fib_used = 1;
	staging->fib[0].value = NULL;

	for (n = rb_first(&trie->routes); n; n = rb_next(n)) {
		struct poptrie_route *r = rb_entry(n, struct poptrie_route, rb);
		staging->fib[r->fib_idx].value = r->value;
		if (r->fib_idx >= staging->fib_used)
			staging->fib_used = r->fib_idx + 1;
	}

	staging->dir = kvzalloc(dir_sz * sizeof(u32), GFP_KERNEL);
	if (!staging->dir) { err = -ENOMEM; goto err_staging_arrays; }
	if (ensure_nodes(staging, 1)) { err = -ENOMEM; goto err_staging_arrays; }

	/* 3. Build the Poptrie Structure */
	for (d = 0; d < dir_sz; d++) {
		u32 bucket_addr = (s_bits == 0) ? 0u : (d << (32 - s_bits));
		u32 best_fib_at_s;
		bool has_deeper_at_s;

		if (flat_n == 0) {
			staging->dir[d] = (1U << 31);
			continue;
		}

		struct bucket_ctx bctx;
		u32 blo, bhi, bstart;
		blo = flat_lo_s; bhi = flat_n;
		while (blo < bhi) {
			u32 mid  = blo + (bhi - blo) / 2;
			u32 bidx = (s_bits > 0) ? (flat[mid].addr >> (32 - s_bits)) : 0u;
			if (bidx < d) blo = mid + 1; else bhi = mid;
		}
		bstart = blo;
		bhi = flat_n;
		while (blo < bhi) {
			u32 mid  = blo + (bhi - blo) / 2;
			u32 bidx = (s_bits > 0) ? (flat[mid].addr >> (32 - s_bits)) : 0u;
			if (bidx <= d) blo = mid + 1; else bhi = mid;
		}
		bctx.entries = flat + bstart;
		bctx.count   = blo - bstart;
		bctx.inherit = bucket_inherit ? bucket_inherit[d] : 0u;
		bctx.s_bits  = s_bits;

		bctx_query(&bctx, s_bits, bucket_addr, &best_fib_at_s, &has_deeper_at_s);

		if (!has_deeper_at_s || s_bits >= 32) {
			staging->dir[d] = (1U << 31) | (best_fib_at_s & ((1U << 31) - 1));
		} else {
			u32 node_idx = staging->nodes_used++;
			if (ensure_nodes(staging, staging->nodes_used + 1)) {
				err = -ENOMEM;
				goto err_staging_arrays;
			}
			memset(&staging->nodes[node_idx], 0, sizeof(struct poptrie_node));
			err = build_node(&bctx, staging, node_idx, bucket_addr, s_bits);
			if (err) goto err_staging_arrays;
			staging->dir[d] = node_idx;
		}
	}

	/* 4. ATOMIC SWAP */
	rcu_assign_pointer(trie->snap, staging);

	/* 5. WAIT for active XDP readers to finish using the 'old' snapshot */
	synchronize_rcu();

	if (old) {
		snapshot_free_arrays(old);
		kvfree(old);
	}

	kvfree(bucket_inherit);
	kvfree(flat);
	return 0;

err_staging_arrays:
	snapshot_free_arrays(staging);
err_flat:
	kvfree(bucket_inherit);
	kvfree(flat);
err_staging_struct:
	kvfree(staging);
	return err;
}

/* -------------------------------------------------------------------------
 * Poptrie lookup
 * ------------------------------------------------------------------------- */
static void *poptrie_lookup(const struct poptrie_snapshot *s, u32 addr)
{
	u32 index, dindex, offset;
	const u32 k = s->k;

	if (unlikely(!s->dir))
		return NULL;

	index  = (s->s == 0) ? 0u : extract32(addr, 0, s->s);
	dindex = s->dir[index];

	if (dindex & (1U << 31)) {
		u32 fib_idx = dindex & ((1U << 31) - 1);
		return fib_idx ? s->fib[fib_idx].value : NULL;
	}

	offset = s->s;
	while (offset < KEYLENGTH) {
		const struct poptrie_node *pn = &s->nodes[dindex];
		u32 rem     = min(k, (u32)(KEYLENGTH - offset));
		u32 pad_    = k - rem;
		u32 chunk_r = extract32(addr, offset, rem);
		u32 chunk   = chunk_r << pad_;
		u64 bit     = 1ULL << chunk;

		if (pn->vector & bit) {
			u64 m    = low_mask64(chunk + 1);
			u32 rank = hweight64(pn->vector & m) - 1;
			dindex   = pn->base1 + rank;
			offset  += rem;
		} else {
			u64 m       = low_mask64(chunk + 1);
			u32 rank    = hweight64(pn->leafvec & m) - 1;
			u32 fib_idx = s->leaves[pn->base0 + rank];
			return fib_idx ? s->fib[fib_idx].value : NULL;
		}
	}
	return NULL;
}

/* -------------------------------------------------------------------------
 * BPF map constants
 * ------------------------------------------------------------------------- */

#define LPM_DATA_SIZE_MAX	256
#define LPM_DATA_SIZE_MIN	1
#define LPM_VAL_SIZE_MAX	(KMALLOC_MAX_SIZE - LPM_DATA_SIZE_MAX - \
				 sizeof(struct poptrie_route))
#define LPM_VAL_SIZE_MIN	1
#define LPM_KEY_SIZE(X)		(sizeof(struct bpf_lpm_trie_key_u8) + (X))
#define LPM_KEY_SIZE_MAX	LPM_KEY_SIZE(LPM_DATA_SIZE_MAX)
#define LPM_KEY_SIZE_MIN	LPM_KEY_SIZE(LPM_DATA_SIZE_MIN)
#define LPM_CREATE_FLAG_MASK	(BPF_F_NO_PREALLOC | BPF_F_NUMA_NODE | \
				 BPF_F_ACCESS_MASK)

/* -------------------------------------------------------------------------
 * BPF map ops
 * ------------------------------------------------------------------------- */

static void *trie_lookup_elem(struct bpf_map *map, void *_key)
{
	struct lpm_trie *trie = container_of(map, struct lpm_trie, map);
	struct bpf_lpm_trie_key_u8 *key = _key;
	struct poptrie_snapshot *s;
	void *ret;

	if (unlikely(key->prefixlen == POPTRIE_BULK_SENTINEL ||
		     key->prefixlen == POPTRIE_COMMIT_SENTINEL))
		return NULL;

	rcu_read_lock();
	/* Safely fetch the current snapshot pointer */
	s = rcu_dereference(trie->snap);
	if (unlikely(!s)) {
		rcu_read_unlock();
		return NULL;
	}

	/* Perform the actual trie traversal */
	ret = poptrie_lookup(s, be32_to_cpu(*(__be32 *)key->data));
	rcu_read_unlock();

	return ret;
}

static long trie_update_elem(struct bpf_map *map,
			     void *_key, void *value, u64 flags)
{
	struct lpm_trie *trie = container_of(map, struct lpm_trie, map);
	struct bpf_lpm_trie_key_u8 *key = _key;
	struct poptrie_route *r, *nr = NULL;
	void *v = NULL;
	u32 addr, plen, mask;
	int ret = 0;

	if (unlikely(flags > BPF_EXIST))
		return -EINVAL;

	plen = key->prefixlen;

	if (plen == POPTRIE_BULK_SENTINEL) {
		mutex_lock(&trie->update_mutex);
		trie->bulk_loading = true;
		mutex_unlock(&trie->update_mutex);
		return 0;
	}
	if (plen == POPTRIE_COMMIT_SENTINEL) {
		mutex_lock(&trie->update_mutex);
		trie->bulk_loading = false;
		ret = poptrie_rebuild(trie);
		mutex_unlock(&trie->update_mutex);
		return ret;
	}

	if (plen > trie->max_prefixlen)
		return -EINVAL;

	addr = be32_to_cpu(*(__be32 *)key->data);
	mask = (plen == 0) ? 0u : (~0U << (32 - plen));
	addr &= mask;

	mutex_lock(&trie->update_mutex);

	r = route_find(trie, addr, plen);
	if (flags == BPF_NOEXIST && r)  { ret = -EEXIST;  goto out; }
	if (flags == BPF_EXIST   && !r) { ret = -ENOENT;  goto out; }

	v = bpf_map_kmalloc_node(map, map->value_size,
				 GFP_KERNEL | __GFP_NOWARN, map->numa_node);
	if (!v) { ret = -ENOMEM; goto out; }
	memcpy(v, value, map->value_size);

	if (r) {
		/*
		 * FIX #4: The original code called synchronize_rcu() then
		 * kfree(r->value) here, BEFORE installing the new snapshot.
		 * That created a window where new XDP readers could arrive on
		 * the still-live snapshot and dereference the freed pointer.
		 *
		 * Correct ordering:
		 *   1. Install new value into the RIB node.
		 *   2. Call poptrie_rebuild(), which atomically swaps in a new
		 *      snapshot and then calls synchronize_rcu() — so when it
		 *      returns, no reader can still see the old fib[].value.
		 *   3. Only then free old_val.
		 *
		 * In bulk mode there is no rebuild, so an explicit
		 * synchronize_rcu() is still needed before the free.
		 */
		void *old_val = r->value;
		r->value = v;
		v = NULL;
		if (!trie->bulk_loading) {
			ret = poptrie_rebuild(trie);
			/* synchronize_rcu() was called inside poptrie_rebuild() */
		} else {
			synchronize_rcu();
		}
		kfree(old_val);
	} else {
		if (trie->n_entries == map->max_entries) { ret = -ENOSPC; goto out; }
		nr = kzalloc(sizeof(*nr), GFP_KERNEL | __GFP_NOWARN);
		if (!nr) { ret = -ENOMEM; goto out; }
		nr->addr = addr; nr->prefixlen = plen; nr->value = v; v = NULL;
		ret = route_insert(trie, nr);
		if (ret) { kfree(nr->value); kfree(nr); nr = NULL; goto out; }
		trie->n_entries++;
		nr = NULL;

		if (!trie->bulk_loading)
			ret = poptrie_rebuild(trie);
	}

out:
	mutex_unlock(&trie->update_mutex);
	kfree(v);
	kfree(nr);
	return ret;
}

static long trie_delete_elem(struct bpf_map *map, void *_key)
{
	struct lpm_trie *trie = container_of(map, struct lpm_trie, map);
	struct bpf_lpm_trie_key_u8 *key = _key;
	struct poptrie_route *r;
	u32 addr, plen, mask;
	int ret = 0;

	plen = key->prefixlen;
	if (plen == POPTRIE_BULK_SENTINEL || plen == POPTRIE_COMMIT_SENTINEL)
		return -ENOENT;
	if (plen > trie->max_prefixlen)
		return -EINVAL;

	addr = be32_to_cpu(*(__be32 *)key->data);
	mask = (plen == 0) ? 0u : (~0U << (32 - plen));
	addr &= mask;

	mutex_lock(&trie->update_mutex);
	r = route_find(trie, addr, plen);
	if (!r) { ret = -ENOENT; goto out; }

	rb_erase(&r->rb, &trie->routes);
	trie->n_entries--;

	/*
	 * FIX #5: Same use-after-free as FIX #4.  The original freed r->value
	 * before installing the new snapshot, so live XDP readers on the old
	 * snapshot could dereference freed memory.
	 *
	 * Now: rebuild first (which swaps + synchronize_rcu() internally),
	 * or synchronize_rcu() explicitly in bulk mode, then free.
	 */
	if (!trie->bulk_loading)
		ret = poptrie_rebuild(trie);
	else
		synchronize_rcu();

	kfree(r->value);
	kfree(r);

out:
	mutex_unlock(&trie->update_mutex);
	return ret;
}

static int trie_get_next_key(struct bpf_map *map, void *_key, void *_next_key)
{
	struct lpm_trie *trie = container_of(map, struct lpm_trie, map);
	struct bpf_lpm_trie_key_u8 *key      = _key;
	struct bpf_lpm_trie_key_u8 *next_key = _next_key;
	struct rb_node *n;
	struct poptrie_route *r;
	u32 addr, plen, mask;
	int ret = 0;

	mutex_lock(&trie->update_mutex);
	n = rb_first(&trie->routes);
	if (!n) { ret = -ENOENT; goto out; }

	if (!key || key->prefixlen > trie->max_prefixlen) {
		r = rb_entry(n, struct poptrie_route, rb);
		goto found;
	}

	plen = key->prefixlen;
	addr = be32_to_cpu(*(__be32 *)key->data);
	mask = (plen == 0) ? 0u : (~0U << (32 - plen));
	addr &= mask;

	r = route_find(trie, addr, plen);
	if (r) {
		n = rb_next(&r->rb);
		if (!n) { ret = -ENOENT; goto out; }
		r = rb_entry(n, struct poptrie_route, rb);
		goto found;
	}

	{
		struct rb_node *cur = trie->routes.rb_node;
		struct poptrie_route *succ = NULL;
		while (cur) {
			struct poptrie_route *cr =
				rb_entry(cur, struct poptrie_route, rb);
			int c = route_cmp(addr, plen, cr->addr, cr->prefixlen);
			if (c < 0) { succ = cr; cur = cur->rb_left; }
			else        {           cur = cur->rb_right; }
		}
		if (!succ) { ret = -ENOENT; goto out; }
		r = succ;
	}

found:
	next_key->prefixlen       = r->prefixlen;
	*(__be32 *)next_key->data = cpu_to_be32(r->addr);
out:
	mutex_unlock(&trie->update_mutex);
	return ret;
}

static int trie_check_btf(const struct bpf_map *map, const struct btf *btf,
			  const struct btf_type *key_type,
			  const struct btf_type *value_type)
{
	return BTF_INFO_KIND(key_type->info) != BTF_KIND_STRUCT ? -EINVAL : 0;
}

static struct bpf_map *trie_alloc(union bpf_attr *attr)
{
	struct lpm_trie *trie;
	struct poptrie_snapshot *s;

	if (attr->max_entries == 0 || !(attr->map_flags & BPF_F_NO_PREALLOC) ||
	    attr->key_size != LPM_KEY_SIZE(4) || attr->value_size < 1)
		return ERR_PTR(-EINVAL);

	trie = bpf_map_area_alloc(sizeof(*trie), NUMA_NO_NODE);
	if (!trie) return ERR_PTR(-ENOMEM);

	bpf_map_init_from_attr(&trie->map, attr);
	mutex_init(&trie->update_mutex);

	trie->data_size     = 4;
	trie->max_prefixlen = 32;
	trie->routes        = RB_ROOT;

	/* Allocate initial (empty) snapshot */
	s = kvzalloc(sizeof(*s), GFP_KERNEL);
	if (!s) { bpf_map_area_free(trie); return ERR_PTR(-ENOMEM); }

	s->k      = POPTRIE_K;
	s->s      = POPTRIE_S;
	s->dir_sz = (POPTRIE_S == 0) ? 1U : (1U << POPTRIE_S);

	if (ensure_fib(s, 1)) { kvfree(s); bpf_map_area_free(trie); return ERR_PTR(-ENOMEM); }
	s->fib_used = 1;

	RCU_INIT_POINTER(trie->snap, s);
	return &trie->map;
}

static void trie_free(struct bpf_map *map)
{
	struct lpm_trie *trie = container_of(map, struct lpm_trie, map);
	struct rb_node *n, *next;
	struct poptrie_snapshot *s;

	for (n = rb_first(&trie->routes); n; n = next) {
		struct poptrie_route *r = rb_entry(n, struct poptrie_route, rb);
		next = rb_next(n);
		rb_erase(n, &trie->routes);
		kfree(r->value);
		kfree(r);
	}

	s = rcu_dereference_raw(trie->snap);
	if (s) {
		snapshot_free_arrays(s);
		kvfree(s);
	}
	bpf_map_area_free(trie);
}

static u64 trie_mem_usage(const struct bpf_map *map)
{
	struct lpm_trie *trie = container_of(map, struct lpm_trie, map);
	/*
	 * FIX #1: trie->snap is `struct poptrie_snapshot __rcu *`, a pointer.
	 * The original code accessed trie->snap.nodes etc. with '.' instead of
	 * '->', which does not compile.  Use rcu_dereference_raw() (safe outside
	 * of RCU read-side critical sections, appropriate for a stats/accounting
	 * function) and then access members via '->'.
	 *
	 * We use the explicit _cap fields (FIX #6) rather than ksize() because
	 * ksize() is unreliable for vmalloc-backed memory.
	 */
	struct poptrie_snapshot *s;
	u64 usage = (u64)READ_ONCE(trie->n_entries) *
		    (sizeof(struct poptrie_route) + trie->map.value_size);

	s = rcu_dereference_raw(trie->snap);
	if (s) {
		usage += (u64)s->nodes_cap  * sizeof(struct poptrie_node);
		usage += (u64)s->leaves_cap * sizeof(poptrie_leaf_t);
		usage += (u64)s->dir_sz     * sizeof(u32);
		usage += (u64)s->fib_cap    * sizeof(struct poptrie_fib_entry);
	}
	return usage;
}

BTF_ID_LIST_SINGLE(trie_map_btf_ids, struct, lpm_trie)
const struct bpf_map_ops trie_map_ops = {
	.map_meta_equal    = bpf_map_meta_equal,
	.map_alloc         = trie_alloc,
	.map_free          = trie_free,
	.map_get_next_key  = trie_get_next_key,
	.map_lookup_elem   = trie_lookup_elem,
	.map_update_elem   = trie_update_elem,
	.map_delete_elem   = trie_delete_elem,
	.map_lookup_batch  = generic_map_lookup_batch,
	.map_update_batch  = generic_map_update_batch,
	.map_delete_batch  = generic_map_delete_batch,
	.map_check_btf     = trie_check_btf,
	.map_mem_usage     = trie_mem_usage,
	.map_btf_id        = &trie_map_btf_ids[0],
};
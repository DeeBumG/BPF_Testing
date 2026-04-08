// SPDX-License-Identifier: GPL-2.0-only
/*
 * Poptrie-backed BPF LPM trie (BPF_MAP_TYPE_LPM_TRIE) — IPv4 only
 *
 * Drop-in replacement for lpm_trie.c.  All external ABI is preserved.
 *
 * Algorithm follows Hirochika Asai's reference poptrie implementation
 * (https://github.com/pixos/poptrie).
 *
 * Control plane — a binary radix tree (RIB).  Each node carries an `ext`
 * pointer to the nearest valid ancestor so the effective next-hop for any
 * address is always immediately available without traversing ancestors.
 *
 * Data plane — a poptrie snapshot rebuilt on every insert/delete and
 * swapped in atomically under RCU:
 *
 *   dir[]   : 2^POPTRIE_S direct-pointing entries.
 *             Bit 31 set   → leaf; low 31 bits = fib index (0 = no route).
 *             Bit 31 clear → index of an internal node in nodes[].
 *   nodes[] : poptrie internal nodes (leafvec, vector, base0, base1).
 *   leaves[]: packed array of fib indices for leaf slots.
 *   fib[]   : maps fib index → caller value pointer (index 0 = no route).
 *
 * Node invariant for popcnt-rank lookup:
 *   For each internal node N, its direct internal children must occupy a
 *   contiguous block in nodes[] starting at N.base1.  Similarly, its leaf
 *   children must occupy a contiguous block in leaves[] starting at N.base0.
 *   Both are satisfied by the pre-order builder: for each node we first
 *   reserve contiguous blocks for its children, fill them, then recurse
 *   into each child to build its own subtree.
 *
 * Lookup mirrors Asai's poptrie_lookup() (poptrie4.c) exactly, including
 * the advancing `pos` variable that tracks which 6-bit window of the
 * address is read at each level.
 */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/err.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <uapi/linux/btf.h>

/* -------------------------------------------------------------------------
 * Tunables — Asai's defaults
 * ------------------------------------------------------------------------- */

#define POPTRIE_S	18
#define POPTRIE_K	6
#define KEYLENGTH	32

#define DIR_LEAF_BIT	((u32)1 << 31)

/*
 * Extract n bits of `a` starting at MSB-first bit offset s.
 * Matches Asai's INDEX macro exactly.
 *
 * Note: `a` is placed in the high 32 bits of a u64, so valid offsets are
 * s+n <= 32.  The last poptrie level reaches s=30, n=6 → s+n=36 which
 * would read garbage; that case never arises because depth+K > KEYLENGTH
 * causes those slots to be classified as leaves before INDEX is called.
 */
#define INDEX(a, s, n) \
	(((u64)(a) << 32 >> (64 - ((s) + (n)))) & ((1U << (n)) - 1U))

/* Test bit at MSB-first offset b of addr (b=0 is the highest bit). */
#define BT(addr, b)	(!!((addr) & (1U << (KEYLENGTH - 1 - (b)))))

/* -------------------------------------------------------------------------
 * Poptrie structures — from Asai's poptrie.h
 * ------------------------------------------------------------------------- */

struct poptrie_node {
	u64 leafvec;	/* Asai: leafvec first */
	u64 vector;
	u32 base0;	/* first index in leaves[] for this node's leaf slots */
	u32 base1;	/* first index in nodes[]  for this node's internal slots */
};

typedef u32 poptrie_leaf_t;

struct poptrie_fib_entry {
	void *value;
};

struct poptrie_snapshot {
	u32			 *dir;
	struct poptrie_node	 *nodes;
	poptrie_leaf_t		 *leaves;
	struct poptrie_fib_entry *fib;
	u32 nodes_used,  nodes_cap;
	u32 leaves_used, leaves_cap;
	u32 fib_used;
};

/* -------------------------------------------------------------------------
 * Radix tree (RIB) — Asai's struct radix_node
 * ------------------------------------------------------------------------- */

struct radix_node {
	int valid;
	struct radix_node *left;
	struct radix_node *right;
	void *value;		/* caller-supplied value (owned here)     */
	u32   fib_idx;		/* assigned during rebuild; 0 = no route  */
	struct radix_node *ext;	/* nearest valid ancestor, or NULL        */
};

/* -------------------------------------------------------------------------
 * Map wrapper
 * ------------------------------------------------------------------------- */

struct lpm_trie {
	struct bpf_map map;
	struct mutex   update_mutex;
	size_t         n_entries;
	struct radix_node *radix;
	struct poptrie_snapshot __rcu *snap;
};

/* -------------------------------------------------------------------------
 * Snapshot growth helpers
 * ------------------------------------------------------------------------- */

static int snap_grow_nodes(struct poptrie_snapshot *s)
{
	u32 nc = s->nodes_cap ? s->nodes_cap * 2 : 256;
	struct poptrie_node *p = kvrealloc(s->nodes, nc * sizeof(*p),
					   GFP_KERNEL | __GFP_NOWARN);
	if (!p)
		return -ENOMEM;
	memset(p + s->nodes_cap, 0, (nc - s->nodes_cap) * sizeof(*p));
	s->nodes     = p;
	s->nodes_cap = nc;
	return 0;
}

static int snap_grow_leaves(struct poptrie_snapshot *s)
{
	u32 nc = s->leaves_cap ? s->leaves_cap * 2 : 256;
	poptrie_leaf_t *p = kvrealloc(s->leaves, nc * sizeof(*p),
				      GFP_KERNEL | __GFP_NOWARN);
	if (!p)
		return -ENOMEM;
	memset(p + s->leaves_cap, 0, (nc - s->leaves_cap) * sizeof(*p));
	s->leaves     = p;
	s->leaves_cap = nc;
	return 0;
}

static void snap_free(struct poptrie_snapshot *s)
{
	if (!s)
		return;
	kvfree(s->dir);
	kvfree(s->nodes);
	kvfree(s->leaves);
	kvfree(s->fib);
	kvfree(s);
}

/* -------------------------------------------------------------------------
 * Radix tree helpers — Asai's _route_add / _route_del logic
 * ------------------------------------------------------------------------- */

/*
 * Propagate correct ext pointers through the subtree rooted at n.
 * Called after inserting or deleting a valid node.
 */
static void radix_set_ext(struct radix_node *n, struct radix_node *ext)
{
	if (!n)
		return;
	n->ext = ext;
	if (n->valid)
		ext = n;
	radix_set_ext(n->left,  ext);
	radix_set_ext(n->right, ext);
}

/* Insert prefix/plen.  val is consumed (owned by node) on success. */
static int radix_insert(struct radix_node **pp, u32 prefix, int plen,
			void *val, int depth, struct radix_node *ext)
{
	struct radix_node *n = *pp;

	if (!n) {
		n = kzalloc(sizeof(*n), GFP_KERNEL);
		if (!n)
			return -ENOMEM;
		n->ext = ext;
		*pp = n;
	}
	if (depth == plen) {
		if (n->valid)
			return -EEXIST;
		n->valid = 1;
		n->value = val;
		radix_set_ext(n, n->ext);
		return 0;
	}
	if (n->valid)
		ext = n;
	if (BT(prefix, depth))
		return radix_insert(&n->right, prefix, plen, val,
				    depth + 1, ext);
	else
		return radix_insert(&n->left, prefix, plen, val,
				    depth + 1, ext);
}

/* Delete prefix/plen.  Returns old value in *oval for deferred free. */
static int radix_delete(struct radix_node **pp, u32 prefix, int plen,
			int depth, struct radix_node *ext, void **oval)
{
	struct radix_node *n = *pp;
	int ret;

	if (!n)
		return -ENOENT;
	if (depth == plen) {
		if (!n->valid)
			return -ENOENT;
		*oval    = n->value;
		n->valid = 0;
		n->value = NULL;
		radix_set_ext(n, n->ext);
		if (!n->left && !n->right) {
			kfree(n);
			*pp = NULL;
		}
		return 0;
	}
	if (n->valid)
		ext = n;
	if (BT(prefix, depth))
		ret = radix_delete(&n->right, prefix, plen,
				   depth + 1, ext, oval);
	else
		ret = radix_delete(&n->left, prefix, plen,
				   depth + 1, ext, oval);
	if (ret)
		return ret;
	if (!n->valid && !n->left && !n->right) {
		kfree(n);
		*pp = NULL;
	}
	return 0;
}

static void radix_free(struct radix_node *n)
{
	if (!n)
		return;
	radix_free(n->left);
	radix_free(n->right);
	kfree(n->value);
	kfree(n);
}

/* True if rnode has any children (i.e. routes exist below its depth). */
static bool radix_has_children(const struct radix_node *n)
{
	return n && (n->left || n->right);
}

/* Effective fib index: this node's own if valid, else nearest ancestor. */
static inline u32 eff_fib(const struct radix_node *n,
			  const struct radix_node *ext)
{
	if (n && n->valid)
		return n->fib_idx;
	return ext ? ext->fib_idx : 0;
}

/* -------------------------------------------------------------------------
 * FIB index assignment — walk the radix tree, number each valid node.
 * fib[] must be allocated with at least n_entries+1 slots.
 * ------------------------------------------------------------------------- */

static void assign_fib(struct poptrie_snapshot *s, struct radix_node *n)
{
	if (!n)
		return;
	if (n->valid) {
		n->fib_idx = s->fib_used;
		s->fib[s->fib_used].value = n->value;
		s->fib_used++;
	} else {
		n->fib_idx = 0;
	}
	assign_fib(s, n->left);
	assign_fib(s, n->right);
}

/* -------------------------------------------------------------------------
 * Radix descent helper
 *
 * Descend the radix tree by exactly POPTRIE_K steps following the bits of
 * `slot` MSB-first (bit POPTRIE_K-1 of slot = first step), updating
 * *ext_io along the way.  Returns the node reached (may be NULL if the
 * tree ends before K steps are exhausted — this is normal for prefixes
 * shorter than the current depth).
 * ------------------------------------------------------------------------- */

static struct radix_node *
radix_step_k(struct radix_node *n, u32 slot,
	     const struct radix_node **ext_io)
{
	int i;

	for (i = POPTRIE_K - 1; i >= 0; i--) {
		if (!n)
			break;
		if (n->valid)
			*ext_io = n;
		if (slot & (1U << i))
			n = n->right;
		else
			n = n->left;
	}
	return n;
}

/* -------------------------------------------------------------------------
 * Poptrie node builder — pre-order, contiguous-block allocation.
 *
 * For each internal node we:
 *   1. Descend each of the 2^POPTRIE_K slots once, classify as internal or
 *      leaf, and cache the result (child node pointer + effective ext).
 *   2. Reserve a contiguous block of `node_cnt` entries in nodes[] for the
 *      internal children and a contiguous block of `leaf_cnt` entries in
 *      leaves[] for the leaf children.  This satisfies the popcnt-rank
 *      invariant before any recursion happens.
 *   3. Fill the leaf block immediately (leaf values are known now).
 *   4. Write this node into nodes[] at the freshly allocated index.
 *   5. Recurse into each internal child, passing the index already reserved
 *      for it.
 *
 * Caching the per-slot descent results in step 1 means the radix tree is
 * walked only once per node — no redundant second pass.
 * ------------------------------------------------------------------------- */

static int build_subtree_at(struct poptrie_snapshot *s,
			    struct radix_node *rnode, int depth,
			    const struct radix_node *ext, u32 my_idx);

static int build_subtree_at(struct poptrie_snapshot *s,
			    struct radix_node *rnode, int depth,
			    const struct radix_node *ext, u32 my_idx)
{
	const int fanout = 1 << POPTRIE_K;
	u64 vector = 0, leafvec = 0;

	/* Cached per-slot classification results (avoids a second descent). */
	struct radix_node      *slot_node[64];
	const struct radix_node *slot_ext[64];
	bool is_int[64];
	u32  leaf_fib[64];

	int  slot, err;
	int  node_cnt = 0, leaf_cnt = 0;
	u32  base0, base1;
	u32  child_base;

	/* Pass 1: descend each slot once, classify, cache results. */
	for (slot = 0; slot < fanout; slot++) {
		const struct radix_node *cext = ext;
		struct radix_node *cn;

		cn = radix_step_k(rnode, (u32)slot, &cext);
		if (cn && cn->valid)
			cext = cn;

		slot_node[slot] = cn;
		slot_ext[slot]  = cext;

		if (depth + POPTRIE_K < KEYLENGTH && radix_has_children(cn)) {
			is_int[slot] = true;
			vector |= (1ULL << slot);
			node_cnt++;
		} else {
			is_int[slot]   = false;
			leaf_fib[slot] = eff_fib(cn, cext);
			leafvec |= (1ULL << slot);
			leaf_cnt++;
		}
	}

	/*
	 * Reserve a contiguous block for internal children NOW, before any
	 * recursion, so base1 is valid before we descend into any child.
	 */
	if (node_cnt > 0) {
		while (s->nodes_used + node_cnt > s->nodes_cap) {
			err = snap_grow_nodes(s);
			if (err)
				return err;
		}
		child_base = s->nodes_used;
		s->nodes_used += node_cnt;
		base1 = child_base;
	} else {
		child_base = 0;
		base1 = 0;
	}

	/* Reserve and fill the leaf block. */
	while (s->leaves_used + leaf_cnt > s->leaves_cap) {
		err = snap_grow_leaves(s);
		if (err)
			return err;
	}
	base0 = s->leaves_used;
	s->leaves_used += leaf_cnt;

	{
		int li = 0;

		for (slot = 0; slot < fanout; slot++) {
			if (!is_int[slot])
				s->leaves[base0 + li++] = leaf_fib[slot];
		}
	}

	/* Write this node at its pre-assigned index. */
	s->nodes[my_idx].leafvec = leafvec;
	s->nodes[my_idx].vector  = vector;
	s->nodes[my_idx].base0   = base0;
	s->nodes[my_idx].base1   = base1;

	/*
	 * Pass 2: recurse into internal children using cached slot results.
	 * Each child is placed at the index already reserved for it.
	 */
	if (node_cnt > 0) {
		int ni = 0;

		for (slot = 0; slot < fanout; slot++) {
			if (!is_int[slot])
				continue;

			err = build_subtree_at(s, slot_node[slot],
					       depth + POPTRIE_K,
					       slot_ext[slot],
					       child_base + ni);
			if (err)
				return err;
			ni++;
		}
	}

	return 0;
}

/* -------------------------------------------------------------------------
 * poptrie_rebuild — full rebuild from radix tree
 * ------------------------------------------------------------------------- */

static int poptrie_rebuild(struct lpm_trie *trie)
{
	struct poptrie_snapshot *s, *old;
	u32 n = (u32)trie->n_entries;
	u32 i;
	int err = 0;

	s = kvzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;

	s->dir = kvmalloc_array(1U << POPTRIE_S, sizeof(u32),
				GFP_KERNEL | __GFP_NOWARN);
	if (!s->dir) {
		err = -ENOMEM;
		goto err;
	}
	for (i = 0; i < (1U << POPTRIE_S); i++)
		s->dir[i] = DIR_LEAF_BIT;	/* default: no route (fib 0) */

	if (n == 0)
		goto install;

	s->fib = kvzalloc((n + 1) * sizeof(*s->fib), GFP_KERNEL);
	if (!s->fib) {
		err = -ENOMEM;
		goto err;
	}
	s->fib_used = 1;	/* index 0 reserved for "no route" */

	assign_fib(s, trie->radix);

	err = snap_grow_nodes(s);
	if (err)
		goto err;
	err = snap_grow_leaves(s);
	if (err)
		goto err;

	for (i = 0; i < (1U << POPTRIE_S); i++) {
		struct radix_node *rnode = trie->radix;
		const struct radix_node *ext = NULL;
		int d;

		/* Descend to depth POPTRIE_S following bucket i's bits. */
		for (d = 0; d < POPTRIE_S && rnode; d++) {
			if (rnode->valid)
				ext = rnode;
			if (i & (1U << (POPTRIE_S - 1 - d)))
				rnode = rnode->right;
			else
				rnode = rnode->left;
		}
		if (rnode && rnode->valid)
			ext = rnode;

		if (radix_has_children(rnode)) {
			u32 node_idx;

			/* Reserve a slot for this subtree root. */
			while (s->nodes_used >= s->nodes_cap) {
				err = snap_grow_nodes(s);
				if (err)
					goto err;
			}
			node_idx = s->nodes_used++;

			err = build_subtree_at(s, rnode, POPTRIE_S, ext,
					       node_idx);
			if (err)
				goto err;

			s->dir[i] = node_idx; /* MSB clear → internal node */
		} else {
			s->dir[i] = DIR_LEAF_BIT | eff_fib(rnode, ext);
		}
	}

install:
	old = rcu_dereference_protected(trie->snap,
				lockdep_is_held(&trie->update_mutex));
	rcu_assign_pointer(trie->snap, s);
	synchronize_rcu();
	snap_free(old);
	return 0;

err:
	snap_free(s);
	return err;
}

/* -------------------------------------------------------------------------
 * Poptrie lookup — Asai's poptrie_lookup() (poptrie4.c), ported verbatim.
 *
 * Key fidelity point: `pos` advances by POPTRIE_K on every level so that
 * successive INDEX() calls read successive non-overlapping windows of the
 * address.
 * ------------------------------------------------------------------------- */

static void *poptrie_lookup(const struct poptrie_snapshot *s, u32 addr)
{
	u32 dir_entry = s->dir[INDEX(addr, 0, POPTRIE_S)];
	u32 base;
	u32 idx;
	int pos;

	/* Direct-pointing tier */
	if (dir_entry & DIR_LEAF_BIT) {
		u32 fi = dir_entry & ~DIR_LEAF_BIT;

		return fi ? s->fib[fi].value : NULL;
	}

	base = dir_entry;
	idx  = INDEX(addr, POPTRIE_S, POPTRIE_K);
	pos  = POPTRIE_S + POPTRIE_K;

	/* Internal node traversal — mirrors Asai's loop exactly. */
	for (;;) {
		const struct poptrie_node *pn = &s->nodes[base];

		if (pn->vector & (1ULL << idx)) {
			/* Internal child: rank into vector, advance pos. */
			u64 mask = (2ULL << idx) - 1;
			u32 rank = hweight64(pn->vector & mask);

			base = pn->base1 + (rank - 1);
			idx  = INDEX(addr, pos, POPTRIE_K);
			pos += POPTRIE_K;
		} else {
			/* Leaf child: rank into leafvec, return fib entry. */
			u64 mask = (2ULL << idx) - 1;
			u32 rank = hweight64(pn->leafvec & mask);
			u32 fi   = s->leaves[pn->base0 + (rank - 1)];

			return fi ? s->fib[fi].value : NULL;
		}
	}
}

/* -------------------------------------------------------------------------
 * BPF map constants — identical to lpm_trie.c
 * ------------------------------------------------------------------------- */

#define LPM_DATA_SIZE_MAX	256
#define LPM_DATA_SIZE_MIN	1
#define LPM_VAL_SIZE_MAX	(KMALLOC_MAX_SIZE - LPM_DATA_SIZE_MAX - \
				 sizeof(struct radix_node))
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

	if (key->prefixlen > 32)
		return NULL;

	rcu_read_lock();
	s = rcu_dereference(trie->snap);
	if (unlikely(!s)) {
		rcu_read_unlock();
		return NULL;
	}
	ret = poptrie_lookup(s, be32_to_cpu(*(__be32 *)key->data));
	rcu_read_unlock();
	return ret;
}

static long trie_update_elem(struct bpf_map *map,
			     void *_key, void *value, u64 flags)
{
	struct lpm_trie *trie = container_of(map, struct lpm_trie, map);
	struct bpf_lpm_trie_key_u8 *key = _key;
	u32 addr, plen, mask;
	void *val, *old_val = NULL;
	int ret;

	if (unlikely(flags > BPF_EXIST))
		return -EINVAL;
	if (key->prefixlen > 32)
		return -EINVAL;

	plen = key->prefixlen;
	addr = be32_to_cpu(*(__be32 *)key->data);
	mask = plen ? (~0U << (32 - plen)) : 0u;
	addr &= mask;

	val = bpf_map_kmalloc_node(map, map->value_size,
				   GFP_KERNEL | __GFP_NOWARN, map->numa_node);
	if (!val)
		return -ENOMEM;
	memcpy(val, value, map->value_size);

	mutex_lock(&trie->update_mutex);

	if (flags == BPF_EXIST) {
		/* Replace: entry must already exist */
		ret = radix_delete(&trie->radix, addr, (int)plen,
				   0, NULL, &old_val);
		if (ret)
			goto out_free_val;
		ret = radix_insert(&trie->radix, addr, (int)plen, val,
				   0, NULL);
		if (unlikely(ret))
			goto out_free_val;
		/* n_entries unchanged */
	} else {
		ret = radix_insert(&trie->radix, addr, (int)plen, val,
				   0, NULL);
		if (ret == -EEXIST && flags == BPF_ANY) {
			ret = radix_delete(&trie->radix, addr, (int)plen,
					   0, NULL, &old_val);
			if (ret)
				goto out_free_val;
			ret = radix_insert(&trie->radix, addr, (int)plen,
					   val, 0, NULL);
			if (unlikely(ret))
				goto out_free_val;
			/* n_entries unchanged: deleted then re-inserted */
		} else if (ret == -EEXIST) {
			/* BPF_NOEXIST and already exists */
			goto out_free_val;
		} else if (ret) {
			goto out_free_val;
		} else {
			if (trie->n_entries == map->max_entries) {
				/* Undo insert */
				radix_delete(&trie->radix, addr, (int)plen,
					     0, NULL, &val);
				ret = -ENOSPC;
				goto out_free_val;
			}
			trie->n_entries++;
		}
	}

	ret = poptrie_rebuild(trie);
	/* synchronize_rcu() ran inside rebuild; safe to free old value now. */
	kfree(old_val);
	old_val = NULL;
	goto out;

out_free_val:
	kfree(val);
out:
	mutex_unlock(&trie->update_mutex);
	kfree(old_val);
	return ret;
}

static long trie_delete_elem(struct bpf_map *map, void *_key)
{
	struct lpm_trie *trie = container_of(map, struct lpm_trie, map);
	struct bpf_lpm_trie_key_u8 *key = _key;
	u32 addr, plen, mask;
	void *old_val = NULL;
	int ret;

	if (key->prefixlen > 32)
		return -EINVAL;

	plen = key->prefixlen;
	addr = be32_to_cpu(*(__be32 *)key->data);
	mask = plen ? (~0U << (32 - plen)) : 0u;
	addr &= mask;

	mutex_lock(&trie->update_mutex);

	ret = radix_delete(&trie->radix, addr, (int)plen, 0, NULL, &old_val);
	if (ret)
		goto out;

	trie->n_entries--;
	ret = poptrie_rebuild(trie);
	kfree(old_val);
	old_val = NULL;

out:
	mutex_unlock(&trie->update_mutex);
	kfree(old_val);
	return ret;
}

/*
 * trie_get_next_key — postorder iteration (more-specific first).
 *
 * Iterative postorder DFS with an explicit stack.  Bit 31 of `depth` is
 * used as a "visited" marker: on first pop we push self (marked) then
 * children; on second pop (bit 31 set) we process the node itself.
 * Children are visited before parents, giving more-specific before
 * less-specific order.
 *
 * Stack sizing: at any point the stack holds at most one frame per level
 * of depth (32 levels) plus up to two child frames pushed but not yet
 * popped for the current node, giving a safe upper bound of 3*32 = 96.
 * Use 128 for a comfortable power-of-two margin.
 */

#define DFS_VISITED	0x80000000u
#define DFS_STACK_SIZE	128

struct dfs_frame {
	struct radix_node *node;
	u32 depth;
	u32 prefix;
};

static int trie_get_next_key(struct bpf_map *map, void *_key, void *_next_key)
{
	struct lpm_trie *trie = container_of(map, struct lpm_trie, map);
	struct bpf_lpm_trie_key_u8 *key      = _key;
	struct bpf_lpm_trie_key_u8 *next_key = _next_key;
	struct dfs_frame stack[DFS_STACK_SIZE];
	int sp = 0;
	bool null_key, found = false;
	u32  taddr = 0, tplen = 0;
	int  ret = -ENOENT;

	mutex_lock(&trie->update_mutex);

	if (!trie->radix)
		goto out;

	null_key = (!key || key->prefixlen > 32);
	if (!null_key) {
		tplen = key->prefixlen;
		taddr = be32_to_cpu(*(__be32 *)key->data);
		if (tplen)
			taddr &= ~0U << (32 - tplen);
	}

	stack[sp++] = (struct dfs_frame){ trie->radix, 0, 0 };

	while (sp > 0) {
		struct dfs_frame f = stack[--sp];
		struct radix_node *n = f.node;
		u32 d = f.depth, pre = f.prefix;

		if (!n)
			continue;

		if (!(d & DFS_VISITED)) {
			/* First visit: push self (marked), then children. */
			stack[sp++] = (struct dfs_frame){ n, d | DFS_VISITED, pre };
			if (n->right && sp < DFS_STACK_SIZE)
				stack[sp++] = (struct dfs_frame){
					n->right, d + 1,
					pre | (1U << (KEYLENGTH - d - 1)) };
			if (n->left && sp < DFS_STACK_SIZE)
				stack[sp++] = (struct dfs_frame){
					n->left, d + 1, pre };
		} else {
			d &= ~DFS_VISITED;
			if (!n->valid)
				continue;
			if (null_key || found) {
				next_key->prefixlen       = d;
				*(__be32 *)next_key->data = cpu_to_be32(pre);
				ret = 0;
				goto out;
			}
			if (d == tplen && pre == taddr)
				found = true;
		}
	}

out:
	mutex_unlock(&trie->update_mutex);
	return ret;
}

static int trie_check_btf(const struct bpf_map *map,
			  const struct btf *btf,
			  const struct btf_type *key_type,
			  const struct btf_type *value_type)
{
	return BTF_INFO_KIND(key_type->info) != BTF_KIND_STRUCT ? -EINVAL : 0;
}

static struct bpf_map *trie_alloc(union bpf_attr *attr)
{
	struct lpm_trie *trie;
	struct poptrie_snapshot *s;
	u32 i;

	if (attr->max_entries == 0 ||
	    !(attr->map_flags & BPF_F_NO_PREALLOC) ||
	    attr->map_flags & ~LPM_CREATE_FLAG_MASK ||
	    !bpf_map_flags_access_ok(attr->map_flags) ||
	    attr->key_size != LPM_KEY_SIZE(4) ||
	    attr->value_size < LPM_VAL_SIZE_MIN ||
	    attr->value_size > LPM_VAL_SIZE_MAX)
		return ERR_PTR(-EINVAL);

	trie = bpf_map_area_alloc(sizeof(*trie), NUMA_NO_NODE);
	if (!trie)
		return ERR_PTR(-ENOMEM);

	bpf_map_init_from_attr(&trie->map, attr);
	mutex_init(&trie->update_mutex);

	s = kvzalloc(sizeof(*s), GFP_KERNEL);
	if (!s) {
		bpf_map_area_free(trie);
		return ERR_PTR(-ENOMEM);
	}
	s->dir = kvmalloc_array(1U << POPTRIE_S, sizeof(u32),
				GFP_KERNEL | __GFP_NOWARN);
	if (!s->dir) {
		kvfree(s);
		bpf_map_area_free(trie);
		return ERR_PTR(-ENOMEM);
	}
	for (i = 0; i < (1U << POPTRIE_S); i++)
		s->dir[i] = DIR_LEAF_BIT;

	RCU_INIT_POINTER(trie->snap, s);
	return &trie->map;
}

static void trie_free(struct bpf_map *map)
{
	struct lpm_trie *trie = container_of(map, struct lpm_trie, map);

	radix_free(trie->radix);
	snap_free(rcu_dereference_raw(trie->snap));
	bpf_map_area_free(trie);
}

static u64 trie_mem_usage(const struct bpf_map *map)
{
	struct lpm_trie *trie = container_of(map, struct lpm_trie, map);
	struct poptrie_snapshot *s = rcu_dereference_raw(trie->snap);
	u64 usage = (u64)READ_ONCE(trie->n_entries) *
		    (sizeof(struct radix_node) + trie->map.value_size);

	if (s) {
		usage += (u64)(1U << POPTRIE_S) * sizeof(u32);
		usage += (u64)s->nodes_cap  * sizeof(struct poptrie_node);
		usage += (u64)s->leaves_cap * sizeof(poptrie_leaf_t);
		usage += (u64)s->fib_used   * sizeof(struct poptrie_fib_entry);
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

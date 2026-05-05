/**
 * HookFlow — Hook 9: Royalty Cascade (Multi-Split)
 *
 * Automatically splits incoming XAH payments across up to 4
 * destination wallets, each with its own configurable percentage.
 * The remainder stays with the hook account.
 *
 * Hook Parameters:
 *   DEST_01  (20 bytes) — AccountID of recipient 1 (required)
 *   PCT_01   (1 byte)   — Percentage for recipient 1 (required)
 *   DEST_02  (20 bytes) — AccountID of recipient 2 (optional)
 *   PCT_02   (1 byte)   — Percentage for recipient 2 (optional)
 *   DEST_03  (20 bytes) — AccountID of recipient 3 (optional)
 *   PCT_03   (1 byte)   — Percentage for recipient 3 (optional)
 *   DEST_04  (20 bytes) — AccountID of recipient 4 (optional)
 *   PCT_04   (1 byte)   — Percentage for recipient 4 (optional)
 *   MIN_DROPS (8 bytes) — Minimum drops to trigger split (default: 1 XAH)
 *
 * Rules:
 *   - At least DEST_01 + PCT_01 must be set
 *   - Each PCT must be 1-99
 *   - Total of all PCTs must be <= 100
 *   - Remainder stays with the hook account owner
 *   - Slots are independent: DEST_01+03 with no 02 is valid
 *
 * Website: https://xrplhookflow.com
 * GitHub:  https://github.com/slassu/hookflow
 */

#include "hookapi.h"

#define GUARD(maxiter) _g(__LINE__, (maxiter)+1)

int64_t hook(uint32_t reserved) {

    GUARD(1);
    TRACESTR("Cascade: called.");

    // ── 1. Only act on Payment transactions ──────────────────
    if (otxn_type() != ttPAYMENT) {
        accept("Cascade: not a payment.", 23, 0);
        return 0;
    }

    // ── 2. Ignore outgoing (our own split emissions) ─────────
    uint8_t hook_acc[20];
    uint8_t otxn_acc[20];
    hook_account(SBUF(hook_acc));
    otxn_field(SBUF(otxn_acc), sfAccount);

    GUARD(2);
    if (BUFFER_EQUAL_20(hook_acc, otxn_acc)) {
        accept("Cascade: outgoing, skip.", 24, 0);
        return 0;
    }

    // ── 3. Read incoming XRP amount ──────────────────────────
    uint8_t amt_buf[8];
    int64_t amt_len = otxn_field(SBUF(amt_buf), sfAmount);
    if (amt_len != 8) {
        accept("Cascade: IOU, skip.", 19, 0);
        return 0;
    }
    int64_t drops = (int64_t)(UINT64_FROM_BUF(amt_buf) & 0x3FFFFFFFFFFFFFFFULL);
    TRACEVAR(drops);

    // ── 4. Read MIN_DROPS parameter (default: 1 XAH) ─────────
    uint8_t min_buf[8];
    uint8_t min_key[] = "MIN_DROPS";
    int64_t min_drops = 1000000;
    int64_t mp = hook_param(SBUF(min_buf), min_key, 9);
    if (mp == 8)
        min_drops = (int64_t)UINT64_FROM_BUF(min_buf);
    TRACEVAR(min_drops);

    // ── 5. Skip if below minimum (avoid splitting dust) ──────
    GUARD(3);
    if (drops < min_drops) {
        accept("Cascade: below minimum.", 23, 0);
        return 0;
    }

    // ── 6. Read all destination/percentage pairs ──────────────
    //    Up to 4 slots. Each slot needs both DEST_XX and PCT_XX.
    //    Missing or invalid slots are skipped.

    uint8_t dest[4][20];
    uint8_t pct[4];
    int     active[4];
    int     num_active = 0;
    int     total_pct  = 0;

    // Parameter key names
    uint8_t dest_keys[4][8] = {
        "DEST_01", "DEST_02", "DEST_03", "DEST_04"
    };
    uint8_t pct_keys[4][7] = {
        "PCT_01", "PCT_02", "PCT_03", "PCT_04"
    };

    // Read each slot
    GUARD(5);
    for (int i = 0; GUARD(5), i < 4; i++) {
        active[i] = 0;
        pct[i] = 0;

        // Read destination (20 bytes)
        int64_t dp = hook_param(dest[i], 20, dest_keys[i], 7);
        if (dp != 20)
            continue;

        // Read percentage (1 byte)
        uint8_t pct_buf[1];
        int64_t pp = hook_param(SBUF(pct_buf), pct_keys[i], 6);
        if (pp != 1)
            continue;

        // Validate percentage range
        if (pct_buf[0] == 0 || pct_buf[0] > 99)
            continue;

        pct[i] = pct_buf[0];
        active[i] = 1;
        num_active++;
        total_pct += pct_buf[0];
    }

    // ── 7. Validate: at least 1 active, total <= 100 ─────────
    GUARD(6);
    if (num_active == 0) {
        accept("Cascade: no valid slots.", 24, 0);
        return 0;
    }

    if (total_pct > 100) {
        accept("Cascade: PCT sum > 100.", 23, 0);
        return 0;
    }

    TRACEVAR(num_active);
    TRACEVAR(total_pct);

    // ── 8. Reserve emission slots ────────────────────────────
    etxn_reserve(num_active);

    // ── 9. Calculate and emit each split ─────────────────────
    int emitted = 0;

    GUARD(9);
    for (int i = 0; GUARD(9), i < 4; i++) {
        if (!active[i])
            continue;

        int64_t split_amount = (drops * (int64_t)pct[i]) / 100;

        // Skip if split rounds to zero
        if (split_amount < 1)
            continue;

        TRACEVAR(split_amount);

        // Build and emit payment
        uint8_t txn[PREPARE_PAYMENT_SIMPLE_SIZE];
        PREPARE_PAYMENT_SIMPLE(txn, split_amount, dest[i], 0, 0);

        uint8_t emithash[32];
        int64_t emit_result = emit(SBUF(emithash), SBUF(txn));

        if (emit_result < 0) {
            TRACEVAR(emit_result);
            // Continue with remaining splits — don't block the payment
            continue;
        }

        emitted++;
    }

    TRACEVAR(emitted);

    if (emitted == 0) {
        accept("Cascade: no emissions.", 22, 0);
        return 0;
    }

    accept("Cascade: splits emitted.", 24, 0);
    return 0;
}

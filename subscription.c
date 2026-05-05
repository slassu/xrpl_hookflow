#include <stdint.h>
#include "hookapi.h"

/**
 * HookFlow Hook #10 - Subscription (Recurring Payment Authorization)
 *
 * Allows a pre-authorized merchant to pull fixed subscription payments
 * at regular intervals. Merchant triggers by sending any payment to
 * the subscriber's hooked account.
 *
 * Parameters:
 *   AUTHADDR - 20-byte AccountID of authorized merchant
 *   SUBAMT   - 8-byte BE uint64: subscription amount in drops
 *   INTRVL   - 4-byte BE uint32: minimum ledger sequences between pulls
 *
 * State: "LASTPULL" - 4-byte ledger sequence of last pull
 */

int64_t hook(uint32_t reserved)
{
    _g(1, 1);

    uint8_t tt_buf[4];
    int64_t tt_len = otxn_field(SBUF(tt_buf), sfTransactionType);
    if (tt_len < 0)
        accept(SBUF("Subscription: could not read txn type"), 0);

    uint16_t tt = ((uint16_t)tt_buf[0] << 8) | tt_buf[1];
    if (tt != 0)
        accept(SBUF("Subscription: not a payment, passing through"), 0);

    unsigned char hook_accid[20];
    hook_account((uint32_t)hook_accid, 20);

    uint8_t sender[20];
    int32_t sender_len = otxn_field(SBUF(sender), sfAccount);
    if (sender_len != 20)
        accept(SBUF("Subscription: could not read sender"), 0);

    int is_outgoing = 0;
    BUFFER_EQUAL(is_outgoing, hook_accid, sender, 20);
    if (is_outgoing)
        accept(SBUF("Subscription: outgoing, pass-through"), 0);

    uint8_t auth_addr[20];
    int64_t auth_len = hook_param(SBUF(auth_addr), "AUTHADDR", 8);
    if (auth_len != 20)
        accept(SBUF("Subscription: AUTHADDR param missing"), 0);

    int is_auth = 0;
    BUFFER_EQUAL(is_auth, sender, auth_addr, 20);
    if (!is_auth)
        accept(SBUF("Subscription: not authorized, pass-through"), 0);

    uint8_t amt_buf[8];
    int64_t amt_len = hook_param(SBUF(amt_buf), "SUBAMT", 6);
    if (amt_len != 8)
        rollback(SBUF("Subscription: SUBAMT param missing"), 0);

    int64_t sub_drops = ((int64_t)amt_buf[0] << 56) |
                        ((int64_t)amt_buf[1] << 48) |
                        ((int64_t)amt_buf[2] << 40) |
                        ((int64_t)amt_buf[3] << 32) |
                        ((int64_t)amt_buf[4] << 24) |
                        ((int64_t)amt_buf[5] << 16) |
                        ((int64_t)amt_buf[6] << 8)  |
                        ((int64_t)amt_buf[7]);

    if (sub_drops <= 0)
        rollback(SBUF("Subscription: amount must be > 0"), 0);

    uint8_t intrvl_buf[4];
    int64_t intrvl_len = hook_param(SBUF(intrvl_buf), "INTRVL", 6);
    if (intrvl_len != 4)
        rollback(SBUF("Subscription: INTRVL param missing"), 0);

    uint32_t interval = ((uint32_t)intrvl_buf[0] << 24) |
                        ((uint32_t)intrvl_buf[1] << 16) |
                        ((uint32_t)intrvl_buf[2] << 8)  |
                        ((uint32_t)intrvl_buf[3]);

    int64_t cur_ledger = ledger_seq();
    if (cur_ledger <= 0)
        rollback(SBUF("Subscription: could not read ledger seq"), 0);

    uint8_t state_key[32];
    for (int i = 0; GUARD(32), i < 32; i++)
        state_key[i] = 0;
    state_key[0] = 'L'; state_key[1] = 'A'; state_key[2] = 'S';
    state_key[3] = 'T'; state_key[4] = 'P'; state_key[5] = 'U';
    state_key[6] = 'L'; state_key[7] = 'L';

    uint8_t last_pull_buf[4];
    int64_t state_len = state(SBUF(last_pull_buf), SBUF(state_key));

    uint32_t last_pull = 0;
    if (state_len == 4)
    {
        last_pull = ((uint32_t)last_pull_buf[0] << 24) |
                    ((uint32_t)last_pull_buf[1] << 16) |
                    ((uint32_t)last_pull_buf[2] << 8)  |
                    ((uint32_t)last_pull_buf[3]);
    }

    if (last_pull > 0 && (uint32_t)cur_ledger - last_pull < interval)
        rollback(SBUF("Subscription: too soon, interval not elapsed"), 0);

    etxn_reserve(1);

    unsigned char tx[PREPARE_PAYMENT_SIMPLE_SIZE];
    PREPARE_PAYMENT_SIMPLE(tx, sub_drops, auth_addr, 0, 0);

    uint8_t emithash[32];
    int64_t emit_result = emit(SBUF(emithash), SBUF(tx));
    if (emit_result < 0)
        rollback(SBUF("Subscription: emit failed"), 0);

    uint8_t new_pull[4];
    new_pull[0] = (uint8_t)((cur_ledger >> 24) & 0xFF);
    new_pull[1] = (uint8_t)((cur_ledger >> 16) & 0xFF);
    new_pull[2] = (uint8_t)((cur_ledger >> 8) & 0xFF);
    new_pull[3] = (uint8_t)(cur_ledger & 0xFF);

    int64_t set_result = state_set(SBUF(new_pull), SBUF(state_key));
    if (set_result < 0)
        rollback(SBUF("Subscription: state_set failed"), 0);

    TRACESTR("HookFlow #10: Subscription payment emitted");

    accept(SBUF("Subscription: payment sent to merchant"), 0);

    _g(1, 1);
    return 0;
}

/* TETRA Call Tracker Implementation
 *
 * Tracks call state across all 4 timeslots for the "Mute Encrypted Calls"
 * feature with priority-based auto-selection.
 */

#include <string.h>
#include "tetra_call_tracker.h"

/* Compute the combined encryption state from the 3 flags.
 * A call is clear (unencrypted) only if ALL THREE flags are 0. */
static void compute_encryption_state(struct tetra_call_state_ts *ts_state)
{
    ts_state->is_encrypted = (ts_state->encryption_mode != 0) ||
                             (ts_state->encryption_control != 0) ||
                             (ts_state->basic_service_encryption != 0);
}

void tetra_call_tracker_init(struct tetra_call_tracker *tracker)
{
    if (!tracker)
        return;

    memset(tracker, 0, sizeof(*tracker));
    tracker->selected_timeslot = -1;
    tracker->mute_encrypted = false;

    for (int i = 0; i < TETRA_NUM_TIMESLOTS; i++) {
        tracker->timeslots[i].state = TETRA_CALL_STATE_IDLE;
    }
}

void tetra_call_tracker_reset_timeslot(struct tetra_call_tracker *tracker, int ts)
{
    if (!tracker || ts < 0 || ts >= TETRA_NUM_TIMESLOTS)
        return;

    struct tetra_call_state_ts *ts_state = &tracker->timeslots[ts];
    memset(ts_state, 0, sizeof(*ts_state));
    ts_state->state = TETRA_CALL_STATE_IDLE;
}

void tetra_call_tracker_update_mac_encryption(struct tetra_call_tracker *tracker,
                                               int ts, uint8_t encryption_mode)
{
    if (!tracker || ts < 0 || ts >= TETRA_NUM_TIMESLOTS)
        return;

    struct tetra_call_state_ts *ts_state = &tracker->timeslots[ts];
    ts_state->encryption_mode = encryption_mode;

    /* Mark timeslot as active when we see MAC traffic on it.
     * This ensures encryption tracking works even without CMCE PDUs. */
    if (ts_state->state == TETRA_CALL_STATE_IDLE) {
        ts_state->state = TETRA_CALL_STATE_ACTIVE;
    }

    compute_encryption_state(ts_state);
}

void tetra_call_tracker_setup(struct tetra_call_tracker *tracker, int ts,
                              uint16_t call_id, uint32_t ssi, uint8_t priority,
                              uint8_t encryption_control,
                              uint8_t basic_service_encryption)
{
    if (!tracker || ts < 0 || ts >= TETRA_NUM_TIMESLOTS)
        return;

    struct tetra_call_state_ts *ts_state = &tracker->timeslots[ts];

    ts_state->state = TETRA_CALL_STATE_SETUP;
    ts_state->call_id = call_id;
    ts_state->ssi = ssi;
    ts_state->priority = priority;
    ts_state->encryption_control = encryption_control;
    ts_state->basic_service_encryption = basic_service_encryption;

    compute_encryption_state(ts_state);
}

void tetra_call_tracker_connect(struct tetra_call_tracker *tracker, int ts,
                                uint16_t call_id,
                                uint8_t encryption_control,
                                uint8_t basic_service_encryption)
{
    if (!tracker || ts < 0 || ts >= TETRA_NUM_TIMESLOTS)
        return;

    struct tetra_call_state_ts *ts_state = &tracker->timeslots[ts];

    /* If we see a D-CONNECT without a prior D-SETUP, initialize the call */
    if (ts_state->state == TETRA_CALL_STATE_IDLE) {
        ts_state->call_id = call_id;
        ts_state->priority = 0; /* Default priority */
    }

    ts_state->state = TETRA_CALL_STATE_ACTIVE;
    ts_state->encryption_control = encryption_control;
    ts_state->basic_service_encryption = basic_service_encryption;

    compute_encryption_state(ts_state);
}

void tetra_call_tracker_tx_granted(struct tetra_call_tracker *tracker, int ts,
                                   uint16_t call_id,
                                   uint8_t encryption_control)
{
    if (!tracker || ts < 0 || ts >= TETRA_NUM_TIMESLOTS)
        return;

    struct tetra_call_state_ts *ts_state = &tracker->timeslots[ts];

    /* If we see TX_GRANTED without prior setup/connect, mark as active */
    if (ts_state->state == TETRA_CALL_STATE_IDLE) {
        ts_state->call_id = call_id;
        ts_state->priority = 0; /* Default priority */
    }

    ts_state->state = TETRA_CALL_STATE_ACTIVE;
    ts_state->encryption_control = encryption_control;
    /* Keep existing basic_service_encryption if already set */

    compute_encryption_state(ts_state);
}

void tetra_call_tracker_release(struct tetra_call_tracker *tracker, int ts,
                                uint16_t call_id)
{
    if (!tracker || ts < 0 || ts >= TETRA_NUM_TIMESLOTS)
        return;

    struct tetra_call_state_ts *ts_state = &tracker->timeslots[ts];

    /* Only release if the call_id matches (or call_id is 0 = release any) */
    if (call_id == 0 || ts_state->call_id == call_id) {
        tetra_call_tracker_reset_timeslot(tracker, ts);
    }
}

int tetra_call_tracker_select_timeslot(struct tetra_call_tracker *tracker)
{
    if (!tracker)
        return -1;

    int best_ts = -1;
    int best_priority = -1;
    bool best_is_clear = false;

    for (int ts = 0; ts < TETRA_NUM_TIMESLOTS; ts++) {
        struct tetra_call_state_ts *ts_state = &tracker->timeslots[ts];

        /* Skip idle timeslots */
        if (ts_state->state == TETRA_CALL_STATE_IDLE)
            continue;

        /* If mute_encrypted is enabled, skip encrypted calls */
        if (tracker->mute_encrypted && ts_state->is_encrypted)
            continue;

        bool is_clear = !ts_state->is_encrypted;
        int priority = ts_state->priority;

        /* Selection criteria (in order):
         * 1. Prefer clear over encrypted
         * 2. Higher priority wins
         * 3. Lower timeslot number wins (tiebreaker)
         */
        bool is_better = false;

        if (best_ts < 0) {
            /* No candidate yet */
            is_better = true;
        } else if (is_clear && !best_is_clear) {
            /* Prefer clear over encrypted */
            is_better = true;
        } else if (is_clear == best_is_clear) {
            /* Same encryption status, compare priority */
            if (priority > best_priority) {
                is_better = true;
            }
            /* Same priority: lower timeslot wins (first one found) */
        }

        if (is_better) {
            best_ts = ts;
            best_priority = priority;
            best_is_clear = is_clear;
        }
    }

    tracker->selected_timeslot = best_ts;
    return best_ts;
}

bool tetra_call_tracker_is_clear(struct tetra_call_tracker *tracker, int ts)
{
    if (!tracker || ts < 0 || ts >= TETRA_NUM_TIMESLOTS)
        return true; /* Default to clear if invalid */

    return !tracker->timeslots[ts].is_encrypted;
}

enum tetra_call_state tetra_call_tracker_get_state(struct tetra_call_tracker *tracker, int ts)
{
    if (!tracker || ts < 0 || ts >= TETRA_NUM_TIMESLOTS)
        return TETRA_CALL_STATE_IDLE;

    return tracker->timeslots[ts].state;
}

void tetra_call_tracker_set_mute_encrypted(struct tetra_call_tracker *tracker, bool mute)
{
    if (!tracker)
        return;

    tracker->mute_encrypted = mute;
}

bool tetra_call_tracker_get_mute_encrypted(struct tetra_call_tracker *tracker)
{
    if (!tracker)
        return false;

    return tracker->mute_encrypted;
}

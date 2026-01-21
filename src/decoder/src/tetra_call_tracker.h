/* TETRA Call Tracker - Per-timeslot call state tracking
 *
 * This module tracks call state across all 4 timeslots, including:
 * - Encryption status from 3 sources (MAC, CMCE control, Basic Service)
 * - Call priority for auto-selection
 * - Call ID and SSI
 *
 * Used to implement "Mute Encrypted Calls" feature with priority-based
 * auto-selection of clear calls.
 */

#ifndef TETRA_CALL_TRACKER_H
#define TETRA_CALL_TRACKER_H

#include <stdint.h>
#include <stdbool.h>

/* Number of timeslots in TETRA */
#define TETRA_NUM_TIMESLOTS 4

/* Call states */
enum tetra_call_state {
    TETRA_CALL_STATE_IDLE = 0,
    TETRA_CALL_STATE_SETUP,
    TETRA_CALL_STATE_ACTIVE,
};

/* Per-timeslot call state tracking */
struct tetra_call_state_ts {
    enum tetra_call_state state;

    /* Call identification */
    uint16_t call_id;
    uint32_t ssi;

    /* Priority (higher = more important, 0-7 per ETSI) */
    uint8_t priority;

    /* The 3 encryption flags per SDR-Tetra-Plugin:
     * - encryption_mode: from MAC-RESOURCE PDU (2 bits, 0=clear)
     * - encryption_control: from D-SETUP/D-CONNECT/D-TX_GRANTED (1 bit)
     * - basic_service_encryption: from Basic Service Info element (1 bit)
     *
     * Call is clear only if ALL three are 0.
     */
    uint8_t encryption_mode;         /* From MAC-RESOURCE */
    uint8_t encryption_control;      /* From CMCE PDUs */
    uint8_t basic_service_encryption; /* From Basic Service Info */

    /* Combined encryption state (computed from the 3 flags above) */
    bool is_encrypted;
};

/* Main call tracker structure */
struct tetra_call_tracker {
    /* Per-timeslot state */
    struct tetra_call_state_ts timeslots[TETRA_NUM_TIMESLOTS];

    /* Mute encrypted calls setting */
    bool mute_encrypted;

    /* Currently selected timeslot for voice output (-1 = none) */
    int selected_timeslot;
};

/* Initialize call tracker */
void tetra_call_tracker_init(struct tetra_call_tracker *tracker);

/* Reset a specific timeslot */
void tetra_call_tracker_reset_timeslot(struct tetra_call_tracker *tracker, int ts);

/* Update MAC-level encryption mode for a timeslot */
void tetra_call_tracker_update_mac_encryption(struct tetra_call_tracker *tracker,
                                               int ts, uint8_t encryption_mode);

/* Handle D-SETUP: new call being set up */
void tetra_call_tracker_setup(struct tetra_call_tracker *tracker, int ts,
                              uint16_t call_id, uint32_t ssi, uint8_t priority,
                              uint8_t encryption_control,
                              uint8_t basic_service_encryption);

/* Handle D-CONNECT: call connected */
void tetra_call_tracker_connect(struct tetra_call_tracker *tracker, int ts,
                                uint16_t call_id,
                                uint8_t encryption_control,
                                uint8_t basic_service_encryption);

/* Handle D-TX_GRANTED: transmission granted */
void tetra_call_tracker_tx_granted(struct tetra_call_tracker *tracker, int ts,
                                   uint16_t call_id,
                                   uint8_t encryption_control);

/* Handle D-RELEASE: call released */
void tetra_call_tracker_release(struct tetra_call_tracker *tracker, int ts,
                                uint16_t call_id);

/* Select the best timeslot for voice output based on:
 * 1. Skip IDLE timeslots
 * 2. If mute_encrypted: skip encrypted timeslots
 * 3. Prefer clear over encrypted
 * 4. Higher priority wins
 * 5. Lower timeslot number as tiebreaker
 * Returns: timeslot number (0-3) or -1 if none available
 */
int tetra_call_tracker_select_timeslot(struct tetra_call_tracker *tracker);

/* Check if a timeslot has a clear (unencrypted) call */
bool tetra_call_tracker_is_clear(struct tetra_call_tracker *tracker, int ts);

/* Get call state for a timeslot */
enum tetra_call_state tetra_call_tracker_get_state(struct tetra_call_tracker *tracker, int ts);

/* Set mute encrypted flag */
void tetra_call_tracker_set_mute_encrypted(struct tetra_call_tracker *tracker, bool mute);

/* Get mute encrypted flag */
bool tetra_call_tracker_get_mute_encrypted(struct tetra_call_tracker *tracker);

#endif /* TETRA_CALL_TRACKER_H */

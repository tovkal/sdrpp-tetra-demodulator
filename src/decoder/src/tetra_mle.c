#include <stdint.h>
#include <stdio.h>
// #include <unistd.h>
#include <string.h>

// #include <osmocom/core/msgb.h>
// #include <osmocom/core/talloc.h>
// #include <osmocom/core/bits.h>

#include "tetra_mle_pdu.h"
#include "tetra_mle.h"
#include "tetra_mm_pdu.h"
#include "tetra_cmce_pdu.h"
#include "tetra_sndcp_pdu.h"
#include "tetra_mle_pdu.h"
#include "tetra_call_tracker.h"

/* Handle CMCE PDU for call tracking (encryption status, priority) */
static void rx_cmce_pdu(struct tetra_mac_state *tms, uint8_t *bits, unsigned int len)
{
	uint8_t cmce_pdu_type;
	int ts;

	if (!tms || !tms->call_tracker || len < 8)
		return;

	/* Get current timeslot from MAC state */
	ts = tms->cur_timeslot;
	if (ts < 0 || ts >= 4)
		return;

	/* PDU type is at bits 3-7 (5 bits) after 3-bit protocol discriminator */
	cmce_pdu_type = bits_to_uint(bits + 3, 5);

	/* Point to start of PDU content (after pdisc + pdu_type = 8 bits) */
	uint8_t *pdu_bits = bits + 8;
	int pdu_len = len - 8;

	switch (cmce_pdu_type) {
	case TCMCE_PDU_T_D_SETUP: {
		struct tetra_cmce_d_setup_decoded setup;
		if (cmce_decode_d_setup(&setup, pdu_bits, pdu_len) > 0 && setup.valid) {
			tetra_call_tracker_setup(tms->call_tracker, ts,
				setup.call_identifier,
				tms->ssi,
				setup.call_priority,
				setup.encryption_control,
				setup.basic_service.encryption_flag);
			/* Update display state */
			tms->t_display_st->timeslot_encrypted[ts] =
				!tetra_call_tracker_is_clear(tms->call_tracker, ts);
		}
		break;
	}
	case TCMCE_PDU_T_D_CONNECT: {
		struct tetra_cmce_d_connect_decoded conn;
		if (cmce_decode_d_connect(&conn, pdu_bits, pdu_len) > 0 && conn.valid) {
			tetra_call_tracker_connect(tms->call_tracker, ts,
				conn.call_identifier,
				conn.encryption_control,
				conn.basic_service.encryption_flag);
			/* Update display state */
			tms->t_display_st->timeslot_encrypted[ts] =
				!tetra_call_tracker_is_clear(tms->call_tracker, ts);
		}
		break;
	}
	case TCMCE_PDU_T_D_TX_GRANTED: {
		struct tetra_cmce_d_tx_granted_decoded txg;
		if (cmce_decode_d_tx_granted(&txg, pdu_bits, pdu_len) > 0 && txg.valid) {
			tetra_call_tracker_tx_granted(tms->call_tracker, ts,
				txg.call_identifier,
				txg.encryption_control);
			/* Update display state */
			tms->t_display_st->timeslot_encrypted[ts] =
				!tetra_call_tracker_is_clear(tms->call_tracker, ts);
		}
		break;
	}
	case TCMCE_PDU_T_D_RELEASE: {
		struct tetra_cmce_d_release_decoded rel;
		if (cmce_decode_d_release(&rel, pdu_bits, pdu_len) > 0 && rel.valid) {
			tetra_call_tracker_release(tms->call_tracker, ts,
				rel.call_identifier);
			/* Update display state */
			tms->t_display_st->timeslot_encrypted[ts] = false;
		}
		break;
	}
	default:
		/* Other CMCE PDU types - not relevant for call tracking */
		break;
	}
}

/* Receive TL-SDU (LLC SDU == MLE PDU) */
int rx_tl_sdu(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
	uint8_t *bits = msg->l3h;
	uint8_t mle_pdisc = bits_to_uint(bits, 3);

	// printf("TL-SDU(%s): %s ", tetra_get_mle_pdisc_name(mle_pdisc),
		// osmo_ubit_dump(bits, len));
	switch (mle_pdisc) {
	case TMLE_PDISC_MM:
		// printf("%s\n", tetra_get_mm_pdut_name(bits_to_uint(bits+3, 4), 0));
		break;
	case TMLE_PDISC_CMCE:
		// printf("%s\n", tetra_get_cmce_pdut_name(bits_to_uint(bits+3, 5), 0));
		/* Parse CMCE PDUs for call tracking */
		rx_cmce_pdu(tms, bits, len);
		break;
	case TMLE_PDISC_SNDCP:
		// printf("%s ", tetra_get_sndcp_pdut_name(bits_to_uint(bits+3, 4), 0));
		// printf(" NSAPI=%u PCOMP=%u, DCOMP=%u",
			// bits_to_uint(bits+3+4, 4),
			// bits_to_uint(bits+3+4+4, 4),
			// bits_to_uint(bits+3+4+4+4, 4));
		// printf(" V%u, IHL=%u",
			// bits_to_uint(bits+3+4+4+4+4, 4),
			// 4*bits_to_uint(bits+3+4+4+4+4+4, 4));
		// printf(" Proto=%u\n",
			// bits_to_uint(bits+3+4+4+4+4+4+4+64, 8));
		break;
	case TMLE_PDISC_MLE:
		// printf("%s\n", tetra_get_mle_pdut_name(bits_to_uint(bits+3, 3), 0));
		break;
	default:
		break;
	}
	return len;
}

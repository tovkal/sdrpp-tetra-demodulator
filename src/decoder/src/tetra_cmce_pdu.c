/* Implementation of TETRA CMCE PDU parsing */

/* (C) 2011 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

// #include <unistd.h>
// #include <osmocom/core/utils.h>

#include <string.h>
#include "tetra_cmce_pdu.h"

static const struct value_string cmce_pdut_d_names[] = {
	{ TCMCE_PDU_T_D_ALERT,			"D-ALERT" },
	{ TCMCE_PDU_T_D_CALL_PROCEEDING,	"D-CALL PROCEEDING" },
	{ TCMCE_PDU_T_D_CONNECT,		"D-CONNECT" },
	{ TCMCE_PDU_T_D_CONNECT_ACK,		"D-CONNECT ACK" },
	{ TCMCE_PDU_T_D_DISCONNECT,		"D-DISCONNECT" },
	{ TCMCE_PDU_T_D_INFO,			"D-INFO" },
	{ TCMCE_PDU_T_D_RELEASE,		"D-RELEASE" },
	{ TCMCE_PDU_T_D_SETUP,			"D-SETUP" },
	{ TCMCE_PDU_T_D_STATUS,			"D-STATUS" },
	{ TCMCE_PDU_T_D_TX_CEASED,		"D-TX CEASED" },
	{ TCMCE_PDU_T_D_TX_CONTINUE,		"D-TX CONTINUE" },
	{ TCMCE_PDU_T_D_TX_GRANTED,		"D-TX GRANTED" },
	{ TCMCE_PDU_T_D_TX_WAIT,		"D-TX WAIT" },
	{ TCMCE_PDU_T_D_TX_INTERRUPT,		"D-TX INTERRUPT" },
	{ TCMCE_PDU_T_D_CALL_RESTORE,		"D-TX CALL RESTORE" },
	{ TCMCE_PDU_T_D_SDS_DATA,		"D-SDS DATA" },
	{ TCMCE_PDU_T_D_FACILITY,		"D-FACILITY" },
	{ 0, NULL }
};

static const struct value_string cmce_pdut_u_names[] = {
	{ TCMCE_PDU_T_U_ALERT,		"U-ALERT" },
	{ TCMCE_PDU_T_U_CONNECT,	"U-CONNECT" },
	{ TCMCE_PDU_T_U_DISCONNECT,	"U-DISCONNECT" },
	{ TCMCE_PDU_T_U_INFO,		"U-INFO" },
	{ TCMCE_PDU_T_U_RELEASE,	"U-RELEASE" },
	{ TCMCE_PDU_T_U_SETUP,		"U-SETUP" },
	{ TCMCE_PDU_T_U_STATUS,		"U-STATUS" },
	{ TCMCE_PDU_T_U_TX_CEASED,	"U-TX CEASED" },
	{ TCMCE_PDU_T_U_TX_DEMAND,	"U-TX DEMAND" },
	{ TCMCE_PDU_T_U_CALL_RESTORE,	"U-TX CALL RESTORE" },
	{ TCMCE_PDU_T_U_SDS_DATA,	"U-SDS DATA" },
	{ TCMCE_PDU_T_U_FACILITY,	"U-FACILITY" },
	{ 0, NULL }
};

const char *tetra_get_cmce_pdut_name(uint16_t pdut, int uplink)
{
	if (uplink == 0)
		return get_value_string(cmce_pdut_d_names, pdut);
	else
		return get_value_string(cmce_pdut_u_names, pdut);
}

/* Decode Basic Service Information element (14.8.4)
 * This contains the critical "encryption flag" (1 bit)
 *
 * Structure per ETSI EN 300 392-2:
 * - Circuit mode type: 4 bits
 * - Encryption flag: 1 bit
 * - Communication type: 2 bits
 * - Slots/frame: 2 bits (circuit mode)
 * - Speech service: 4 bits (if speech)
 *
 * Returns number of bits consumed, or -1 on error */
int cmce_decode_basic_service_info(struct tetra_basic_service_info *bsi, const uint8_t *bits, int len)
{
	int n = 0;

	if (!bsi || !bits || len < 7)
		return -1;

	memset(bsi, 0, sizeof(*bsi));

	/* Circuit mode type: 4 bits */
	bsi->circuit_mode_type = bits_to_uint(bits + n, 4); n += 4;

	/* Encryption flag: 1 bit - THIS IS THE KEY FLAG */
	bsi->encryption_flag = bits_to_uint(bits + n, 1); n += 1;

	/* Communication type: 2 bits */
	bsi->communication_type = bits_to_uint(bits + n, 2); n += 2;

	/* Slots/frame: 2 bits (only present for circuit mode) */
	if (n + 2 <= len) {
		bsi->slots_per_frame = bits_to_uint(bits + n, 2); n += 2;
	}

	/* Speech service: 4 bits (if speech service, indicated by circuit_mode_type) */
	/* Circuit mode type 0-7 are speech-related */
	if (bsi->circuit_mode_type <= 7 && n + 4 <= len) {
		bsi->speech_service = bits_to_uint(bits + n, 4); n += 4;
	}

	return n;
}

/* Decode D-SETUP PDU (14.7.1.8)
 *
 * PDU structure (after 3-bit pdisc + 5-bit pdu_type):
 * - Call identifier: 14 bits
 * - Call timeout: 4 bits
 * - Hook method selection: 1 bit
 * - Simplex/duplex selection: 1 bit
 * - Basic service information: variable (includes encryption flag)
 * - Request to transmit/send data: 1 bit
 * - Call priority: 4 bits
 * - End to end encryption flag: 1 bit (not same as basic service encryption)
 * - Type2/3 elements (optional)
 *
 * For encryption, we extract:
 * - call_priority (4 bits)
 * - encryption_control (from Type2 if present, or default 0)
 * - basic_service.encryption_flag
 */
int cmce_decode_d_setup(struct tetra_cmce_d_setup_decoded *setup, const uint8_t *bits, int len)
{
	int n = 0;
	int bsi_len;

	if (!setup || !bits || len < 25)
		return -1;

	memset(setup, 0, sizeof(*setup));

	/* Call identifier: 14 bits */
	setup->call_identifier = bits_to_uint(bits + n, 14); n += 14;

	/* Call timeout: 4 bits */
	setup->call_timeout = bits_to_uint(bits + n, 4); n += 4;

	/* Hook method selection: 1 bit */
	setup->hook_method_sel = bits_to_uint(bits + n, 1); n += 1;

	/* Simplex/duplex selection: 1 bit */
	setup->simplex_duplex = bits_to_uint(bits + n, 1); n += 1;

	/* Basic service information (variable length, contains encryption flag) */
	bsi_len = cmce_decode_basic_service_info(&setup->basic_service, bits + n, len - n);
	if (bsi_len < 0)
		return -1;
	n += bsi_len;

	/* Request to transmit/send data: 1 bit */
	if (n + 1 > len) goto done;
	n += 1;

	/* Call priority: 4 bits */
	if (n + 4 > len) goto done;
	setup->call_priority = bits_to_uint(bits + n, 4); n += 4;

	/* End to end encryption flag: 1 bit - this is the "encryption_control" flag */
	if (n + 1 > len) goto done;
	setup->encryption_control = bits_to_uint(bits + n, 1); n += 1;

done:
	setup->valid = 1;
	return n;
}

/* Decode D-CONNECT PDU (14.7.1.3)
 *
 * PDU structure (after 3-bit pdisc + 5-bit pdu_type):
 * - Call identifier: 14 bits
 * - Call timeout: 4 bits
 * - Hook method selection: 1 bit
 * - Simplex/duplex selection: 1 bit
 * - Transmission grant: 2 bits
 * - Transmission request permission: 1 bit
 * - Call ownership: 1 bit
 * - Basic service information
 * - End to end encryption flag: 1 bit
 * - Type2/3 elements
 */
int cmce_decode_d_connect(struct tetra_cmce_d_connect_decoded *conn, const uint8_t *bits, int len)
{
	int n = 0;
	int bsi_len;

	if (!conn || !bits || len < 24)
		return -1;

	memset(conn, 0, sizeof(*conn));

	/* Call identifier: 14 bits */
	conn->call_identifier = bits_to_uint(bits + n, 14); n += 14;

	/* Call timeout: 4 bits */
	conn->call_timeout = bits_to_uint(bits + n, 4); n += 4;

	/* Hook method selection: 1 bit */
	conn->hook_method_sel = bits_to_uint(bits + n, 1); n += 1;

	/* Simplex/duplex selection: 1 bit */
	conn->simplex_duplex = bits_to_uint(bits + n, 1); n += 1;

	/* Transmission grant: 2 bits */
	conn->transmission_grant = bits_to_uint(bits + n, 2); n += 2;

	/* Transmission request permission: 1 bit */
	conn->transmission_req_per = bits_to_uint(bits + n, 1); n += 1;

	/* Call ownership: 1 bit */
	conn->call_ownership = bits_to_uint(bits + n, 1); n += 1;

	/* Basic service information */
	bsi_len = cmce_decode_basic_service_info(&conn->basic_service, bits + n, len - n);
	if (bsi_len < 0)
		return -1;
	n += bsi_len;

	/* End to end encryption flag: 1 bit */
	if (n + 1 > len) goto done;
	conn->encryption_control = bits_to_uint(bits + n, 1); n += 1;

done:
	conn->valid = 1;
	return n;
}

/* Decode D-TX_GRANTED PDU (14.7.1.12)
 *
 * PDU structure (after 3-bit pdisc + 5-bit pdu_type):
 * - Call identifier: 14 bits
 * - Transmission grant: 2 bits
 * - Transmission request permission: 1 bit
 * - Encryption control: 1 bit
 * - Reserved: 1 bit
 * - Type2/3 elements
 */
int cmce_decode_d_tx_granted(struct tetra_cmce_d_tx_granted_decoded *txg, const uint8_t *bits, int len)
{
	int n = 0;

	if (!txg || !bits || len < 18)
		return -1;

	memset(txg, 0, sizeof(*txg));

	/* Call identifier: 14 bits */
	txg->call_identifier = bits_to_uint(bits + n, 14); n += 14;

	/* Transmission grant: 2 bits */
	txg->transmission_grant = bits_to_uint(bits + n, 2); n += 2;

	/* Transmission request permission: 1 bit */
	txg->transmission_req_per = bits_to_uint(bits + n, 1); n += 1;

	/* Encryption control: 1 bit */
	txg->encryption_control = bits_to_uint(bits + n, 1); n += 1;

	/* Reserved: 1 bit (skip) */
	if (n + 1 <= len) n += 1;

	txg->valid = 1;
	return n;
}

/* Decode D-RELEASE PDU (14.7.1.6)
 *
 * PDU structure (after 3-bit pdisc + 5-bit pdu_type):
 * - Call identifier: 14 bits
 * - Disconnect cause: 5 bits
 * - Type2/3 elements
 */
int cmce_decode_d_release(struct tetra_cmce_d_release_decoded *rel, const uint8_t *bits, int len)
{
	int n = 0;

	if (!rel || !bits || len < 19)
		return -1;

	memset(rel, 0, sizeof(*rel));

	/* Call identifier: 14 bits */
	rel->call_identifier = bits_to_uint(bits + n, 14); n += 14;

	/* Disconnect cause: 5 bits */
	rel->disconnect_cause = bits_to_uint(bits + n, 5); n += 5;

	rel->valid = 1;
	return n;
}

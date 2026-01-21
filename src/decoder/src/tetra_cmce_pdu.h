#ifndef TETRA_CMCE_PDU_H
#define TETRA_CMCE_PDU_H

#include "tetra_common.h"
#include <stdint.h>

/* 14.8.28 */
enum tetra_cmce_pdu_type_d {
	TCMCE_PDU_T_D_ALERT		= 0x00,
	TCMCE_PDU_T_D_CALL_PROCEEDING	= 0x01,
	TCMCE_PDU_T_D_CONNECT		= 0x02,
	TCMCE_PDU_T_D_CONNECT_ACK	= 0x03,
	TCMCE_PDU_T_D_DISCONNECT	= 0x04,
	TCMCE_PDU_T_D_INFO		= 0x05,
	TCMCE_PDU_T_D_RELEASE		= 0x06,
	TCMCE_PDU_T_D_SETUP		= 0x07,
	TCMCE_PDU_T_D_STATUS		= 0x08,
	TCMCE_PDU_T_D_TX_CEASED		= 0x09,
	TCMCE_PDU_T_D_TX_CONTINUE	= 0x0a,
	TCMCE_PDU_T_D_TX_GRANTED	= 0x0b,
	TCMCE_PDU_T_D_TX_WAIT		= 0x0c,
	TCMCE_PDU_T_D_TX_INTERRUPT	= 0x0d,
	TCMCE_PDU_T_D_CALL_RESTORE	= 0x0e,
	TCMCE_PDU_T_D_SDS_DATA		= 0x0f,
	TCMCE_PDU_T_D_FACILITY		= 0x10,
};

enum tetra_cmce_pdu_type_u {
	TCMCE_PDU_T_U_ALERT		= 0x00,
	/* reserved */
	TCMCE_PDU_T_U_CONNECT		= 0x02,
	/* reserved */
	TCMCE_PDU_T_U_DISCONNECT	= 0x04,
	TCMCE_PDU_T_U_INFO		= 0x05,
	TCMCE_PDU_T_U_RELEASE		= 0x06,
	TCMCE_PDU_T_U_SETUP		= 0x07,
	TCMCE_PDU_T_U_STATUS		= 0x08,
	TCMCE_PDU_T_U_TX_CEASED		= 0x09,
	TCMCE_PDU_T_U_TX_DEMAND		= 0x0a,
	/*reserved*/
	TCMCE_PDU_T_U_CALL_RESTORE	= 0x0e,
	TCMCE_PDU_T_U_SDS_DATA		= 0x0f,
	TCMCE_PDU_T_U_FACILITY		= 0x10,
	/*reserved*/
};

const char *tetra_get_cmce_pdut_name(uint16_t pdut, int uplink);

/* Basic Service Information element (14.8.4)
 * Contains circuit mode type, encryption flag, and communication type */
struct tetra_basic_service_info {
	uint8_t circuit_mode_type;    /* 4 bits */
	uint8_t encryption_flag;      /* 1 bit - THE CRITICAL FLAG */
	uint8_t communication_type;   /* 2 bits */
	uint8_t slots_per_frame;      /* 2 bits (for circuit mode) */
	uint8_t speech_service;       /* 4 bits (if circuit mode) */
};

/* D-SETUP decoded structure (14.7.1.8) */
struct tetra_cmce_d_setup_decoded {
	uint16_t call_identifier;     /* 14 bits */
	uint8_t call_timeout;         /* 4 bits */
	uint8_t hook_method_sel;      /* 1 bit */
	uint8_t simplex_duplex;       /* 1 bit */
	uint8_t call_priority;        /* 4 bits */
	uint8_t encryption_control;   /* 1 bit - CRITICAL FLAG */
	struct tetra_basic_service_info basic_service;
	uint8_t valid;                /* 1 if successfully decoded */
};

/* D-CONNECT decoded structure (14.7.1.3) */
struct tetra_cmce_d_connect_decoded {
	uint16_t call_identifier;     /* 14 bits */
	uint8_t call_timeout;         /* 4 bits */
	uint8_t hook_method_sel;      /* 1 bit */
	uint8_t simplex_duplex;       /* 1 bit */
	uint8_t transmission_grant;   /* 2 bits */
	uint8_t transmission_req_per; /* 1 bit */
	uint8_t call_ownership;       /* 1 bit */
	uint8_t encryption_control;   /* 1 bit - CRITICAL FLAG */
	struct tetra_basic_service_info basic_service;
	uint8_t valid;
};

/* D-TX_GRANTED decoded structure (14.7.1.12) */
struct tetra_cmce_d_tx_granted_decoded {
	uint16_t call_identifier;     /* 14 bits */
	uint8_t transmission_grant;   /* 2 bits */
	uint8_t transmission_req_per; /* 1 bit */
	uint8_t encryption_control;   /* 1 bit - CRITICAL FLAG */
	uint8_t valid;
};

/* D-RELEASE decoded structure (14.7.1.6) */
struct tetra_cmce_d_release_decoded {
	uint16_t call_identifier;     /* 14 bits */
	uint8_t disconnect_cause;     /* 5 bits */
	uint8_t valid;
};

/* Decode Basic Service Info element
 * bits: pointer to start of element
 * len: available bits
 * returns: number of bits consumed, or negative on error */
int cmce_decode_basic_service_info(struct tetra_basic_service_info *bsi, const uint8_t *bits, int len);

/* Decode D-SETUP PDU
 * bits: pointer to start of PDU (after protocol discriminator + PDU type)
 * len: available bits
 * returns: number of bits consumed, or negative on error */
int cmce_decode_d_setup(struct tetra_cmce_d_setup_decoded *setup, const uint8_t *bits, int len);

/* Decode D-CONNECT PDU */
int cmce_decode_d_connect(struct tetra_cmce_d_connect_decoded *conn, const uint8_t *bits, int len);

/* Decode D-TX_GRANTED PDU */
int cmce_decode_d_tx_granted(struct tetra_cmce_d_tx_granted_decoded *txg, const uint8_t *bits, int len);

/* Decode D-RELEASE PDU */
int cmce_decode_d_release(struct tetra_cmce_d_release_decoded *rel, const uint8_t *bits, int len);

#endif /* TETRA_CMCE_PDU_H */

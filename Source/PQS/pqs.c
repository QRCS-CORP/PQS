#include "pqs.h"
#include "logger.h"
#include "async.h"
#include "acp.h"
#include "encoding.h"
#include "intutils.h"
#include "memutils.h"
#include "stringutils.h"
#include "timestamp.h"

void pqs_connection_close(pqs_connection_state* cns, pqs_errors err, bool notify)
{
	PQS_ASSERT(cns != NULL);

	if (cns != NULL)
	{
		if (qsc_socket_is_connected(&cns->target) == true)
		{
			if (notify == true)
			{
				pqs_network_packet resp = { 0U };

				/* build a disconnect message */
				cns->txseq += 1U;
				resp.flag = pqs_flag_error_condition;
				resp.sequence = cns->txseq;
				resp.msglen = PQS_MACTAG_SIZE + 1U;

				pqs_packet_time_set(&resp);

				/* tunnel gets encrypted message */
				if (cns->exflag == pqs_flag_session_established)
				{
					uint8_t spct[PQS_HEADER_SIZE + PQS_MACTAG_SIZE + 1U] = { 0U };
					uint8_t pmsg[1U] = { 0U };

					resp.pmessage = spct + PQS_HEADER_SIZE;
					pqs_packet_header_serialize(&resp, spct);
					/* the error is the message */
					pmsg[0U] = (uint8_t)err;

					/* add the header to aad */
					pqs_cipher_set_associated(&cns->txcpr, spct, PQS_HEADER_SIZE);
					/* encrypt the message */
					pqs_cipher_transform(&cns->txcpr, resp.pmessage, pmsg, sizeof(pmsg));
					/* send the message */
					qsc_socket_send(&cns->target, spct, sizeof(spct), qsc_socket_send_flag_none);
				}
				else
				{
					/* pre-established phase */
					uint8_t spct[PQS_HEADER_SIZE + 1U] = { 0U };

					pqs_packet_header_serialize(&resp, spct);
					spct[PQS_HEADER_SIZE] = (uint8_t)err;
					/* send the message */
					qsc_socket_send(&cns->target, spct, sizeof(spct), qsc_socket_send_flag_none);
				}
			}

			/* close the socket */
			qsc_socket_close_socket(&cns->target);
		}
	}
}

bool pqs_decrypt_error_message(pqs_errors* merr, pqs_connection_state* cns, const uint8_t* message)
{
	PQS_ASSERT(merr != NULL);
	PQS_ASSERT(cns != NULL);
	PQS_ASSERT(message != NULL);

	pqs_network_packet pkt = { 0U };
	uint8_t dmsg[1U] = { 0U };
	const uint8_t* emsg;
	size_t mlen;
	pqs_errors err;
	bool res;

	mlen = 0U;
	res = false;
	err = pqs_error_invalid_input;

	if (cns->exflag == pqs_flag_session_established)
	{
		pqs_packet_header_deserialize(message, &pkt);
		emsg = message + PQS_HEADER_SIZE;

		if (cns != NULL && message != NULL)
		{
			cns->rxseq += 1;

			if (pkt.sequence == cns->rxseq)
			{
				if (cns->exflag == pqs_flag_session_established)
				{
					/* anti-replay; verify the packet time */
					if (pqs_packet_time_validate(&pkt) == true)
					{
						pqs_cipher_set_associated(&cns->rxcpr, message, PQS_HEADER_SIZE);
						mlen = pkt.msglen - PQS_MACTAG_SIZE;

						if (mlen == 1U)
						{
							/* authenticate then decrypt the data */
							if (pqs_cipher_transform(&cns->rxcpr, dmsg, emsg, mlen) == true)
							{
								err = (pqs_errors)dmsg[0U];
								res = true;
							}
						}
					}
				}
			}
		}
	}

	*merr = err;

	return res;
}

void pqs_connection_state_dispose(pqs_connection_state* cns)
{
	PQS_ASSERT(cns != NULL);

	if (cns != NULL)
	{
		pqs_cipher_dispose(&cns->rxcpr);
		pqs_cipher_dispose(&cns->txcpr);
		qsc_memutils_clear((uint8_t*)&cns->target, sizeof(qsc_socket));
		cns->cid = 0U;
		cns->rxseq = 0U;
		cns->txseq = 0U;
		cns->exflag = pqs_flag_none;
	}
}

const char* pqs_error_description(pqs_messages message)
{
	const char* dsc;

	dsc = NULL;

	if ((uint32_t)message < PQS_MESSAGE_STRING_DEPTH)
	{
		dsc = PQS_MESSAGE_STRINGS[(size_t)message];

	}

	return dsc;
}

const char* pqs_error_to_string(pqs_errors error)
{
	const char* dsc;

	dsc = NULL;

	if ((uint32_t)error < PQS_ERROR_STRING_DEPTH)
	{
		dsc = PQS_ERROR_STRINGS[(size_t)error];
	}

	return dsc;
}

void pqs_generate_keypair(pqs_client_verification_key* pubkey, pqs_server_signature_key* prikey, const uint8_t keyid[PQS_KEYID_SIZE])
{
	PQS_ASSERT(prikey != NULL);
	PQS_ASSERT(pubkey != NULL);

	if (prikey != NULL && pubkey != NULL)
	{
		/* add the timestamp plus duration to the key */
		prikey->expiration = qsc_timestamp_datetime_utc() + PQS_PUBKEY_DURATION_SECONDS;

		/* set the configuration string and key-identity strings */
		qsc_memutils_copy(prikey->config, PQS_CONFIG_STRING, PQS_CONFIG_SIZE);
		qsc_memutils_copy(prikey->keyid, keyid, PQS_KEYID_SIZE);

		/* generate the signature key-pair */
		pqs_signature_generate_keypair(prikey->verkey, prikey->sigkey, qsc_acp_generate);

		/* copy the key expiration, config, key-id, and the signatures verification key, to the public key structure */
		pubkey->expiration = prikey->expiration;
		qsc_memutils_copy(pubkey->config, prikey->config, PQS_CONFIG_SIZE);
		qsc_memutils_copy(pubkey->keyid, prikey->keyid, PQS_KEYID_SIZE);
		qsc_memutils_copy(pubkey->verkey, prikey->verkey, PQS_ASYMMETRIC_VERIFY_KEY_SIZE);
	}
}

void pqs_log_error(pqs_messages emsg, qsc_socket_exceptions err, const char* msg)
{
	PQS_ASSERT(msg != NULL);

	const char* pmsg;

	if (emsg != pqs_messages_none)
	{
		pmsg = pqs_error_description(emsg);

		if (pmsg != NULL)
		{
			if (msg != NULL)
			{
				char mtmp[PQS_ERROR_STRING_WIDTH * 2U] = { 0 };

				qsc_stringutils_copy_string(mtmp, sizeof(mtmp), pmsg);
				qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), msg);
				pqs_logger_write(mtmp);
			}
			else
			{
				pqs_logger_write(pmsg);
			}
		}
	}

	if (err != qsc_socket_exception_success)
	{
		const char* perr;
		const char* phdr;
		
		phdr = pqs_error_description(pqs_messages_socket_message);

		if (phdr != NULL)
		{
			pqs_logger_write(phdr);
		}

		perr = qsc_socket_error_to_string(err);

		if (perr != NULL)
		{
			pqs_logger_write(perr);
		}
	}
}

void pqs_log_message(pqs_messages emsg)
{
	const char* msg = pqs_error_description(emsg);

	if (msg != NULL)
	{
		pqs_logger_write(msg);
	}
}

void pqs_log_system_error(pqs_errors err)
{
	char mtmp[PQS_ERROR_STRING_WIDTH * 2U] = { 0 };
	const char* perr;
	const char* pmsg;

	perr = pqs_error_to_string(pqs_messages_system_message);
	pmsg = pqs_error_to_string(err);

	qsc_stringutils_copy_string(mtmp, sizeof(mtmp), perr);
	qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), ": ");
	qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), pmsg);

	pqs_logger_write(mtmp);
}

void pqs_log_write(pqs_messages emsg, const char* msg)
{
	PQS_ASSERT(msg != NULL);

	const char* pmsg = pqs_error_description(emsg);

	if (pmsg != NULL)
	{
		if (msg != NULL)
		{
			char mtmp[PQS_ERROR_STRING_WIDTH] = { 0 };

			qsc_stringutils_copy_string(mtmp, sizeof(mtmp), pmsg);
			qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), msg);
			pqs_logger_write(mtmp);
		}
		else
		{
			pqs_logger_write(pmsg);
		}
	}
}

void pqs_packet_clear(pqs_network_packet* packet)
{
	packet->flag = (uint8_t)pqs_flag_none;
	packet->msglen = 0U;
	packet->sequence = 0U;

	if (packet->msglen != 0U)
	{
		qsc_memutils_clear(packet->pmessage, packet->msglen);
	}
}

pqs_errors pqs_packet_decrypt(pqs_connection_state* cns, uint8_t* message, size_t* msglen, const pqs_network_packet* packetin)
{
	PQS_ASSERT(cns != NULL);
	PQS_ASSERT(packetin != NULL);
	PQS_ASSERT(message != NULL);
	PQS_ASSERT(msglen != NULL);

	uint8_t hdr[PQS_HEADER_SIZE] = { 0U };
	pqs_errors qerr;

	qerr = pqs_error_invalid_input;
	*msglen = 0U;

	if (cns != NULL && message != NULL && msglen != NULL && packetin != NULL)
	{
		cns->rxseq += 1;

		if (packetin->sequence == cns->rxseq)
		{
			if (cns->exflag == pqs_flag_session_established)
			{
				if (pqs_packet_time_validate(packetin) == true)
				{
					/* serialize the header and add it to the ciphers associated data */
					pqs_packet_header_serialize(packetin, hdr);

					pqs_cipher_set_associated(&cns->rxcpr, hdr, PQS_HEADER_SIZE);
					*msglen = packetin->msglen - PQS_MACTAG_SIZE;

					/* authenticate then decrypt the data */
					if (pqs_cipher_transform(&cns->rxcpr, message, packetin->pmessage, *msglen) == true)
					{
						qerr = pqs_error_none;
					}
					else
					{
						*msglen = 0U;
						qerr = pqs_error_authentication_failure;
					}
				}
				else
				{
					qerr = pqs_error_message_time_invalid;
				}
			}
			else
			{
				qerr = pqs_error_channel_down;
			}
		}
		else
		{
			qerr = pqs_error_packet_unsequenced;
		}
	}

	return qerr;
}

pqs_errors pqs_packet_encrypt(pqs_connection_state* cns, pqs_network_packet* packetout, const uint8_t* message, size_t msglen)
{
	PQS_ASSERT(cns != NULL);
	PQS_ASSERT(message != NULL);
	PQS_ASSERT(packetout != NULL);

	pqs_errors qerr;

	qerr = pqs_error_invalid_input;

	if (cns != NULL && message != NULL && packetout != NULL)
	{
		if (cns->exflag == pqs_flag_session_established && msglen != 0U)
		{
			uint8_t hdr[PQS_HEADER_SIZE] = { 0U };

			/* assemble the encryption packet */
			cns->txseq += 1U;
			pqs_packet_header_create(packetout, pqs_flag_encrypted_message, cns->txseq, (uint32_t)msglen + PQS_MACTAG_SIZE);

			/* serialize the header and add it to the ciphers associated data */
			pqs_packet_header_serialize(packetout, hdr);
			pqs_cipher_set_associated(&cns->txcpr, hdr, PQS_HEADER_SIZE);

			/* encrypt the message */
			pqs_cipher_transform(&cns->txcpr, packetout->pmessage, message, msglen);

			qerr = pqs_error_none;
		}
		else
		{
			qerr = pqs_error_channel_down;
		}
	}

	return qerr;
}

void pqs_packet_error_message(pqs_network_packet* packet, pqs_errors error)
{
	PQS_ASSERT(packet != NULL);

	if (packet != NULL)
	{
		packet->flag = pqs_flag_error_condition;
		packet->msglen = PQS_ERROR_MESSAGE_SIZE;
		packet->sequence = PQS_ERROR_SEQUENCE;
		packet->pmessage[0U] = (uint8_t)error;
	}
}

void pqs_packet_header_create(pqs_network_packet* packetout, pqs_flags flag, uint64_t sequence, uint32_t msglen)
{
	packetout->flag = flag;
	packetout->sequence = sequence;
	packetout->msglen = msglen;
	/* set the packet creation time */
	pqs_packet_time_set(packetout);
}

void pqs_packet_header_deserialize(const uint8_t* header, pqs_network_packet* packet)
{
	PQS_ASSERT(header != NULL);
	PQS_ASSERT(packet != NULL);

	if (header != NULL && packet != NULL)
	{
		size_t pos;

		packet->flag = header[0U];
		pos = PQS_FLAG_SIZE;
		packet->msglen = qsc_intutils_le8to32(header + pos);
		pos += PQS_MSGLEN_SIZE;
		packet->sequence = qsc_intutils_le8to64(header + pos);
		pos += PQS_SEQUENCE_SIZE;
		packet->utctime = qsc_intutils_le8to64(header + pos);
	}
}

void pqs_packet_header_serialize(const pqs_network_packet* packet, uint8_t* header)
{
	PQS_ASSERT(header != NULL);
	PQS_ASSERT(packet != NULL);

	if (header != NULL && packet != NULL)
	{
		size_t pos;

		header[0U] = packet->flag;
		pos = PQS_FLAG_SIZE;
		qsc_intutils_le32to8(header + pos, packet->msglen);
		pos += PQS_MSGLEN_SIZE;
		qsc_intutils_le64to8(header + pos, packet->sequence);
		pos += PQS_SEQUENCE_SIZE;
		qsc_intutils_le64to8(header + pos, packet->utctime);
	}
}

pqs_errors pqs_header_validate(pqs_connection_state* cns, const pqs_network_packet* packetin, pqs_flags kexflag, pqs_flags pktflag, uint64_t sequence, uint32_t msglen)
{
	pqs_errors merr;

	if (packetin->flag == pqs_flag_error_condition)
	{
		merr = (pqs_errors)packetin->pmessage[0U];
	}
	else
	{
		if (pqs_packet_time_validate(packetin) == true)
		{
			if (packetin->msglen == msglen)
			{
				if (packetin->sequence == sequence)
				{
					if (packetin->flag == pktflag)
					{
						if (cns->exflag == kexflag)
						{
							cns->rxseq += 1U;
							merr = pqs_error_none;
						}
						else
						{
							merr = pqs_error_invalid_request;
						}
					}
					else
					{
						merr = pqs_error_invalid_request;
					}
				}
				else
				{
					merr = pqs_error_packet_unsequenced;
				}
			}
			else
			{
				merr = pqs_error_receive_failure;
			}
		}
		else
		{
			merr = pqs_error_message_time_invalid;
		}
	}

	return merr;
}

void pqs_packet_time_set(pqs_network_packet* packet)
{
	packet->utctime = qsc_timestamp_datetime_utc();
}

bool pqs_packet_time_validate(const pqs_network_packet* packet)
{
	uint64_t ltime;

	ltime = qsc_timestamp_datetime_utc();

	return (ltime >= packet->utctime - PQS_PACKET_TIME_THRESHOLD && ltime <= packet->utctime + PQS_PACKET_TIME_THRESHOLD);
}

size_t pqs_packet_to_stream(const pqs_network_packet* packet, uint8_t* pstream)
{
	PQS_ASSERT(packet != NULL);
	PQS_ASSERT(pstream != NULL);

	size_t pos;
	size_t res;

	res = 0U;

	if (packet != NULL && pstream != NULL)
	{
		pstream[0U] = packet->flag;
		pos = PQS_FLAG_SIZE;
		qsc_intutils_le32to8(pstream + pos, packet->msglen);
		pos += PQS_MSGLEN_SIZE;
		qsc_intutils_le64to8(pstream + pos, packet->sequence);
		pos += PQS_SEQUENCE_SIZE;
		qsc_intutils_le64to8(pstream + pos, packet->utctime);
		pos += PQS_TIMESTAMP_SIZE;
		qsc_memutils_copy(pstream + pos, packet->pmessage, packet->msglen);
		res = (size_t)PQS_HEADER_SIZE + packet->msglen;
	}

	return res;
}

bool pqs_public_key_decode(pqs_client_verification_key* pubk, const char enck[PQS_PUBKEY_STRING_SIZE])
{
	PQS_ASSERT(pubk != NULL);

	char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
	char tmpvk[PQS_PUBKEY_ENCODING_SIZE] = { 0 };
	size_t spos;
	size_t slen;
	bool res;

	res = false;

	if (pubk != NULL)
	{
		spos = sizeof(PQS_PUBKEY_HEADER) + sizeof(PQS_PUBKEY_VERSION) + sizeof(PQS_PUBKEY_CONFIG_PREFIX) - 1U;
		slen = PQS_CONFIG_SIZE - 1U;
		qsc_memutils_copy(pubk->config, (enck + spos), slen);

		spos += slen + sizeof(PQS_PUBKEY_EXPIRATION_PREFIX) - 3U;
		qsc_intutils_hex_to_bin((enck + spos), pubk->keyid, PQS_KEYID_SIZE * 2U);

		spos += (PQS_KEYID_SIZE * 2) + sizeof(PQS_PUBKEY_EXPIRATION_PREFIX);
		slen = QSC_TIMESTAMP_STRING_SIZE - 1U;
		qsc_memutils_copy(dtm, (enck + spos), slen);

		pubk->expiration = qsc_timestamp_datetime_to_seconds(dtm);
		spos += QSC_TIMESTAMP_STRING_SIZE;

		qsc_stringutils_remove_line_breaks(tmpvk, sizeof(tmpvk), (enck + spos), (PQS_PUBKEY_STRING_SIZE - (spos + sizeof(PQS_PUBKEY_FOOTER))));
		res = qsc_encoding_base64_decode(pubk->verkey, PQS_ASYMMETRIC_VERIFY_KEY_SIZE, tmpvk, PQS_PUBKEY_ENCODING_SIZE);
	}

	return res;
}

void pqs_public_key_encode(char enck[PQS_PUBKEY_STRING_SIZE], const pqs_client_verification_key* pubkey)
{
	PQS_ASSERT(pubkey != NULL);

	char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
	char hexid[(PQS_KEYID_SIZE * 2)] = { 0 };
	char tmpvk[PQS_PUBKEY_ENCODING_SIZE] = { 0 };
	size_t slen;
	size_t spos;

	if (pubkey != NULL)
	{
		slen = sizeof(PQS_PUBKEY_HEADER) - 1U;
		qsc_memutils_copy(enck, PQS_PUBKEY_HEADER, slen);
		spos = slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(PQS_PUBKEY_VERSION) - 1U;
		qsc_memutils_copy((enck + spos), PQS_PUBKEY_VERSION, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(PQS_PUBKEY_CONFIG_PREFIX) - 1U;
		qsc_memutils_copy((enck + spos), PQS_PUBKEY_CONFIG_PREFIX, slen);
		spos += slen;
		slen = sizeof(PQS_CONFIG_STRING) - 1U;
		qsc_memutils_copy((enck + spos), PQS_CONFIG_STRING, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(PQS_PUBKEY_KEYID_PREFIX) - 1U;
		qsc_memutils_copy((enck + spos), PQS_PUBKEY_KEYID_PREFIX, slen);
		spos += slen;
		qsc_intutils_bin_to_hex(pubkey->keyid, hexid, PQS_KEYID_SIZE);
		slen = sizeof(hexid);
		qsc_memutils_copy((enck + spos), hexid, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(PQS_PUBKEY_EXPIRATION_PREFIX) - 1U;
		qsc_memutils_copy((enck + spos), PQS_PUBKEY_EXPIRATION_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(pubkey->expiration, dtm);
		slen = sizeof(dtm) - 1U;
		qsc_memutils_copy((enck + spos), dtm, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		//size_t enclen = qsc_encoding_base64_encoded_size(sizeof(pubkey->verkey));
		slen = PQS_ASYMMETRIC_VERIFY_KEY_SIZE;
		qsc_encoding_base64_encode(tmpvk, PQS_PUBKEY_ENCODING_SIZE, pubkey->verkey, slen);
		spos += qsc_stringutils_add_line_breaks((enck + spos), PQS_PUBKEY_STRING_SIZE - spos, PQS_PUBKEY_LINE_LENGTH, tmpvk, sizeof(tmpvk));
		enck[spos] = '\n';
		++spos;

		slen = sizeof(PQS_PUBKEY_FOOTER) - 1U;
		qsc_memutils_copy((enck + spos), PQS_PUBKEY_FOOTER, slen);
		spos += slen;
		enck[spos] = '\n';
	}
}

void pqs_public_key_hash(uint8_t* hash, const pqs_client_verification_key* pubk)
{
	qsc_keccak_state ctx = { 0 };
	uint8_t exp[PQS_TIMESTAMP_SIZE] = { 0U };

	qsc_intutils_le64to8(exp, pubk->expiration);

	qsc_sha3_initialize(&ctx);
	qsc_sha3_update(&ctx, qsc_keccak_rate_256, pubk->config, PQS_CONFIG_SIZE);
	qsc_sha3_update(&ctx, qsc_keccak_rate_256, exp, PQS_TIMESTAMP_SIZE);
	qsc_sha3_update(&ctx, qsc_keccak_rate_256, pubk->keyid, PQS_KEYID_SIZE);
	qsc_sha3_update(&ctx, qsc_keccak_rate_256, pubk->verkey, PQS_ASYMMETRIC_VERIFY_KEY_SIZE);
	qsc_sha3_finalize(&ctx, qsc_keccak_rate_256, hash);
}

void pqs_signature_key_deserialize(pqs_server_signature_key* kset, const uint8_t serk[PQS_SIGKEY_ENCODED_SIZE])
{
	PQS_ASSERT(kset != NULL);

	size_t pos;

	qsc_memutils_copy(kset->config, serk, PQS_CONFIG_SIZE);
	pos = PQS_CONFIG_SIZE;
	kset->expiration = qsc_intutils_le8to64((serk + pos));
	pos += PQS_TIMESTAMP_SIZE;
	qsc_memutils_copy(kset->keyid, (serk + pos), PQS_KEYID_SIZE);
	pos += PQS_KEYID_SIZE;
	qsc_memutils_copy(kset->rkhash, (serk + pos), PQS_HASH_SIZE);
	pos += PQS_HASH_SIZE;
	qsc_memutils_copy(kset->sigkey, (serk + pos), PQS_ASYMMETRIC_SIGNING_KEY_SIZE);
	pos += PQS_ASYMMETRIC_SIGNING_KEY_SIZE;
	qsc_memutils_copy(kset->verkey, (serk + pos), PQS_ASYMMETRIC_VERIFY_KEY_SIZE);
}

void pqs_signature_key_serialize(uint8_t serk[PQS_SIGKEY_ENCODED_SIZE], const pqs_server_signature_key* kset)
{
	PQS_ASSERT(kset != NULL);

	size_t pos;

	qsc_memutils_copy(serk, kset->config, PQS_CONFIG_SIZE);
	pos = PQS_CONFIG_SIZE;
	qsc_intutils_le64to8((serk + pos), kset->expiration);
	pos += PQS_TIMESTAMP_SIZE;
	qsc_memutils_copy((serk + pos), kset->keyid, PQS_KEYID_SIZE);
	pos += PQS_KEYID_SIZE;
	qsc_memutils_copy((serk + pos), kset->rkhash, PQS_HASH_SIZE);
	pos += PQS_HASH_SIZE;
	qsc_memutils_copy((serk + pos), kset->sigkey, PQS_ASYMMETRIC_SIGNING_KEY_SIZE);
	pos += PQS_ASYMMETRIC_SIGNING_KEY_SIZE;
	qsc_memutils_copy((serk + pos), kset->verkey, PQS_ASYMMETRIC_VERIFY_KEY_SIZE);
}

void pqs_stream_to_packet(const uint8_t* pstream, pqs_network_packet* packet)
{
	PQS_ASSERT(packet != NULL);
	PQS_ASSERT(pstream != NULL);

	size_t pos;

	if (packet != NULL && pstream != NULL)
	{
		packet->flag = pstream[0U];
		pos = PQS_FLAG_SIZE;
		packet->msglen = qsc_intutils_le8to32(pstream + pos);
		pos += PQS_MSGLEN_SIZE;
		packet->sequence = qsc_intutils_le8to64(pstream + pos);
		pos += PQS_SEQUENCE_SIZE;
		packet->utctime = qsc_intutils_le8to64(pstream + pos);
		pos += PQS_TIMESTAMP_SIZE;
		qsc_memutils_copy(packet->pmessage, pstream + pos, packet->msglen);
	}
}

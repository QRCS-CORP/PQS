#include "kex.h"
#include "../../QSC/QSC/acp.h"
#include "../../QSC/QSC/encoding.h"
#include "../../QSC/QSC/intutils.h"
#include "../../QSC/QSC/memutils.h"
#include "../../QSC/QSC/rcs.h"
#include "../../QSC/QSC/sha3.h"
#include "../../QSC/QSC/socketserver.h"
#include "../../QSC/QSC/stringutils.h"
#include "../../QSC/QSC/timestamp.h"

/** \cond DOXYGEN_IGNORE */
#define KEX_CONNECT_REQUEST_MESSAGE_SIZE (PQS_KEYID_SIZE + PQS_CONFIG_SIZE)
#define KEX_CONNECT_REQUEST_PACKET_SIZE (PQS_HEADER_SIZE + KEX_CONNECT_REQUEST_MESSAGE_SIZE)
#define KEX_CONNECT_RESPONSE_MESSAGE_SIZE (PQS_ASYMMETRIC_PUBLIC_KEY_SIZE + PQS_HASH_SIZE + PQS_ASYMMETRIC_SIGNATURE_SIZE)
#define KEX_CONNECT_RESPONSE_PACKET_SIZE (PQS_HEADER_SIZE + KEX_CONNECT_RESPONSE_MESSAGE_SIZE)

#define KEX_EXCHANGE_REQUEST_MESSAGE_SIZE (PQS_ASYMMETRIC_CIPHER_TEXT_SIZE)
#define KEX_EXCHANGE_REQUEST_PACKET_SIZE (PQS_HEADER_SIZE + KEX_EXCHANGE_REQUEST_MESSAGE_SIZE)
#define KEX_EXCHANGE_RESPONSE_MESSAGE_SIZE (0)
#define KEX_EXCHANGE_RESPONSE_PACKET_SIZE (PQS_HEADER_SIZE + KEX_EXCHANGE_RESPONSE_MESSAGE_SIZE)
/** \endcond DOXYGEN_IGNORE */

/** \cond DOXYGEN_IGNORE */
static void kex_subheader_serialize(uint8_t* pstream, const pqs_network_packet* packetin)
{
	qsc_intutils_le64to8(pstream, packetin->sequence);
	qsc_intutils_le64to8(pstream + sizeof(uint64_t), packetin->utctime);
}

static void kex_send_network_error(const qsc_socket* sock, pqs_errors error)
{
	assert(sock != NULL);

	if (qsc_socket_is_connected(sock) == true)
	{
		pqs_network_packet resp = { 0 };
		uint8_t spct[PQS_HEADER_SIZE + PQS_ERROR_MESSAGE_SIZE] = { 0 };

		resp.pmessage = spct + PQS_HEADER_SIZE;
		pqs_packet_error_message(&resp, error);
		pqs_packet_header_serialize(&resp, spct);
		qsc_socket_send(sock, spct, sizeof(spct), qsc_socket_send_flag_none);
	}
}

static void kex_client_reset(pqs_kex_client_state* kcs)
{
	assert(kcs != NULL);

	if (kcs != NULL)
	{
		qsc_memutils_clear(kcs->keyid, PQS_KEYID_SIZE);
		qsc_memutils_clear(kcs->schash, PQS_SCHASH_SIZE);
		qsc_memutils_clear(kcs->verkey, PQS_ASYMMETRIC_VERIFY_KEY_SIZE);
		kcs->expiration = 0;
	}
}

static bool kex_server_keyid_verify(const uint8_t* keyid, const uint8_t* message)
{
	bool res;

	res = (qsc_intutils_verify(keyid, message, PQS_KEYID_SIZE) == 0);

	return res;
}

static void kex_server_reset(pqs_kex_server_state* kss)
{
	assert(kss != NULL);

	if (kss != NULL)
	{
		qsc_memutils_clear(kss->keyid, PQS_KEYID_SIZE);
		qsc_memutils_clear(kss->schash, PQS_SCHASH_SIZE);
		qsc_memutils_clear(kss->prikey, PQS_ASYMMETRIC_PRIVATE_KEY_SIZE);
		qsc_memutils_clear(kss->pubkey, PQS_ASYMMETRIC_PUBLIC_KEY_SIZE);
		qsc_memutils_clear(kss->sigkey, PQS_ASYMMETRIC_SIGNING_KEY_SIZE);
		qsc_memutils_clear(kss->verkey, PQS_ASYMMETRIC_VERIFY_KEY_SIZE);
		kss->expiration = 0;
	}
}

/*
The client sends a connection request with its configuration string, and asymmetric public signature key identity.
The key identity (kid) is a multi-part 16-byte address and key identification array, 
used to match the intended target to the corresponding key. 
The configuration string defines the cryptographic protocol set being used, these must be identical.
The client stores a hash of the configuration string, the key id, 
and of the servers public asymmetric signature verification-key, which is used as a session cookie during the exchange.
sch <- H(cfg || kid || pvk)
The client sends the key identity string, and the configuration string to the server.
C{ kid, cfg }-> S
*/
static pqs_errors kex_client_connect_request(pqs_kex_client_state* kcs, pqs_connection_state* cns, pqs_network_packet* packetout)
{
	assert(kcs != NULL);
	assert(cns != NULL);
	assert(packetout != NULL);

	pqs_errors qerr;

	if (kcs != NULL && packetout != NULL)
	{
		uint64_t tm;

		tm = qsc_timestamp_datetime_utc();

		if (tm <= kcs->expiration)
		{
			qsc_keccak_state kstate = { 0 };

			/* copy the key-id and configuration string to the message */
			qsc_memutils_copy(packetout->pmessage, kcs->keyid, PQS_KEYID_SIZE);
			qsc_memutils_copy(((uint8_t*)packetout->pmessage + PQS_KEYID_SIZE), PQS_CONFIG_STRING, PQS_CONFIG_SIZE);
			/* assemble the connection-request packet */
			pqs_packet_header_create(packetout, pqs_flag_connect_request, cns->txseq, KEX_CONNECT_REQUEST_MESSAGE_SIZE);

			/* store a hash of the configuration string, and the public signature key: pkh = H(cfg || pvk) */
			qsc_memutils_clear(kcs->schash, PQS_SCHASH_SIZE);
			qsc_sha3_initialize(&kstate);
			qsc_sha3_update(&kstate, qsc_keccak_rate_256, (const uint8_t*)PQS_CONFIG_STRING, PQS_CONFIG_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_256, kcs->keyid, PQS_KEYID_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_256, kcs->verkey, PQS_ASYMMETRIC_VERIFY_KEY_SIZE);
			qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, kcs->schash);

			qerr = pqs_error_none;
			cns->exflag = pqs_flag_connect_request;
		}
		else
		{
			cns->exflag = pqs_flag_none;
			qerr = pqs_error_key_expired;
		}
	}
	else
	{
		cns->exflag = pqs_flag_none;
		qerr = pqs_error_invalid_input;
	}

	return qerr;
}

/*
Exchange Request:
The client verifies the signature of the hash, then generates its own hash of the public key, 
and compares it with the one contained in the message. 
If the hash matches, the client uses the public-key to encapsulate a shared secret.
cond <- AVpk(H(pk)) = (true ?= pk : 0)
cpt, sec <- AEpk(sec)
The client combines the secret and the session cookie to create the session keys, and two unique nonce, 
one key-nonce pair for each channel of the communications stream.
k1, k2, n1, n2 <- KDF(sec, sch)
The receive and transmit channel ciphers are initialized.
cprrx(k2,n2)
cprtx(k1,n1)
The client sends the cipher-text to the server.
C{ cpt } -> S
*/
static pqs_errors kex_client_exchange_request(const pqs_kex_client_state* kcs, pqs_connection_state* cns, const pqs_network_packet* packetin, pqs_network_packet* packetout)
{
	assert(kcs != NULL);
	assert(cns != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	uint8_t khash[PQS_SCHASH_SIZE] = { 0 };
	size_t mlen;
	size_t slen;
	pqs_errors qerr;

	if (kcs != NULL && packetin != NULL && packetout != NULL)
	{
		slen = 0;
		mlen = PQS_ASYMMETRIC_SIGNATURE_SIZE + PQS_HASH_SIZE;

		/* verify the asymmetric signature */
		if (pqs_signature_verify(khash, &slen, packetin->pmessage, mlen, kcs->verkey) == true)
		{
			qsc_keccak_state kstate = { 0 };
			uint8_t phash[PQS_HASH_SIZE] = { 0 };
			uint8_t shdr[PQS_HEADER_SIZE] = { 0 };
			uint8_t ssec[PQS_SECRET_SIZE] = { 0 };
			const uint8_t* pubk = packetin->pmessage + mlen;

			pqs_packet_header_serialize(packetin, shdr);

			/* version 1.2 hash the header and public encapsulation key */
			qsc_sha3_initialize(&kstate);
			qsc_sha3_update(&kstate, qsc_keccak_rate_256, shdr, PQS_HEADER_SIZE);
			qsc_sha3_update(&kstate, qsc_keccak_rate_256, pubk, PQS_ASYMMETRIC_PUBLIC_KEY_SIZE);
			qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, phash);

			//qsc_sha3_compute256(phash, pubk, PQS_ASYMMETRIC_PUBLIC_KEY_SIZE);

			/* verify the public key hash */
			if (qsc_intutils_verify(phash, khash, PQS_HASH_SIZE) == 0)
			{
				uint8_t prnd[(QSC_KECCAK_256_RATE * 2)] = { 0 };

				/* generate, and encapsulate the secret */

				/* store the cipher-text in the message */
				pqs_cipher_encapsulate(ssec, packetout->pmessage, pubk, qsc_acp_generate);

				/* assemble the exchange-request packet */
				pqs_packet_header_create(packetout, pqs_flag_exchange_request, cns->txseq, KEX_EXCHANGE_REQUEST_MESSAGE_SIZE);

				/* initialize cSHAKE k = H(sec, sch) */
				qsc_cshake_initialize(&kstate, qsc_keccak_rate_256, ssec, PQS_SECRET_SIZE, kcs->schash, PQS_SCHASH_SIZE, NULL, 0);
				qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_256, prnd, 2);

				/* initialize the symmetric cipher, and raise client channel-1 tx */
				qsc_rcs_keyparams kp1;
				kp1.key = prnd;
				kp1.keylen = PQS_SYMMETRIC_KEY_SIZE;
				kp1.nonce = prnd + PQS_SYMMETRIC_KEY_SIZE;
				kp1.info = NULL;
				kp1.infolen = 0;
				qsc_rcs_initialize(&cns->txcpr, &kp1, true);

				/* initialize the symmetric cipher, and raise client channel-1 rx */
				qsc_rcs_keyparams kp2;
				kp2.key = prnd + PQS_SYMMETRIC_KEY_SIZE + PQS_NONCE_SIZE;
				kp2.keylen = PQS_SYMMETRIC_KEY_SIZE;
				kp2.nonce = prnd + PQS_SYMMETRIC_KEY_SIZE + PQS_NONCE_SIZE + PQS_SYMMETRIC_KEY_SIZE;
				kp2.info = NULL;
				kp2.infolen = 0;
				qsc_rcs_initialize(&cns->rxcpr, &kp2, false);

				cns->exflag = pqs_flag_exchange_request;
				qerr = pqs_error_none;
			}
			else
			{
				cns->exflag = pqs_flag_none;
				qerr = pqs_error_hash_invalid;
			}
		}
		else
		{
			cns->exflag = pqs_flag_none;
			qerr = pqs_error_authentication_failure;
		}
	}
	else
	{
		cns->exflag = pqs_flag_none;
		qerr = pqs_error_invalid_input;
	}

	return qerr;
}

/*
Establish Verify:
The client checks the flag of the exchange response packet sent by the server. 
If the flag is set to indicate an error state, the tunnel is torn down on both sides,
otherwise the client tunnel is established and in an operational state.
The client sets the operational state to session established, and is now ready to process data.
*/
static pqs_errors kex_client_establish_verify(const pqs_kex_client_state* kcs, pqs_connection_state* cns, const pqs_network_packet* packetin)
{
	assert(kcs != NULL);
	assert(cns != NULL);
	assert(packetin != NULL);

	pqs_errors qerr;

	if (kcs != NULL && packetin != NULL)
	{
		cns->exflag = pqs_flag_session_established;
		qerr = pqs_error_none;
	}
	else
	{
		cns->exflag = pqs_flag_none;
		qerr = pqs_error_invalid_input;
	}

	return qerr;
}

/*
Connect Response:
The server responds with either an error message, or a response packet. 
Any error during the key exchange will generate an error-packet sent to the remote host, 
which will trigger a tear down of the session, and network connection on both sides.
The server first checks that it has the requested asymmetric signature verification key corresponding to that host 
using the key-identity array, then verifies that it has a compatible protocol configuration. 
The server stores a hash of the configuration string, key id, and the public signature verification-key, to create the session cookie hash.
sch <- H(cfg || kid || pvk)
The server then generates an asymmetric encryption key-pair, stores the private key, hashes the public encapsulation key, and then signs the hash of the public encapsulation key using the asymmetric signature key. The public signature verification key can itself be signed by a ‘chain of trust’ model, like X.509, using a signature verification extension to this protocol. 
pk, sk <- AG(cfg)
pkh <- H(pk)
spkh <- ASsk(pkh)
The server sends a connect response message containing a signed hash of the public asymmetric encapsulation-key, and a copy of that key.
S{ spkh, pk } -> C
*/
static pqs_errors kex_server_connect_response(pqs_kex_server_state* kss, pqs_connection_state* cns, const pqs_network_packet* packetin, pqs_network_packet* packetout)
{
	assert(kss != NULL);
	assert(cns != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	char confs[PQS_CONFIG_SIZE + 1] = { 0 };
	uint8_t phash[PQS_HASH_SIZE] = { 0 };
	qsc_keccak_state kstate = { 0 };
	pqs_errors qerr;
	uint64_t tm;
	size_t mlen;

	qerr = pqs_error_invalid_input;

	if (cns != NULL && kss != NULL && packetin != NULL && packetout != NULL)
	{
		/* compare the state key-id to the id in the message */
		if (kex_server_keyid_verify(kss->keyid, packetin->pmessage) == true)
		{
			tm = qsc_timestamp_datetime_utc();

			/* check the keys expiration date */
			if (tm <= kss->expiration)
			{
				/* get a copy of the configuration string */
				qsc_memutils_copy(confs, (packetin->pmessage + PQS_KEYID_SIZE), PQS_CONFIG_SIZE);

				/* compare the state configuration string to the message configuration string */
				if (qsc_stringutils_compare_strings(confs, PQS_CONFIG_STRING, PQS_CONFIG_SIZE) == true)
				{
					uint8_t shdr[PQS_HEADER_SIZE] = { 0 };

					qsc_memutils_clear(kss->schash, PQS_SCHASH_SIZE);

					/* store a hash of the configuration string, and the public signature key: sch = H(cfg || pvk) */
					qsc_sha3_initialize(&kstate);
					qsc_sha3_update(&kstate, qsc_keccak_rate_256, (const uint8_t*)PQS_CONFIG_STRING, PQS_CONFIG_SIZE);
					qsc_sha3_update(&kstate, qsc_keccak_rate_256, kss->keyid, PQS_KEYID_SIZE);
					qsc_sha3_update(&kstate, qsc_keccak_rate_256, kss->verkey, PQS_ASYMMETRIC_VERIFY_KEY_SIZE);
					qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, kss->schash);

					/* initialize the packet and asymmetric encryption keys */
					qsc_memutils_clear(kss->pubkey, PQS_ASYMMETRIC_PUBLIC_KEY_SIZE);
					qsc_memutils_clear(kss->prikey, PQS_ASYMMETRIC_PRIVATE_KEY_SIZE);

					/* generate the asymmetric encryption key-pair */
					pqs_cipher_generate_keypair(kss->pubkey, kss->prikey, qsc_acp_generate);

					/* assemble the connection-response packet */
					pqs_packet_header_create(packetout, pqs_flag_connect_response, cns->txseq, KEX_CONNECT_RESPONSE_MESSAGE_SIZE);
					pqs_packet_header_serialize(packetout, shdr);

					/* version 1.2 hash the header and public encapsulation key */
					qsc_sha3_initialize(&kstate);
					qsc_sha3_update(&kstate, qsc_keccak_rate_256, shdr, PQS_HEADER_SIZE);
					qsc_sha3_update(&kstate, qsc_keccak_rate_256, kss->pubkey, PQS_ASYMMETRIC_PUBLIC_KEY_SIZE);
					qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, phash);

					/* sign the hash and add it to the message */
					mlen = 0;
					pqs_signature_sign(packetout->pmessage, &mlen, phash, PQS_HASH_SIZE, kss->sigkey, qsc_acp_generate);

					/* copy the public key to the message */
					qsc_memutils_copy(((uint8_t*)packetout->pmessage + mlen), kss->pubkey, PQS_ASYMMETRIC_PUBLIC_KEY_SIZE);

					qerr = pqs_error_none;
					cns->exflag = pqs_flag_connect_response;
				}
				else
				{
					qerr = pqs_error_unknown_protocol;
				}
			}
			else
			{
				qerr = pqs_error_key_expired;
			}
		}
		else
		{
			qerr = pqs_error_key_unrecognized;
		}
	}

	return qerr;
}

/*
Exchange Response:
The server decapsulates the shared-secret.
sec <- -AEsk(cpt)
The server combines the shared secret and the session cookie hash to create two session keys, 
and two unique nonce, one key-nonce pair for each channel of the communications stream.
k1, k2, n1, n2 <- KDF(sec, sch)
The receive and transmit channel ciphers are initialized.
cprrx(k1,n1)
cprtx(k2,n2)
The server sets the packet flag to exchange response, indicating that the encrypted channels have been raised, 
and sends the notification to the client. The server sets the operational state to session established, 
and is now ready to process data.
S{ f } -> C
*/
static pqs_errors kex_server_exchange_response(const pqs_kex_server_state* kss, pqs_connection_state* cns, const pqs_network_packet* packetin, pqs_network_packet* packetout)
{
	assert(kss != NULL);
	assert(cns != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	pqs_errors qerr;

	if (kss != NULL && packetin != NULL && packetout != NULL)
	{
		uint8_t ssec[PQS_SECRET_SIZE] = { 0 };

		/* decapsulate the shared secret */
		if (pqs_cipher_decapsulate(ssec, packetin->pmessage, kss->prikey) == true)
		{
			qsc_keccak_state kstate = { 0 };
			uint8_t prnd[(QSC_KECCAK_256_RATE * 2)] = { 0 };

			/* initialize cSHAKE k = H(ssec, sch) */
			qsc_cshake_initialize(&kstate, qsc_keccak_rate_256, ssec, sizeof(ssec), kss->schash, PQS_SCHASH_SIZE, NULL, 0);
			qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_256, prnd, 2);

			/* initialize the symmetric cipher, and raise client channel-1 tx */
			qsc_rcs_keyparams kp1;
			kp1.key = prnd;
			kp1.keylen = PQS_SYMMETRIC_KEY_SIZE;
			kp1.nonce = prnd + PQS_SYMMETRIC_KEY_SIZE;
			kp1.info = NULL;
			kp1.infolen = 0;
			qsc_rcs_initialize(&cns->rxcpr, &kp1, false);

			/* initialize the symmetric cipher, and raise client channel-1 rx */
			qsc_rcs_keyparams kp2;
			kp2.key = prnd + PQS_SYMMETRIC_KEY_SIZE + PQS_NONCE_SIZE;
			kp2.keylen = PQS_SYMMETRIC_KEY_SIZE;
			kp2.nonce = prnd + PQS_SYMMETRIC_KEY_SIZE + PQS_NONCE_SIZE + PQS_SYMMETRIC_KEY_SIZE;
			kp2.info = NULL;
			kp2.infolen = 0;
			qsc_rcs_initialize(&cns->txcpr, &kp2, true);

			/* assemble the exchange-response packet */
			pqs_packet_header_create(packetout, pqs_flag_exchange_response, cns->txseq, KEX_EXCHANGE_RESPONSE_MESSAGE_SIZE);

			qerr = pqs_error_none;
			cns->exflag = pqs_flag_session_established;
		}
		else
		{
			qerr = pqs_error_decapsulation_failure;
			cns->exflag = pqs_flag_none;
		}
	}
	else
	{
		cns->exflag = pqs_flag_none;
		qerr = pqs_error_invalid_input;
	}

	return qerr;
}
/** \endcond DOXYGEN_IGNORE */

pqs_errors pqs_kex_client_key_exchange(pqs_kex_client_state* kcs, pqs_connection_state* cns)
{
	assert(kcs != NULL);
	assert(cns != NULL);

	uint8_t* rbuf;
	uint8_t* sbuf;
	size_t rlen;
	size_t slen;
	pqs_errors qerr;

	if (kcs != NULL && cns != NULL)
	{
		sbuf = qsc_memutils_malloc(KEX_CONNECT_REQUEST_PACKET_SIZE);

		if (sbuf != NULL)
		{
			pqs_network_packet reqt = { 0 };

			/* create the connection request packet */
			qsc_memutils_clear(sbuf, KEX_CONNECT_REQUEST_PACKET_SIZE);
			reqt.pmessage = sbuf + PQS_HEADER_SIZE;

			qerr = kex_client_connect_request(kcs, cns, &reqt);
			pqs_packet_header_serialize(&reqt, sbuf);

			if (qerr == pqs_error_none)
			{
				/* send the connection request */
				slen = qsc_socket_send(&cns->target, sbuf, KEX_CONNECT_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

				if (slen == KEX_CONNECT_REQUEST_PACKET_SIZE)
				{
					cns->txseq += 1;
					rbuf = qsc_memutils_malloc(KEX_CONNECT_RESPONSE_PACKET_SIZE);

					if (rbuf != NULL)
					{
						pqs_network_packet resp = { 0 };

						qsc_memutils_clear(rbuf, KEX_CONNECT_RESPONSE_PACKET_SIZE);
						resp.pmessage = rbuf + PQS_HEADER_SIZE;

						/* blocking receive waits for server */
						rlen = qsc_socket_receive(&cns->target, rbuf, KEX_CONNECT_RESPONSE_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

						if (rlen == KEX_CONNECT_RESPONSE_PACKET_SIZE)
						{
							pqs_packet_header_deserialize(rbuf, &resp);
							qerr = pqs_header_validate(cns, &resp, pqs_flag_connect_request, pqs_flag_connect_response, cns->rxseq, KEX_CONNECT_RESPONSE_MESSAGE_SIZE);

							if (qerr == pqs_error_none)
							{
								sbuf = qsc_memutils_realloc(sbuf, KEX_EXCHANGE_REQUEST_PACKET_SIZE);

								if (sbuf != NULL)
								{
									/* clear the request packet */
									qsc_memutils_clear(sbuf, KEX_EXCHANGE_REQUEST_PACKET_SIZE);
									reqt.pmessage = sbuf + PQS_HEADER_SIZE;

									/* create the exstart request packet */
									qerr = kex_client_exchange_request(kcs, cns, &resp, &reqt);
									pqs_packet_header_serialize(&reqt, sbuf);
									
									if (qerr == pqs_error_none)
									{
										slen = qsc_socket_send(&cns->target, sbuf, KEX_EXCHANGE_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);
										/* clear the transmit buffer */
										qsc_memutils_clear(sbuf, KEX_EXCHANGE_REQUEST_PACKET_SIZE);

										if (slen == KEX_EXCHANGE_REQUEST_PACKET_SIZE)
										{
											cns->txseq += 1;
											rbuf = qsc_memutils_realloc(rbuf, KEX_EXCHANGE_RESPONSE_PACKET_SIZE);

											if (rbuf != NULL)
											{
												qsc_memutils_clear(rbuf, KEX_EXCHANGE_RESPONSE_PACKET_SIZE);
												resp.pmessage = rbuf + PQS_HEADER_SIZE;

												rlen = qsc_socket_receive(&cns->target, rbuf, KEX_EXCHANGE_RESPONSE_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

												if (rlen == KEX_EXCHANGE_RESPONSE_PACKET_SIZE)
												{
													pqs_packet_header_deserialize(rbuf, &resp);
													qerr = pqs_header_validate(cns, &resp, pqs_flag_exchange_request, pqs_flag_exchange_response, cns->rxseq, KEX_EXCHANGE_RESPONSE_MESSAGE_SIZE);

													if (qerr == pqs_error_none)
													{
														/* verify the exchange  */
														qerr = kex_client_establish_verify(kcs, cns, &resp);
														/* clear the transmit buffer */
														qsc_memutils_clear(rbuf, KEX_EXCHANGE_RESPONSE_PACKET_SIZE);
													}
													else
													{
														qerr = pqs_error_packet_unsequenced;
													}
												}
												else
												{
													qerr = pqs_error_receive_failure;
												}
											}
											else
											{
												qerr = pqs_error_memory_allocation;
											}
										}
										else
										{
											qerr = pqs_error_transmit_failure;
										}
									}
								}
								else
								{
									qerr = pqs_error_memory_allocation;
								}
							}
							else
							{
								qerr = pqs_error_packet_unsequenced;
							}
						}
						else
						{
							qerr = pqs_error_receive_failure;
						}

						qsc_memutils_alloc_free(rbuf);
					}
					else
					{
						qerr = pqs_error_memory_allocation;
					}
				}
				else
				{
					qerr = pqs_error_transmit_failure;
				}
			}

			qsc_memutils_alloc_free(sbuf);
		}
		else
		{
			qerr = pqs_error_memory_allocation;
		}

		kex_client_reset(kcs);

		if (qerr != pqs_error_none)
		{
			if (cns->target.connection_status == qsc_socket_state_connected)
			{
				kex_send_network_error(&cns->target, qerr);
				qsc_socket_shut_down(&cns->target, qsc_socket_shut_down_flag_both);
			}

			pqs_connection_state_dispose(cns);
		}
	}
	else
	{
		qerr = pqs_error_invalid_input;
	}

	return qerr;
}

pqs_errors pqs_kex_server_key_exchange(pqs_kex_server_state* kss, pqs_connection_state* cns)
{
	assert(kss != NULL);
	assert(cns != NULL);

	uint8_t* rbuf;
	uint8_t* sbuf;
	size_t rlen;
	size_t slen;
	pqs_errors qerr;

	rbuf = qsc_memutils_malloc(KEX_CONNECT_REQUEST_PACKET_SIZE);

	if (rbuf != NULL)
	{
		pqs_network_packet reqt = { 0 };

		qsc_memutils_clear(rbuf, KEX_CONNECT_REQUEST_PACKET_SIZE);
		reqt.pmessage = rbuf + PQS_HEADER_SIZE;

		/* blocking receive waits for client */
		rlen = qsc_socket_receive(&cns->target, rbuf, KEX_CONNECT_REQUEST_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

		if (rlen == KEX_CONNECT_REQUEST_PACKET_SIZE)
		{
			/* convert client request to packet */
			pqs_packet_header_deserialize(rbuf, &reqt);
			qerr = pqs_header_validate(cns, &reqt, pqs_flag_none, pqs_flag_connect_request, cns->rxseq, KEX_CONNECT_REQUEST_MESSAGE_SIZE);

			if (qerr == pqs_error_none)
			{
				pqs_network_packet resp = { 0 };

				sbuf = qsc_memutils_malloc(KEX_CONNECT_RESPONSE_PACKET_SIZE);

				if (sbuf != NULL)
				{
					qsc_memutils_clear(sbuf, KEX_CONNECT_RESPONSE_PACKET_SIZE);
					resp.pmessage = sbuf + PQS_HEADER_SIZE;

					/* create the connection response packet */
					qerr = kex_server_connect_response(kss, cns, &reqt, &resp);

					if (qerr == pqs_error_none)
					{
						pqs_packet_header_serialize(&resp, sbuf);
						slen = qsc_socket_send(&cns->target, sbuf, KEX_CONNECT_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

						if (slen == KEX_CONNECT_RESPONSE_PACKET_SIZE)
						{
							cns->txseq += 1;
							rbuf = qsc_memutils_realloc(rbuf, KEX_EXCHANGE_REQUEST_PACKET_SIZE);

							if (rbuf != NULL)
							{
								qsc_memutils_clear(rbuf, KEX_EXCHANGE_REQUEST_PACKET_SIZE);
								reqt.pmessage = rbuf + PQS_HEADER_SIZE;

								/* wait for the exchange request */
								rlen = qsc_socket_receive(&cns->target, rbuf, KEX_EXCHANGE_REQUEST_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

								if (rlen == KEX_EXCHANGE_REQUEST_PACKET_SIZE)
								{
									pqs_packet_header_deserialize(rbuf, &reqt);
									qerr = pqs_header_validate(cns, &reqt, pqs_flag_connect_response, pqs_flag_exchange_request, cns->rxseq, KEX_EXCHANGE_REQUEST_MESSAGE_SIZE);

									if (qerr == pqs_error_none)
									{
										qsc_memutils_clear(sbuf, KEX_EXCHANGE_RESPONSE_PACKET_SIZE);
										/* create the exchange response packet */
										qerr = kex_server_exchange_response(kss, cns, &reqt, &resp);
										/* clear the receive buffer */
										qsc_memutils_clear(rbuf, KEX_EXCHANGE_REQUEST_PACKET_SIZE);

										if (qerr == pqs_error_none)
										{
											pqs_packet_header_serialize(&resp, sbuf);
											/* send the exchange response */
											slen = qsc_socket_send(&cns->target, sbuf, KEX_EXCHANGE_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);
											/* clear the transmit buffer */
											qsc_memutils_clear(sbuf, KEX_EXCHANGE_RESPONSE_PACKET_SIZE);

											if (slen == KEX_EXCHANGE_RESPONSE_PACKET_SIZE)
											{
												cns->txseq += 1;
											}
											else
											{
												qerr = pqs_error_transmit_failure;
											}
										}
									}
								}
								else
								{
									qerr = pqs_error_receive_failure;
								}
							}
							else
							{
								qerr = pqs_error_memory_allocation;
							}
						}
						else
						{
							qerr = pqs_error_transmit_failure;
						}
					}

					qsc_memutils_alloc_free(sbuf);
				}
				else
				{
					qerr = pqs_error_memory_allocation;
				}
			}
			else
			{
				qerr = pqs_error_packet_unsequenced;
			}
		}
		else
		{
			qerr = pqs_error_receive_failure;
		}

		qsc_memutils_alloc_free(rbuf);
	}
	else
	{
		qerr = pqs_error_memory_allocation;
	}

	kex_server_reset(kss);

	if (qerr != pqs_error_none)
	{
		if (cns->target.connection_status == qsc_socket_state_connected)
		{
			kex_send_network_error(&cns->target, qerr);
			qsc_socket_shut_down(&cns->target, qsc_socket_shut_down_flag_both);
		}

		pqs_connection_state_dispose(cns);
	}

	return qerr;
}
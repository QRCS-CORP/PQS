#include "client.h"
#include "kex.h"
#include "logger.h"
#include "acp.h"
#include "async.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#include "socketserver.h"
#include "timestamp.h"

/** \cond DOXYGEN_IGNORE */
typedef struct client_receiver_state
{
	pqs_connection_state* pcns;
	void (*callback)(pqs_connection_state*, const uint8_t*, size_t);
} client_receiver_state;
/** \endcond DOXYGEN_IGNORE */

/* Private Functions */

/** \cond DOXYGEN_IGNORE */
static void client_state_initialize(pqs_kex_client_state* kcs, pqs_connection_state* cns, const pqs_client_verification_key* pubk)
{
	qsc_memutils_copy(kcs->keyid, pubk->keyid, PQS_KEYID_SIZE);
	qsc_memutils_copy(kcs->verkey, pubk->verkey, PQS_ASYMMETRIC_VERIFY_KEY_SIZE);
	kcs->expiration = pubk->expiration;
	pqs_cipher_dispose(&cns->rxcpr);
	pqs_cipher_dispose(&cns->txcpr);
	cns->exflag = pqs_flag_none;
	cns->cid = 0;
	cns->rxseq = 0;
	cns->txseq = 0;
}

static void client_receive_loop(client_receiver_state* prcv)
{
	assert(prcv != NULL);

	pqs_network_packet pkt = { 0 };
	char cadd[QSC_SOCKET_ADDRESS_MAX_SIZE] = { 0 };
	uint8_t* rbuf;
	size_t mlen;
	size_t plen;
	size_t slen;
	pqs_errors qerr;

	qsc_memutils_copy(cadd, (const char*)prcv->pcns->target.address, sizeof(cadd));

	rbuf = (uint8_t*)qsc_memutils_malloc(PQS_HEADER_SIZE);

	if (rbuf != NULL)
	{
		while (prcv->pcns->target.connection_status == qsc_socket_state_connected)
		{
			mlen = 0;
			slen = 0;
			qsc_memutils_clear(rbuf, PQS_HEADER_SIZE);

			plen = qsc_socket_peek(&prcv->pcns->target, rbuf, PQS_HEADER_SIZE);

			if (plen == PQS_HEADER_SIZE)
			{
				pqs_packet_header_deserialize(rbuf, &pkt);

				if (pkt.msglen > 0 && pkt.msglen <= PQS_MESSAGE_MAX)
				{
					plen = pkt.msglen + PQS_HEADER_SIZE;
					rbuf = (uint8_t*)qsc_memutils_realloc(rbuf, plen);

					if (rbuf != NULL)
					{
						qsc_memutils_clear(rbuf, plen);
						mlen = qsc_socket_receive(&prcv->pcns->target, rbuf, plen, qsc_socket_receive_flag_wait_all);

						if (mlen > 0)
						{
							pkt.pmessage = rbuf + PQS_HEADER_SIZE;

							if (pkt.flag == pqs_flag_encrypted_message)
							{
								uint8_t* mstr;

								slen = pkt.msglen + PQS_MACTAG_SIZE;
								mstr = (uint8_t*)qsc_memutils_malloc(slen);

								if (mstr != NULL)
								{
									qsc_memutils_clear(mstr, slen);
									qerr = pqs_packet_decrypt(prcv->pcns, mstr, &mlen, &pkt);

									if (qerr == pqs_error_none)
									{
										prcv->callback(prcv->pcns, mstr, mlen);
									}
									else
									{
										/* close the connection on authentication failure */
										pqs_log_write(pqs_messages_decryption_fail, cadd);
										break;
									}

									qsc_memutils_alloc_free(mstr);
								}
								else
								{
									/* close the connection on memory allocation failure */
									pqs_log_write(pqs_messages_allocate_fail, cadd);
									break;
								}
							}
							else if (pkt.flag == pqs_error_connection_refused)
							{
								pqs_log_write(pqs_messages_connection_refused, cadd);
								break;
							}
							else if (pkt.flag == pqs_flag_connection_terminate)
							{
								pqs_log_write(pqs_messages_disconnect, cadd);
								break;
							}
							else
							{
								qsc_socket_exceptions err = qsc_socket_get_last_error();

								if (err != qsc_socket_exception_success)
								{
									pqs_log_error(pqs_messages_receive_fail, err, cadd);

									/* fatal socket errors */
									if (err == qsc_socket_exception_circuit_reset ||
										err == qsc_socket_exception_circuit_terminated ||
										err == qsc_socket_exception_circuit_timeout ||
										err == qsc_socket_exception_dropped_connection ||
										err == qsc_socket_exception_network_failure ||
										err == qsc_socket_exception_shut_down)
									{
										pqs_log_write(pqs_messages_connection_fail, cadd);
										break;
									}
								}
							}
						}
						else
						{
							pqs_log_write(pqs_messages_receive_fail, cadd);
							break;
						}
					}
				}
				else
				{
					/* close the connection on memory allocation failure */
					pqs_log_write(pqs_messages_allocate_fail, cadd);
					break;
				}
			}
			else
			{
				pqs_log_write(pqs_messages_receive_fail, cadd);
				break;
			}
		}

		qsc_memutils_alloc_free(rbuf);
	}
	else
	{
		pqs_log_write(pqs_messages_allocate_fail, cadd);
	}
}

static void client_connection_dispose(client_receiver_state* prcv)
{
	/* send a close notification to the server */
	if (qsc_socket_is_connected(&prcv->pcns->target) == true)
	{
		pqs_connection_close(prcv->pcns, pqs_error_none, true);
	}

	/* dispose of resources */
	pqs_connection_state_dispose(prcv->pcns);
}
/** \endcond DOXYGEN_IGNORE */

/* Public Functions */

pqs_errors pqs_client_connect_ipv4(const pqs_client_verification_key* pubk, 
	const qsc_ipinfo_ipv4_address* address, uint16_t port, 
	void (*send_func)(pqs_connection_state*), 
	void (*receive_callback)(pqs_connection_state*, const uint8_t*, size_t))
{
	assert(pubk != NULL);
	assert(send_func != NULL);
	assert(send_func != NULL);
	assert(receive_callback != NULL);

	pqs_kex_client_state* kcs;
	client_receiver_state* prcv;
	qsc_socket_exceptions serr;
	pqs_errors qerr;

	kcs = NULL;
	prcv = NULL;
	pqs_logger_initialize(NULL);

	if (address != NULL && send_func != NULL && receive_callback != NULL)
	{
		kcs = (pqs_kex_client_state*)qsc_memutils_malloc(sizeof(pqs_kex_client_state));
		prcv = (client_receiver_state*)qsc_memutils_malloc(sizeof(client_receiver_state));

		if (kcs != NULL && prcv != NULL)
		{
			qsc_memutils_clear(kcs, sizeof(pqs_kex_client_state));
			qsc_memutils_clear(prcv, sizeof(client_receiver_state));

			prcv->pcns = (pqs_connection_state*)qsc_memutils_malloc(sizeof(pqs_connection_state));

			if (prcv->pcns != NULL)
			{
				prcv->callback = receive_callback;
				qsc_socket_client_initialize(&prcv->pcns->target);

				serr = qsc_socket_client_connect_ipv4(&prcv->pcns->target, address, port);

				if (serr == qsc_socket_exception_success)
				{
					/* initialize the client */
					client_state_initialize(kcs, prcv->pcns, pubk);
					/* perform the simplex key exchange */
					qerr = pqs_kex_client_key_exchange(kcs, prcv->pcns);
					qsc_memutils_alloc_free(kcs);
					kcs = NULL;

					if (qerr == pqs_error_none)
					{
						/* start the receive loop on a new thread */
						qsc_async_thread_create((void*)&client_receive_loop, prcv);

						/* start the send loop on the main thread */
						send_func(prcv->pcns);

						/* disconnect the socket */
						client_connection_dispose(prcv);
					}
					else
					{
						pqs_log_write(pqs_messages_kex_fail, (const char*)prcv->pcns->target.address);
						qerr = pqs_error_exchange_failure;
					}
				}
				else
				{
					pqs_log_write(pqs_messages_kex_fail, (const char*)prcv->pcns->target.address);
					qerr = pqs_error_connection_failure;
				}
			}
			else
			{
				pqs_log_message(pqs_messages_allocate_fail);
				qerr = pqs_error_memory_allocation;
			}
		}
		else
		{
			pqs_log_message(pqs_messages_allocate_fail);
			qerr = pqs_error_memory_allocation;
		}
	}
	else
	{
		pqs_log_message(pqs_messages_invalid_request);
		qerr = pqs_error_invalid_input;
	}

	if (kcs != NULL)
	{
		qsc_memutils_alloc_free(kcs);
		kcs = NULL;
	}

	if (prcv != NULL)
	{
		if (prcv->pcns != NULL)
		{
			qsc_memutils_alloc_free(prcv->pcns);
			prcv->pcns = NULL;
		}

		prcv->callback = NULL;
		qsc_memutils_alloc_free(prcv);
		prcv = NULL;
	}

	return qerr;
}

pqs_errors pqs_client_connect_ipv6(const pqs_client_verification_key* pubk, 
	const qsc_ipinfo_ipv6_address* address, uint16_t port, 
	void (*send_func)(pqs_connection_state*), 
	void (*receive_callback)(pqs_connection_state*, const uint8_t*, size_t))
{
	assert(pubk != NULL);
	assert(send_func != NULL);
	assert(send_func != NULL);
	assert(receive_callback != NULL);

	pqs_kex_client_state* kcs;
	client_receiver_state* prcv;
	qsc_socket_exceptions serr;
	pqs_errors qerr;

	kcs = NULL;
	prcv = NULL;
	pqs_logger_initialize(NULL);

	if (address != NULL && send_func != NULL && receive_callback != NULL)
	{
		kcs = (pqs_kex_client_state*)qsc_memutils_malloc(sizeof(pqs_kex_client_state));
		prcv = (client_receiver_state*)qsc_memutils_malloc(sizeof(client_receiver_state));

		if (kcs != NULL && prcv != NULL)
		{
			qsc_memutils_clear(kcs, sizeof(pqs_kex_client_state));
			qsc_memutils_clear(prcv, sizeof(client_receiver_state));

			prcv->pcns = (pqs_connection_state*)qsc_memutils_malloc(sizeof(pqs_connection_state));

			if (prcv->pcns != NULL)
			{
				prcv->callback = receive_callback;
				qsc_socket_client_initialize(&prcv->pcns->target);

				serr = qsc_socket_client_connect_ipv6(&prcv->pcns->target, address, port);

				if (serr == qsc_socket_exception_success)
				{
					/* initialize the client */
					client_state_initialize(kcs, prcv->pcns, pubk);
					qerr = pqs_kex_client_key_exchange(kcs, prcv->pcns);
					qsc_memutils_alloc_free(kcs);
					kcs = NULL;

					if (qerr == pqs_error_none)
					{
						/* start the receive loop on a new thread */
						qsc_async_thread_create((void*)&client_receive_loop, prcv);

						/* start the send loop on the main thread */
						send_func(prcv->pcns);

						/* disconnect the socket */
						client_connection_dispose(prcv);
					}
					else
					{
						pqs_log_write(pqs_messages_kex_fail, (const char*)prcv->pcns->target.address);
						qerr = pqs_error_exchange_failure;
					}
				}
				else
				{
					pqs_log_write(pqs_messages_kex_fail, (const char*)prcv->pcns->target.address);
					qerr = pqs_error_connection_failure;
				}
			}
			else
			{
				pqs_log_message(pqs_messages_allocate_fail);
				qerr = pqs_error_memory_allocation;
			}
		}
		else
		{
			pqs_log_message(pqs_messages_allocate_fail);
			qerr = pqs_error_memory_allocation;
		}
	}
	else
	{
		pqs_log_message(pqs_messages_invalid_request);
		qerr = pqs_error_invalid_input;
	}

	if (kcs != NULL)
	{
		qsc_memutils_alloc_free(kcs);
		kcs = NULL;
	}

	if (prcv != NULL)
	{
		if (prcv->pcns != NULL)
		{
			qsc_memutils_alloc_free(prcv->pcns);
			prcv->pcns = NULL;
		}

		prcv->callback = NULL;
		qsc_memutils_alloc_free(prcv);
		prcv = NULL;
	}

	return qerr;
}


#include "server.h"
//#include "connections.h"
#include "kex.h"
#include "logger.h"
#include "acp.h"
#include "async.h"
#include "encoding.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#include "stringutils.h"
#include "timestamp.h"

/** \cond DOXYGEN_IGNORE */
typedef struct server_receiver_state
{
	pqs_connection_state* pcns;
	const pqs_server_signature_key* pprik;
	void (*receive_callback)(pqs_connection_state*, const uint8_t*, size_t);
	void (*disconnect_callback)(pqs_connection_state*);
} server_receiver_state;

static qsc_socket m_connected_client;
static bool m_server_connected;
static bool m_server_pause;
static bool m_server_run;

static void server_state_initialize(pqs_kex_server_state* kss, const server_receiver_state* prcv)
{
	qsc_memutils_copy(kss->keyid, prcv->pprik->keyid, PQS_KEYID_SIZE);
	qsc_memutils_copy(kss->sigkey, prcv->pprik->sigkey, PQS_ASYMMETRIC_SIGNING_KEY_SIZE);
	qsc_memutils_copy(kss->verkey, prcv->pprik->verkey, PQS_ASYMMETRIC_VERIFY_KEY_SIZE);
	kss->expiration = prcv->pprik->expiration;
	prcv->pcns->target.instance = qsc_acp_uint32();
	pqs_cipher_dispose(&prcv->pcns->rxcpr);
	pqs_cipher_dispose(&prcv->pcns->txcpr);
	prcv->pcns->exflag = pqs_flag_none;
	prcv->pcns->cid = 0;
	prcv->pcns->rxseq = 0;
	prcv->pcns->txseq = 0;
}

static pqs_errors server_key_exchange(server_receiver_state* prcv)
{
	pqs_kex_server_state* pkss;
	pqs_errors qerr;

	qerr = pqs_error_exchange_failure;
	pkss = (pqs_kex_server_state*)qsc_memutils_malloc(sizeof(pqs_kex_server_state));

	if (pkss != NULL)
	{
		server_state_initialize(pkss, prcv);
		qerr = pqs_kex_server_key_exchange(pkss, prcv->pcns);
		qsc_memutils_alloc_free(pkss);
	}

	return qerr;
}

static void server_receiver_dispose(server_receiver_state* prcv)
{
	if (prcv != NULL)
	{
		if (prcv->disconnect_callback != NULL)
		{
			prcv->disconnect_callback = NULL;
		}

		if (prcv->receive_callback != NULL)
		{
			prcv->receive_callback = NULL;
		}

		if (prcv->pcns != NULL)
		{
			qsc_memutils_alloc_free(prcv->pcns);
			prcv->pcns = NULL;
		}

		qsc_memutils_alloc_free(prcv);
		prcv = NULL;
	}
}

static void server_receive_loop(server_receiver_state* prcv)
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
	qerr = server_key_exchange(prcv);

	if (qerr == pqs_error_none)
	{
		rbuf = (uint8_t*)qsc_memutils_malloc(PQS_HEADER_SIZE);

		if (rbuf != NULL)
		{
			while (prcv->pcns->target.connection_status == qsc_socket_state_connected)
			{
				mlen = 0;
				slen = 0;

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
							mlen = qsc_socket_receive(&prcv->pcns->target, rbuf, plen, qsc_socket_receive_flag_none);

							if (mlen != 0)
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
											/* send the decrypted message to the receive callback */
											prcv->receive_callback(prcv->pcns, mstr, mlen);
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
								else if (pkt.flag == pqs_flag_connection_terminate)
								{
									/* close the connection */
									pqs_log_write(pqs_messages_disconnect, cadd);
									break;
								}
								else
								{
									/* unknown message type, we fail out of caution but could ignore */
									pqs_log_write(pqs_messages_receive_fail, cadd);
									break;
								}
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
							/* close the connection on memory allocation failure */
							pqs_log_write(pqs_messages_allocate_fail, cadd);
							break;
						}
					}
					else
					{
						pqs_log_write(pqs_messages_invalid_request, cadd);
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
			/* close the connection on memory allocation failure */
			pqs_log_write(pqs_messages_allocate_fail, cadd);
		}

		pqs_connection_close(prcv->pcns, pqs_error_none, false);

		if (prcv->disconnect_callback != NULL)
		{
			prcv->disconnect_callback(prcv->pcns);
		}
	}
	else
	{
		pqs_log_message(pqs_messages_kex_fail);
	}

	server_receiver_dispose(prcv);
}

static pqs_errors server_start(const pqs_server_signature_key* kset, 
	const qsc_socket* source, 
	void (*receive_callback)(pqs_connection_state*, const uint8_t*, size_t),
	void (*disconnect_callback)(pqs_connection_state*))
{
	assert(kset != NULL);
	assert(source != NULL);
	assert(receive_callback != NULL);

	qsc_socket_exceptions res;
	pqs_errors qerr;

	qerr = pqs_error_none;
	m_server_pause = false;
	m_server_run = true;

	pqs_logger_initialize(NULL);

	do
	{
		pqs_connection_state* pcns = (pqs_connection_state*)qsc_memutils_malloc(sizeof(pqs_connection_state));
		m_server_connected = false;

		if (pcns != NULL)
		{
			res = qsc_socket_accept(source, &pcns->target);

			if (res == qsc_socket_exception_success)
			{
				m_server_connected = true;
				qsc_memutils_copy(&m_connected_client, &pcns->target, sizeof(qsc_socket));

				server_receiver_state* prcv = (server_receiver_state*)qsc_memutils_malloc(sizeof(server_receiver_state));

				if (prcv != NULL)
				{
					pcns->target.connection_status = qsc_socket_state_connected;
					prcv->pcns = pcns;
					prcv->pprik = kset;
					prcv->receive_callback = receive_callback;
					prcv->disconnect_callback = disconnect_callback;

					pqs_log_write(pqs_messages_connect_success, (const char*)pcns->target.address);

					/* restricted to one active client */
					server_receive_loop(prcv);
				}
				else
				{
					qerr = pqs_error_memory_allocation;
					pqs_log_message(pqs_messages_sockalloc_fail);
				}
			}
			else
			{
				if (pcns != NULL)
				{
					qsc_memutils_alloc_free(pcns);
					pcns = NULL;
				}

				qerr = pqs_error_accept_fail;
				pqs_log_message(pqs_messages_accept_fail);
			}
		}
		else
		{
			qerr = pqs_error_hosts_exceeded;
			pqs_log_message(pqs_messages_queue_empty);
		}

		while (m_server_pause == true)
		{
			qsc_async_thread_sleep(PQS_SERVER_PAUSE_INTERVAL);
		}
	} 
	while (m_server_run == true);

	return qerr;
}
/** \endcond DOXYGEN_IGNORE */

/* Public Functions */

void pqs_server_pause()
{
	m_server_pause = true;
}

void pqs_server_quit(qsc_socket* listener)
{
	m_server_pause = false;
	m_server_run = false;
	qsc_socket_close_socket(listener);

	if (m_server_connected)
	{
		qsc_socket_shut_down(&m_connected_client, qsc_socket_shut_down_flag_both);
	}
}

void pqs_server_resume()
{
	m_server_pause = false;
}

pqs_errors pqs_server_start_ipv4(qsc_socket* source, 
	const pqs_server_signature_key* kset,
	void (*receive_callback)(pqs_connection_state*, const uint8_t*, size_t),
	void (*disconnect_callback)(pqs_connection_state*))
{
	assert(kset != NULL);
	assert(receive_callback != NULL);

	qsc_ipinfo_ipv4_address addt = { 0 };
	qsc_socket_exceptions res;
	pqs_errors qerr;

	addt = qsc_ipinfo_ipv4_address_any();
	qsc_socket_server_initialize(source);
	res = qsc_socket_create(source, qsc_socket_address_family_ipv4, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

	if (res == qsc_socket_exception_success)
	{
		res = qsc_socket_bind_ipv4(source, &addt, PQS_SERVER_PORT);

		if (res == qsc_socket_exception_success)
		{
			res = qsc_socket_listen(source, PQS_SERVER_LISTEN_BACKLOG);

			if (res == qsc_socket_exception_success)
			{
				qerr = server_start(kset, source, receive_callback, disconnect_callback);
			}
			else
			{
				qerr = pqs_error_listener_fail;
				pqs_log_message(pqs_messages_listener_fail);
			}
		}
		else
		{
			qerr = pqs_error_connection_failure;
			pqs_log_message(pqs_messages_bind_fail);
		}
	}
	else
	{
		qerr = pqs_error_connection_failure;
		pqs_log_message(pqs_messages_create_fail);
	}

	return qerr;
}

pqs_errors pqs_server_start_ipv6(qsc_socket* source,
	const pqs_server_signature_key* kset,
	void (*receive_callback)(pqs_connection_state*, const uint8_t*, size_t),
	void (*disconnect_callback)(pqs_connection_state*))
{
	assert(kset != NULL);
	assert(receive_callback != NULL);

	qsc_ipinfo_ipv6_address addt = { 0 };
	qsc_socket_exceptions res;
	pqs_errors qerr;

	addt = qsc_ipinfo_ipv6_address_any();
	qsc_socket_server_initialize(source);
	res = qsc_socket_create(source, qsc_socket_address_family_ipv6, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

	if (res == qsc_socket_exception_success)
	{
		res = qsc_socket_bind_ipv6(source, &addt, PQS_SERVER_PORT);

		if (res == qsc_socket_exception_success)
		{
			res = qsc_socket_listen(source, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

			if (res == qsc_socket_exception_success)
			{
				qerr = server_start(kset, source, receive_callback, disconnect_callback);
			}
			else
			{
				qerr = pqs_error_listener_fail;
				pqs_log_message(pqs_messages_listener_fail);
			}
		}
		else
		{
			qerr = pqs_error_connection_failure;
			pqs_log_message(pqs_messages_bind_fail);
		}
	}
	else
	{
		qerr = pqs_error_connection_failure;
		pqs_log_message(pqs_messages_create_fail);
	}

	return qerr;
}

/* 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#include "appsrv.h"
#include "pqs.h"
#include "interpreter.h"
#include "server.h"
#include "acp.h"
#include "async.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "folderutils.h"
#include "ipinfo.h"
#include "netutils.h"
#include "stringutils.h"

typedef struct server_connection_state
{
	char prompt[PQS_SERVER_PROMPT_MAX];
	uint32_t instance;
} server_connection_state;


typedef struct server_command_loop_args_t
{
	qsc_socket* source;
} server_command_loop_args;

static server_connection_state m_server_connection_state;

static size_t server_get_host_name(char* name)
{
	char host[QSC_NETUTILS_HOSTS_NAME_SIZE] = { 0 };
	size_t hlen;

	hlen = 0;

	if (qsc_netutils_get_host_name(host) == true)
	{
		hlen = qsc_stringutils_string_size(host);

		if (hlen >= PQS_SERVER_PROMPT_MAX - 2U)
		{
			hlen = PQS_SERVER_PROMPT_MAX - 2U;
		}

		qsc_memutils_copy(name, host, hlen);
	}

	return hlen;
}

static void server_get_prompt(void)
{
	char host[PQS_SERVER_PROMPT_MAX] = { 0 };
	size_t hlen;

	hlen = server_get_host_name(host);

	if (hlen > 0)
	{
		qsc_stringutils_copy_string(m_server_connection_state.prompt, PQS_SERVER_PROMPT_MAX, host);
		qsc_stringutils_concat_strings(m_server_connection_state.prompt, PQS_SERVER_PROMPT_MAX, "> ");
	}
	else
	{
		qsc_stringutils_copy_string(m_server_connection_state.prompt, PQS_SERVER_PROMPT_MAX, "pqs-server> ");
	}
}

static void server_print_prompt(void)
{
	qsc_consoleutils_print_safe(m_server_connection_state.prompt);
}

static void server_print_message(const char* message)
{
	size_t slen;

	if (message != NULL)
	{
		slen = qsc_stringutils_string_size(message);

		if (slen != 0U)
		{
			server_print_prompt();
			qsc_consoleutils_print_line(message);
		}
		else
		{
			qsc_consoleutils_print_line("");
			server_print_prompt();
		}
	}
}

static void server_print_error(qsms_errors error)
{
	const char* msg;

	msg = qsms_error_to_string(error);

	if (msg != NULL)
	{
		server_print_message(msg);
	}
}

static void server_print_banner(void)
{
	qsc_consoleutils_print_line("PQS: Post Quantum Shell Server");
	qsc_consoleutils_print_line("Quantum-Secure remote command shell server.");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("Release:   v1.1.0.0a (A1)");
	qsc_consoleutils_print_line("Date:      March 05, 2026");
	qsc_consoleutils_print_line("Contact:   contact@pqrcscorp.ca");
	qsc_consoleutils_print_line("");
}

static bool server_get_storage_path(char* fpath, size_t pathlen)
{
	bool res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	qsc_folderutils_get_directory(qsc_folderutils_directories_user_app_data, fpath);
#else
	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, fpath);
#endif
	qsc_folderutils_append_delimiter(fpath);
	qsc_stringutils_concat_strings(fpath, pathlen, PQS_APP_PATH);
	res = qsc_folderutils_directory_exists(fpath);

	if (res == false)
	{
		res = qsc_folderutils_create_directory(fpath);
	}

	return res;
}

static bool server_prikey_exists(void)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = server_get_storage_path(fpath, sizeof(fpath));

	if (res == true)
	{
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, sizeof(fpath), PQS_PRIKEY_NAME);
		res = qsc_fileutils_exists(fpath);
	}

	return res;
}

static bool server_key_dialogue(qsms_server_signature_key* prik, qsms_client_verification_key* pubk, uint8_t keyid[QSMS_KEYID_SIZE])
{
	char* spub;
	uint8_t spri[QSMS_SIGNATURE_KEY_SERIALIZED_SIZE] = { 0U };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0 };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	size_t plen;
	bool res;

	res = false;

	if (server_prikey_exists() == true)
	{
		res = server_get_storage_path(dir, sizeof(dir));

		if (res == true)
		{
			qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
			qsc_folderutils_append_delimiter(fpath);
			qsc_stringutils_concat_strings(fpath, sizeof(fpath), PQS_PRIKEY_NAME);
			res = qsc_fileutils_copy_file_to_stream(fpath, (char*)spri, sizeof(spri));

			if (res == true)
			{
				qsms_signature_key_deserialize(prik, spri);

				/* load the state */
				qsc_memutils_copy(keyid, prik->keyid, QSMS_KEYID_SIZE);
				qsc_memutils_copy(pubk->config, prik->config, QSMS_CONFIG_SIZE);
				qsc_memutils_copy(pubk->keyid, prik->keyid, QSMS_KEYID_SIZE);
				qsc_memutils_copy(pubk->verkey, prik->verkey, QSMS_ASYMMETRIC_VERIFY_KEY_SIZE);
				pubk->expiration = prik->expiration;
				server_print_message("The private-key has been loaded.");
			}
			else
			{
				server_print_message("Could not load the key-pair, aborting startup.");
			}
		}
		else
		{
			server_print_message("Could not get the storage path, aborting startup.");
		}
	}
	else
	{
		res = server_get_storage_path(dir, sizeof(dir));

		if (res == true)
		{
			qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
			qsc_folderutils_append_delimiter(fpath);
			qsc_stringutils_concat_strings(fpath, sizeof(fpath), PQS_PUBKEY_NAME);

			server_print_message("The private-key was not detected, generating a new private/public keypair...");
			res = qsc_acp_generate(keyid, QSMS_KEYID_SIZE);

			if (res == true)
			{
				plen = qsms_public_key_encoding_size();
				spub = qsc_memutils_malloc(plen);

				if (spub != NULL)
				{
					qsc_memutils_clear(spub, plen);
					qsms_generate_keypair(pubk, prik, keyid);
					plen = qsms_public_key_encode(spub, plen, pubk);
					server_print_message((const char*)spub);

					res = qsc_fileutils_copy_stream_to_file(fpath, spub, plen);

					if (res == true)
					{
						server_print_prompt();
						qsc_consoleutils_print_safe("The public-key has been saved to ");
						qsc_consoleutils_print_line(fpath);
						server_print_message("Distribute the public-key to intended clients.");

						qsc_stringutils_clear_string(fpath);
						qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
						qsc_folderutils_append_delimiter(fpath);
						qsc_stringutils_concat_strings(fpath, sizeof(fpath), PQS_PRIKEY_NAME);
						qsms_signature_key_serialize(spri, prik);
						qsc_fileutils_copy_stream_to_file(fpath, (char*)spri, sizeof(spri));
					}
					else
					{
						server_print_message("Could not load the key-pair, aborting startup.");
					}

					qsc_memutils_alloc_free(spub);
				}
				else
				{
					server_print_message("Could not allocate the key memory, aborting startup.");
				}
			}
			else
			{
				server_print_message("Could not create the key-pair, aborting startup.");
			}
		}
	}

	return res;
}

static void server_send_message(qsms_connection_state* cns, const uint8_t* message, size_t msglen)
{
	PQS_ASSERT(cns != NULL);
	PQS_ASSERT(message != NULL);
	PQS_ASSERT(msglen != 0U);

	uint8_t* pmsg;
	size_t mlen;

	if (msglen > 0U)
	{
		mlen = QSMS_HEADER_SIZE + msglen + QSMS_SIMPLEX_MACTAG_SIZE;
		pmsg = (uint8_t*)qsc_memutils_malloc(mlen);

		if (pmsg != NULL)
		{
			qsms_network_packet spkt = { 0 };

			qsc_memutils_clear(pmsg, mlen);
			spkt.pmessage = pmsg + QSMS_HEADER_SIZE;

			qsms_packet_encrypt(cns, &spkt, message, msglen);
			qsms_packet_header_serialize(&spkt, pmsg);
			qsc_socket_send(&cns->target, pmsg, mlen, qsc_socket_send_flag_none);
			qsc_memutils_alloc_free(pmsg);
		}
	}
}

static bool server_command_execute(qsms_connection_state* cns, const char* message, size_t msglen)
{
	char* sres;
	size_t slen;

	(void)msglen;
	slen = PQS_INTERPRETER_COMMAND_EXECUTE_SIZE;
	sres = (char*)qsc_memutils_malloc(slen);

	if (sres != NULL)
	{
		qsc_memutils_clear(sres, slen);
		slen = pqs_interpreter_command_execute(sres, slen, message);

		if (slen > 0U)
		{
			slen = qsc_stringutils_remove_null_chars(sres, slen);
			
			if (slen > 0U)
			{
				server_send_message(cns, (const uint8_t*)sres, slen + 1U);
				server_print_message(sres);
			}
		}

		qsc_memutils_alloc_free(sres);
	}

	return (slen > 0U);
}

static void server_disconnect_callback(qsms_connection_state* cns)
{
	m_server_connection_state.instance = 0U;

	pqs_interpreter_cleanup();
	qsc_consoleutils_print_safe("Disconnected from host: ");
	qsc_consoleutils_print_line((const char*)cns->target.address);
	server_print_prompt();
}

static bool server_instance_check(qsms_connection_state* cns)
{
	return (cns->target.instance == m_server_connection_state.instance);
}

static void server_receive_callback(qsms_connection_state* cns, const uint8_t* message, size_t msglen)
{
	if (m_server_connection_state.instance == 0U)
	{
		char msg[QSC_NETUTILS_NAME_BUFFER_SIZE] = { 0U };

		qsc_stringutils_copy_string(msg, sizeof(msg), "Connected to ");
		qsc_stringutils_concat_strings(msg, sizeof(msg), (char*)cns->target.address);
		qsc_consoleutils_set_window_title(msg);
		qsc_consoleutils_print_line(msg);
		server_print_prompt();

		m_server_connection_state.instance = cns->target.instance;
		pqs_interpreter_initialize();
	}

	if (server_instance_check(cns) == true)
	{
		/* process the message */
		if (server_command_execute(cns, (const char*)message, msglen) == false)
		{
			server_print_message("Command unknown or invalid.");
		}
	}
	else
	{
		/* if a second connection is trying to log on, send a refusal message and close the socket */
		if (qsc_socket_is_connected(&cns->target) == true)
		{
			qsms_connection_close(cns, qsms_error_connection_failure, true);
		}
	}
}

static void server_command_loop(void* src)
{
	char sin[PQS_SERVER_INPUT_MAX] = { 0 };
	size_t mlen;

	(void)src;
	mlen = 0U;

	server_print_message("Type 'quit' to shut down the server.");

	/* start the send loop */
	while (true)
	{
		server_print_prompt();
		mlen = qsc_consoleutils_get_line(sin, sizeof(sin)) - 1U;

		if (mlen > 0U)
		{
			if (qsc_stringutils_strings_equal(sin, "quit") == true)
			{
				qsms_server_quit();
				break;
			}
		}

		qsc_memutils_clear((uint8_t*)sin, sizeof(sin));
	}

	server_print_prompt();
}

int main(void)
{
	qsms_client_verification_key pubk = { 0 };
	qsms_server_signature_key prik = { 0 };
	qsc_socket source = { 0 };
	uint8_t kid[QSMS_KEYID_SIZE] = { 0U };
	qsms_errors qerr;

	qsc_consoleutils_set_virtual_terminal();
	qsc_consoleutils_set_window_title("PQS Server");
	qsc_consoleutils_set_window_buffer(2000U, 6000U);
	qsc_consoleutils_set_window_size(1000U, 600U);

	server_get_prompt();
	server_print_banner();

	if (server_key_dialogue(&prik, &pubk, kid) == true)
	{
		server_print_message("Waiting for a connection...");
		qsc_async_thread_create(&server_command_loop, &source);

		qerr = qsms_server_start_ipv4(&source, &prik, &server_receive_callback, &server_disconnect_callback);

		if (qerr != qsms_error_none && qerr != qsms_error_accept_fail)
		{
			server_print_error(qerr);
			server_print_message("The network key-exchange failed, the application will exit.");
		}
	}
	else
	{
		server_print_message("The state could not be loaded, the application will exit.");
	}

	qsc_consoleutils_print_line("Press any key to close...");
	qsc_consoleutils_get_wait();

	return 0;
}

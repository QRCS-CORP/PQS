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
 * Contact: john.underhill@protonmail.com
 */

#include "appsrv.h"
#include "interpreter.h"
#include "server.h"
#include "acp.h"
#include "async.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "folderutils.h"
#include "ipinfo.h"
#include "netutils.h"
#include "scb.h"
#include "sha3.h"
#include "stringutils.h"
#include "winutils.h"

typedef struct server_connection_state
{
	char prompt[PQS_SERVER_PROMPT_MAX];
	uint8_t rkhash[PQS_HASH_SIZE];
	uint32_t instance;
	uint32_t lcount;
	bool connected;
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

		if (hlen >= PQS_SERVER_PROMPT_MAX - 2)
		{
			hlen = PQS_SERVER_PROMPT_MAX - 2;
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

		if (slen != 0)
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

static void server_print_error(pqs_errors error)
{
	const char* msg;

	msg = pqs_error_to_string(error);

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
	qsc_consoleutils_print_line("Release:   v1.0.0.0a (A1)");
	qsc_consoleutils_print_line("Date:      August 1, 2024");
	qsc_consoleutils_print_line("Contact:   john.underhill@protonmail.com");
	qsc_consoleutils_print_line("");
}

static bool server_get_storage_path(char* path, size_t pathlen)
{
	bool res;

	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, path);
	qsc_folderutils_append_delimiter(path);
	qsc_stringutils_concat_strings(path, pathlen, PQS_APP_PATH);
	res = qsc_folderutils_directory_exists(path);

	if (res == false)
	{
		res = qsc_folderutils_create_directory(path);
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

static bool server_password_minimum_check(const char* password, size_t passlen)
{
	assert(password != NULL);
	assert(passlen != 0);

	bool res;
	uint8_t hsp;
	uint8_t lsp;
	uint8_t nsp;

	res = false;
	hsp = 0;
	lsp = 0;
	nsp = 0;

	if (password != NULL && passlen != 0)
	{
		if (passlen >= PQS_SERVER_PASSWORD_MIN && passlen <= PQS_SERVER_PASSWORD_MAX)
		{
			for (size_t i = 0; i < passlen; ++i)
			{
				if (((uint8_t)password[i] >= 65 && (uint8_t)password[i] <= 90) ||
					((uint8_t)password[i] >= 97 && (uint8_t)password[i] <= 122))
				{
					++lsp;
				}

				if (((uint8_t)password[i] >= 33 && (uint8_t)password[i] <= 46) ||
					((uint8_t)password[i] >= 58 && (uint8_t)password[i] <= 64))
				{
					++hsp;
				}

				if ((uint8_t)password[i] >= 48 && (uint8_t)password[i] <= 57)
				{
					++nsp;
				}
			}

			if ((lsp > 0 && hsp > 0 && nsp > 0) && (lsp + hsp + nsp) >= 8)
			{
				res = true;
			}
		}
	}

	return res;
}

static void server_hash_remote_password(uint8_t* rhash, const char* password, size_t passlen)
{
	qsc_scb_state scbx = { 0 };

	/* use cost based kdf to generate the stored comparison value */
	qsc_scb_initialize(&scbx, (const uint8_t*)password, passlen, NULL, 0, PQS_CRYPTO_PHASH_CPU_COST, PQS_CRYPTO_PHASH_MEMORY_COST);
	qsc_scb_generate(&scbx, rhash, PQS_HASH_SIZE);
	qsc_scb_dispose(&scbx);
}

static bool server_password_challenge(uint8_t* rkhash)
{
	size_t lcnt;
	bool res;

	lcnt = 0;
	res = false;

	server_print_message("Enter the remote password to start.");
	server_print_prompt();

	while (true)
	{
		char pass[PQS_SERVER_PASSWORD_MAX] = { 0 };
		uint8_t phsh[QSC_SHA3_256_HASH_SIZE] = { 0 };
		uint8_t rhsh[QSC_SHA3_256_HASH_SIZE] = { 0 };
		size_t plen;

		++lcnt;
		plen = qsc_consoleutils_masked_password(pass, sizeof(pass));

		qsc_sha3_compute256(rhsh, (const uint8_t*)pass, plen);
		server_hash_remote_password(phsh, (const char*)rhsh, sizeof(rhsh));

		if (qsc_memutils_are_equal(phsh, rkhash, PQS_HASH_SIZE) == true)
		{
			res = true;
			break;
		}
		else
		{
			if (lcnt >= PQS_SERVER_MAX_LOGIN)
			{
				server_print_message("The maximum login attempts have been exceeded.");
				res = false;
				break;
			}
			else
			{
				server_print_message("The password is incorrect, enter the password.");
				server_print_prompt();
			}
		}
	}

	return res;
}

static bool server_key_dialogue(pqs_server_signature_key* prik, pqs_client_verification_key* pubk, uint8_t keyid[PQS_KEYID_SIZE])
{
	uint8_t spub[PQS_PUBKEY_STRING_SIZE] = { 0 };
	uint8_t spri[PQS_SIGKEY_ENCODED_SIZE] = { 0 };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0 };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

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
				pqs_signature_key_deserialize(prik, spri);

				/* password challenge */
				if (server_password_challenge(prik->rkhash) == true)
				{
					/* load the state */
					qsc_memutils_copy(m_server_connection_state.rkhash, prik->rkhash, PQS_HASH_SIZE);
					m_server_connection_state.lcount = 0;
					m_server_connection_state.connected = false;

					qsc_memutils_copy(keyid, prik->keyid, PQS_KEYID_SIZE);
					qsc_memutils_copy(pubk->config, prik->config, PQS_CONFIG_SIZE);
					qsc_memutils_copy(pubk->keyid, prik->keyid, PQS_KEYID_SIZE);
					qsc_memutils_copy(pubk->verkey, prik->verkey, PQS_ASYMMETRIC_VERIFY_KEY_SIZE);
					pubk->expiration = prik->expiration;
					server_print_message("The private-key has been loaded.");
				}
				else
				{
					res = false;
				}
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
			res = qsc_acp_generate(keyid, PQS_KEYID_SIZE);

			if (res == true)
			{
				pqs_generate_keypair(pubk, prik, keyid);
				pqs_public_key_encode((char*)spub, pubk);
				server_print_message((const char*)spub);

				res = qsc_fileutils_copy_stream_to_file(fpath, (char*)spub, sizeof(spub));

				if (res == true)
				{
					char pass[PQS_SERVER_PASSWORD_MAX] = { 0 };
					size_t plen;

					server_print_prompt();
					qsc_consoleutils_print_safe("The public-key has been saved to ");
					qsc_consoleutils_print_line(fpath);
					server_print_message("Distribute the public-key to intended clients.");
					server_print_message("Enter the remote access key.");
					
					while (true)
					{
						server_print_message("Password must be 8-128 characters long[a-z, A-Z], at least 1 number, and 1 symbol[0-9][!#$ & '()*+,_./].");
						server_print_prompt();
						plen = qsc_consoleutils_masked_password(pass, sizeof(pass));

						if (server_password_minimum_check(pass, plen) == true)
						{
							uint8_t rhsh[QSC_SHA3_256_HASH_SIZE] = { 0 };

							qsc_sha3_compute256(rhsh, (const uint8_t*)pass, plen);
							server_hash_remote_password(prik->rkhash, (const char*)rhsh, sizeof(rhsh));
							qsc_memutils_copy(m_server_connection_state.rkhash, prik->rkhash, PQS_HASH_SIZE);
							break;
						}
					}

					server_print_message("The remote password hash has been stored.");

					qsc_stringutils_clear_string(fpath);
					qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
					qsc_folderutils_append_delimiter(fpath);
					qsc_stringutils_concat_strings(fpath, sizeof(fpath), PQS_PRIKEY_NAME);
					pqs_signature_key_serialize(spri, prik);
					qsc_fileutils_copy_stream_to_file(fpath, (char*)spri, sizeof(spri));
				}
				else
				{
					server_print_message("Could not load the key-pair, aborting startup.");
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

static void server_send_message(pqs_connection_state* cns, const uint8_t* message, size_t msglen)
{
	assert(cns != NULL);
	assert(message != NULL);
	assert(msglen != 0);

	uint8_t* pmsg;
	size_t mlen;

	if (msglen > 0)
	{
		mlen = PQS_HEADER_SIZE + msglen + PQS_MACTAG_SIZE;
		pmsg = (uint8_t*)qsc_memutils_malloc(mlen);

		if (pmsg != NULL)
		{
			pqs_network_packet spkt = { 0 };

			qsc_memutils_clear(pmsg, mlen);
			spkt.pmessage = pmsg + PQS_HEADER_SIZE;

			pqs_packet_encrypt(cns, &spkt, message, msglen);
			pqs_packet_header_serialize(&spkt, pmsg);
			qsc_socket_send(&cns->target, pmsg, mlen, qsc_socket_send_flag_none);
			qsc_memutils_alloc_free(pmsg);
		}
	}
}

static bool server_command_execute(pqs_connection_state* cns, const char* message, size_t msglen)
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

		if (slen > 0)
		{
			slen = qsc_stringutils_remove_null_chars(sres, slen);
			
			if (slen > 0)
			{
				server_send_message(cns, (const uint8_t*)sres, slen);
			}
		}

		qsc_memutils_alloc_free(sres);
	}

	return (slen > 0);
}

static void server_disconnect_callback(pqs_connection_state* cns)
{
	qsc_mutex mtx;

	m_server_connection_state.connected = false;
	m_server_connection_state.instance = 0;
	m_server_connection_state.lcount = 0;

	mtx = qsc_async_mutex_lock_ex();
	pqs_interpreter_cleanup();
	qsc_consoleutils_print_safe("Disconnected from host: ");
	qsc_consoleutils_print_line((const char*)cns->target.address);
	server_print_prompt();
	qsc_async_mutex_unlock_ex(mtx);
}

static bool server_instance_check(pqs_connection_state* cns)
{
	return (cns->target.instance == m_server_connection_state.instance);
}

static void server_receive_callback(pqs_connection_state* cns, const uint8_t* message, size_t msglen)
{
	if (m_server_connection_state.connected == true)
	{
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
			/* if a second connection is trying to logon, send a refusal message and close the socket */
			if (qsc_socket_is_connected(&cns->target) == true)
			{
				pqs_connection_close(cns, pqs_error_connection_refused, true);
			}
		}
	}
	else
	{
		/* start the login */

		uint8_t pkh[PQS_HASH_SIZE] = { 0 };

		server_hash_remote_password(pkh, (const char*)message, msglen);
		++m_server_connection_state.lcount;

		if (m_server_connection_state.lcount <= PQS_SERVER_MAX_LOGIN)
		{
			uint8_t msg[PQS_HASH_SIZE] = { 0 };

			if (qsc_memutils_are_equal(pkh, m_server_connection_state.rkhash, PQS_HASH_SIZE) == true)
			{
				/* send the servers details */
				 
				msg[0] = (uint8_t)pqs_error_login_success;
				
				server_get_host_name((char*)msg + PQS_ERROR_MESSAGE_SIZE);
				server_send_message(cns, msg, sizeof(msg));

				m_server_connection_state.lcount = 0;
				m_server_connection_state.connected = true;

				qsc_consoleutils_print_safe("Connected to ");
				qsc_consoleutils_print_line((char*)cns->target.address);
				server_print_prompt();
				m_server_connection_state.instance = cns->target.instance;
				pqs_interpreter_initialize();
			}
			else
			{
				/* send the client an error message */
				msg[0] = (uint8_t)pqs_error_login_failure;
				server_send_message(cns, msg, sizeof(msg));
			}
		}
		else
		{
			/* authentication failed, close connection */
			m_server_connection_state.lcount = 0;
			pqs_connection_close(cns, pqs_error_login_failure, true);

			server_print_prompt();
			qsc_consoleutils_print_safe("Failed login attempt by  ");
			qsc_consoleutils_print_line((char*)cns->target.address);
		}
	}
}

static void server_command_loop(qsc_socket* source)
{
	char sin[PQS_SERVER_INPUT_MAX] = { 0 };
	size_t mlen;

	mlen = 0;

	server_print_message("Type 'quit' to shut down the server.");

	/* start the send loop */
	while (true)
	{
		server_print_prompt();
		mlen = qsc_consoleutils_get_line(sin, sizeof(sin)) - 1;

		if (mlen > 0)
		{
			if (qsc_stringutils_strings_equal(sin, "quit") == true)
			{
				pqs_server_quit(source);
				break;
			}
		}

		qsc_memutils_clear((uint8_t*)sin, sizeof(sin));
	}

	server_print_prompt();
}

static void server_command_loop_wrapper(void* state)
{
	server_command_loop_args* args = (server_command_loop_args*)state;

	if (args != NULL)
	{
		server_command_loop(args->source);
	}
}

int main(void)
{
	pqs_client_verification_key pubk = { 0 };
	pqs_server_signature_key prik = { 0 };
	qsc_socket source = { 0 };
	uint8_t kid[PQS_KEYID_SIZE] = { 0 };
	pqs_errors qerr;

	qsc_consoleutils_set_virtual_terminal();
	qsc_consoleutils_set_window_title("PQS Server");
	qsc_consoleutils_set_window_buffer(2000, 6000);
	qsc_consoleutils_set_window_size(1000, 600);

	server_get_prompt();
	m_server_connection_state.connected = false;
	m_server_connection_state.lcount = 0;
	server_print_banner();

	if (server_key_dialogue(&prik, &pubk, kid) == true)
	{
		server_print_message("Waiting for a connection...");
		qsc_async_thread_create(&server_command_loop_wrapper, &source);

		qerr = pqs_server_start_ipv4(&source, &prik, &server_receive_callback, &server_disconnect_callback);

		if (qerr != pqs_error_none && qerr != pqs_error_accept_fail)
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

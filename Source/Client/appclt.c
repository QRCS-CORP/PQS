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

#include "appclt.h"
#include "client.h"
#include "interpreter.h"
#include "async.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "folderutils.h"
#include "memutils.h"
#include "netutils.h"
#include "sha3.h"
#include "stringutils.h"

/** \cond DOXYGEN_IGNORE */
#define PQS_FORMAT_BUFFER_SIZE 1280
/** \endcond DOXYGEN_IGNORE */

/** \cond DOXYGEN_IGNORE */
typedef struct client_connection_state
{
	pqs_client_verification_key pubkey;
	char prompt[PQS_CLIENT_PROMPT_MAX];
	size_t lcounter;
	pqs_client_commands command;
	bool connected;
} client_connection_state;
/** \endcond DOXYGEN_IGNORE */

/** \cond DOXYGEN_IGNORE */
static client_connection_state m_client_connection_state;

static size_t client_get_host_name(char* name)
{
	char host[QSC_NETUTILS_HOSTS_NAME_SIZE] = { 0 };
	size_t hlen;

	hlen = 0;

	if (qsc_netutils_get_host_name(host) == true)
	{
		hlen = qsc_stringutils_string_size(host);

		if (hlen >= PQS_CLIENT_PROMPT_MAX - 2)
		{
			hlen = PQS_CLIENT_PROMPT_MAX - 2;
		}

		qsc_stringutils_copy_string(name, PQS_CLIENT_PROMPT_MAX, host);
	}

	return hlen;
}

static void client_get_prompt(void)
{
	char host[PQS_CLIENT_PROMPT_MAX] = { 0 };
	size_t hlen;

	hlen = client_get_host_name(host);

	if (hlen > 0)
	{
		qsc_stringutils_copy_string(m_client_connection_state.prompt, PQS_CLIENT_PROMPT_MAX, host);
		qsc_stringutils_concat_strings(m_client_connection_state.prompt, PQS_CLIENT_PROMPT_MAX, "> ");
	}
	else
	{
		qsc_stringutils_copy_string(m_client_connection_state.prompt, PQS_CLIENT_PROMPT_MAX, "pqs-client> ");
	}
}

static void client_set_prompt(const char* message, size_t msglen)
{
	if (qsc_stringutils_string_contains(message, ":\\") == true)
	{
		int64_t npos;

		npos = qsc_stringutils_reverse_find_string(message, "\n", msglen - 1);

		if (npos > 0 && msglen - npos > 0)
		{
			++npos;
			qsc_memutils_clear(m_client_connection_state.prompt, PQS_CLIENT_PROMPT_MAX);
			qsc_memutils_copy(m_client_connection_state.prompt, message + npos, msglen - npos);
		}
	}
}

static void client_print_prompt(void)
{
	qsc_consoleutils_print_safe(m_client_connection_state.prompt);
}

static void client_print_error(pqs_errors error)
{
	const char* msg;

	msg = pqs_error_to_string(error);

	if (msg != NULL)
	{
		client_print_prompt();
		qsc_consoleutils_print_line(msg);
	}
}

static void client_print_message(const char* message)
{
	size_t slen;

	if (message != NULL)
	{
		slen = qsc_stringutils_string_size(message);

		if (slen != 0)
		{
			client_print_prompt();
			qsc_consoleutils_print_line(message);
		}
		else
		{
			client_print_prompt();
		}
	}
}

static void client_print_string(const char* message)
{
	if (message != NULL)
	{
		qsc_consoleutils_print_line(message);
	}
}

static void client_print_banner(void)
{
	qsc_consoleutils_print_line("PQS: Post Quantum Shell Client");
	qsc_consoleutils_print_line("Quantum-Secure remote command shell client.");
	qsc_consoleutils_print_line("Enter the address, server public key, and password to connect.");
	qsc_consoleutils_print_line("Type 'quit' to close the connection and exit the application.");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("Release:   v1.0.0.0a (A1)");
	qsc_consoleutils_print_line("Date:      August 1, 2024");
	qsc_consoleutils_print_line("Contact:   john.underhill@protonmail.com");
	qsc_consoleutils_print_line("");
}

static bool client_ipv4_dialogue(qsc_ipinfo_ipv4_address* address)
{
	uint8_t pskey[PQS_PUBKEY_STRING_SIZE] = { 0 };
	char fpath[QSC_SYSTEM_MAX_PATH + 1] = { 0 };
	char sadd[QSC_IPINFO_IPV4_STRNLEN] = { 0 };
	qsc_ipinfo_ipv4_address addv4t = { 0 };
	size_t slen;
	bool res;

	res = false;

	client_print_string("Enter the destination IPv4 address, ex. 192.168.1.1");
	client_print_message("");
	slen = qsc_consoleutils_get_formatted_line(sadd, sizeof(sadd));

	if (slen >= QSC_IPINFO_IPV4_MINLEN)
	{
		addv4t = qsc_ipinfo_ipv4_address_from_string(sadd);

		if (qsc_ipinfo_ipv4_address_is_valid(&addv4t) == true &&
			qsc_ipinfo_ipv4_address_is_zeroed(&addv4t) == false)
		{
			qsc_memutils_copy(address->ipv4, addv4t.ipv4, sizeof(addv4t.ipv4));
			res = true;
		}
		else
		{
			qsc_consoleutils_print_line("The address format is invalid.");
		}
	}
	else
	{
		qsc_consoleutils_print_line("The address format is invalid.");
	}

	if (res == true)
	{
		client_print_message("Enter the path of the public key:");
		client_print_message("");
		slen = qsc_consoleutils_get_line(fpath, sizeof(fpath)) - 1;

		if (slen > 0)
		{
			if (qsc_fileutils_exists(fpath) == true && 
				qsc_stringutils_string_contains(fpath, PQS_PUBKEY_NAME) == true)
			{
				qsc_fileutils_copy_file_to_stream(fpath, (char*)pskey, sizeof(pskey));
				res = pqs_public_key_decode(&m_client_connection_state.pubkey, (char*)pskey);

				if (res == false)
				{
					qsc_consoleutils_print_line("The public key is invalid.");
				}
			}
			else
			{
				res = false;
				qsc_consoleutils_print_line("The path is invalid or inaccessable.");
			}
		}
	}

	return res;
}

static void client_connection_login(pqs_connection_state* cns)
{
	pqs_network_packet spkt = { 0 };
	uint8_t rhsh[QSC_SHA3_256_HASH_SIZE] = { 0 };
	char sin[PQS_CLIENT_PASSWORD_LENGTH_MAX + 1] = { 0 };
	uint8_t smsg[PQS_HEADER_SIZE + PQS_HASH_SIZE + PQS_MACTAG_SIZE] = { 0 };
	size_t mlen;
	size_t slen;

	++m_client_connection_state.lcounter;

	/* the password challenge */
	client_print_message("Enter the remote device login password: ");
	client_print_prompt();
	mlen = qsc_consoleutils_masked_password(sin, sizeof(sin));

	/* hash the password before sending it to the server */
	qsc_sha3_compute256(rhsh, (uint8_t*)sin, mlen);

	/* convert the packet to bytes */
	spkt.pmessage = smsg + PQS_HEADER_SIZE;
	pqs_packet_encrypt(cns, &spkt, rhsh, QSC_SHA3_256_HASH_SIZE);
	pqs_packet_header_serialize(&spkt, smsg);

	/* send to the server */
	slen = qsc_socket_send(&cns->target, smsg, sizeof(smsg), qsc_socket_send_flag_none);
}

static const char* client_format_message(const uint8_t* message, size_t msglen)
{
	int64_t npos;

	(void)msglen;
	npos = qsc_stringutils_find_string((char*)message, "\n");

	if (npos < 0)
	{
		npos = 0;
	}

	return (const char*)message + npos;
}

static void client_receive_callback(pqs_connection_state* cns, const uint8_t* message, size_t msglen)
{
	if (m_client_connection_state.connected == true)
	{
		const char* pstr;

		client_set_prompt((const char*)message, msglen);
		pstr = client_format_message(message, msglen);
		qsc_consoleutils_print_safe(pstr);
	}
	else
	{
		if ((pqs_errors)message[0] == pqs_error_login_success)
		{
			const char* sprmt;
			char title[PQS_CLIENT_TITLE_SIZE] = { 0 };

			sprmt = (const char*)message + PQS_ERROR_MESSAGE_SIZE;
			client_print_prompt();

			qsc_stringutils_copy_string(title, sizeof(title), "PQS Client - connected to ");
			qsc_stringutils_concat_strings(title, sizeof(title), cns->target.address);
			qsc_consoleutils_set_window_title(title);

			qsc_consoleutils_print_safe("Connected to server: ");
			qsc_consoleutils_print_line(sprmt);
			qsc_stringutils_clear_string(m_client_connection_state.prompt);
			qsc_stringutils_copy_string(m_client_connection_state.prompt, PQS_CLIENT_PROMPT_MAX, sprmt);
			qsc_stringutils_concat_strings(m_client_connection_state.prompt, PQS_CLIENT_PROMPT_MAX, "> ");

			m_client_connection_state.connected = true;
			m_client_connection_state.lcounter = 0;
		}
		else
		{
			client_connection_login(cns);
		}
	}
}

static void client_print_pubkey()
{
	char enck[PQS_PUBKEY_STRING_SIZE] = { 0 };

	client_print_string("\n");
	pqs_public_key_encode(enck, &m_client_connection_state.pubkey);
	client_print_string(enck);
}

static size_t client_alloc_file_stream(uint8_t* pmsg, const char* command)
{
	char dst[PQS_CLIENT_INPUT_MAX] = { 0 };
	char src[PQS_CLIENT_INPUT_MAX] = { 0 };
	size_t res;

	res = 0;

	if (pqs_interpreter_extract_paramaters(src, dst, command))
	{
		if (qsc_fileutils_exists(src) == true)
		{
			res = qsc_fileutils_get_size(src);
			res += qsc_stringutils_string_size(command);
			pmsg = (uint8_t*)qsc_memutils_malloc(res);

			if (pmsg != NULL)
			{
				res = pqs_interpreter_file_to_stream(pmsg, res, command);
				pmsg = (uint8_t*)qsc_memutils_realloc(pmsg, res);

				if (pmsg == NULL)
				{
					res = 0;
				}
			}
		}
	}

	return res;
}

static pqs_client_commands client_command_from_string(char* command)
{
	pqs_client_commands ret;

	if (qsc_consoleutils_line_equals(command, "cprint") == true)
	{
		ret = pqs_client_command_cprint;
	}
	else if (qsc_consoleutils_line_equals(command, "quit") == true)
	{
		ret = pqs_client_command_quit;
	}
	else if (qsc_stringutils_string_size(command) >=  PQS_CLIENT_INPUT_MIN)
	{
		ret = pqs_client_command_execute;
	}
	else
	{
		ret = pqs_client_command_none;
	}

	return ret;
}

static bool client_login_loop(pqs_connection_state* cns)
{
	size_t lcnt;
	bool bres;

	lcnt = 0;
	bres = true;

	/* send the login message */
	client_connection_login(cns);

	/* wait for the response */
	qsc_async_thread_sleep(PQS_CLIENT_LOGIN_TIME_INCREMENT);

	while (m_client_connection_state.connected == false)
	{
		if (cns != NULL)
		{
			qsc_async_thread_sleep(PQS_CLIENT_LOGIN_TIME_INCREMENT);
			++lcnt;

			if (m_client_connection_state.lcounter > PQS_CLIENT_LOGIN_ATTEMPTS_MAX)
			{
				qsc_consoleutils_print_safe("Maximum login attempts exceeded, exiting program.");
				m_client_connection_state.lcounter = 0;
				bres = false;
				break;
			}
			else if (lcnt > PQS_CLIENT_LOGIN_TIME_MAXIMUM)
			{
				qsc_consoleutils_print_safe("Maximum login time exceeded, exiting program.");
				m_client_connection_state.lcounter = 0;
				bres = false;
				break;
			}
		}
		else
		{
			bres = false;
			break;
		}
	}

	return bres;
}

static void client_send_loop(pqs_connection_state* cns)
{
	bool bres;

	/* send the login message */
	bres = client_login_loop(cns);

	if (bres == true)
	{
		char sin[PQS_CLIENT_INPUT_MAX + sizeof(char)] = {0};
		size_t mlen;

		mlen = 0;

		/* start the send loop */
		while (true)
		{
			client_print_prompt();

			if (mlen > 0)
			{
				pqs_network_packet spkt = { 0 };
				uint8_t msg[PQS_CLIENT_INPUT_MAX + PQS_MACTAG_SIZE] = { 0 };

				/* cache the command */
				m_client_connection_state.command = client_command_from_string(sin);

				if (cns != NULL)
				{
					if (m_client_connection_state.command == pqs_client_command_execute)
					{
						/* convert the packet to bytes */
						spkt.pmessage = msg + PQS_HEADER_SIZE;
						/* encrypt the message */
						pqs_packet_encrypt(cns, &spkt, (const uint8_t*)sin, mlen);
						/* serialize the header */
						pqs_packet_header_serialize(&spkt, msg);
						mlen = spkt.msglen + PQS_HEADER_SIZE;
						/* send to the server */
						qsc_socket_send(&cns->target, msg, mlen, qsc_socket_send_flag_none);
					}
					else if (m_client_connection_state.command == pqs_client_command_quit)
					{
						qsc_consoleutils_print_line("Disconnected from the remote server.");
						break;
					}
					else if (m_client_connection_state.command == pqs_client_command_cprint)
					{
						client_print_pubkey();
						client_print_message("");
					}
				}
				else
				{
					client_print_message("The remote host has disconnected.");
					break;
				}

				qsc_memutils_clear((uint8_t*)sin, sizeof(sin));
			}

			mlen = qsc_consoleutils_get_line(sin, sizeof(sin)) - 1;

			if (mlen > 0 && (sin[0] == '\n' || sin[0] == '\r'))
			{
				client_print_message("");
				mlen = 0;
			}
		}
	}
}
/** \endcond DOXYGEN_IGNORE */

int main(void)
{
	qsc_ipinfo_ipv4_address addv4t = { 0 };
	size_t ectr;
	pqs_errors perr;
	bool res;

	res = false;
	ectr = 0;
	m_client_connection_state.connected = false;
	m_client_connection_state.lcounter = 0;

	qsc_consoleutils_set_virtual_terminal();
	qsc_consoleutils_set_window_title("PQS Client - Not Connected");
	qsc_consoleutils_set_window_buffer(1600, 6000);
	qsc_consoleutils_set_window_size(1000, 600);

	client_get_prompt();
	client_print_banner();

	while (ectr < 3)
	{
		res = client_ipv4_dialogue(&addv4t);

		if (res == true)
		{
			break;
		}
		else
		{
			client_print_message("");
		}

		++ectr;
	}

	if (res == true)
	{
		perr = pqs_client_connect_ipv4(&m_client_connection_state.pubkey, &addv4t, PQS_SERVER_PORT, &client_send_loop, &client_receive_callback);
	
		if (perr != pqs_error_none)
		{
			const char* cerr;

			cerr = pqs_error_to_string(perr);

			if (cerr != NULL)
			{
				client_print_message(cerr);
			}
		}
	}
	else
	{
		client_print_message("Invalid input, exiting the application.");
	}

	client_print_string("The application has exited. Press any key to close..");
	qsc_consoleutils_get_wait();

	return 0;
}

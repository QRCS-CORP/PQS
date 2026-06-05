#include "appclt.h"
#include "pqs.h"
#include "pqslogger.h"
#include "pqshelp.h"
#include "pqsconfig.h"
#include "pqskey.h"
#include "pqsxfer.h"
#include "client.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "folderutils.h"
#include "intutils.h"
#include "memutils.h"
#include "netutils.h"
#include "sha3.h"
#include "stringutils.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#if defined(QSC_SYSTEM_OS_WINDOWS)
#	include <Windows.h>
#elif defined(__linux__)
#	include <sys/prctl.h>
#endif

#define PQS_FORMAT_BUFFER_SIZE 1280U

typedef struct client_connection_state
{
	qsms_client_verification_key pubkey;
	char prompt[PQS_CLIENT_PROMPT_MAX];
	char activeuser[PQS_LOGGER_USER_MAX];
	size_t lcounter;
	pqs_client_commands command;
	pqs_session_states state;
	bool authenticated;
	bool login_pending;
	bool connected;
	bool download_active;
	FILE* download_file;
	char download_path[QSC_SYSTEM_MAX_PATH];
	char download_root[QSC_SYSTEM_MAX_PATH];
	qsc_keccak_state download_hash_state;
	size_t download_bytes;
	bool download_recursive;
} client_connection_state;

typedef struct client_xfer_walk_context
{
	qsms_connection_state* cns;
} client_xfer_walk_context;

static client_connection_state m_client_connection_state;


static bool client_certificate_is_expired(uint64_t expiration)
{
	uint64_t now;
	bool res;

	now = (uint64_t)time(NULL);
	res = false;

	if (expiration != 0U && expiration <= now)
	{
		res = true;
	}

	return res;
}
static pqs_client_config m_client_config;

static bool client_apply_process_hardening(void)
{
	bool res;

	res = true;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	{
		PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extp;

		qsc_memutils_clear(&extp, sizeof(extp));
		extp.DisableExtensionPoints = 1U;

		if (SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy, &extp, sizeof(extp)) == 0)
		{
			res = false;
		}
	}
#elif defined(__linux__)
	if (prctl(PR_SET_DUMPABLE, 0UL, 0UL, 0UL, 0UL) != 0)
	{
		res = false;
	}
#else
	/* no portable process dump suppression is available on this platform */
#endif

	return res;
}

static size_t client_get_host_name(char* name)
{
	char host[QSC_NETUTILS_HOSTS_NAME_SIZE] = { 0 };
	size_t hlen;

	hlen = 0;

	if (qsc_netutils_get_host_name(host) == true)
	{
		hlen = qsc_stringutils_string_size(host);

		if (hlen >= PQS_CLIENT_PROMPT_MAX - 2U)
		{
			hlen = PQS_CLIENT_PROMPT_MAX - 2U;
		}

		qsc_memutils_copy(name, host, hlen);
	}

	return hlen;
}

static void client_get_prompt(void)
{
	char host[PQS_CLIENT_PROMPT_MAX] = { 0 };
	size_t hlen;

	hlen = client_get_host_name(host);

	if (hlen > 0U)
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
	size_t end;
	size_t len;
	size_t pos;
	size_t start;
	bool found;

	if (message != NULL && msglen != 0U)
	{
		end = msglen;

		while (end != 0U && (message[end - 1U] == '\0' || message[end - 1U] == '\n' || message[end - 1U] == '\r'))
		{
			--end;
		}

		if (end != 0U)
		{
			start = 0U;
			pos = end;

			while (pos != 0U)
			{
				--pos;

				if (message[pos] == '\n' || message[pos] == '\r')
				{
					start = pos + 1U;
					break;
				}
			}

			len = end - start;
			found = false;

			if (len >= 2U)
			{
				for (pos = start + 1U; pos < end; ++pos)
				{
					if (message[pos - 1U] == ':' && message[pos] == '\\')
					{
						found = true;
						break;
					}
				}
			}

			if (found == true)
			{
				if (len >= PQS_CLIENT_PROMPT_MAX)
				{
					len = PQS_CLIENT_PROMPT_MAX - 1U;
				}

				qsc_memutils_clear(m_client_connection_state.prompt, PQS_CLIENT_PROMPT_MAX);
				qsc_memutils_copy(m_client_connection_state.prompt, message + start, len);
				m_client_connection_state.prompt[len] = '\0';
			}
		}
	}
}

static void client_print_prompt(void)
{
	qsc_consoleutils_print_safe(m_client_connection_state.prompt);
}

static void client_print_prompt_after_remote_output(const char* message)
{
	size_t slen;

	if (message != NULL)
	{
		slen = qsc_stringutils_string_size(message);

		if (slen != 0U)
		{
			if (message[slen - 1U] != '\n' && message[slen - 1U] != '\r')
			{
				qsc_consoleutils_print_line("");
			}
		}
	}

	client_print_prompt();
}

static void client_print_message(const char* message)
{
	size_t slen;

	if (message != NULL)
	{
		slen = qsc_stringutils_string_size(message);

		if (slen != 0U)
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

static bool client_get_default_storage_path(char* fpath, size_t pathlen)
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

static bool client_get_config_path(char* fpath, size_t pathlen)
{
	bool res;

	res = client_get_default_storage_path(fpath, pathlen);

	if (res == true)
	{
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, pathlen, PQS_CLIENT_CONFIG_NAME);
	}

	return res;
}

static bool client_load_configuration(void)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = client_get_config_path(fpath, sizeof(fpath));

	if (res == true)
	{
		res = pqs_config_client_load(&m_client_config, fpath);
	}

	return res;
}

static bool client_get_storage_path(char* fpath, size_t pathlen)
{
	bool res;

	qsc_memutils_clear(fpath, pathlen);
	qsc_stringutils_copy_string(fpath, pathlen, m_client_config.application_path);
	res = qsc_folderutils_directory_exists(fpath);

	if (res == false)
	{
		res = qsc_folderutils_create_directory(fpath);
	}

	return res;
}

static bool client_get_log_path(char* fpath, size_t pathlen)
{
	bool res;

	res = client_get_storage_path(fpath, pathlen);

	if (res == true)
	{
		qsc_memutils_clear(fpath, pathlen);
		qsc_stringutils_copy_string(fpath, pathlen, m_client_config.log_path);
	}

	return res;
}

static bool client_get_known_hosts_path(char* fpath, size_t pathlen)
{
	bool res;

	res = client_get_storage_path(fpath, pathlen);

	if (res == true)
	{
		qsc_memutils_clear(fpath, pathlen);
		qsc_stringutils_copy_string(fpath, pathlen, m_client_config.known_hosts_path);
	}

	return res;
}

static void client_print_pubkey_fingerprint(void)
{
	char fp[PQS_KEY_FINGERPRINT_STRING_SIZE] = { 0 };

	if (pqs_key_fingerprint_string(fp, sizeof(fp), &m_client_connection_state.pubkey) == true)
	{
		client_print_message("Server public-key fingerprint SHA3-256:");
		client_print_message(fp);
	}
}

static bool client_confirm_host_key(const char* host)
{
	char answer[8] = { 0 };
	char fpath[QSC_SYSTEM_MAX_PATH + 1] = { 0 };
	char fp[PQS_KEY_FINGERPRINT_STRING_SIZE] = { 0 };
	char stored[PQS_KEY_FINGERPRINT_STRING_SIZE] = { 0 };
	bool known;
	bool res;

	res = false;

	if (host != NULL && pqs_key_host_is_valid(host) == true &&
		client_get_known_hosts_path(fpath, sizeof(fpath)) == true &&
		pqs_key_fingerprint_string(fp, sizeof(fp), &m_client_connection_state.pubkey) == true)
	{
		known = pqs_key_known_host_find(fpath, host, stored, sizeof(stored));

		if (known == true)
		{
			if (pqs_key_known_host_verify(fpath, host, fp) == true)
			{
				res = true;
				pqs_logger_write(pqs_log_level_info, pqs_log_event_hostkey_verified, m_client_connection_state.activeuser, host, "known host verified");
			}
			else
			{
				client_print_message("WARNING: The server public-key fingerprint does not match the known-hosts entry.");
				client_print_message("Known fingerprint:");
				client_print_message(stored);
				client_print_message("Presented fingerprint:");
				client_print_message(fp);
				pqs_logger_write(pqs_log_level_error, pqs_log_event_hostkey_changed, m_client_connection_state.activeuser, host, "known host mismatch");
			}
		}
		else
		{
			client_print_message("The server is not present in the PQS known-hosts database.");
			client_print_message("Server public-key fingerprint SHA3-256:");
			client_print_message(fp);

			if (m_client_config.strict_host_checking == true)
			{
				client_print_message("Strict host-key checking is enabled; unknown server keys are rejected.");
				pqs_logger_write(pqs_log_level_warning, pqs_log_event_hostkey_changed, m_client_connection_state.activeuser, host, "unknown host rejected by strict host-key checking");
			}
			else
			{
				client_print_message("Trust and save this server key? [yes/no]");
				(void)qsc_consoleutils_get_line(answer, sizeof(answer));

				if (qsc_consoleutils_line_equals(answer, "yes") == true || qsc_consoleutils_line_equals(answer, "y") == true)
				{
					res = pqs_key_known_host_set(fpath, host, fp);

					if (res == true)
					{
						pqs_logger_write(pqs_log_level_info, pqs_log_event_hostkey_pinned, m_client_connection_state.activeuser, host, "known host pinned");
					}
				}
			}
		}
	}

	return res;
}

static bool client_load_server_public_key_file(const char* fpath, const char* host)
{
	char* spub;
	size_t flen;
	size_t plen;
	bool res;

	res = false;

	if (fpath != NULL && host != NULL && fpath[0U] != '\0')
	{
		if (qsc_fileutils_exists(fpath) == true &&
			qsc_stringutils_string_contains(fpath, PQS_PUBKEY_NAME) == true)
		{
			plen = qsms_public_key_encoding_size();
			spub = qsc_memutils_malloc(plen + PQS_STRING_TERMINATOR_SIZE);

			if (spub != NULL)
			{
				qsc_memutils_clear(spub, plen + PQS_STRING_TERMINATOR_SIZE);
				flen = qsc_fileutils_get_size(fpath);

				if (flen != 0U && flen < plen)
				{
					(void)qsc_fileutils_copy_file_to_stream(fpath, spub, flen);
					spub[flen] = '\0';
					res = qsms_public_key_decode(&m_client_connection_state.pubkey, spub, flen + PQS_STRING_TERMINATOR_SIZE);
				}

				if (res == true)
				{
					if (client_certificate_is_expired(m_client_connection_state.pubkey.expiration) == true)
					{
						client_print_message("The server certificate has expired; connection refused.");
						pqs_logger_write(pqs_log_level_error, pqs_log_event_key_loaded, m_client_connection_state.activeuser, host, "server certificate expired");
						res = false;
					}
					else
					{
						pqs_logger_write(pqs_log_level_info, pqs_log_event_key_loaded, m_client_connection_state.activeuser, NULL, "server public key loaded");
						client_print_pubkey_fingerprint();
						res = client_confirm_host_key(host);
					}
				}

				qsc_memutils_alloc_free(spub);
			}
		}
	}

	return res;
}

static bool client_ipv4_dialogue(qsc_ipinfo_ipv4_address* address)
{
	char fpath[QSC_SYSTEM_MAX_PATH + 1] = { 0 };
	char sadd[QSC_IPINFO_IPV4_STRNLEN] = { 0 };
	qsc_ipinfo_ipv4_address addv4t = { 0 };
	size_t slen;
	bool res;

	res = false;
	slen = 0U;

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
	}

	if (res == false)
	{
		qsc_consoleutils_print_line("The address format is invalid.");
	}

	if (res == true)
	{
		res = client_load_server_public_key_file(m_client_config.server_public_key_path, sadd);

		if (res == false)
		{
			client_print_message("Enter the path of the public key:");
			client_print_message("");
			slen = qsc_consoleutils_get_line(fpath, sizeof(fpath)) - 1U;

			if (slen > 0U)
			{
				res = client_load_server_public_key_file(fpath, sadd);
			}
		}

		if (res == false)
		{
			qsc_consoleutils_print_line("The public key is invalid or could not be trusted.");
		}
	}

	return res;
}

static const char* client_format_message(const char* message, size_t msglen)
{
	int64_t npos;

	(void)msglen;
	npos = qsc_stringutils_find_string(message, "\n");

	if (npos < 0)
	{
		npos = 0;
	}

	return (const char*)message + npos;
}

static void client_xfer_close_download(bool success, const char* metadata)
{
	char expected[PQS_XFER_HASH_TEXT_SIZE] = { 0 };
	char actual[PQS_XFER_HASH_TEXT_SIZE] = { 0 };
	uint8_t hash[PQS_XFER_HASH_SIZE] = { 0U };
	size_t explen;
	bool verified;

	explen = 0U;
	verified = false;

	if (m_client_connection_state.download_file != NULL)
	{
		qsc_fileutils_close(m_client_connection_state.download_file);
		m_client_connection_state.download_file = NULL;
	}

	if (success == true && metadata != NULL)
	{
		qsc_sha3_finalize(&m_client_connection_state.download_hash_state, qsc_keccak_rate_256, hash);
		qsc_intutils_bin_to_hex(hash, actual, sizeof(hash));
		actual[PQS_XFER_HASH_TEXT_SIZE - 1U] = '\0';
		verified = pqs_xfer_parse_metadata(metadata, &explen, expected, sizeof(expected));
		verified = (verified == true && explen == m_client_connection_state.download_bytes && qsc_stringutils_strings_equal(expected, actual) == true);
	}

	if (success == true && verified == true)
	{
		client_print_message("PQS file download completed; SHA3-256 verified.");
	}
	else if (success == true)
	{
		client_print_message("PQS file download completed, but file hash verification failed or metadata was absent.");
	}
	else
	{
		client_print_message("PQS file download failed.");
	}

	m_client_connection_state.download_active = false;
	m_client_connection_state.download_bytes = 0U;
	qsc_memutils_clear((uint8_t*)m_client_connection_state.download_path, sizeof(m_client_connection_state.download_path));

	if (m_client_connection_state.download_recursive == false)
	{
		m_client_connection_state.command = pqs_client_command_none;
		client_print_prompt();
	}
}

static void client_xfer_receive_data(const uint8_t* message, size_t msglen)
{
	const uint8_t* data;
	size_t dlen;

	dlen = pqs_xfer_payload_size(message, msglen);

	if (m_client_connection_state.download_active == true && m_client_connection_state.download_file != NULL && dlen != 0U)
	{
		data = message + PQS_APPLICATION_MESSAGE_HEADER_SIZE + 2U;

		if (fwrite(data, sizeof(uint8_t), dlen, m_client_connection_state.download_file) != dlen)
		{
			client_xfer_close_download(false, NULL);
		}
		else
		{
			char pmsg[128] = { 0 };

			qsc_sha3_update(&m_client_connection_state.download_hash_state, qsc_keccak_rate_256, data, dlen);
			m_client_connection_state.download_bytes += dlen;

			if ((m_client_connection_state.download_bytes % (64U * 1024U)) < dlen)
			{
				snprintf(pmsg, sizeof(pmsg), "PQS transfer progress: %zu bytes received.", m_client_connection_state.download_bytes);
				client_print_message(pmsg);
			}
		}
	}
}

static void client_xfer_receive_directory_begin(const char* relative)
{
	char dpath[QSC_SYSTEM_MAX_PATH] = { 0 };

	if (relative != NULL && pqs_xfer_make_local_recursive_path(dpath, sizeof(dpath), m_client_connection_state.download_root, relative) == true)
	{
		(void)qsc_folderutils_create_directory_tree(dpath);
	}
}

static void client_xfer_receive_file_begin(const char* metadata)
{
	char expected[PQS_XFER_HASH_TEXT_SIZE] = { 0 };
	char rel[PQS_XFER_PATH_MAX] = { 0 };
	char lpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	size_t fsize;

	fsize = 0U;

	if (metadata != NULL && pqs_xfer_parse_file_metadata(metadata, rel, sizeof(rel), &fsize, expected, sizeof(expected)) == true &&
		pqs_xfer_make_local_recursive_path(lpath, sizeof(lpath), m_client_connection_state.download_root, rel) == true && pqs_xfer_create_parent_directories(lpath) == true)
	{
		if (m_client_connection_state.download_file != NULL)
		{
			qsc_fileutils_close(m_client_connection_state.download_file);
			m_client_connection_state.download_file = NULL;
		}

		m_client_connection_state.download_file = qsc_fileutils_open(lpath, qsc_fileutils_mode_write, true);

		if (m_client_connection_state.download_file != NULL)
		{
			qsc_stringutils_copy_string(m_client_connection_state.download_path, sizeof(m_client_connection_state.download_path), lpath);
			m_client_connection_state.download_active = true;
			m_client_connection_state.download_bytes = 0U;
			qsc_sha3_initialize(&m_client_connection_state.download_hash_state);
		}
	}
}

static void client_set_connected(qsms_connection_state* cns)
{
	if (cns != NULL && m_client_connection_state.connected == false)
	{
		char msg[QSC_NETUTILS_NAME_BUFFER_SIZE] = { 0U };

		qsc_stringutils_copy_string(msg, sizeof(msg), "Connected to ");
		qsc_stringutils_concat_strings(msg, sizeof(msg), (char*)cns->target.address);
		qsc_consoleutils_set_window_title(msg);
		client_print_message(msg);
		pqs_logger_write(pqs_log_level_info, pqs_log_event_connection_open, m_client_connection_state.activeuser, (const char*)cns->target.address, "connection opened");
		m_client_connection_state.connected = true;
		m_client_connection_state.authenticated = false;
		m_client_connection_state.login_pending = false;
		m_client_connection_state.state = pqs_session_state_login_required;
	}
}

static bool client_ensure_login_username(void)
{
	char uname[PQS_USERNAME_MAX + 1U] = { 0 };
	size_t ulen;
	bool res;

	res = true;

	if (m_client_config.username[0U] == '\0')
	{
		res = false;
		client_print_string("Enter the PQS username:");
		client_print_message("");
		ulen = qsc_consoleutils_get_line(uname, sizeof(uname)) - 1U;

		if (ulen > 0U && ulen < PQS_USERNAME_MAX)
		{
			qsc_stringutils_copy_string(m_client_config.username, sizeof(m_client_config.username), uname);
			qsc_stringutils_copy_string(m_client_connection_state.activeuser, sizeof(m_client_connection_state.activeuser), uname);
			res = true;
		}
		else
		{
			client_print_message("The PQS username is invalid.");
		}
	}

	qsc_memutils_secure_erase((uint8_t*)uname, sizeof(uname));
	return res;
}

static void client_receive_callback(qsms_connection_state* cns, const uint8_t* message, size_t msglen)
{
	const char* mptr;
	pqs_application_messages type;
	size_t plen;

	mptr = NULL;
	plen = 0U;
	type = pqs_application_message_none;

	client_set_connected(cns);

	if (message != NULL && msglen >= PQS_APPLICATION_MESSAGE_HEADER_SIZE)
	{
		type = (pqs_application_messages)message[0U];
		mptr = (const char*)(message + PQS_APPLICATION_MESSAGE_HEADER_SIZE);
		plen = msglen - PQS_APPLICATION_MESSAGE_HEADER_SIZE;

		if (type == pqs_application_message_response_more || type == pqs_application_message_response_final ||
			type == pqs_application_message_admin_response_more || type == pqs_application_message_admin_response_final)
		{
			if (plen > PQS_STRING_TERMINATOR_SIZE)
			{
				qsc_consoleutils_print_safe(mptr);
			}

			if (type == pqs_application_message_response_final || type == pqs_application_message_admin_response_final)
			{
				m_client_connection_state.command = pqs_client_command_none;
				m_client_connection_state.state = (m_client_connection_state.authenticated == true) ?
					pqs_session_state_authenticated : pqs_session_state_login_required;
				client_print_prompt_after_remote_output((plen > PQS_STRING_TERMINATOR_SIZE) ? mptr : NULL);
			}
		}
		else if (type == pqs_application_message_login_success)
		{
			m_client_connection_state.authenticated = true;
			m_client_connection_state.login_pending = false;
			m_client_connection_state.state = pqs_session_state_authenticated;
			m_client_connection_state.command = pqs_client_command_none;
			client_print_string("PQS login succeeded.");
			client_print_prompt();
			pqs_logger_write(pqs_log_level_info, pqs_log_event_auth_success, m_client_connection_state.activeuser, (const char*)cns->target.address, "login success");
		}
		else if (type == pqs_application_message_login_failure)
		{
			m_client_connection_state.authenticated = false;
			m_client_connection_state.login_pending = false;
			m_client_connection_state.state = pqs_session_state_login_required;
			m_client_connection_state.command = pqs_client_command_none;

			if (plen > PQS_STRING_TERMINATOR_SIZE)
			{
				client_print_string(mptr);
			}
			else
			{
				client_print_string("PQS authentication failed.");
			}

			pqs_logger_write(pqs_log_level_warning, pqs_log_event_auth_failure, m_client_connection_state.activeuser, (const char*)cns->target.address, "login failure");
		}
		else if (type == pqs_application_message_error)
		{
			m_client_connection_state.login_pending = false;
			m_client_connection_state.command = pqs_client_command_none;

			if (plen > PQS_STRING_TERMINATOR_SIZE)
			{
				client_print_string(mptr);
			}
			else
			{
				client_print_string("PQS application error.");
			}

			if (m_client_connection_state.authenticated == true)
			{
				m_client_connection_state.state = pqs_session_state_authenticated;
				client_print_prompt();
			}
			else
			{
				m_client_connection_state.state = pqs_session_state_login_required;
			}

			pqs_logger_write(pqs_log_level_warning, pqs_log_event_protocol_error, m_client_connection_state.activeuser, (const char*)cns->target.address, "application error");
		}
		else if (type == pqs_application_message_file_directory_begin)
		{
			client_xfer_receive_directory_begin(mptr);
		}
		else if (type == pqs_application_message_file_directory_end)
		{
			/* directory end markers are accepted for transfer ordering and future progress reporting. */
		}
		else if (type == pqs_application_message_file_begin)
		{
			client_xfer_receive_file_begin(mptr);
		}
		else if (type == pqs_application_message_file_data)
		{
			client_xfer_receive_data(message, msglen);
		}
		else if (type == pqs_application_message_file_final)
		{
			client_xfer_close_download(true, (plen > 1U) ? mptr : NULL);
			pqs_logger_write(pqs_log_level_audit, pqs_log_event_file_transfer_complete, m_client_connection_state.activeuser, (const char*)cns->target.address, "get");
		}
		else if (type == pqs_application_message_file_status)
		{
			if (plen > PQS_STRING_TERMINATOR_SIZE)
			{
				client_print_message(mptr);
			}

			m_client_connection_state.command = pqs_client_command_none;
			m_client_connection_state.download_recursive = false;
			qsc_memutils_clear((uint8_t*)m_client_connection_state.download_root, sizeof(m_client_connection_state.download_root));
		}
		else if (type == pqs_application_message_disconnect)
		{
			m_client_connection_state.state = pqs_session_state_closing;
			m_client_connection_state.command = pqs_client_command_quit;

			if (plen > PQS_STRING_TERMINATOR_SIZE)
			{
				client_print_message(mptr);
			}
		}
		else
		{
			client_print_message("Invalid PQS application message received.");
			pqs_logger_write(pqs_log_level_warning, pqs_log_event_protocol_error, m_client_connection_state.activeuser, (const char*)cns->target.address, "invalid application message");
		}
	}
}

static void client_print_pubkey(void)
{
	char* spub;
	size_t elen;
	size_t plen;

	plen = qsms_public_key_encoding_size();
	spub = qsc_memutils_malloc(plen + PQS_STRING_TERMINATOR_SIZE);

	if (spub != NULL)
	{
		qsc_memutils_clear(spub, plen + PQS_STRING_TERMINATOR_SIZE);
		elen = qsms_public_key_encode(spub, plen, &m_client_connection_state.pubkey);

		if (elen <= plen)
		{
			spub[elen] = '\0';
		}
		else
		{
			spub[plen] = '\0';
		}

		client_print_string("");
		client_print_string(spub);
		client_print_pubkey_fingerprint();
		qsc_memutils_alloc_free(spub);
	}
}

static void client_print_known_hosts(void)
{
	FILE* fp;
	char fpath[QSC_SYSTEM_MAX_PATH + 1] = { 0 };
	char line[PQS_KEY_KNOWN_HOST_LINE_MAX] = { 0 };
	bool found;

	found = false;

	if (client_get_known_hosts_path(fpath, sizeof(fpath)) == true)
	{
		fp = qsc_fileutils_open(fpath, qsc_fileutils_mode_read, true);

		if (fp != NULL)
		{
			client_print_message("Known PQS hosts:");

			while (fgets(line, sizeof(line), fp) != NULL)
			{
				if (line[0U] != '#' && qsc_stringutils_string_size(line) > 1U)
				{
					client_print_string(line);
					found = true;
				}
			}

			qsc_fileutils_close(fp);
		}
	}

	if (found == false)
	{
		client_print_message("No PQS known-hosts entries are configured.");
	}
}

static void client_remove_known_host(const char* command)
{
	char fpath[QSC_SYSTEM_MAX_PATH + 1] = { 0 };
	const char* host;
	bool res;

	res = false;

	if (command != NULL)
	{
		host = command + qsc_stringutils_string_size("khremove");

		while (*host == ' ' || *host == '\t')
		{
			++host;
		}

		if (*host != '\0' && client_get_known_hosts_path(fpath, sizeof(fpath)) == true)
		{
			res = pqs_key_known_host_remove(fpath, host);
		}
	}

	client_print_message(res == true ? "The PQS known-hosts entry has been removed." : "The PQS known-hosts entry could not be removed.");
}

static bool client_strip_escape_prefix(char* command)
{
	char* src;
	char* dst;
	bool res;

	res = false;

	if (command != NULL && command[0U] == ':')
	{
		src = command + 1U;

		while (*src == ' ' || *src == '\t')
		{
			++src;
		}

		dst = command;

		while (*src != '\0')
		{
			*dst = *src;
			++dst;
			++src;
		}

		*dst = '\0';
		res = true;
	}

	return res;
}

static pqs_client_commands client_command_from_string(char* command, bool local)
{
	pqs_client_commands ret;

	ret = pqs_client_command_none;

	if (command != NULL)
	{
		if (local == false)
		{
			if (qsc_stringutils_string_size(command) >= PQS_CLIENT_INPUT_MIN)
			{
				ret = pqs_client_command_execute;
			}
		}
		else if (qsc_consoleutils_line_equals(command, "cprint") == true ||
			qsc_consoleutils_line_equals(command, "key") == true ||
			qsc_consoleutils_line_equals(command, "fp") == true ||
			qsc_consoleutils_line_equals(command, "fingerprint") == true)
		{
			ret = pqs_client_command_cprint;
		}
		else if (qsc_consoleutils_line_equals(command, "known") == true ||
			qsc_consoleutils_line_equals(command, "khlist") == true)
		{
			ret = pqs_client_command_knownhosts;
		}
		else if (strncmp(command, "khremove", 8U) == 0)
		{
			ret = pqs_client_command_knownhost_remove;
		}
		else if (strncmp(command, "get", 3U) == 0)
		{
			ret = pqs_client_command_file_get;
		}
		else if (strncmp(command, "put", 3U) == 0)
		{
			ret = pqs_client_command_file_put;
		}
		else if (strncmp(command, "list", 4U) == 0)
		{
			ret = pqs_client_command_file_list;
		}
		else if (strncmp(command, "mkdir", 5U) == 0)
		{
			ret = pqs_client_command_file_mkdir;
		}
		else if (strncmp(command, "remove", 6U) == 0)
		{
			ret = pqs_client_command_file_remove;
		}
		else if (strncmp(command, "admin", 5U) == 0)
		{
			ret = pqs_client_command_admin;
		}
		else if (qsc_consoleutils_line_equals(command, "detail") == true ||
			qsc_consoleutils_line_equals(command, "help detail") == true)
		{
			ret = pqs_client_command_help_detail;
		}
		else if (qsc_consoleutils_line_equals(command, "help") == true)
		{
			ret = pqs_client_command_help;
		}
		else if (qsc_consoleutils_line_equals(command, "quit") == true)
		{
			ret = pqs_client_command_quit;
		}
	}

	return ret;
}

static bool client_send_application_message(qsms_connection_state* cns, pqs_application_messages type, const uint8_t* message, size_t msglen)
{
	qsms_network_packet spkt = { 0 };
	uint8_t msg[PQS_CLIENT_INPUT_MAX + QSMS_SIMPLEX_MACTAG_SIZE + QSMS_HEADER_SIZE] = { 0U };
	uint8_t pmsg[PQS_CLIENT_INPUT_MAX] = { 0U };
	size_t mlen;
	bool res;

	res = false;

	if (cns != NULL && msglen <= PQS_CLIENT_COMMAND_PAYLOAD_MAX)
	{
		pmsg[0U] = (uint8_t)type;
		mlen = PQS_APPLICATION_MESSAGE_HEADER_SIZE;

		if (message != NULL && msglen != 0U)
		{
			qsc_memutils_copy(pmsg + PQS_APPLICATION_MESSAGE_HEADER_SIZE, message, msglen);
			mlen += msglen;
		}

		pmsg[mlen] = '\0';
		mlen += PQS_STRING_TERMINATOR_SIZE;
		spkt.pmessage = msg + QSMS_HEADER_SIZE;

		if (qsms_packet_encrypt(cns, &spkt, pmsg, mlen) == qsms_error_none)
		{
			qsms_packet_header_serialize(&spkt, msg);
			mlen = spkt.msglen + QSMS_HEADER_SIZE;

			if (qsc_socket_send(&cns->target, msg, mlen, qsc_socket_send_flag_none) == mlen)
			{
				res = true;
			}
		}
	}

	return res;
}

static char* client_string_token(char* source, const char* delimiters, char** context)
{
#if defined(QSC_SYSTEM_COMPILER_MSC)
	return strtok_s(source, delimiters, context);
#else
	return strtok_r(source, delimiters, context);
#endif
}

static size_t client_tokenize_command(char* line, char* tokens[], size_t tokmax)
{
	char* ctx;
	char* tok;
	size_t count;

	ctx = NULL;
	count = 0U;

	if (line != NULL && tokens != NULL && tokmax != 0U)
	{
		tok = client_string_token(line, " \t\r\n", &ctx);

		while (tok != NULL && count < tokmax)
		{
			tokens[count] = tok;
			++count;
			tok = client_string_token(NULL, " \t\r\n", &ctx);
		}
	}

	return count;
}

static bool client_send_file_data(qsms_connection_state* cns, const uint8_t* data, size_t datalen)
{
	uint8_t msg[PQS_XFER_CHUNK_SIZE + 2U] = { 0U };
	bool res;

	res = false;

	if (data != NULL && datalen != 0U && datalen <= PQS_XFER_CHUNK_SIZE)
	{
		msg[0U] = (uint8_t)((datalen >> 8U) & 0xFFU);
		msg[1U] = (uint8_t)(datalen & 0xFFU);
		qsc_memutils_copy(msg + 2U, data, datalen);
		res = client_send_application_message(cns, pqs_application_message_file_put_data, msg, datalen + 2U);
	}

	return res;
}

static bool client_file_get(qsms_connection_state* cns, const char* command)
{
	char line[PQS_CLIENT_INPUT_MAX] = { 0 };
	char* tokens[4] = { 0 };
	size_t count;
	bool res;

	res = false;

	if (cns != NULL && command != NULL)
	{
		qsc_stringutils_copy_string(line, sizeof(line), command);
		count = client_tokenize_command(line, tokens, 4U);

		if (count == 3U && pqs_xfer_path_is_safe(tokens[1U]) == true)
		{
			if (m_client_connection_state.download_file != NULL)
			{
				qsc_fileutils_close(m_client_connection_state.download_file);
				m_client_connection_state.download_file = NULL;
			}

			m_client_connection_state.download_file = qsc_fileutils_open(tokens[2U], qsc_fileutils_mode_write, true);

			if (m_client_connection_state.download_file != NULL)
			{
				qsc_stringutils_copy_string(m_client_connection_state.download_path, sizeof(m_client_connection_state.download_path), tokens[2U]);
				m_client_connection_state.download_active = true;
				m_client_connection_state.download_recursive = false;
				m_client_connection_state.download_bytes = 0U;
				qsc_sha3_initialize(&m_client_connection_state.download_hash_state);
				m_client_connection_state.command = pqs_client_command_file_get;
				res = client_send_application_message(cns, pqs_application_message_file_get_request, (const uint8_t*)tokens[1U], qsc_stringutils_string_size(tokens[1U]));
			}
		}
		else if (count == 4U && qsc_stringutils_strings_equal(tokens[1U], PQS_XFER_RECURSIVE_PREFIX) == true && pqs_xfer_path_is_safe(tokens[2U]) == true)
		{
			if (qsc_folderutils_directory_exists(tokens[3U]) == false)
			{
				(void)qsc_folderutils_create_directory_tree(tokens[3U]);
			}

			if (qsc_folderutils_directory_exists(tokens[3U]) == true && pqs_xfer_path_is_symlink(tokens[3U]) == false)
			{
				qsc_stringutils_copy_string(m_client_connection_state.download_root, sizeof(m_client_connection_state.download_root), tokens[3U]);
				m_client_connection_state.download_recursive = true;
				m_client_connection_state.command = pqs_client_command_file_get;
				res = client_send_application_message(cns, pqs_application_message_file_get_recursive_request, (const uint8_t*)tokens[2U], qsc_stringutils_string_size(tokens[2U]));
			}
		}
	}

	if (res == false)
	{
		client_print_message("Usage: get [remote-path] [local-path] or get -r [remote-directory] [local-directory]");
	}
	else
	{
		pqs_logger_write(pqs_log_level_audit, pqs_log_event_file_transfer_start, m_client_connection_state.activeuser, "none", "get");
	}

	return res;
}

static bool client_file_put_single(qsms_connection_state* cns, const char* localpath, const char* remotepath)
{
	FILE* fp;
	char metadata[PQS_XFER_METADATA_MAX] = { 0 };
	char hexhash[PQS_XFER_HASH_TEXT_SIZE] = { 0 };
	uint8_t chunk[PQS_XFER_CHUNK_SIZE] = { 0U };
	size_t fsize;
	size_t rlen;
	size_t sent;
	bool res;

	fp = NULL;
	fsize = 0U;
	sent = 0U;
	res = false;

	if (cns != NULL && localpath != NULL && remotepath != NULL && pqs_xfer_path_is_safe(remotepath) == true &&
		qsc_fileutils_exists(localpath) == true && pqs_xfer_path_is_symlink(localpath) == false &&
		pqs_xfer_hash_file(localpath, hexhash, sizeof(hexhash), &fsize) == true)
	{
		fp = qsc_fileutils_open(localpath, qsc_fileutils_mode_read, true);

		if (fp != NULL)
		{
			res = client_send_application_message(cns, pqs_application_message_file_put_start, (const uint8_t*)remotepath, qsc_stringutils_string_size(remotepath));

			while (res == true)
			{
				rlen = fread(chunk, sizeof(uint8_t), sizeof(chunk), fp);

				if (rlen != 0U)
				{
					res = client_send_file_data(cns, chunk, rlen);
					sent += rlen;

					if ((sent % (64U * 1024U)) < rlen || sent == fsize)
					{
						char pmsg[128] = { 0 };

						snprintf(pmsg, sizeof(pmsg), "PQS transfer progress: %zu/%zu bytes sent.", sent, fsize);
						client_print_message(pmsg);
					}

					qsc_memutils_clear(chunk, sizeof(chunk));
				}
				else
				{
					break;
				}
			}

			qsc_fileutils_close(fp);

			if (res == true && pqs_xfer_format_metadata(metadata, sizeof(metadata), fsize, hexhash) == true)
			{
				res = client_send_application_message(cns, pqs_application_message_file_put_final, (const uint8_t*)metadata, qsc_stringutils_string_size(metadata));
			}
		}
	}

	return res;
}

static bool client_xfer_walk_callback(pqs_xfer_walk_events event, const char* localpath, const char* relative, void* context)
{
	client_xfer_walk_context* wctx;
	bool res;

	res = false;
	wctx = (client_xfer_walk_context*)context;

	if (wctx != NULL && wctx->cns != NULL && localpath != NULL && relative != NULL)
	{
		if (event == pqs_xfer_walk_event_directory_begin)
		{
			res = client_send_application_message(wctx->cns, pqs_application_message_file_mkdir_request, (const uint8_t*)relative, qsc_stringutils_string_size(relative));
		}
		else if (event == pqs_xfer_walk_event_file)
		{
			res = client_file_put_single(wctx->cns, localpath, relative);
		}
		else
		{
			res = true;
		}
	}

	return res;
}

static bool client_file_put_recursive(qsms_connection_state* cns, const char* localroot, const char* remoteroot)
{
	client_xfer_walk_context ctx;
	bool res;

	ctx.cns = cns;
	res = false;

	if (cns != NULL && localroot != NULL && remoteroot != NULL)
	{
		res = pqs_xfer_walk_directory(localroot, remoteroot, PQS_XFER_RECURSION_MAX, client_xfer_walk_callback, &ctx);
	}

	return res;
}

static bool client_file_put(qsms_connection_state* cns, const char* command)
{
	char line[PQS_CLIENT_INPUT_MAX] = { 0 };
	char* tokens[4] = { 0 };
	size_t count;
	bool res;

	res = false;

	if (cns != NULL && command != NULL)
	{
		qsc_stringutils_copy_string(line, sizeof(line), command);
		count = client_tokenize_command(line, tokens, 4U);

		if (count == 3U)
		{
			res = client_file_put_single(cns, tokens[1U], tokens[2U]);
		}
		else if (count == 4U && qsc_stringutils_strings_equal(tokens[1U], PQS_XFER_RECURSIVE_PREFIX) == true)
		{
			res = client_file_put_recursive(cns, tokens[2U], tokens[3U]);
		}
	}

	if (res == false)
	{
		client_print_message("Usage: put [local-path] [remote-path] or put -r [local-directory] [remote-directory]");
	}
	else
	{
		pqs_logger_write(pqs_log_level_audit, pqs_log_event_file_transfer_start, m_client_connection_state.activeuser, "none", "put");
	}

	return res;
}

static bool client_file_simple(qsms_connection_state* cns, const char* command, pqs_application_messages type, const char* usage)
{
	char line[PQS_CLIENT_INPUT_MAX] = { 0 };
	char* tokens[2] = { 0 };
	size_t count;
	bool res;

	res = false;

	if (cns != NULL && command != NULL)
	{
		qsc_stringutils_copy_string(line, sizeof(line), command);
		count = client_tokenize_command(line, tokens, 2U);

		if (count == 2U && pqs_xfer_path_is_safe(tokens[1U]) == true)
		{
			res = client_send_application_message(cns, type, (const uint8_t*)tokens[1U], qsc_stringutils_string_size(tokens[1U]));
		}
		else if (type == pqs_application_message_file_list_request && count == 1U)
		{
			res = client_send_application_message(cns, type, (const uint8_t*)".", 1U);
		}
	}

	if (res == false)
	{
		client_print_message(usage);
	}

	return res;
}

static bool client_send_login_request(qsms_connection_state* cns, const char* passphrase)
{
	uint8_t payload[PQS_LOGIN_REQUEST_PAYLOAD_SIZE] = { 0U };
	size_t plen;
	bool res;

	res = false;

	if (cns != NULL && passphrase != NULL)
	{
		plen = qsc_stringutils_string_size(passphrase);

		if (m_client_config.username[0U] == '\0')
		{
			client_print_message("The PQS client username is not configured. Set the username field in the client configuration.");
		}
		else if (plen < PQS_PASSPHRASE_MIN || plen >= PQS_PASSPHRASE_MAX)
		{
			client_print_message("The PQS passphrase length is invalid.");
		}
		else
		{
			qsc_stringutils_copy_string((char*)payload, PQS_USERNAME_MAX, m_client_config.username);
			qsc_stringutils_copy_string((char*)(payload + PQS_USERNAME_MAX), PQS_PASSPHRASE_MAX, passphrase);
			res = client_send_application_message(cns, pqs_application_message_login_request, payload, sizeof(payload));

			if (res == false)
			{
				client_print_message("The PQS login request could not be sent.");
			}
		}
	}

	qsc_memutils_secure_erase(payload, sizeof(payload));
	return res;
}

static void client_send_loop(qsms_connection_state* cns)
{
	char lmsg[128] = { 0 };
	char sin[PQS_CLIENT_INPUT_MAX + sizeof(char)] = { 0 };
	size_t mlen;

	mlen = 0U;

	client_set_connected(cns);
	(void)client_ensure_login_username();

	/* start the send loop */
	while (true)
	{
		if (mlen > 0U)
		{
			if (cns != NULL)
			{
				bool local;

				local = client_strip_escape_prefix(sin);

				if (m_client_connection_state.authenticated == false &&
					m_client_connection_state.state == pqs_session_state_login_required &&
					local == false)
				{
					if (m_client_connection_state.login_pending == false)
					{
						m_client_connection_state.login_pending = client_send_login_request(cns, sin);
					}

					m_client_connection_state.command = pqs_client_command_none;
				}
				else
				{
					/* cache the command */
					m_client_connection_state.command = client_command_from_string(sin, local);

					if (m_client_connection_state.command == pqs_client_command_execute)
					{
						if (client_send_application_message(cns, pqs_application_message_command_request, (const uint8_t*)sin, mlen) == true)
						{
							qsc_memutils_clear((uint8_t*)lmsg, sizeof(lmsg));
							snprintf(lmsg, sizeof(lmsg), "command-bytes=%zu", mlen);
							pqs_logger_write(pqs_log_level_audit, pqs_log_event_command_received, m_client_connection_state.activeuser, (const char*)cns->target.address, lmsg);
						}
						else
						{
							client_print_message("The command request could not be sent.");
							m_client_connection_state.command = pqs_client_command_none;
						}
					}
					else if (m_client_connection_state.command == pqs_client_command_admin)
					{
						char* acmd;

						acmd = sin + 5U;

						while (*acmd == ' ' || *acmd == '\t')
						{
							++acmd;
						}

						if (*acmd != '\0' && client_send_application_message(cns, pqs_application_message_admin_request, (const uint8_t*)acmd, qsc_stringutils_string_size(acmd)) == true)
						{
							qsc_memutils_clear((uint8_t*)lmsg, sizeof(lmsg));
							snprintf(lmsg, sizeof(lmsg), "admin-command-bytes=%zu", qsc_stringutils_string_size(acmd));
							pqs_logger_write(pqs_log_level_audit, pqs_log_event_admin_request, m_client_connection_state.activeuser, (const char*)cns->target.address, lmsg);
						}
						else
						{
							client_print_message("The administrative request could not be sent.");
							m_client_connection_state.command = pqs_client_command_none;
						}
					}
					else if (m_client_connection_state.command == pqs_client_command_quit)
					{
						qsc_consoleutils_print_line("Disconnected from the remote server.");
						pqs_logger_write(pqs_log_level_info, pqs_log_event_connection_close, m_client_connection_state.activeuser, (const char*)cns->target.address, "client quit");
						break;
					}
					else if (m_client_connection_state.command == pqs_client_command_cprint)
					{
						client_print_pubkey();
						m_client_connection_state.command = pqs_client_command_none;
					}
					else if (m_client_connection_state.command == pqs_client_command_knownhosts)
					{
						client_print_known_hosts();
						m_client_connection_state.command = pqs_client_command_none;
					}
					else if (m_client_connection_state.command == pqs_client_command_knownhost_remove)
					{
						client_remove_known_host(sin);
						m_client_connection_state.command = pqs_client_command_none;
					}
					else if (m_client_connection_state.command == pqs_client_command_help)
					{
						pqs_help_client_print_help();
						m_client_connection_state.command = pqs_client_command_none;
					}
					else if (m_client_connection_state.command == pqs_client_command_help_detail)
					{
						pqs_help_client_print_detail();
						m_client_connection_state.command = pqs_client_command_none;
					}
					else if (m_client_connection_state.command == pqs_client_command_file_get)
					{
						(void)client_file_get(cns, sin);
					}
					else if (m_client_connection_state.command == pqs_client_command_file_put)
					{
						(void)client_file_put(cns, sin);
						m_client_connection_state.command = pqs_client_command_none;
					}
					else if (m_client_connection_state.command == pqs_client_command_file_list)
					{
						(void)client_file_simple(cns, sin, pqs_application_message_file_list_request, "Usage: list [remote-path]");
						m_client_connection_state.command = pqs_client_command_none;
					}
					else if (m_client_connection_state.command == pqs_client_command_file_mkdir)
					{
						(void)client_file_simple(cns, sin, pqs_application_message_file_mkdir_request, "Usage: mkdir [remote-path]");
						m_client_connection_state.command = pqs_client_command_none;
					}
					else if (m_client_connection_state.command == pqs_client_command_file_remove)
					{
						(void)client_file_simple(cns, sin, pqs_application_message_file_remove_request, "Usage: remove [remote-path]");
						m_client_connection_state.command = pqs_client_command_none;
					}
				}
			}
			else
			{
				client_print_message("The remote host has disconnected.");
				break;
			}

			qsc_memutils_secure_erase((uint8_t*)sin, sizeof(sin));
		}

		if (m_client_connection_state.command != pqs_client_command_execute &&
			m_client_connection_state.command != pqs_client_command_admin &&
			m_client_connection_state.command != pqs_client_command_file_get)
		{
			if (m_client_connection_state.authenticated == false &&
				m_client_connection_state.state == pqs_session_state_login_required &&
				m_client_connection_state.login_pending == false)
			{
				client_print_string("Enter PQS passphrase:");
				client_print_message("");
			}
			else
			{
				client_print_prompt();
			}
		}

		mlen = qsc_consoleutils_get_line(sin, sizeof(sin)) - 1U;

		if (mlen > 0U && (sin[0U] == '\n' || sin[0U] == '\r'))
		{
			client_print_message("");
			mlen = 0U;
		}
	}
}

int main(void)
{
	qsc_ipinfo_ipv4_address addv4t = { 0 };
	char lpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	size_t ectr;
	qsms_errors perr;
	bool res;

	res = false;
	ectr = 0;
	m_client_connection_state.connected = false;
	m_client_connection_state.download_active = false;
	m_client_connection_state.download_file = NULL;
	m_client_connection_state.lcounter = 0U;
	m_client_connection_state.command = pqs_client_command_none;
	m_client_connection_state.authenticated = false;
	m_client_connection_state.login_pending = false;
	m_client_connection_state.state = pqs_session_state_none;
	qsc_stringutils_copy_string(m_client_connection_state.activeuser, sizeof(m_client_connection_state.activeuser), "client");

	qsc_consoleutils_set_virtual_terminal();
	qsc_consoleutils_set_window_title("PQS Client - Not Connected");
	qsc_consoleutils_set_window_buffer(1600U, 6000U);
	qsc_consoleutils_set_window_size(1000U, 600U);

	pqs_config_client_defaults(&m_client_config);

	if (client_load_configuration() == false)
	{
		qsc_consoleutils_print_line("The PQS client configuration could not be loaded.");
	}

	client_get_prompt();
	pqs_help_client_print_banner();

	if (client_get_log_path(lpath, sizeof(lpath)) == true)
	{
		pqs_logger_initialize(lpath, m_client_config.log_level);
		pqs_logger_write(pqs_log_level_info, pqs_log_event_application_start, m_client_connection_state.activeuser, NULL, "client start");

		if (client_apply_process_hardening() == true)
		{
			pqs_logger_write(pqs_log_level_info, pqs_log_event_application_start, m_client_connection_state.activeuser, NULL, "process hardening applied");
		}
		else
		{
			pqs_logger_write(pqs_log_level_warning, pqs_log_event_application_start, m_client_connection_state.activeuser, NULL, "process hardening partially applied");
		}
	}

	while (ectr < 3U)
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
		perr = qsms_client_simplex_connect_ipv4(&m_client_connection_state.pubkey, &addv4t, m_client_config.port, &client_send_loop, &client_receive_callback);
	
		if (perr != qsms_error_none)
		{
			const char* cerr;

			cerr = qsms_error_to_string(perr);

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

	pqs_logger_write(pqs_log_level_info, pqs_log_event_application_stop, m_client_connection_state.activeuser, NULL, "client stop");
	pqs_logger_dispose();

	client_print_string("The application has exited. Press any key to close..");
	qsc_consoleutils_get_wait();

	return 0;
}

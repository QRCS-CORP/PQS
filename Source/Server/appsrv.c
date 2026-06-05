#if !defined(QSC_SYSTEM_OS_WINDOWS)
#	if !defined(_POSIX_C_SOURCE)
#		define _POSIX_C_SOURCE 200809L
#	endif
#endif
#include "appsrv.h"
#include "pqs.h"
#include "pqsadmin.h"
#include "pqslogger.h"
#include "pqshelp.h"
#include "pqsconfig.h"
#include "pqskey.h"
#include "pqsuser.h"
#include "pqsshell.h"
#include "pqspolicy.h"
#include "pqssandbox.h"
#include "pqsxfer.h"
#include "pqsprocess.h"
#include "server.h"
#include "acp.h"
#include "async.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "folderutils.h"
#include "ipinfo.h"
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
#else
#	include <sys/stat.h>
#	include <sys/types.h>
#	include <unistd.h>
#	if defined(__linux__)
#		include <sys/prctl.h>
#	endif
#endif

typedef enum server_console_modes
{
	server_console_mode_server = 0x00U,
	server_console_mode_user = 0x01U,
	server_console_mode_shell = 0x02U,
	server_console_mode_policy = 0x03U
} server_console_modes;

typedef struct server_connection_state
{
	char prompt[PQS_SERVER_PROMPT_MAX];
	char activeuser[PQS_LOGGER_USER_MAX];
	pqs_session_states state;
	pqs_user_privileges privilege;
	server_console_modes mode;
	uint32_t instance;
	uint32_t login_attempts;
	bool authenticated;
	bool upload_active;
	FILE* upload_file;
	char upload_path[QSC_SYSTEM_MAX_PATH];
	char upload_root[QSC_SYSTEM_MAX_PATH];
	char upload_relative[PQS_XFER_PATH_MAX];
	char upload_temporary[PQS_XFER_PATH_MAX];
	qsc_keccak_state upload_hash_state;
	size_t upload_bytes;
} server_connection_state;

typedef struct server_xfer_walk_context
{
	qsms_connection_state* cns;
} server_xfer_walk_context;

static server_connection_state m_server_connection_state;
static pqs_user_store m_server_user_store;
static pqs_shell_store m_server_shell_store;
static pqs_policy_store m_server_policy_store;
static pqs_sandbox_profile m_server_sandbox;
static qsms_client_verification_key m_server_public_key;
static pqs_server_config m_server_config;

static bool server_certificate_is_expired(uint64_t expiration)
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

static bool server_apply_process_hardening(void)
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
#else
#	if defined(__linux__)
	if (prctl(PR_SET_DUMPABLE, 0UL, 0UL, 0UL, 0UL) != 0)
	{
		res = false;
	}
#	else
	/* no portable process dump suppression is available on this platform */
#	endif
#endif

	return res;
}

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

static void server_set_prompt(server_console_modes mode)
{
	char host[PQS_SERVER_PROMPT_MAX] = { 0 };
	size_t hlen;

	m_server_connection_state.mode = mode;
	hlen = server_get_host_name(host);

	if (hlen > 0U)
	{
		qsc_stringutils_copy_string(m_server_connection_state.prompt, PQS_SERVER_PROMPT_MAX, host);
	}
	else
	{
		qsc_stringutils_copy_string(m_server_connection_state.prompt, PQS_SERVER_PROMPT_MAX, "pqs-server");
	}

	if (mode == server_console_mode_user)
	{
		qsc_stringutils_concat_strings(m_server_connection_state.prompt, PQS_SERVER_PROMPT_MAX, "-user> ");
	}
	else if (mode == server_console_mode_shell)
	{
		qsc_stringutils_concat_strings(m_server_connection_state.prompt, PQS_SERVER_PROMPT_MAX, "-shell> ");
	}
	else if (mode == server_console_mode_policy)
	{
		qsc_stringutils_concat_strings(m_server_connection_state.prompt, PQS_SERVER_PROMPT_MAX, "-policy> ");
	}
	else
	{
		qsc_stringutils_concat_strings(m_server_connection_state.prompt, PQS_SERVER_PROMPT_MAX, "> ");
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

static bool server_get_default_storage_path(char* fpath, size_t pathlen)
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

static bool server_get_config_path(char* fpath, size_t pathlen)
{
	bool res;

	res = server_get_default_storage_path(fpath, pathlen);

	if (res == true)
	{
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, pathlen, PQS_SERVER_CONFIG_NAME);
	}

	return res;
}

static bool server_load_configuration(void)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = server_get_config_path(fpath, sizeof(fpath));

	if (res == true)
	{
		res = pqs_config_server_load(&m_server_config, fpath);
	}

	return res;
}

static bool server_get_storage_path(char* fpath, size_t pathlen)
{
	bool res;

	qsc_memutils_clear(fpath, pathlen);
	qsc_stringutils_copy_string(fpath, pathlen, m_server_config.application_path);
	res = qsc_folderutils_directory_exists(fpath);

	if (res == false)
	{
		res = qsc_folderutils_create_directory(fpath);
	}

	return res;
}

static bool server_get_log_path(char* fpath, size_t pathlen)
{
	bool res;

	res = server_get_storage_path(fpath, pathlen);

	if (res == true)
	{
		qsc_memutils_clear(fpath, pathlen);
		qsc_stringutils_copy_string(fpath, pathlen, m_server_config.log_path);
	}

	return res;
}

static bool server_get_user_database_path(char* fpath, size_t pathlen)
{
	bool res;

	res = server_get_storage_path(fpath, pathlen);

	if (res == true)
	{
		qsc_memutils_clear(fpath, pathlen);
		qsc_stringutils_copy_string(fpath, pathlen, m_server_config.user_database_path);
	}

	return res;
}

static bool server_get_shell_database_path(char* fpath, size_t pathlen)
{
	bool res;

	res = server_get_storage_path(fpath, pathlen);

	if (res == true)
	{
		qsc_memutils_clear(fpath, pathlen);
		qsc_stringutils_copy_string(fpath, pathlen, m_server_config.shell_database_path);
	}

	return res;
}

static bool server_get_policy_database_path(char* fpath, size_t pathlen)
{
	bool res;

	res = server_get_storage_path(fpath, pathlen);

	if (res == true)
	{
		qsc_memutils_clear(fpath, pathlen);
		qsc_stringutils_copy_string(fpath, pathlen, m_server_config.policy_database_path);
	}

	return res;
}

static bool server_sandbox_initialize(void)
{
	char lmsg[384] = { 0 };
	bool res;

	pqs_sandbox_profile_configure_security(&m_server_sandbox,
		m_server_config.sandbox_enabled,
		m_server_config.sandbox_clear_environment,
		m_server_config.command_timeout_seconds,
		m_server_config.sandbox_working_directory,
		m_server_config.sandbox_run_as_user,
		m_server_config.sandbox_run_as_group,
		m_server_config.sandbox_chroot_enabled);
	pqs_sandbox_profile_set_allow_same_user(&m_server_sandbox, m_server_config.sandbox_allow_same_user);
	pqs_sandbox_profile_set_output_limit(&m_server_sandbox, m_server_config.command_output_max_bytes);

	res = pqs_sandbox_working_directory_valid(&m_server_sandbox);

	if (res == false)
	{
		server_print_message("The PQS sandbox working directory is invalid; command execution is disabled until configuration is corrected.");
		pqs_logger_write(pqs_log_level_error, pqs_log_event_sandbox_violation, m_server_connection_state.activeuser, NULL, "invalid sandbox working directory");
	}
	else
	{
		snprintf(lmsg, sizeof(lmsg), "enabled=%s timeout=%u output-limit=%u clear-env=%s allow-same-user=%s cwd=%s",
			m_server_sandbox.enabled == true ? "true" : "false",
			m_server_sandbox.command_timeout_seconds,
			m_server_sandbox.max_output_bytes,
			m_server_sandbox.clear_environment == true ? "true" : "false",
			m_server_sandbox.allow_same_user == true ? "true" : "false",
			m_server_sandbox.working_directory[0U] != '\0' ? m_server_sandbox.working_directory : "inherit");

		pqs_logger_write(pqs_log_level_info, pqs_log_event_sandbox_enabled, m_server_connection_state.activeuser, NULL, lmsg);
	}

	return res;
}

static bool server_user_database_initialize(void)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	char lmsg[128] = { 0 };
	bool existed;
	bool res;

	existed = false;
	res = server_get_user_database_path(fpath, sizeof(fpath));

	if (res == true)
	{
		existed = qsc_fileutils_exists(fpath);
		res = pqs_user_store_initialize(&m_server_user_store, fpath);

		if (res == true)
		{
			snprintf(lmsg, sizeof(lmsg), "users=%zu", m_server_user_store.count);

			if (existed == true)
			{
				server_print_message("The PQS user database has been loaded.");
				pqs_logger_write(pqs_log_level_info, pqs_log_event_user_database_loaded, m_server_connection_state.activeuser, NULL, lmsg);
			}
			else
			{
				server_print_message("The PQS user database has been created.");
				pqs_logger_write(pqs_log_level_info, pqs_log_event_user_database_created, m_server_connection_state.activeuser, NULL, lmsg);
			}

			if (m_server_user_store.count == 0U)
			{
				server_print_message("No PQS users are defined or configured.");
				server_print_message("Login will reject all clients until an admin user is added.");
			}
		}
		else
		{
			server_print_message("The PQS user database could not be initialized.");
		}
	}

	return res;
}

static bool server_shell_database_initialize(void)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	char lmsg[128] = { 0 };
	bool existed;
	bool res;

	existed = false;
	res = server_get_shell_database_path(fpath, sizeof(fpath));

	if (res == true)
	{
		existed = qsc_fileutils_exists(fpath);
		res = pqs_shell_store_initialize(&m_server_shell_store, fpath);

		if (res == true)
		{
			snprintf(lmsg, sizeof(lmsg), "shells=%zu", m_server_shell_store.count);

			if (existed == true)
			{
				server_print_message("The PQS shell profile database has been loaded.");
				pqs_logger_write(pqs_log_level_info, pqs_log_event_shell_database_loaded, m_server_connection_state.activeuser, NULL, lmsg);
			}
			else
			{
				server_print_message("The PQS shell profile database has been created.");
				pqs_logger_write(pqs_log_level_info, pqs_log_event_shell_database_created, m_server_connection_state.activeuser, NULL, lmsg);
			}

			if (m_server_shell_store.count == 0U)
			{
				server_print_message("No PQS shell profiles are configured.");
			}
		}
		else
		{
			server_print_message("The PQS shell profile database could not be initialized.");
		}
	}

	return res;
}

static bool server_policy_database_initialize(void)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	char lmsg[128] = { 0 };
	bool existed;
	bool res;

	existed = false;
	res = server_get_policy_database_path(fpath, sizeof(fpath));

	if (res == true)
	{
		existed = qsc_fileutils_exists(fpath);
		res = pqs_policy_store_initialize(&m_server_policy_store, fpath);

		if (res == true)
		{
			snprintf(lmsg, sizeof(lmsg), "policies=%zu", m_server_policy_store.count);

			if (existed == true)
			{
				server_print_message("The PQS command policy database has been loaded.");
				pqs_logger_write(pqs_log_level_info, pqs_log_event_policy_database_loaded, m_server_connection_state.activeuser, NULL, lmsg);
			}
			else
			{
				server_print_message("The PQS command policy database has been created.");
				pqs_logger_write(pqs_log_level_info, pqs_log_event_policy_database_created, m_server_connection_state.activeuser, NULL, lmsg);
			}

			if (m_server_policy_store.count == 0U)
			{
				server_print_message("No PQS command policies are configured.");
			}
		}
		else
		{
			server_print_message("The PQS command policy database could not be initialized.");
		}
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
		qsc_stringutils_copy_string(fpath, sizeof(fpath), m_server_config.private_key_path);
		res = qsc_fileutils_exists(fpath);
	}

	return res;
}

static bool server_key_dialogue(qsms_server_signature_key* prik, qsms_client_verification_key* pubk, uint8_t keyid[QSMS_KEYID_SIZE])
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	char* spub;
	uint8_t* spri;
	char dir[QSC_SYSTEM_MAX_PATH] = { 0 };
	size_t plen;
	bool res;

	res = false;
	spri = (uint8_t*)qsc_memutils_secure_malloc(QSMS_SIGNATURE_KEY_SERIALIZED_SIZE);

	if (spri != NULL)
	{
		qsc_memutils_clear(spri, QSMS_SIGNATURE_KEY_SERIALIZED_SIZE);
	}

	if (spri == NULL)
	{
		server_print_message("Could not allocate secure key memory, aborting startup.");
	}
	else if (server_prikey_exists() == true)
	{
		res = server_get_storage_path(dir, sizeof(dir));

		if (res == true)
		{
			qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
			qsc_folderutils_append_delimiter(fpath);
			qsc_stringutils_copy_string(fpath, sizeof(fpath), m_server_config.private_key_path);
			res = qsc_fileutils_copy_file_to_stream(fpath, (char*)spri, QSMS_SIGNATURE_KEY_SERIALIZED_SIZE);

			if (res == true && pqs_key_private_file_permissions_are_strict(fpath) == false)
			{
				server_print_message("The server private-key file permissions are too broad; aborting startup.");
				pqs_logger_write(pqs_log_level_error, pqs_log_event_key_loaded, m_server_connection_state.activeuser, NULL, "server private key permissions rejected");
				res = false;
			}

			if (res == true)
			{
				qsms_signature_key_deserialize(prik, spri);

				/* load the state */
				qsc_memutils_copy(keyid, prik->keyid, QSMS_KEYID_SIZE);
				qsc_memutils_copy(pubk->config, prik->config, QSMS_CONFIG_SIZE);
				qsc_memutils_copy(pubk->keyid, prik->keyid, QSMS_KEYID_SIZE);
				qsc_memutils_copy(pubk->verkey, prik->verkey, QSMS_ASYMMETRIC_VERIFY_KEY_SIZE);
				pubk->expiration = prik->expiration;

				if (server_certificate_is_expired(pubk->expiration) == true)
				{
					server_print_message("The server certificate has expired; refusing to start.");
					pqs_logger_write(pqs_log_level_error, pqs_log_event_key_loaded, m_server_connection_state.activeuser, NULL, "server certificate expired");
					res = false;
				}
				else
				{
					qsc_memutils_copy(&m_server_public_key, pubk, sizeof(m_server_public_key));
					server_print_message("The private-key has been loaded.");
					pqs_logger_write(pqs_log_level_info, pqs_log_event_key_loaded, m_server_connection_state.activeuser, NULL, "server key loaded");
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
			qsc_stringutils_copy_string(fpath, sizeof(fpath), m_server_config.public_key_path);

			server_print_message("The private-key was not detected, generating a new private/public keypair...");
			res = qsc_acp_generate(keyid, QSMS_KEYID_SIZE);

			if (res == true)
			{
				plen = qsms_public_key_encoding_size();
				spub = qsc_memutils_malloc(plen + PQS_STRING_TERMINATOR_SIZE);

				if (spub != NULL)
				{
					qsc_memutils_clear(spub, plen + PQS_STRING_TERMINATOR_SIZE);
					qsms_generate_keypair(pubk, prik, keyid);
					qsc_memutils_copy(&m_server_public_key, pubk, sizeof(m_server_public_key));
					plen = qsms_public_key_encode(spub, plen, pubk);
					spub[plen] = '\0';
					server_print_message((const char*)spub);

					res = qsc_fileutils_copy_stream_to_file(fpath, spub, plen);

					if (res == true)
					{
						server_print_message("The server public-key certificate file has been saved to:");
						server_print_message(fpath);
						server_print_message("Distribute the public-key certificate to intended clients.");
						pqs_logger_write(pqs_log_level_info, pqs_log_event_key_generated, m_server_connection_state.activeuser, NULL, "server key generated");

						qsc_stringutils_clear_string(fpath);
						qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
						qsc_folderutils_append_delimiter(fpath);
						qsc_stringutils_copy_string(fpath, sizeof(fpath), m_server_config.private_key_path);
						qsms_signature_key_serialize(spri, prik);
						if (qsc_fileutils_copy_stream_to_file(fpath, (char*)spri, QSMS_SIGNATURE_KEY_SERIALIZED_SIZE) == true)
						{
#if !defined(QSC_SYSTEM_OS_WINDOWS)
							(void)chmod(fpath, S_IRUSR | S_IWUSR);
#endif
							server_print_message("The server private-key file has been saved to:");
							server_print_message(fpath);
						}
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

	if (spri != NULL)
	{
		qsc_memutils_secure_free(spri, QSMS_SIGNATURE_KEY_SERIALIZED_SIZE);
	}

	return res;
}

static bool server_send_message(qsms_connection_state* cns, const uint8_t* message, size_t msglen)
{
	PQS_ASSERT(cns != NULL);
	PQS_ASSERT(message != NULL);
	PQS_ASSERT(msglen != 0U);

	uint8_t* pmsg;
	qsms_errors qerr;
	size_t mlen;	
	bool res;

	res = false;

	if (cns != NULL && message != NULL && msglen != 0U && msglen <= PQS_SERVER_COMMAND_OUTPUT_CHUNK)
	{
		mlen = QSMS_HEADER_SIZE + msglen + QSMS_SIMPLEX_MACTAG_SIZE;
		pmsg = (uint8_t*)qsc_memutils_malloc(mlen);

		if (pmsg != NULL)
		{
			qsms_network_packet spkt = { 0 };

			qsc_memutils_clear(pmsg, mlen);
			spkt.pmessage = pmsg + QSMS_HEADER_SIZE;

			qerr = qsms_packet_encrypt(cns, &spkt, message, msglen);

			if (qerr == qsms_error_none)
			{
				qsms_packet_header_serialize(&spkt, pmsg);

				if (qsc_socket_send(&cns->target, pmsg, mlen, qsc_socket_send_flag_none) == mlen)
				{
					res = true;
				}
			}

			qsc_memutils_alloc_free(pmsg);
		}
	}

	return res;
}

static bool server_send_application_message(qsms_connection_state* cns, pqs_application_messages type, const uint8_t* message, size_t msglen)
{
	uint8_t cmsg[PQS_INTERPRETER_COMMAND_BUFFER_SIZE + PQS_APPLICATION_MESSAGE_HEADER_SIZE + PQS_STRING_TERMINATOR_SIZE] = { 0U };
	size_t mlen;
	bool res;

	res = false;
	mlen = PQS_APPLICATION_MESSAGE_HEADER_SIZE;

	if (cns != NULL && msglen <= PQS_INTERPRETER_COMMAND_BUFFER_SIZE)
	{
		cmsg[0U] = (uint8_t)type;

		if (message != NULL && msglen != 0U)
		{
			qsc_memutils_copy(cmsg + PQS_APPLICATION_MESSAGE_HEADER_SIZE, message, msglen);
			mlen += msglen;
		}

		cmsg[mlen] = '\0';
		mlen += PQS_STRING_TERMINATOR_SIZE;
		res = server_send_message(cns, cmsg, mlen);
	}

	return res;
}

static bool server_send_error_message(qsms_connection_state* cns, const char* message)
{
	size_t mlen;
	bool res;

	res = false;

	if (message != NULL)
	{
		mlen = qsc_stringutils_string_size(message);
		res = server_send_application_message(cns, pqs_application_message_error, (const uint8_t*)message, mlen);
	}

	return res;
}


static bool server_send_admin_chunk(qsms_connection_state* cns, const char* message, size_t msglen, bool final)
{
	pqs_application_messages type;
	bool res;

	type = (final == true) ? pqs_application_message_admin_response_final : pqs_application_message_admin_response_more;
	res = server_send_application_message(cns, type, (const uint8_t*)message, msglen);

	return res;
}

static bool server_send_admin_output(qsms_connection_state* cns, const char* message)
{
	char cmsg[PQS_INTERPRETER_COMMAND_BUFFER_SIZE + 1U] = { 0 };
	size_t blen;
	size_t msglen;
	size_t pos;
	bool res;

	res = false;
	blen = 0U;
	pos = 0U;

	if (cns != NULL && message != NULL)
	{
		res = true;
		msglen = qsc_stringutils_string_size(message);

		while (pos < msglen)
		{
			if (message[pos] != '\0')
			{
				cmsg[blen] = message[pos];
				++blen;
			}

			++pos;

			if (blen == sizeof(cmsg) - 1U)
			{
				cmsg[blen] = '\0';
				res = server_send_admin_chunk(cns, cmsg, blen, false);

				if (res == false)
				{
					break;
				}

				qsc_consoleutils_print_safe(cmsg);
				qsc_memutils_clear((uint8_t*)cmsg, sizeof(cmsg));
				blen = 0U;
			}
		}

		if (res == true && blen != 0U)
		{
			cmsg[blen] = '\0';
			res = server_send_admin_chunk(cns, cmsg, blen, false);

			if (res == true)
			{
				qsc_consoleutils_print_safe(cmsg);
			}
		}

		if (res == true)
		{
			res = server_send_admin_chunk(cns, NULL, 0U, true);
		}
	}

	return res;
}

static bool server_send_command_chunk(qsms_connection_state* cns, const char* message, size_t msglen, bool final)
{
	pqs_application_messages type;
	bool res;

	type = (final == true) ? pqs_application_message_response_final : pqs_application_message_response_more;
	res = server_send_application_message(cns, type, (const uint8_t*)message, msglen);

	return res;
}

static bool server_send_command_output(qsms_connection_state* cns, const char* message, size_t msglen)
{
	char cmsg[PQS_INTERPRETER_COMMAND_BUFFER_SIZE + 1U] = { 0 };
	size_t blen;
	size_t pos;
	bool res;

	res = true;
	blen = 0U;
	pos = 0U;

	while (pos < msglen)
	{
		if (message[pos] != '\0')
		{
			cmsg[blen] = message[pos];
			++blen;
		}

		++pos;

		if (blen == sizeof(cmsg) - 1U)
		{
			cmsg[blen] = '\0';
			res = server_send_command_chunk(cns, cmsg, blen, false);

			if (res == false)
			{
				break;
			}

			qsc_consoleutils_print_safe(cmsg);
			qsc_memutils_clear((uint8_t*)cmsg, sizeof(cmsg));
			blen = 0U;
		}
	}

	if (res == true && blen != 0U)
	{
		cmsg[blen] = '\0';
		res = server_send_command_chunk(cns, cmsg, blen, false);

		if (res == true)
		{
			qsc_consoleutils_print_safe(cmsg);
		}
	}

	return res;
}

static bool server_shell_profile_resolve(const pqs_shell_profile** profile)
{
	const pqs_shell_profile* selected;
	const pqs_user_record* user;
	bool res;

	selected = NULL;
	res = false;

	if (profile != NULL)
	{
		*profile = NULL;
	}

	if (m_server_connection_state.authenticated == true && m_server_connection_state.activeuser[0U] != '\0')
	{
		user = pqs_user_store_find(&m_server_user_store, m_server_connection_state.activeuser);

		if (user != NULL && user->shellprofile[0U] != '\0')
		{
			selected = pqs_shell_store_find(&m_server_shell_store, user->shellprofile);
		}

		if (selected == NULL)
		{
			selected = pqs_shell_store_default(&m_server_shell_store);
		}

		if (selected != NULL && pqs_shell_profile_allows_privilege(selected, m_server_connection_state.privilege) == true &&
			qsc_fileutils_exists(selected->path) == true)
		{
			if (profile != NULL)
			{
				*profile = selected;
			}

			res = true;
		}
	}

	return res;
}

static bool server_command_output_callback(void* context, const char* message, size_t msglen)
{
	return server_send_command_output((qsms_connection_state*)context, message, msglen);
}

static bool server_command_execute(qsms_connection_state* cns, const char* message, size_t msglen, const pqs_shell_profile* profile)
{
	char lmsg[192] = { 0 };
	bool timedout;
	bool outputlimited;
	bool res;

	res = false;
	timedout = false;
	outputlimited = false;

	if (cns != NULL && message != NULL && profile != NULL && profile->path[0U] != '\0')
	{
		snprintf(lmsg, sizeof(lmsg), "command-bytes=%zu shell=%s type=%s", msglen, profile->name, profile->type);
		pqs_logger_write(pqs_log_level_audit, pqs_log_event_command_received, m_server_connection_state.activeuser, (const char*)cns->target.address, lmsg);

		res = pqs_process_execute(message, msglen, profile, &m_server_sandbox, &server_command_output_callback, cns, &timedout, &outputlimited);

		if (timedout == true)
		{
			static const char tout[] = "PQS command terminated by sandbox timeout.\n";

			(void)server_send_command_output(cns, tout, sizeof(tout) - 1U);
			pqs_logger_write(pqs_log_level_warning, pqs_log_event_command_timeout, m_server_connection_state.activeuser, (const char*)cns->target.address, "command timeout");
			res = true;
		}
		else if (outputlimited == true)
		{
			static const char lout[] = "PQS command terminated by sandbox output limit.\n";

			(void)server_send_command_output(cns, lout, sizeof(lout) - 1U);
			pqs_logger_write(pqs_log_level_warning, pqs_log_event_command_output_limit, m_server_connection_state.activeuser, (const char*)cns->target.address, "command output limit");
			res = true;
		}

		if (res == true)
		{
			res = server_send_command_chunk(cns, NULL, 0U, true);
			snprintf(lmsg, sizeof(lmsg), "command output sent shell=%s", profile->name);
			pqs_logger_write(pqs_log_level_audit, pqs_log_event_command_complete, m_server_connection_state.activeuser, (const char*)cns->target.address, lmsg);
		}
		else if (timedout == false && outputlimited == false)
		{
			static const char errmsg[] = "PQS command execution failed. Check the shell profile path and sandbox configuration.";

			(void)server_send_application_message(cns, pqs_application_message_error, (const uint8_t*)errmsg, sizeof(errmsg));
			snprintf(lmsg, sizeof(lmsg), "command execution failed shell=%s type=%s", profile->name, profile->type);
			pqs_logger_write(pqs_log_level_error, pqs_log_event_command_failed, m_server_connection_state.activeuser, (const char*)cns->target.address, lmsg);
		}
	}

	return res;
}

static void server_disconnect_callback(qsms_connection_state* cns)
{
	if (m_server_connection_state.upload_file != NULL)
	{
		qsc_fileutils_close(m_server_connection_state.upload_file);
		m_server_connection_state.upload_file = NULL;
	}

	if (m_server_connection_state.upload_temporary[0U] != '\0' && m_server_connection_state.upload_root[0U] != '\0')
	{
		(void)pqs_xfer_remove_confined(m_server_connection_state.upload_root, m_server_connection_state.upload_temporary);
	}

	m_server_connection_state.upload_active = false;
	m_server_connection_state.upload_path[0U] = '\0';
	m_server_connection_state.upload_root[0U] = '\0';
	m_server_connection_state.upload_relative[0U] = '\0';
	m_server_connection_state.upload_temporary[0U] = '\0';
	m_server_connection_state.instance = 0U;
	m_server_connection_state.authenticated = false;
	m_server_connection_state.privilege = pqs_user_privilege_none;
	m_server_connection_state.login_attempts = 0U;
	m_server_connection_state.state = pqs_session_state_closing;

	qsc_consoleutils_print_safe("Disconnected from host: ");
	qsc_consoleutils_print_line((const char*)cns->target.address);
	server_print_prompt();

	pqs_logger_write(pqs_log_level_info, pqs_log_event_connection_close, m_server_connection_state.activeuser, (const char*)cns->target.address, "connection closed");
	qsc_stringutils_clear_string(m_server_connection_state.activeuser);
	qsc_stringutils_copy_string(m_server_connection_state.activeuser, sizeof(m_server_connection_state.activeuser), "anonymous");
	
	m_server_connection_state.privilege = pqs_user_privilege_none;
	m_server_connection_state.login_attempts = 0U;
	m_server_connection_state.state = pqs_session_state_none;
}

static bool server_instance_check(qsms_connection_state* cns)
{
	return (cns->target.instance == m_server_connection_state.instance);
}

static size_t server_xfer_chunk_limit(void)
{
	return (PQS_INTERPRETER_COMMAND_BUFFER_SIZE > 2U) ? (PQS_INTERPRETER_COMMAND_BUFFER_SIZE - 2U) : 0U;
}

static bool server_xfer_send_status(qsms_connection_state* cns, const char* status)
{
	bool res;

	res = false;

	if (status != NULL)
	{
		res = server_send_application_message(cns, pqs_application_message_file_status, (const uint8_t*)status, qsc_stringutils_string_size(status));
	}

	return res;
}

static bool server_xfer_send_data(qsms_connection_state* cns, const uint8_t* data, size_t datalen)
{
	uint8_t msg[PQS_INTERPRETER_COMMAND_BUFFER_SIZE] = { 0U };
	bool res;

	res = false;

	if (cns != NULL && data != NULL && datalen != 0U && datalen <= server_xfer_chunk_limit())
	{
		msg[0U] = (uint8_t)((datalen >> 8U) & 0xFFU);
		msg[1U] = (uint8_t)(datalen & 0xFFU);
		qsc_memutils_copy(msg + 2U, data, datalen);
		res = server_send_application_message(cns, pqs_application_message_file_data, msg, datalen + 2U);
	}

	return res;
}

static bool server_xfer_is_authorized(const char* verb)
{
	const pqs_policy_record* policy;
	bool res;

	policy = NULL;
	res = false;

	if (m_server_connection_state.authenticated == true && m_server_connection_state.state == pqs_session_state_authenticated)
	{
		res = pqs_policy_store_authorize(&m_server_policy_store, m_server_connection_state.privilege, verb, &policy);
	}

	return res;
}

static const char* server_xfer_base_root(void)
{
	const char* res;

	res = m_server_config.application_path;

	if (m_server_sandbox.enabled == true && m_server_sandbox.working_directory[0U] != '\0')
	{
		res = m_server_sandbox.working_directory;
	}

	return res;
}

static bool server_xfer_user_root(char* root, size_t rootlen)
{
	bool res;

	res = false;

	if (root != NULL && rootlen != 0U && m_server_connection_state.activeuser[0U] != '\0')
	{
		res = pqs_xfer_make_user_root(root, rootlen, server_xfer_base_root(), m_server_connection_state.activeuser);
	}

	return res;
}

static bool server_xfer_get(qsms_connection_state* cns, const uint8_t* message, size_t msglen)
{
	FILE* fp;
	char rel[PQS_XFER_PATH_MAX] = { 0 };
	char root[QSC_SYSTEM_MAX_PATH] = { 0 };
	char hexhash[PQS_XFER_HASH_TEXT_SIZE] = { 0 };
	char metadata[PQS_XFER_METADATA_MAX] = { 0 };
	uint8_t chunk[PQS_INTERPRETER_COMMAND_BUFFER_SIZE] = { 0U };
	qsc_keccak_state hstate;
	size_t rlen;
	size_t total;
	bool res;

	fp = NULL;
	total = 0U;
	res = false;

	if (cns != NULL && message != NULL && msglen > PQS_APPLICATION_MESSAGE_HEADER_SIZE && server_xfer_is_authorized("get") == true)
	{
		if (pqs_xfer_extract_relative(rel, sizeof(rel), message, msglen) == true &&
			server_xfer_user_root(root, sizeof(root)) == true)
		{
			fp = pqs_xfer_open_read_confined(root, rel);

			if (fp != NULL)
			{
				qsc_sha3_initialize(&hstate);
				pqs_logger_write(pqs_log_level_audit, pqs_log_event_file_transfer_start, m_server_connection_state.activeuser, (const char*)cns->target.address, "get");

				while (true)
				{
					rlen = fread(chunk, sizeof(uint8_t), server_xfer_chunk_limit(), fp);

					if (rlen != 0U)
					{
						qsc_sha3_update(&hstate, qsc_keccak_rate_256, chunk, rlen);
						total += rlen;

						if (server_xfer_send_data(cns, chunk, rlen) == false)
						{
							break;
						}

						res = true;
					}
					else
					{
						res = true;
						break;
					}

					qsc_memutils_clear(chunk, sizeof(chunk));
				}

				qsc_fileutils_close(fp);
			}
		}
	}

	if (res == true && cns != NULL)
	{
		uint8_t hash[PQS_XFER_HASH_SIZE] = { 0U };

		qsc_sha3_finalize(&hstate, qsc_keccak_rate_256, hash);
		qsc_intutils_bin_to_hex(hash, hexhash, sizeof(hash));
		hexhash[PQS_XFER_HASH_TEXT_SIZE - 1U] = '\0';

		if (pqs_xfer_format_metadata(metadata, sizeof(metadata), total, hexhash) == true)
		{
			(void)server_send_application_message(cns, pqs_application_message_file_final, (const uint8_t*)metadata, qsc_stringutils_string_size(metadata));
		}
		else
		{
			(void)server_send_application_message(cns, pqs_application_message_file_final, NULL, 0U);
		}

		pqs_logger_write(pqs_log_level_audit, pqs_log_event_file_transfer_complete, m_server_connection_state.activeuser, (const char*)cns->target.address, "get");
	}
	else
	{
		if (cns != NULL)
		{
			(void)server_xfer_send_status(cns, "PQS file get failed.");
			pqs_logger_write(pqs_log_level_warning, pqs_log_event_file_transfer_failed, m_server_connection_state.activeuser, (const char*)cns->target.address, "get");
		}
	}

	return res;
}

static bool server_xfer_send_directory_begin(qsms_connection_state* cns, const char* relative)
{
	bool res;

	res = false;

	if (cns != NULL && relative != NULL && pqs_xfer_path_is_safe(relative) == true)
	{
		res = server_send_application_message(cns, pqs_application_message_file_directory_begin, (const uint8_t*)relative, qsc_stringutils_string_size(relative));
	}

	return res;
}

static bool server_xfer_send_directory_end(qsms_connection_state* cns, const char* relative)
{
	bool res;

	res = false;

	if (cns != NULL && relative != NULL && pqs_xfer_path_is_safe(relative) == true)
	{
		res = server_send_application_message(cns, pqs_application_message_file_directory_end, (const uint8_t*)relative, qsc_stringutils_string_size(relative));
	}

	return res;
}

static bool server_xfer_send_recursive_file(qsms_connection_state* cns, const char* fpath, const char* relative)
{
	FILE* fp;
	char hexhash[PQS_XFER_HASH_TEXT_SIZE] = { 0 };
	char metadata[PQS_XFER_METADATA_MAX] = { 0 };
	uint8_t chunk[PQS_INTERPRETER_COMMAND_BUFFER_SIZE] = { 0U };
	size_t fsize;
	size_t rlen;
	size_t sent;
	bool res;

	fp = NULL;
	fsize = 0U;
	sent = 0U;
	res = false;

	if (cns != NULL && fpath != NULL && relative != NULL && pqs_xfer_path_is_safe(relative) == true &&
		qsc_fileutils_exists(fpath) == true && pqs_xfer_path_is_symlink(fpath) == false &&
		pqs_xfer_hash_file(fpath, hexhash, sizeof(hexhash), &fsize) == true &&
		pqs_xfer_format_file_metadata(metadata, sizeof(metadata), relative, fsize, hexhash) == true)
	{
		fp = qsc_fileutils_open(fpath, qsc_fileutils_mode_read, true);

		if (fp != NULL)
		{
			res = server_send_application_message(cns, pqs_application_message_file_begin, (const uint8_t*)metadata, qsc_stringutils_string_size(metadata));

			while (res == true)
			{
				rlen = fread(chunk, sizeof(uint8_t), server_xfer_chunk_limit(), fp);

				if (rlen != 0U)
				{
					res = server_xfer_send_data(cns, chunk, rlen);
					sent += rlen;
					qsc_memutils_clear(chunk, sizeof(chunk));
				}
				else
				{
					break;
				}
			}

			qsc_fileutils_close(fp);

			if (res == true && sent == fsize)
			{
				res = server_send_application_message(cns, pqs_application_message_file_final, (const uint8_t*)metadata, qsc_stringutils_string_size(metadata));
			}
		}
	}

	return res;
}

static bool server_xfer_walk_callback(pqs_xfer_walk_events event, const char* localpath, const char* relative, void* context)
{
	server_xfer_walk_context* wctx;
	bool res;

	res = false;
	wctx = (server_xfer_walk_context*)context;

	if (wctx != NULL && wctx->cns != NULL && localpath != NULL && relative != NULL)
	{
		if (event == pqs_xfer_walk_event_directory_begin)
		{
			res = server_xfer_send_directory_begin(wctx->cns, relative);
		}
		else if (event == pqs_xfer_walk_event_file)
		{
			res = server_xfer_send_recursive_file(wctx->cns, localpath, relative);
		}
		else if (event == pqs_xfer_walk_event_directory_end)
		{
			res = server_xfer_send_directory_end(wctx->cns, relative);
		}
		else
		{
			res = false;
		}
	}

	return res;
}

static bool server_xfer_get_recursive(qsms_connection_state* cns, const uint8_t* message, size_t msglen)
{
	char dpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	char rel[PQS_XFER_PATH_MAX] = { 0 };
	char root[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = false;

	if (cns != NULL && message != NULL && msglen > PQS_APPLICATION_MESSAGE_HEADER_SIZE && server_xfer_is_authorized("get") == true)
	{
		if (pqs_xfer_extract_relative(rel, sizeof(rel), message, msglen) == true &&
			server_xfer_user_root(root, sizeof(root)) == true &&
			pqs_xfer_make_path(dpath, sizeof(dpath), root, rel) == true &&
			pqs_xfer_path_is_confined(root, dpath, true) == true &&
			pqs_xfer_local_path_is_directory(dpath) == true && pqs_xfer_path_is_symlink(dpath) == false)
		{
			pqs_logger_write(pqs_log_level_audit, pqs_log_event_file_transfer_start, m_server_connection_state.activeuser, (const char*)cns->target.address, "get recursive");
			
			{
				server_xfer_walk_context ctx;

				ctx.cns = cns;
				res = pqs_xfer_walk_directory(dpath, ".", PQS_XFER_RECURSION_MAX, server_xfer_walk_callback, &ctx);
			}
		}
	}

	(void)server_xfer_send_status(cns, res == true ? "PQS recursive download completed." : "PQS recursive download failed.");

	if (res == true && cns != NULL)
	{
		pqs_logger_write(pqs_log_level_audit, pqs_log_event_file_transfer_complete, m_server_connection_state.activeuser, (const char*)cns->target.address, "get recursive");
	}
	else
	{
		if (cns != NULL)
		{
			pqs_logger_write(pqs_log_level_warning, pqs_log_event_file_transfer_failed, m_server_connection_state.activeuser, (const char*)cns->target.address, "get recursive");
		}
	}

	return res;
}

static bool server_xfer_list(qsms_connection_state* cns, const uint8_t* message, size_t msglen)
{
	char dpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	char rel[PQS_XFER_PATH_MAX] = { 0 };
	char root[QSC_SYSTEM_MAX_PATH] = { 0 };
	char list[PQS_XFER_LIST_BUFFER_SIZE] = { 0 };
	size_t llen;
	bool res;

	res = false;

	if (cns != NULL && server_xfer_is_authorized("list") == true)
	{
		if (message != NULL && msglen > PQS_APPLICATION_MESSAGE_HEADER_SIZE && message[PQS_APPLICATION_MESSAGE_HEADER_SIZE] != '\0')
		{
			res = pqs_xfer_extract_relative(rel, sizeof(rel), message, msglen);
		}
		else
		{
			qsc_stringutils_copy_string(rel, sizeof(rel), ".");
			res = true;
		}

		if (res == true && server_xfer_user_root(root, sizeof(root)) == true && pqs_xfer_make_path(dpath, sizeof(dpath), root, rel) == true && pqs_xfer_path_is_confined(root, dpath, true) == true && qsc_folderutils_directory_exists(dpath) == true && pqs_xfer_path_is_symlink(dpath) == false)
		{
			llen = qsc_fileutils_list_files(list, sizeof(list), dpath);

			if (llen != 0U)
			{
				res = server_send_application_message(cns, pqs_application_message_file_status, (const uint8_t*)list, llen);
			}
			else
			{
				res = server_xfer_send_status(cns, "No files were found.");
			}
		}
	}

	if (res == false)
	{
		(void)server_xfer_send_status(cns, "PQS file list failed.");
	}

	return res;
}

static bool server_xfer_mkdir(qsms_connection_state* cns, const uint8_t* message, size_t msglen)
{
	char dpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	char rel[PQS_XFER_PATH_MAX] = { 0 };
	char root[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = false;

	if (cns != NULL && message != NULL && msglen > PQS_APPLICATION_MESSAGE_HEADER_SIZE && server_xfer_is_authorized("mkdir") == true)
	{
		if (pqs_xfer_extract_relative(rel, sizeof(rel), message, msglen) == true &&
			server_xfer_user_root(root, sizeof(root)) == true)
		{
			(void)dpath;
			res = pqs_xfer_make_directory_confined(root, rel);
		}
	}

	(void)server_xfer_send_status(cns, res == true ? "PQS directory created." : "PQS directory creation failed.");

	return res;
}

static bool server_xfer_remove(qsms_connection_state* cns, const uint8_t* message, size_t msglen)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	char rel[PQS_XFER_PATH_MAX] = { 0 };
	char root[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = false;

	if (cns != NULL && message != NULL && msglen > PQS_APPLICATION_MESSAGE_HEADER_SIZE && server_xfer_is_authorized("remove") == true)
	{
		if (pqs_xfer_extract_relative(rel, sizeof(rel), message, msglen) == true &&
			server_xfer_user_root(root, sizeof(root)) == true)
		{
			(void)fpath;
			res = pqs_xfer_remove_confined(root, rel);
		}
	}

	(void)server_xfer_send_status(cns, res == true ? "PQS file removed." : "PQS file removal failed.");

	return res;
}

static bool server_xfer_put_start(qsms_connection_state* cns, const uint8_t* message, size_t msglen)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	char rel[PQS_XFER_PATH_MAX] = { 0 };
	char root[QSC_SYSTEM_MAX_PATH] = { 0 };
	char temporary[PQS_XFER_PATH_MAX] = { 0 };
	bool res;

	res = false;

	if (cns != NULL && message != NULL && msglen > PQS_APPLICATION_MESSAGE_HEADER_SIZE && server_xfer_is_authorized("put") == true)
	{
		if (pqs_xfer_extract_relative(rel, sizeof(rel), message, msglen) == true &&
			server_xfer_user_root(root, sizeof(root)) == true &&
			pqs_xfer_make_temporary_path(temporary, sizeof(temporary), rel) == true &&
			pqs_xfer_make_path(fpath, sizeof(fpath), root, rel) == true &&
			pqs_xfer_path_is_confined(root, fpath, false) == true)
		{
			if (m_server_connection_state.upload_file != NULL)
			{
				qsc_fileutils_close(m_server_connection_state.upload_file);
				m_server_connection_state.upload_file = NULL;
			}

			if (m_server_connection_state.upload_temporary[0U] != '\0' && m_server_connection_state.upload_root[0U] != '\0')
			{
				(void)pqs_xfer_remove_confined(m_server_connection_state.upload_root, m_server_connection_state.upload_temporary);
			}

			m_server_connection_state.upload_file = pqs_xfer_open_write_confined(root, temporary);

			if (m_server_connection_state.upload_file != NULL)
			{
				qsc_stringutils_copy_string(m_server_connection_state.upload_path, sizeof(m_server_connection_state.upload_path), fpath);
				qsc_stringutils_copy_string(m_server_connection_state.upload_root, sizeof(m_server_connection_state.upload_root), root);
				qsc_stringutils_copy_string(m_server_connection_state.upload_relative, sizeof(m_server_connection_state.upload_relative), rel);
				qsc_stringutils_copy_string(m_server_connection_state.upload_temporary, sizeof(m_server_connection_state.upload_temporary), temporary);
				m_server_connection_state.upload_active = true;
				m_server_connection_state.upload_bytes = 0U;
				qsc_sha3_initialize(&m_server_connection_state.upload_hash_state);
				res = server_xfer_send_status(cns, "PQS file upload started.");
				pqs_logger_write(pqs_log_level_audit, pqs_log_event_file_transfer_start, m_server_connection_state.activeuser, (const char*)cns->target.address, "put staged");
			}
		}
	}

	if (res == false)
	{
		(void)server_xfer_send_status(cns, "PQS file upload could not be started.");
	}

	return res;
}

static bool server_xfer_put_data(qsms_connection_state* cns, const uint8_t* message, size_t msglen)
{
	const uint8_t* data;
	size_t payload;
	size_t dlen;
	bool res;

	(void)cns;
	res = false;
	payload = pqs_xfer_payload_size(message, msglen);
	dlen = 0U;
	data = NULL;

	if (m_server_connection_state.upload_active == true && m_server_connection_state.upload_file != NULL &&
		message != NULL && payload >= 2U)
	{
		dlen = ((size_t)message[PQS_APPLICATION_MESSAGE_HEADER_SIZE] << 8U) |
			(size_t)message[PQS_APPLICATION_MESSAGE_HEADER_SIZE + 1U];

		if (dlen != 0U && dlen <= (payload - 2U))
		{
			data = message + PQS_APPLICATION_MESSAGE_HEADER_SIZE + 2U;
			res = (fwrite(data, sizeof(uint8_t), dlen, m_server_connection_state.upload_file) == dlen);
		}

		if (res == true)
		{
			qsc_sha3_update(&m_server_connection_state.upload_hash_state, qsc_keccak_rate_256, data, dlen);
			m_server_connection_state.upload_bytes += dlen;
		}
	}

	return res;
}

static bool server_xfer_put_final(qsms_connection_state* cns, const uint8_t* message, size_t msglen)
{
	char expected[PQS_XFER_HASH_TEXT_SIZE] = { 0 };
	char actual[PQS_XFER_HASH_TEXT_SIZE] = { 0 };
	uint8_t hash[PQS_XFER_HASH_SIZE] = { 0U };
	size_t expected_size;
	bool verified;
	bool res;

	expected_size = 0U;
	verified = false;
	res = false;

	if (m_server_connection_state.upload_file != NULL)
	{
		qsc_fileutils_close(m_server_connection_state.upload_file);
		m_server_connection_state.upload_file = NULL;
		m_server_connection_state.upload_active = false;

		qsc_sha3_finalize(&m_server_connection_state.upload_hash_state, qsc_keccak_rate_256, hash);
		qsc_intutils_bin_to_hex(hash, actual, sizeof(hash));
		actual[PQS_XFER_HASH_TEXT_SIZE - 1U] = '\0';

		if (message != NULL && msglen > PQS_APPLICATION_MESSAGE_HEADER_SIZE)
		{
			verified = pqs_xfer_parse_metadata((const char*)(message + PQS_APPLICATION_MESSAGE_HEADER_SIZE), &expected_size, expected, sizeof(expected));
			verified = (verified == true && expected_size == m_server_connection_state.upload_bytes && qsc_stringutils_strings_equal(expected, actual) == true);
		}

		if (verified == true)
		{
			verified = pqs_xfer_publish_temporary_file(m_server_connection_state.upload_root,
				m_server_connection_state.upload_temporary, m_server_connection_state.upload_relative);

			if (verified == true)
			{
				res = server_xfer_send_status(cns, "PQS file upload completed; SHA3-256 verified.");
				pqs_logger_write(pqs_log_level_audit, pqs_log_event_file_transfer_complete, m_server_connection_state.activeuser, (const char*)cns->target.address, "put verified");
			}
			else
			{
				(void)pqs_xfer_remove_confined(m_server_connection_state.upload_root, m_server_connection_state.upload_temporary);
				res = server_xfer_send_status(cns, "PQS file upload publish failed.");
				pqs_logger_write(pqs_log_level_warning, pqs_log_event_file_transfer_failed, m_server_connection_state.activeuser, (const char*)cns->target.address, "put publish failed");
			}
		}
		else
		{
			(void)pqs_xfer_remove_confined(m_server_connection_state.upload_root, m_server_connection_state.upload_temporary);
			res = server_xfer_send_status(cns, "PQS file upload hash verification failed.");
			pqs_logger_write(pqs_log_level_warning, pqs_log_event_file_transfer_failed, m_server_connection_state.activeuser, (const char*)cns->target.address, "put hash failed");
		}

		m_server_connection_state.upload_path[0U] = '\0';
		m_server_connection_state.upload_root[0U] = '\0';
		m_server_connection_state.upload_relative[0U] = '\0';
		m_server_connection_state.upload_temporary[0U] = '\0';
	}
	else
	{
		(void)server_xfer_send_status(cns, "PQS file upload was not active.");
	}

	return res;
}

static bool server_handle_file_request(qsms_connection_state* cns, pqs_application_messages type, const uint8_t* message, size_t msglen)
{
	bool res;

	res = false;

	if (m_server_connection_state.authenticated == true && m_server_connection_state.state == pqs_session_state_authenticated)
	{
		if (type == pqs_application_message_file_get_request)
		{
			res = server_xfer_get(cns, message, msglen);
		}
		else if (type == pqs_application_message_file_get_recursive_request)
		{
			res = server_xfer_get_recursive(cns, message, msglen);
		}
		else if (type == pqs_application_message_file_list_request)
		{
			res = server_xfer_list(cns, message, msglen);
		}
		else if (type == pqs_application_message_file_mkdir_request)
		{
			res = server_xfer_mkdir(cns, message, msglen);
		}
		else if (type == pqs_application_message_file_remove_request)
		{
			res = server_xfer_remove(cns, message, msglen);
		}
		else if (type == pqs_application_message_file_put_start)
		{
			res = server_xfer_put_start(cns, message, msglen);
		}
		else if (type == pqs_application_message_file_put_data)
		{
			res = server_xfer_put_data(cns, message, msglen);
		}
		else if (type == pqs_application_message_file_put_final)
		{
			res = server_xfer_put_final(cns, message, msglen);
		}
	}
	else
	{
		(void)server_send_error_message(cns, "PQS authentication is required before file transfer.");
	}

	return res;
}

static bool server_handle_login_request(qsms_connection_state* cns, const uint8_t* message, size_t msglen)
{
	pqs_user_record* record;
	char username[PQS_USERNAME_MAX] = { 0 };
	char passphrase[PQS_PASSPHRASE_MAX] = { 0 };
	char lmsg[160] = { 0 };
	const char* loguser;
	bool namevalid;
	bool passvalid;
	bool locked;
	bool verified;
	bool res;

	record = NULL;
	loguser = m_server_connection_state.activeuser;
	namevalid = false;
	passvalid = false;
	locked = false;
	verified = false;
	res = false;

	if (cns != NULL && message != NULL && msglen >= (PQS_LOGIN_REQUEST_MESSAGE_SIZE + PQS_STRING_TERMINATOR_SIZE))
	{
		qsc_memutils_copy(username, message + PQS_APPLICATION_MESSAGE_HEADER_SIZE, PQS_USERNAME_TEXT_MAX);
		qsc_memutils_copy(passphrase, message + PQS_APPLICATION_MESSAGE_HEADER_SIZE + PQS_USERNAME_MAX, PQS_PASSPHRASE_TEXT_MAX);
		username[PQS_USERNAME_TEXT_MAX] = '\0';
		passphrase[PQS_PASSPHRASE_TEXT_MAX] = '\0';
		namevalid = pqs_user_name_is_valid(username);
		passvalid = pqs_user_passphrase_is_valid(passphrase);

		if (namevalid == true)
		{
			loguser = username;
		}

		if (namevalid == true && passvalid == true)
		{
			record = pqs_user_store_find_mutable(&m_server_user_store, username);
			verified = pqs_user_verify_passphrase_timing_neutral(record, username, passphrase);
		}
		else
		{
			(void)pqs_user_verify_passphrase_timing_neutral(NULL, NULL, passphrase);
			verified = false;
		}

		if (record != NULL && record->enabled == true)
		{
			if (record->failures >= PQS_SERVER_MAX_LOGIN)
			{
				record->enabled = false;
				verified = false;
				locked = true;
				(void)pqs_user_store_save(&m_server_user_store);
				pqs_logger_write(pqs_log_level_warning, pqs_log_event_auth_lockout, username, (const char*)cns->target.address, "account already locked by failed login counter");
			}

			if (verified == true)
			{
				record->failures = 0U;
				(void)pqs_user_store_save(&m_server_user_store);
				qsc_stringutils_clear_string(m_server_connection_state.activeuser);
				qsc_stringutils_copy_string(m_server_connection_state.activeuser, sizeof(m_server_connection_state.activeuser), record->username);
				
				m_server_connection_state.privilege = record->privilege;
				m_server_connection_state.authenticated = true;
				m_server_connection_state.login_attempts = 0U;
				m_server_connection_state.state = pqs_session_state_authenticated;

				res = server_send_application_message(cns, pqs_application_message_login_success, NULL, 0U);
				snprintf(lmsg, sizeof(lmsg), "privilege=%s", pqs_user_privilege_to_string(record->privilege));
				pqs_logger_write(pqs_log_level_audit, pqs_log_event_auth_success, m_server_connection_state.activeuser, (const char*)cns->target.address, lmsg);
			}
			else if (locked == false)
			{
				if (record->failures < UINT32_MAX)
				{
					++record->failures;
				}

				if (record->failures >= PQS_SERVER_MAX_LOGIN)
				{
					record->enabled = false;
					locked = true;
					pqs_logger_write(pqs_log_level_warning, pqs_log_event_auth_lockout, username, (const char*)cns->target.address, "account locked by failed login counter");
				}

				(void)pqs_user_store_save(&m_server_user_store);
			}
		}

		if (verified == false)
		{
			if (m_server_connection_state.login_attempts < UINT32_MAX)
			{
				++m_server_connection_state.login_attempts;
			}

			(void)server_send_application_message(cns, pqs_application_message_login_failure, (const uint8_t*)"PQS authentication failed.", qsc_stringutils_string_size("PQS authentication failed."));

			if (namevalid == false || passvalid == false)
			{
				pqs_logger_write(pqs_log_level_warning, pqs_log_event_auth_failure, loguser, (const char*)cns->target.address, "login failed invalid request fields");
			}
			else
			{
				pqs_logger_write(pqs_log_level_warning, pqs_log_event_auth_failure, loguser, (const char*)cns->target.address, "login failed");
			}

			if (m_server_connection_state.login_attempts >= PQS_SERVER_MAX_LOGIN)
			{
				m_server_connection_state.state = pqs_session_state_closing;
				pqs_logger_write(pqs_log_level_warning, pqs_log_event_connection_close, loguser, (const char*)cns->target.address, "maximum login attempts exceeded");
				qsms_connection_close(cns, qsms_error_authentication_failure, true);
			}
		}
	}
	else if (cns != NULL)
	{
		(void)server_send_application_message(cns, pqs_application_message_login_failure, (const uint8_t*)"Invalid PQS login request.", qsc_stringutils_string_size("Invalid PQS login request."));
		pqs_logger_write(pqs_log_level_warning, pqs_log_event_protocol_error, m_server_connection_state.activeuser, (const char*)cns->target.address, "invalid login request");
	}

	qsc_memutils_secure_erase((uint8_t*)passphrase, sizeof(passphrase));
	return res;
}


static bool server_handle_admin_request(qsms_connection_state* cns, const uint8_t* message, size_t msglen)
{
	pqs_admin_context context = { 0 };
	pqs_admin_request request = { 0 };
	char output[PQS_ADMIN_OUTPUT_MAX] = { 0 };
	char lmsg[192] = { 0 };
	const char* request_text;
	size_t rlen;
	bool res;

	res = false;
	request_text = NULL;

	if (cns != NULL && message != NULL && msglen > PQS_APPLICATION_MESSAGE_HEADER_SIZE)
	{
		rlen = msglen - PQS_APPLICATION_MESSAGE_HEADER_SIZE;

		if (rlen > PQS_STRING_TERMINATOR_SIZE && rlen <= PQS_ADMIN_ARGUMENT_MAX && message[msglen - 1U] == '\0')
		{
			request_text = (const char*)(message + PQS_APPLICATION_MESSAGE_HEADER_SIZE);
			pqs_logger_write(pqs_log_level_audit, pqs_log_event_admin_request, m_server_connection_state.activeuser, (const char*)cns->target.address, "typed admin request");

			if (m_server_connection_state.authenticated == true && m_server_connection_state.state == pqs_session_state_authenticated &&
				pqs_admin_request_parse(&request, request_text) == true)
			{
				context.user = m_server_connection_state.activeuser;
				context.peer = (const char*)cns->target.address;
				context.privilege = m_server_connection_state.privilege;
				context.authenticated = m_server_connection_state.authenticated;
				context.config = &m_server_config;
				context.users = &m_server_user_store;
				context.shells = &m_server_shell_store;
				context.policies = &m_server_policy_store;
				context.sandbox = &m_server_sandbox;
				context.public_key = &m_server_public_key;
				context.logger_failed = pqs_logger_failure_occurred();

				if (pqs_admin_authorize(&context, &request) == true)
				{
					snprintf(lmsg, sizeof(lmsg), "command=%s policy=%s", pqs_admin_command_to_string(request.command), pqs_admin_policy_verb(request.command));
					pqs_logger_write(pqs_log_level_audit, pqs_log_event_admin_allowed, m_server_connection_state.activeuser, (const char*)cns->target.address, lmsg);

					if (pqs_admin_execute(&context, &request, output, sizeof(output)) == true)
					{
						res = server_send_admin_output(cns, output);
						pqs_logger_write(pqs_log_level_audit, pqs_log_event_admin_complete, m_server_connection_state.activeuser, (const char*)cns->target.address, lmsg);
					}
					else
					{
						(void)server_send_error_message(cns, "PQS administrative command failed.");
						pqs_logger_write(pqs_log_level_warning, pqs_log_event_admin_failed, m_server_connection_state.activeuser, (const char*)cns->target.address, lmsg);
					}
				}
				else
				{
					snprintf(lmsg, sizeof(lmsg), "command=%s privilege=%s", pqs_admin_command_to_string(request.command), pqs_user_privilege_to_string(m_server_connection_state.privilege));
					(void)server_send_error_message(cns, "PQS administrative command denied.");
					pqs_logger_write(pqs_log_level_warning, pqs_log_event_admin_denied, m_server_connection_state.activeuser, (const char*)cns->target.address, lmsg);
				}
			}
			else
			{
				(void)server_send_error_message(cns, "Invalid or unauthenticated PQS administrative command.");
				pqs_logger_write(pqs_log_level_warning, pqs_log_event_admin_denied, m_server_connection_state.activeuser, (const char*)cns->target.address, "invalid admin request");
			}
		}
	}

	return res;
}

static bool server_handle_command_request(qsms_connection_state* cns, const uint8_t* message, size_t msglen)
{
	char cmd[PQS_SERVER_COMMAND_MAX] = { 0 };
	size_t clen;
	bool res;

	res = false;

	if (cns != NULL && message != NULL && msglen > PQS_APPLICATION_MESSAGE_HEADER_SIZE)
	{
		clen = msglen - PQS_APPLICATION_MESSAGE_HEADER_SIZE;

		if (clen > PQS_STRING_TERMINATOR_SIZE && clen <= sizeof(cmd))
		{
			if (message[msglen - 1U] == '\0')
			{
				qsc_memutils_copy(cmd, message + PQS_APPLICATION_MESSAGE_HEADER_SIZE, clen);

				if (m_server_connection_state.authenticated == true &&
					m_server_connection_state.state == pqs_session_state_authenticated)
				{
					const pqs_policy_record* policy;
					char lmsg[192] = { 0 };

					policy = NULL;

					if (pqs_policy_store_authorize(&m_server_policy_store, m_server_connection_state.privilege, cmd, &policy) == true)
					{
						const pqs_shell_profile* profile;
						const char* execmd;

						profile = NULL;
						execmd = cmd;

						if (policy != NULL && policy->mode == pqs_policy_mode_forced && policy->forced[0U] != '\0')
						{
							execmd = policy->forced;
						}

						if (server_shell_profile_resolve(&profile) == true)
						{
							snprintf(lmsg, sizeof(lmsg), "policy=%s mode=%s privilege=%s shell=%s exec-bytes=%zu",
								(policy != NULL) ? policy->name : "none",
								(policy != NULL) ? pqs_policy_mode_to_string(policy->mode) : "none",
								pqs_user_privilege_to_string(m_server_connection_state.privilege),
								(profile != NULL) ? profile->name : "none",
								qsc_stringutils_string_size(execmd));
							
							pqs_logger_write(pqs_log_level_audit, pqs_log_event_policy_allowed, m_server_connection_state.activeuser, (const char*)cns->target.address, lmsg);
							m_server_connection_state.state = pqs_session_state_command_active;
							res = server_command_execute(cns, execmd, qsc_stringutils_string_size(execmd), profile);
							m_server_connection_state.state = pqs_session_state_authenticated;
						}
						else
						{
							(void)server_send_error_message(cns, "No permitted PQS shell profile is available for the authenticated user.");
							pqs_logger_write(pqs_log_level_warning, pqs_log_event_command_failed, m_server_connection_state.activeuser, (const char*)cns->target.address, "shell profile unavailable");
						}
					}
					else
					{
						snprintf(lmsg, sizeof(lmsg), "policy=%s privilege=%s",
							(policy != NULL) ? policy->name : "none",
							pqs_user_privilege_to_string(m_server_connection_state.privilege));
						
						(void)server_send_error_message(cns, "PQS command policy denied the requested command.");
						pqs_logger_write(pqs_log_level_warning, pqs_log_event_policy_denied, m_server_connection_state.activeuser, (const char*)cns->target.address, lmsg);
					}
				}
				else
				{
					(void)server_send_error_message(cns, "PQS authentication is required before command execution.");
					pqs_logger_write(pqs_log_level_warning, pqs_log_event_auth_failure, m_server_connection_state.activeuser, (const char*)cns->target.address, "command rejected before authentication");
				}
			}
		}
	}

	return res;
}

static void server_receive_callback(qsms_connection_state* cns, const uint8_t* message, size_t msglen)
{
	pqs_application_messages type;

	type = pqs_application_message_none;

	if (m_server_connection_state.instance == 0U)
	{
		char msg[QSC_NETUTILS_NAME_BUFFER_SIZE] = { 0U };

		qsc_stringutils_copy_string(msg, sizeof(msg), "Connected to ");
		qsc_stringutils_concat_strings(msg, sizeof(msg), (char*)cns->target.address);
		qsc_consoleutils_set_window_title(msg);
		qsc_consoleutils_print_line(msg);
		server_print_prompt();

		pqs_logger_write(pqs_log_level_info, pqs_log_event_connection_open, m_server_connection_state.activeuser, (const char*)cns->target.address, "connection opened");
		
		m_server_connection_state.instance = cns->target.instance;
		m_server_connection_state.authenticated = false;
		m_server_connection_state.privilege = pqs_user_privilege_none;
		m_server_connection_state.login_attempts = 0U;
		m_server_connection_state.state = pqs_session_state_login_required;
	}

	if (server_instance_check(cns) == true)
	{
		if (message != NULL && msglen >= PQS_APPLICATION_MESSAGE_HEADER_SIZE)
		{
			type = (pqs_application_messages)message[0U];
		}

		if (type == pqs_application_message_admin_request)
		{
			(void)server_handle_admin_request(cns, message, msglen);
		}
		else if (type == pqs_application_message_command_request)
		{
			if (server_handle_command_request(cns, message, msglen) == false)
			{
				pqs_logger_write(pqs_log_level_warning, pqs_log_event_command_failed, m_server_connection_state.activeuser, (const char*)cns->target.address, "command rejected or failed");
			}
		}
		else if (type == pqs_application_message_login_request)
		{
			(void)server_handle_login_request(cns, message, msglen);
		}
		else if (type == pqs_application_message_file_get_request ||
			type == pqs_application_message_file_put_start ||
			type == pqs_application_message_file_put_data ||
			type == pqs_application_message_file_put_final ||
			type == pqs_application_message_file_get_recursive_request ||
			type == pqs_application_message_file_list_request ||
			type == pqs_application_message_file_mkdir_request ||
			type == pqs_application_message_file_remove_request)
		{
			(void)server_handle_file_request(cns, type, message, msglen);
		}
		else
		{
			(void)server_send_error_message(cns, "Invalid PQS application message.");
			pqs_logger_write(pqs_log_level_warning, pqs_log_event_protocol_error, m_server_connection_state.activeuser, (const char*)cns->target.address, "invalid application message");
		}
	}
	else
	{
		/* if a second connection is trying to log on, send a refusal message and close the socket */
		if (qsc_socket_is_connected(&cns->target) == true)
		{
			pqs_logger_write(pqs_log_level_warning, pqs_log_event_connection_refused, m_server_connection_state.activeuser, (const char*)cns->target.address, "single-session policy");
			qsms_connection_close(cns, qsms_error_connection_failure, true);
		}
	}
}

static char* server_string_token(char* source, const char* delimiters, char** context)
{
#if defined(QSC_SYSTEM_COMPILER_MSC)
	return strtok_s(source, delimiters, context);
#else
	return strtok_r(source, delimiters, context);
#endif
}

static size_t server_tokenize_command(char* line, char* tokens[], size_t tokmax)
{
	char* ctx;
	char* tok;
	size_t count;

	ctx = NULL;
	count = 0U;

	if (line != NULL && tokens != NULL && tokmax != 0U)
	{
		tok = server_string_token(line, " \t\r\n", &ctx);

		while (tok != NULL && count < tokmax)
		{
			tokens[count] = tok;
			++count;
			tok = server_string_token(NULL, " \t\r\n", &ctx);
		}
	}

	return count;
}

static bool server_generate_passphrase(char* passphrase, size_t passlen)
{
	/* the generated passphrase uses a 32-symbol, transcription-safe alphabet.
	 * I, O, 0, and 1 are excluded to reduce visual ambiguity.
	 * lowercase and shell metacharacters are excluded to improve portability across consoles, 
	 * configuration files, scripts, and remote terminals.
	 * The 20 random symbols provide 100 bits of entropy. */

	static const char symbols[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
	uint8_t rnd[20U] = { 0U };
	size_t pos;
	bool res;

	res = false;

	if (passphrase != NULL && passlen >= 25U)
	{
		res = qsc_acp_generate(rnd, sizeof(rnd));

		if (res == true)
		{
			for (pos = 0U; pos < sizeof(rnd); ++pos)
			{
				passphrase[pos + (pos / 4U)] = symbols[rnd[pos] % (sizeof(symbols) - 1U)];

				if (((pos + 1U) % 4U) == 0U && pos != (sizeof(rnd) - 1U))
				{
					passphrase[pos + (pos / 4U) + 1U] = '-';
				}
			}

			passphrase[24U] = '\0';
		}
	}

	qsc_memutils_secure_erase(rnd, sizeof(rnd));

	return res;
}

static void server_shell_list(void)
{
	size_t pos;

	if (m_server_shell_store.count == 0U)
	{
		server_print_message("No PQS shell profiles are configured.");
	}
	else
	{
		for (pos = 0U; pos < m_server_shell_store.count; ++pos)
		{
			const pqs_shell_profile* profile;
			char msg[512] = { 0 };

			profile = &m_server_shell_store.profiles[pos];

			snprintf(msg, sizeof(msg), "%s type=%s enabled=%s default=%s mask=%u path=%s",
				profile->name,
				profile->type,
				(profile->enabled == true) ? "yes" : "no",
				(profile->isdefault == true) ? "yes" : "no",
				profile->privilege_mask,
				profile->path);

			server_print_message(msg);
		}
	}
}

static void server_shell_show(const char* name)
{
	const pqs_shell_profile* profile;
	char msg[512] = { 0 };

	profile = pqs_shell_store_find(&m_server_shell_store, name);

	if (profile != NULL)
	{
		snprintf(msg, sizeof(msg), "name=%s type=%s enabled=%s default=%s mask=%u path=%s",
			profile->name,
			profile->type,
			(profile->enabled == true) ? "yes" : "no",
			(profile->isdefault == true) ? "yes" : "no",
			profile->privilege_mask,
			profile->path);

		server_print_message(msg);
	}
	else
	{
		server_print_message("The requested PQS shell profile was not found.");
	}
}

static const char* server_shell_remainder_after_tokens(const char* line, size_t tskip)
{
	const char* ptr;
	size_t count;

	ptr = line;
	count = 0U;

	if (line != NULL)
	{
		while (*ptr != '\0' && count < tskip)
		{
			while (*ptr == ' ' || *ptr == '\t')
			{
				++ptr;
			}

			while (*ptr != '\0' && *ptr != ' ' && *ptr != '\t' && *ptr != '\r' && *ptr != '\n')
			{
				++ptr;
			}

			++count;
		}

		while (*ptr == ' ' || *ptr == '\t')
		{
			++ptr;
		}
	}

	return ptr;
}

static void server_shell_mode_execute(char* line, char* tokens[], size_t tcount)
{
	char msg[256] = { 0 };
	const char* path;
	pqs_user_privileges privilege;
	bool res;

	res = false;

	if (tcount == 0U)
	{
		/* no action */
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "help") == true)
	{
		if (tcount > 1U && qsc_stringutils_strings_equal(tokens[1U], "detail") == true)
		{
			pqs_help_server_print_detail();
		}
		else
		{
			pqs_help_server_print_help();
		}
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "exit") == true)
	{
		server_set_prompt(server_console_mode_server);
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "list") == true)
	{
		server_shell_list();
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "show") == true && tcount == 2U)
	{
		server_shell_show(tokens[1U]);
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "add") == true && tcount >= 4U)
	{
		path = server_shell_remainder_after_tokens(line, 3U);

		if (path != NULL && path[0U] != '\0')
		{
			res = pqs_shell_store_add(&m_server_shell_store, tokens[1U], tokens[2U], path, PQS_SHELL_PRIVILEGE_ALL, true);
		}

		server_print_message(res == true ? "The PQS shell profile has been added." : "The PQS shell profile could not be added.");

		if (res == true)
		{
			snprintf(msg, sizeof(msg), "shell=%s type=%s", tokens[1U], tokens[2U]);
			pqs_logger_write(pqs_log_level_audit, pqs_log_event_shell_added, m_server_connection_state.activeuser, NULL, msg);
		}
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "remove") == true && tcount == 2U)
	{
		res = pqs_shell_store_remove(&m_server_shell_store, tokens[1U]);
		server_print_message(res == true ? "The PQS shell profile has been removed." : "The PQS shell profile could not be removed.");

		if (res == true)
		{
			snprintf(msg, sizeof(msg), "shell=%s", tokens[1U]);
			pqs_logger_write(pqs_log_level_audit, pqs_log_event_shell_removed, m_server_connection_state.activeuser, NULL, msg);
		}
	}
	else if ((qsc_stringutils_strings_equal(tokens[0U], "enable") == true ||
		qsc_stringutils_strings_equal(tokens[0U], "disable") == true) && tcount == 2U)
	{
		res = pqs_shell_store_enable(&m_server_shell_store, tokens[1U], qsc_stringutils_strings_equal(tokens[0U], "enable"));
		server_print_message(res == true ? "The PQS shell profile has been updated." : "The PQS shell profile could not be updated.");

		if (res == true)
		{
			snprintf(msg, sizeof(msg), "shell=%s state=%s", tokens[1U], tokens[0U]);
			pqs_logger_write(pqs_log_level_audit, pqs_log_event_shell_updated, m_server_connection_state.activeuser, NULL, msg);
		}
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "default") == true && tcount == 2U)
	{
		res = pqs_shell_store_set_default(&m_server_shell_store, tokens[1U]);
		server_print_message(res == true ? "The default PQS shell profile has been updated." : "The default PQS shell profile could not be updated.");

		if (res == true)
		{
			snprintf(msg, sizeof(msg), "shell=%s default", tokens[1U]);
			pqs_logger_write(pqs_log_level_audit, pqs_log_event_shell_updated, m_server_connection_state.activeuser, NULL, msg);
		}
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "assign") == true && tcount == 3U)
	{
		if (pqs_shell_store_find(&m_server_shell_store, tokens[2U]) != NULL)
		{
			res = pqs_user_store_set_shell_profile(&m_server_user_store, tokens[1U], tokens[2U]);
		}

		server_print_message(res == true ? "The PQS user shell profile has been assigned." : "The PQS user shell profile could not be assigned.");

		if (res == true)
		{
			snprintf(msg, sizeof(msg), "user=%s shell=%s", tokens[1U], tokens[2U]);
			pqs_logger_write(pqs_log_level_audit, pqs_log_event_user_updated, m_server_connection_state.activeuser, NULL, msg);
		}
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "force") == true && tcount == 3U)
	{
		res = pqs_policy_store_set_forced(&m_server_policy_store, tokens[1U], tokens[2U]);
		server_print_message(res == true ? "The PQS command policy forced command has been updated." : "The PQS command policy forced command could not be updated.");

		if (res == true)
		{
			snprintf(msg, sizeof(msg), "policy=%s forced=%s", tokens[1U], tokens[2U]);
			pqs_logger_write(pqs_log_level_audit, pqs_log_event_policy_updated, m_server_connection_state.activeuser, NULL, msg);
		}
	}
	else if ((qsc_stringutils_strings_equal(tokens[0U], "allow") == true ||
		qsc_stringutils_strings_equal(tokens[0U], "deny") == true) && tcount == 3U)
	{
		privilege = pqs_user_privilege_from_string(tokens[1U]);
		res = pqs_shell_store_set_privilege(&m_server_shell_store, tokens[2U], privilege, qsc_stringutils_strings_equal(tokens[0U], "allow"));
		server_print_message(res == true ? "The PQS shell privilege mask has been updated." : "The PQS shell privilege mask could not be updated.");

		if (res == true)
		{
			snprintf(msg, sizeof(msg), "shell=%s privilege=%s action=%s", tokens[2U], tokens[1U], tokens[0U]);
			pqs_logger_write(pqs_log_level_audit, pqs_log_event_shell_updated, m_server_connection_state.activeuser, NULL, msg);
		}
	}
	else
	{
		server_print_message("The shell command was not recognized.");
		pqs_help_server_print_help();
	}
}

static void server_policy_list(void)
{
	char msg[512] = { 0 };
	size_t pos;

	snprintf(msg, sizeof(msg), "assignments guest=%s user=%s admin=%s",
		m_server_policy_store.guest_policy,
		m_server_policy_store.user_policy,
		m_server_policy_store.admin_policy);

	server_print_message(msg);

	if (m_server_policy_store.count == 0U)
	{
		server_print_message("No PQS command policies are configured.");
	}
	else
	{
		for (pos = 0U; pos < m_server_policy_store.count; ++pos)
		{
			const pqs_policy_record* record;

			record = &m_server_policy_store.records[pos];

			snprintf(msg, sizeof(msg), "%s mode=%s enabled=%s mask=%u allow=[%s] deny=[%s] forced=%s",
				record->name,
				pqs_policy_mode_to_string(record->mode),
				(record->enabled == true) ? "yes" : "no",
				record->privilege_mask,
				record->allowlist,
				record->denylist,
				record->forced);

			server_print_message(msg);
		}
	}
}

static void server_policy_show(const char* name)
{
	char msg[512] = { 0 };
	const pqs_policy_record* record;

	record = pqs_policy_store_find(&m_server_policy_store, name);

	if (record != NULL)
	{
		snprintf(msg, sizeof(msg), "name=%s mode=%s enabled=%s mask=%u allow=[%s] deny=[%s] forced=%s",
			record->name,
			pqs_policy_mode_to_string(record->mode),
			(record->enabled == true) ? "yes" : "no",
			record->privilege_mask,
			record->allowlist,
			record->denylist,
			record->forced);

		server_print_message(msg);
	}
	else
	{
		server_print_message("The requested PQS command policy was not found.");
	}
}

static void server_policy_mode_execute(char* tokens[], size_t tcount)
{
	char msg[256] = { 0 };
	pqs_policy_modes mode;
	pqs_user_privileges privilege;
	bool res;

	res = false;

	if (tcount == 0U)
	{
		/* no action */
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "help") == true)
	{
		if (tcount > 1U && qsc_stringutils_strings_equal(tokens[1U], "detail") == true)
		{
			pqs_help_server_print_detail();
		}
		else
		{
			pqs_help_server_print_policy();
		}
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "exit") == true)
	{
		server_set_prompt(server_console_mode_server);
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "list") == true)
	{
		server_policy_list();
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "show") == true && tcount == 2U)
	{
		server_policy_show(tokens[1U]);
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "add") == true && tcount == 3U)
	{
		mode = pqs_policy_mode_from_string(tokens[2U]);
		res = pqs_policy_store_add(&m_server_policy_store, tokens[1U], mode, 0x07U, true);
		server_print_message(res == true ? "The PQS command policy has been added." : "The PQS command policy could not be added.");

		if (res == true)
		{
			snprintf(msg, sizeof(msg), "policy=%s mode=%s", tokens[1U], tokens[2U]);
			pqs_logger_write(pqs_log_level_audit, pqs_log_event_policy_added, m_server_connection_state.activeuser, NULL, msg);
		}
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "remove") == true && tcount == 2U)
	{
		res = pqs_policy_store_remove(&m_server_policy_store, tokens[1U]);
		server_print_message(res == true ? "The PQS command policy has been removed." : "The PQS command policy could not be removed.");

		if (res == true)
		{
			snprintf(msg, sizeof(msg), "policy=%s", tokens[1U]);
			pqs_logger_write(pqs_log_level_audit, pqs_log_event_policy_removed, m_server_connection_state.activeuser, NULL, msg);
		}
	}
	else if ((qsc_stringutils_strings_equal(tokens[0U], "enable") == true ||
		qsc_stringutils_strings_equal(tokens[0U], "disable") == true) && tcount == 2U)
	{
		res = pqs_policy_store_enable(&m_server_policy_store, tokens[1U], qsc_stringutils_strings_equal(tokens[0U], "enable"));
		server_print_message(res == true ? "The PQS command policy has been updated." : "The PQS command policy could not be updated.");

		if (res == true)
		{
			snprintf(msg, sizeof(msg), "policy=%s state=%s", tokens[1U], tokens[0U]);
			pqs_logger_write(pqs_log_level_audit, pqs_log_event_policy_updated, m_server_connection_state.activeuser, NULL, msg);
		}
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "mode") == true && tcount == 3U)
	{
		mode = pqs_policy_mode_from_string(tokens[2U]);
		res = pqs_policy_store_set_mode(&m_server_policy_store, tokens[1U], mode);
		server_print_message(res == true ? "The PQS command policy mode has been updated." : "The PQS command policy mode could not be updated.");

		if (res == true)
		{
			snprintf(msg, sizeof(msg), "policy=%s mode=%s", tokens[1U], tokens[2U]);
			pqs_logger_write(pqs_log_level_audit, pqs_log_event_policy_updated, m_server_connection_state.activeuser, NULL, msg);
		}
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "force") == true && tcount == 3U)
	{
		res = pqs_policy_store_set_forced(&m_server_policy_store, tokens[1U], tokens[2U]);
		server_print_message(res == true ? "The PQS command policy forced command has been updated." : "The PQS command policy forced command could not be updated.");

		if (res == true)
		{
			snprintf(msg, sizeof(msg), "policy=%s forced=%s", tokens[1U], tokens[2U]);
			pqs_logger_write(pqs_log_level_audit, pqs_log_event_policy_updated, m_server_connection_state.activeuser, NULL, msg);
		}
	}
	else if ((qsc_stringutils_strings_equal(tokens[0U], "allow") == true ||
		qsc_stringutils_strings_equal(tokens[0U], "deny") == true) && tcount == 3U)
	{
		res = pqs_policy_store_add_command(&m_server_policy_store, tokens[1U], tokens[2U], qsc_stringutils_strings_equal(tokens[0U], "allow"));
		server_print_message(res == true ? "The PQS command policy list has been updated." : "The PQS command policy list could not be updated.");

		if (res == true)
		{
			snprintf(msg, sizeof(msg), "policy=%s command=%s action=%s", tokens[1U], tokens[2U], tokens[0U]);
			pqs_logger_write(pqs_log_level_audit, pqs_log_event_policy_updated, m_server_connection_state.activeuser, NULL, msg);
		}
	}
	else if ((qsc_stringutils_strings_equal(tokens[0U], "unallow") == true ||
		qsc_stringutils_strings_equal(tokens[0U], "undeny") == true) && tcount == 3U)
	{
		res = pqs_policy_store_remove_command(&m_server_policy_store, tokens[1U], tokens[2U], qsc_stringutils_strings_equal(tokens[0U], "unallow"));
		server_print_message(res == true ? "The PQS command policy list has been updated." : "The PQS command policy list could not be updated.");

		if (res == true)
		{
			snprintf(msg, sizeof(msg), "policy=%s command=%s action=%s", tokens[1U], tokens[2U], tokens[0U]);
			pqs_logger_write(pqs_log_level_audit, pqs_log_event_policy_updated, m_server_connection_state.activeuser, NULL, msg);
		}
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "assign") == true && tcount == 3U)
	{
		privilege = pqs_user_privilege_from_string(tokens[1U]);
		res = pqs_policy_store_assign_privilege(&m_server_policy_store, privilege, tokens[2U]);
		server_print_message(res == true ? "The PQS privilege policy assignment has been updated." : "The PQS privilege policy assignment could not be updated.");

		if (res == true)
		{
			snprintf(msg, sizeof(msg), "privilege=%s policy=%s", tokens[1U], tokens[2U]);
			pqs_logger_write(pqs_log_level_audit, pqs_log_event_policy_updated, m_server_connection_state.activeuser, NULL, msg);
		}
	}
	else
	{
		server_print_message("The policy command was not recognized.");
		pqs_help_server_print_policy();
	}
}

static void server_print_user_help(void)
{
	server_print_message("user mode commands:");
	server_print_message("add [username] <guest|user|admin> -Add a user and generate a passphrase.");
	server_print_message("remove [username] -Remove a user.");
	server_print_message("enable [username] -Enable a user account.");
	server_print_message("disable [username] -Disable a user account.");
	server_print_message("passwd [username] -Generate a new user passphrase.");
	server_print_message("privilege [username] [guest|user|admin] -Change a user's privilege level.");
	server_print_message("show [username] -Show a user record without secret fields.");
	server_print_message("list -List all users.");
	server_print_message("help -Show this help.");
	server_print_message("detail -Show detailed setup and operations help.");
	server_print_message("exit -Return to server mode.");
}

static void server_print_host_key(void)
{
	char fp[PQS_KEY_FINGERPRINT_STRING_SIZE] = { 0 };

	if (pqs_key_fingerprint_string(fp, sizeof(fp), &m_server_public_key) == true)
	{
		server_print_message("Server public-key fingerprint SHA3-256:");
		server_print_message(fp);
		pqs_logger_write(pqs_log_level_info, pqs_log_event_hostkey_loaded, m_server_connection_state.activeuser, NULL, "server host key fingerprint displayed");
	}
	else
	{
		server_print_message("The server public-key fingerprint could not be computed.");
	}
}

static void server_print_public_key(void)
{
	char* spub;
	size_t plen;

	plen = qsms_public_key_encoding_size();
	spub = qsc_memutils_malloc(plen);

	if (spub != NULL)
	{
		qsc_memutils_clear(spub, plen);
		(void)qsms_public_key_encode(spub, plen, &m_server_public_key);
		server_print_message(spub);
		server_print_host_key();
		qsc_memutils_alloc_free(spub);
	}
	else
	{
		server_print_message("The public-key buffer could not be allocated.");
	}
}

static void server_print_keyscan_line(void)
{
	char host[PQS_SERVER_PROMPT_MAX] = { 0 };
	char fp[PQS_KEY_FINGERPRINT_STRING_SIZE] = { 0 };
	char line[PQS_SERVER_PROMPT_MAX + PQS_KEY_FINGERPRINT_STRING_SIZE + 2U] = { 0 };
	size_t hlen;

	hlen = server_get_host_name(host);

	if (hlen == 0U)
	{
		qsc_stringutils_copy_string(host, sizeof(host), "pqs-server");
	}

	if (pqs_key_fingerprint_string(fp, sizeof(fp), &m_server_public_key) == true)
	{
		qsc_stringutils_copy_string(line, sizeof(line), host);
		qsc_stringutils_concat_strings(line, sizeof(line), "|");
		qsc_stringutils_concat_strings(line, sizeof(line), fp);
		server_print_message("PQS known-hosts entry:");
		server_print_message(line);
	}
	else
	{
		server_print_message("The server public-key fingerprint could not be computed.");
	}
}

static void server_print_sandbox_status(void)
{
	char msg[512U] = { 0 };

	snprintf(msg, sizeof(msg), "sandbox enabled=%s timeout=%u output-limit=%u clear-env=%s cwd=%s run-user=%s chroot=%s",
		m_server_sandbox.enabled == true ? "yes" : "no",
		m_server_sandbox.command_timeout_seconds,
		m_server_sandbox.max_output_bytes,
		m_server_sandbox.clear_environment == true ? "yes" : "no",
		m_server_sandbox.working_directory[0U] != '\0' ? m_server_sandbox.working_directory : "inherit",
		m_server_sandbox.run_as_user[0U] != '\0' ? m_server_sandbox.run_as_user : "service-account",
		m_server_sandbox.chroot_enabled == true ? "yes" : "no");

	server_print_message(msg);
}

static void server_print_root_help(void)
{
	server_print_message("server mode commands:");
	server_print_message("user -Enter user administration mode.");
	server_print_message("shell -Enter shell profile administration mode.");
	server_print_message("policy -Enter command policy administration mode.");
	server_print_message("key -Display the server public key and fingerprint.");
	server_print_message("fp -Display the server public-key fingerprint.");
	server_print_message("keyscan -Display the known-hosts line for this server.");
	server_print_message("sandbox -Display command sandbox status.");
	server_print_message("help -Show this help.");
	server_print_message("detail -Show detailed setup and operations help.");
	server_print_message("quit -Shut down the PQS server.");
}

static void server_user_list(void)
{
	size_t pos;

	if (m_server_user_store.count == 0U)
	{
		server_print_message("No PQS users are configured.");
	}
	else
	{
		for (pos = 0U; pos < m_server_user_store.count; ++pos)
		{
			const pqs_user_record* record;
			char msg[256] = { 0 };

			record = &m_server_user_store.records[pos];

			snprintf(msg, sizeof(msg), "%s privilege=%s enabled=%s shell=%s failures=%u",
				record->username,
				pqs_user_privilege_to_string(record->privilege),
				(record->enabled == true) ? "yes" : "no",
				record->shellprofile,
				record->failures);

			server_print_message(msg);
		}
	}
}

static void server_format_epoch_time(char* output, size_t outlen, uint64_t seconds)
{
	struct tm tms;
	time_t tval;
	bool res;

	res = false;

	if (output != NULL && outlen != 0U)
	{
		output[0U] = '\0';
		tval = (time_t)seconds;

#if defined(QSC_SYSTEM_COMPILER_MSC)
		res = (gmtime_s(&tms, &tval) == 0);
#else
		res = (gmtime_r(&tval, &tms) != NULL);
#endif

		if (res == true)
		{
			if (strftime(output, outlen, "%Y-%m-%d %H:%M:%S UTC", &tms) == 0U)
			{
				output[0U] = '\0';
			}
		}

		if (output[0U] == '\0')
		{
			(void)snprintf(output, outlen, "%llu", (unsigned long long)seconds);
		}
	}
}

static void server_user_show(const char* username)
{
	const pqs_user_record* record;
	char created[32] = { 0 };
	char modified[32] = { 0 };
	char msg[320] = { 0 };

	record = pqs_user_store_find(&m_server_user_store, username);

	if (record != NULL)
	{
		server_format_epoch_time(created, sizeof(created), record->created);
		server_format_epoch_time(modified, sizeof(modified), record->modified);

		snprintf(msg, sizeof(msg), "username=%s privilege=%s enabled=%s shell=%s failures=%u created=%s modified=%s",
			record->username,
			pqs_user_privilege_to_string(record->privilege),
			(record->enabled == true) ? "yes" : "no",
			record->shellprofile,
			record->failures,
			created,
			modified);

		server_print_message(msg);
	}
	else
	{
		server_print_message("The requested PQS user was not found.");
	}
}

static void server_user_print_generated_passphrase(const char* username, const char* passphrase)
{
	char msg[256] = { 0 };

	snprintf(msg, sizeof(msg), "Generated passphrase for %s: %s", username, passphrase);
	server_print_message(msg);
	server_print_message("Store this passphrase securely. It will not be displayed again.");
}

static void server_user_mode_execute(char* tokens[], size_t tcount)
{
	char msg[192] = { 0 };
	char passphrase[PQS_PASSPHRASE_MAX] = { 0 };
	pqs_user_privileges privilege;
	bool res;

	res = false;

	if (tcount == 0U)
	{
		/* no action */
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "help") == true)
	{
		server_print_user_help();
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "detail") == true)
	{
		pqs_help_server_print_detail();
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "exit") == true)
	{
		server_set_prompt(server_console_mode_server);
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "list") == true)
	{
		server_user_list();
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "show") == true && tcount == 2U)
	{
		server_user_show(tokens[1U]);
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "add") == true && tcount == 3U)
	{
		privilege = pqs_user_privilege_from_string(tokens[2U]);

		if (privilege != pqs_user_privilege_none && server_generate_passphrase(passphrase, sizeof(passphrase)) == true)
		{
			res = pqs_user_store_add(&m_server_user_store, tokens[1U], passphrase, privilege);

			if (res == true)
			{
				server_user_print_generated_passphrase(tokens[1U], passphrase);
				snprintf(msg, sizeof(msg), "user=%s privilege=%s", tokens[1U], tokens[2U]);
				pqs_logger_write(pqs_log_level_audit, pqs_log_event_user_added, m_server_connection_state.activeuser, NULL, msg);
			}
		}

		if (res == false)
		{
			server_print_message("The PQS user could not be added.");
		}
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "remove") == true && tcount == 2U)
	{
		res = pqs_user_store_remove(&m_server_user_store, tokens[1U]);
		server_print_message(res == true ? "The PQS user has been removed." : "The PQS user could not be removed.");

		if (res == true)
		{
			snprintf(msg, sizeof(msg), "user=%s", tokens[1U]);
			pqs_logger_write(pqs_log_level_audit, pqs_log_event_user_removed, m_server_connection_state.activeuser, NULL, msg);
		}
	}
	else if ((qsc_stringutils_strings_equal(tokens[0U], "enable") == true ||
		qsc_stringutils_strings_equal(tokens[0U], "disable") == true) && tcount == 2U)
	{
		res = pqs_user_store_enable(&m_server_user_store, tokens[1U], qsc_stringutils_strings_equal(tokens[0U], "enable"));
		server_print_message(res == true ? "The PQS user has been updated." : "The PQS user could not be updated.");

		if (res == true)
		{
			snprintf(msg, sizeof(msg), "user=%s state=%s", tokens[1U], tokens[0U]);
			pqs_logger_write(pqs_log_level_audit, pqs_log_event_user_updated, m_server_connection_state.activeuser, NULL, msg);
		}
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "passwd") == true && tcount == 2U)
	{
		if (server_generate_passphrase(passphrase, sizeof(passphrase)) == true)
		{
			res = pqs_user_store_set_passphrase(&m_server_user_store, tokens[1U], passphrase);

			if (res == true)
			{
				server_user_print_generated_passphrase(tokens[1U], passphrase);
				snprintf(msg, sizeof(msg), "user=%s passphrase-reset", tokens[1U]);
				pqs_logger_write(pqs_log_level_audit, pqs_log_event_user_updated, m_server_connection_state.activeuser, NULL, msg);
			}
		}

		if (res == false)
		{
			server_print_message("The PQS passphrase could not be reset.");
		}
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "privilege") == true && tcount == 3U)
	{
		privilege = pqs_user_privilege_from_string(tokens[2U]);
		res = pqs_user_store_set_privilege(&m_server_user_store, tokens[1U], privilege);
		server_print_message(res == true ? "The PQS user privilege has been updated." : "The PQS user privilege could not be updated.");

		if (res == true)
		{
			snprintf(msg, sizeof(msg), "user=%s privilege=%s", tokens[1U], tokens[2U]);
			pqs_logger_write(pqs_log_level_audit, pqs_log_event_user_updated, m_server_connection_state.activeuser, NULL, msg);
		}
	}
	else
	{
		server_print_message("The user command was not recognized.");
		server_print_user_help();
	}

	qsc_memutils_secure_erase((uint8_t*)passphrase, sizeof(passphrase));
}

static bool server_root_mode_execute(char* tokens[], size_t tcount)
{
	bool res;

	res = true;

	if (tcount == 0U)
	{
		/* no action */
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "quit") == true)
	{
		qsms_server_quit();
		res = false;
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "detail") == true)
	{
		pqs_help_server_print_detail();
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "help") == true)
	{
		server_print_root_help();
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "user") == true)
	{
		server_set_prompt(server_console_mode_user);
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "shell") == true)
	{
		server_set_prompt(server_console_mode_shell);
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "policy") == true)
	{
		server_set_prompt(server_console_mode_policy);
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "key") == true)
	{
		server_print_public_key();
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "fp") == true || qsc_stringutils_strings_equal(tokens[0U], "fingerprint") == true)
	{
		server_print_host_key();
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "keyscan") == true)
	{
		server_print_keyscan_line();
	}
	else if (qsc_stringutils_strings_equal(tokens[0U], "sandbox") == true)
	{
		server_print_sandbox_status();
	}
	else
	{
		server_print_message("The server command was not recognized.");
		server_print_root_help();
	}

	return res;
}

static void server_command_loop(void* src)
{
	char sin[PQS_SERVER_INPUT_MAX] = { 0 };
	char raw[PQS_SERVER_INPUT_MAX] = { 0 };
	char* tokens[8] = { 0 };
	size_t rlen;
	size_t tcount;
	bool run;

	(void)src;
	run = true;

	server_print_message("Type 'help' for server commands or 'quit' to shut down the server.");

	while (run == true)
	{
		server_print_prompt();
		rlen = qsc_consoleutils_get_line(sin, sizeof(sin));

		if (rlen > 0U)
		{
			qsc_stringutils_copy_string(raw, sizeof(raw), sin);
			tcount = server_tokenize_command(sin, tokens, sizeof(tokens) / sizeof(tokens[0U]));

			if (m_server_connection_state.mode == server_console_mode_user)
			{
				server_user_mode_execute(tokens, tcount);
			}
			else if (m_server_connection_state.mode == server_console_mode_shell)
			{
				server_shell_mode_execute(raw, tokens, tcount);
			}
			else if (m_server_connection_state.mode == server_console_mode_policy)
			{
				server_policy_mode_execute(tokens, tcount);
			}
			else
			{
				run = server_root_mode_execute(tokens, tcount);
			}
		}

		qsc_memutils_clear((uint8_t*)tokens, sizeof(tokens));
		qsc_memutils_clear((uint8_t*)raw, sizeof(raw));
		qsc_memutils_clear((uint8_t*)sin, sizeof(sin));
	}

	server_set_prompt(server_console_mode_server);
	server_print_prompt();
}

int main(void)
{
	qsms_client_verification_key pubk = { 0 };
	qsms_server_signature_key* prik;
	qsc_socket source = { 0 };
	char lpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	uint8_t kid[QSMS_KEYID_SIZE] = { 0U };
	qsms_errors qerr;

	prik = (qsms_server_signature_key*)qsc_memutils_secure_malloc(sizeof(qsms_server_signature_key));

	if (prik != NULL)
	{
		qsc_memutils_clear(prik, sizeof(qsms_server_signature_key));
	}

	qsc_consoleutils_set_virtual_terminal();
	qsc_consoleutils_set_window_title("PQS Server");
	qsc_consoleutils_set_window_buffer(2000U, 6000U);
	qsc_consoleutils_set_window_size(1000U, 600U);

	pqs_config_server_defaults(&m_server_config);

	if (server_load_configuration() == false)
	{
		qsc_consoleutils_print_line("The PQS server configuration could not be loaded.");
	}

	server_set_prompt(server_console_mode_server);
	qsc_stringutils_copy_string(m_server_connection_state.activeuser, sizeof(m_server_connection_state.activeuser), "anonymous");

	m_server_connection_state.authenticated = false;
	m_server_connection_state.privilege = pqs_user_privilege_none;
	m_server_connection_state.login_attempts = 0U;
	m_server_connection_state.state = pqs_session_state_none;

	pqs_help_server_print_banner();

	if (server_get_log_path(lpath, sizeof(lpath)) == true)
	{
		pqs_logger_initialize(lpath, m_server_config.log_level);
		pqs_logger_write(pqs_log_level_info, pqs_log_event_application_start, m_server_connection_state.activeuser, NULL, "server start");

		if (server_apply_process_hardening() == true)
		{
			pqs_logger_write(pqs_log_level_info, pqs_log_event_application_start, m_server_connection_state.activeuser, NULL, "process hardening applied");
		}
		else
		{
			pqs_logger_write(pqs_log_level_warning, pqs_log_event_application_start, m_server_connection_state.activeuser, NULL, "process hardening partially applied");
		}
	}

	if (prik != NULL && server_key_dialogue(prik, &pubk, kid) == true && server_user_database_initialize() == true && server_shell_database_initialize() == true && server_policy_database_initialize() == true && server_sandbox_initialize() == true)
	{
		server_print_host_key();
		server_print_message("Waiting for a connection...");
		qsc_async_thread_create(&server_command_loop, &source);

		qerr = qsms_server_start_ipv4(&source, prik, &server_receive_callback, &server_disconnect_callback);

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

	pqs_logger_write(pqs_log_level_info, pqs_log_event_application_stop, m_server_connection_state.activeuser, NULL, "server stop");
	pqs_logger_dispose();

	if (prik != NULL)
	{
		qsc_memutils_secure_free(prik, sizeof(qsms_server_signature_key));
	}

	qsc_consoleutils_print_line("Press any key to close...");
	qsc_consoleutils_get_wait();

	return 0;
}

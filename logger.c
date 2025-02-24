#include "logger.h"
#include "../../QSC/QSC/async.h"
#include "../../QSC/QSC/consoleutils.h"
#include "../../QSC/QSC/fileutils.h"
#include "../../QSC/QSC/folderutils.h"
#include "../../QSC/QSC/memutils.h"
#include "../../QSC/QSC/stringutils.h"
#include "../../QSC/QSC/timestamp.h"

static char m_log_path[QSC_SYSTEM_MAX_PATH] = { 0 };

static void logger_default_path(char* path, size_t pathlen)
{
	bool res;

	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, path);
	qsc_folderutils_append_delimiter(path);
	qsc_stringutils_concat_strings(path, pathlen, PQS_LOGGER_PATH);
	res = qsc_folderutils_directory_exists(path);

	if (res == false)
	{
		res = qsc_folderutils_create_directory(path);
	}

	if (res == true)
	{
		qsc_folderutils_append_delimiter(path);
		qsc_stringutils_concat_strings(path, pathlen, PQS_LOGGER_FILE);
	}
}

void pqs_logger_initialize(const char* path)
{
	logger_default_path(m_log_path, QSC_SYSTEM_MAX_PATH);

	if (pqs_logger_exists() == false)
	{
		qsc_memutils_clear(m_log_path, sizeof(m_log_path));

		if (path != NULL)
		{
			if (qsc_fileutils_valid_path(path) == true)
			{
				size_t plen;

				plen = qsc_stringutils_string_size(path);
				qsc_memutils_copy(m_log_path, path, plen);
			}
		}

		if (qsc_stringutils_string_size(m_log_path) == 0)
		{
			logger_default_path(m_log_path, sizeof(m_log_path));
		}

		pqs_logger_reset();
	}
}

bool pqs_logger_exists()
{
	bool res;

	res = qsc_fileutils_valid_path(m_log_path);

	if (res == true)
	{
		res = qsc_fileutils_exists(m_log_path);
	}

	return res;
}

void pqs_logger_print()
{
	char buf[PQS_LOGGING_MESSAGE_MAX] = { 0 };
	size_t lctr;
	size_t mlen;

	lctr = 0;

	if (pqs_logger_exists() == true)
	{
		do
		{
			mlen = qsc_fileutils_read_line(m_log_path, buf, sizeof(buf), lctr);
			++lctr;

			if (mlen > 0)
			{
				qsc_consoleutils_print_line(buf);
				qsc_memutils_clear(buf, mlen);
			}
		} 
		while (mlen > 0);
	}
}

void pqs_logger_read(char* output, size_t otplen)
{
	qsc_mutex mtx;

	if (pqs_logger_exists() == true)
	{
		mtx = qsc_async_mutex_lock_ex();
		qsc_fileutils_safe_read(m_log_path, 0, output, otplen);
		qsc_async_mutex_unlock_ex(mtx);
	}
}

void pqs_logger_reset()
{
	char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
	char msg[PQS_LOGGING_MESSAGE_MAX] = "Created: ";
	size_t mlen;

	if (pqs_logger_exists() == true)
	{
		qsc_fileutils_erase(m_log_path);
	}
	else
	{
		qsc_fileutils_create(m_log_path);
	}

	qsc_fileutils_write_line(m_log_path, PQS_LOGGER_HEAD, sizeof(PQS_LOGGER_HEAD) - 1);
	qsc_timestamp_current_datetime(dtm);
	mlen = qsc_stringutils_concat_strings(msg, sizeof(msg), dtm);
	qsc_fileutils_write_line(m_log_path, msg, mlen);
}

size_t pqs_logger_size()
{
	size_t res;

	res = 0;

	if (pqs_logger_exists() == true)
	{
		res = qsc_fileutils_get_size(m_log_path);
	}

	return res;
}

bool pqs_logger_write(const char* message)
{
	char buf[PQS_LOGGING_MESSAGE_MAX + QSC_TIMESTAMP_STRING_SIZE + 4] = { 0 };
	char dlm[4] = " : ";
	qsc_mutex mtx;
	size_t blen;
	size_t mlen;
	bool res;

	res = pqs_logger_exists();
	mlen = qsc_stringutils_string_size(message);

	if (res == true && mlen <= PQS_LOGGING_MESSAGE_MAX && mlen > 0)
	{
		qsc_timestamp_current_datetime(buf);
		qsc_stringutils_concat_strings(buf, sizeof(buf), dlm);
		blen = qsc_stringutils_concat_strings(buf, sizeof(buf), message);

		mtx = qsc_async_mutex_lock_ex();
		res = qsc_fileutils_write_line(m_log_path, buf, blen);
		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

bool pqs_logger_test()
{
	char buf[4 * PQS_LOGGING_MESSAGE_MAX] = { 0 };
	char msg1[] = "This is a test message: 1";
	char msg2[] = "This is a test message: 2";
	char msg3[] = "This is a test message: 3";
	char msg4[] = "This is a test message: 4";
	size_t flen;
	size_t mlen;
	bool res;

	mlen = qsc_stringutils_string_size(msg1);
	pqs_logger_initialize(NULL);
	res = pqs_logger_exists();

	if (res == true)
	{
		pqs_logger_write(msg1);
		pqs_logger_write(msg2);
		flen = pqs_logger_size();

		pqs_logger_print();
		pqs_logger_reset();
		flen = pqs_logger_size();

		pqs_logger_write(msg3);
		pqs_logger_write(msg4);
		pqs_logger_print();

		flen = pqs_logger_size();
		pqs_logger_read(buf, flen);
	}

	return res;
}
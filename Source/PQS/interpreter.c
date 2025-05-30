#include "interpreter.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "memutils.h"
#include "stringutils.h"
#if defined(QSC_SYSTEM_OS_WINDOWS)
#   include <windows.h>
#elif defined(QSC_SYSTEM_OS_POSIX)
#   include <stdio.h>
#   include <stdlib.h>
#   include <string.h>
#else
#   error The operating system is not supported!
#endif

#if defined(QSC_SYSTEM_OS_WINDOWS)
typedef struct interpreter_command_state
{
    HANDLE hinpw;
    HANDLE hotpr;
    HANDLE hproc;
    bool active;
} interpreter_command_state;

static interpreter_command_state m_interpreter_command_state = { 0 };
#endif

static void interpreter_print_message(const char* prompt, const char* line)
{
    qsc_consoleutils_print_safe(prompt);
    qsc_consoleutils_print_line(line);
}

bool pqs_interpreter_extract_paramater(char* param, const char* message)
{
    const char* pstr;
    size_t slen;
    int64_t ipos;

    slen = 0;
    ipos = qsc_stringutils_find_string(message, " ");

    if (ipos > 0)
    {
        pstr = message + ipos + 1;
        slen = qsc_stringutils_string_size(pstr);

        if (slen > 0)
        {
            slen = qsc_stringutils_copy_string(param, slen, pstr);
        }
    }

    return (slen > 0);
}

bool pqs_interpreter_extract_paramaters(char* param1, char* param2, const char* message)
{
    const char* pstr;
    int64_t ibeg;
    int64_t iend;
    size_t slen;

    slen = 0;

    ibeg = qsc_stringutils_find_string(message, ",") + 1;
    if (ibeg > 0)
    {
        pstr = qsc_stringutils_reverse_sub_string(message, ", ") + 1;

        if (pstr != NULL)
        {
            slen = qsc_stringutils_string_size(pstr);

            if (slen > 0)
            {
                qsc_stringutils_copy_string(param2, slen, pstr);
                pstr = qsc_stringutils_sub_string(message, " ");

                if (pstr != NULL)
                {
                    iend = qsc_stringutils_find_string(pstr, ",");

                    if (iend > 0)
                    {
                        slen = qsc_stringutils_copy_substring(param1, (size_t)iend, pstr, (size_t)iend);
                    }
                }
            }
        }
    }

    return (slen > 0);
}

size_t pqs_interpreter_file_buffer_length(const char* parameter)
{
    char dpath[QSC_FILEUTILS_MAX_PATH] = { 0 };
    char spath[QSC_FILEUTILS_MAX_PATH] = { 0 };
    size_t slen;

    slen = 0;

    pqs_interpreter_extract_paramaters(spath, dpath, parameter);

    if (spath != NULL)
    {
        if (qsc_fileutils_exists(spath) == true)
        {
            slen = qsc_fileutils_get_size(spath) + QSC_FILEUTILS_MAX_PATH;
        }
    }

    return slen;
}

size_t pqs_interpreter_file_to_stream(uint8_t* result, size_t reslen, const char* parameter)
{
    char dpath[QSC_FILEUTILS_MAX_PATH] = { 0 };
    char spath[QSC_FILEUTILS_MAX_PATH] = { 0 };
    size_t slen;

    slen = 0;

    if (pqs_interpreter_extract_paramaters(spath, dpath, parameter) == true)
    {
        if (qsc_fileutils_exists(spath) == true && qsc_stringutils_string_size(dpath) > 0)
        {
            /* copy the path string */
            slen = qsc_stringutils_copy_string((char*)result, reslen, dpath);

            if ((char)result[slen - 1] != '\\')
            {
                slen += qsc_stringutils_copy_string((char*)result + slen, reslen - slen, "\\");
            }

            slen += qsc_fileutils_get_name((char*)result + slen, reslen - slen, spath);
            slen += qsc_fileutils_get_extension((char*)result + slen, reslen - slen, spath);
            slen += qsc_stringutils_copy_string((char*)result + slen, reslen - slen, "\n");

            /* copy the file to the stream */
            slen += qsc_fileutils_copy_file_to_stream(spath, (char*)result + slen, reslen - slen);
        }
    }

    return slen;
}

size_t pqs_interpreter_stream_to_file(uint8_t* result, size_t reslen, const char* parameter, size_t parlen)
{
    char* pstr;
    size_t plen;
    size_t slen;

    slen = 0;
    pstr = qsc_stringutils_sub_string(parameter, "\n");

    if (pstr != NULL)
    {
        plen = qsc_stringutils_string_size(pstr);

        if (plen > 0)
        {
            slen = qsc_fileutils_copy_stream_to_file(pstr, parameter + plen, parlen - plen);

            if (slen == parlen - plen)
            {
                plen = qsc_stringutils_copy_string((char*)result, reslen, "File written to ");
                plen = qsc_stringutils_copy_string((char*)result + plen, reslen - plen, pstr);
                result[plen] = 0;
            }
        }
    }

    if (slen == 0)
    {
        slen = qsc_stringutils_copy_string((char*)result, reslen, "The file could not be saved, check the arguments.");
    }

    return slen;
}

bool pqs_interpreter_initialize()
{
#if defined(QSC_SYSTEM_OS_WINDOWS)

    if (m_interpreter_command_state.active == false)
    {
        PROCESS_INFORMATION pi;
        SECURITY_ATTRIBUTES sa;
        STARTUPINFOW si;
        HANDLE hinpr;
        HANDLE hotpw;
        wchar_t cline[32] = L"cmd.exe";

        ZeroMemory(&sa, sizeof(sa));
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = TRUE;

        if (CreatePipe(&hinpr, &m_interpreter_command_state.hinpw, &sa, 0) == TRUE &&
            CreatePipe(&m_interpreter_command_state.hotpr, &hotpw, &sa, 0) == TRUE)
        {
            if (SetHandleInformation(m_interpreter_command_state.hinpw, HANDLE_FLAG_INHERIT, 0) == TRUE &&
                SetHandleInformation(m_interpreter_command_state.hotpr, HANDLE_FLAG_INHERIT, 0) == TRUE)
            {
                ZeroMemory(&si, sizeof(si));
                si.cb = sizeof(si);
                si.dwFlags = STARTF_USESTDHANDLES;
                si.hStdInput = hinpr;
                si.hStdOutput = hotpw;
                si.hStdError = hotpw;

                if (CreateProcessW(NULL, cline, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi) == TRUE)
                {
                    m_interpreter_command_state.hproc = pi.hProcess;
                    m_interpreter_command_state.active = true;
                }
                else
                {
                    CloseHandle(m_interpreter_command_state.hotpr);
                    CloseHandle(m_interpreter_command_state.hinpw);
                }
            }
            else
            {
                CloseHandle(m_interpreter_command_state.hotpr);
                CloseHandle(m_interpreter_command_state.hinpw);
            }

            CloseHandle(hinpr);
            CloseHandle(hotpw);
        }
    }

#else
    m_interpreter_command_state.active = true;
#endif

    return m_interpreter_command_state.active;
}

size_t pqs_interpreter_command_execute(char* result, size_t reslen, const char* parameter)
{
    assert(m_interpreter_command_state.active == true);
    assert(parameter != NULL);
    assert(result != NULL);
    assert(reslen > 0);

    size_t tlen;

    tlen = 0;
#if defined(QSC_SYSTEM_OS_WINDOWS)

    if (m_interpreter_command_state.active == true && parameter != NULL && result != NULL && reslen > 0)
    {
        char param[1024] = { 0 };
        DWORD bwrit;
        size_t slen;

        slen = strnlen_s(parameter, sizeof(param) - 1);
        qsc_memutils_copy(param, parameter, slen);
        param[slen] = '\n';
        ++slen;

        if (WriteFile(m_interpreter_command_state.hinpw, param, (DWORD)slen, &bwrit, NULL) == TRUE)
        {
            DWORD bavail;
            DWORD bread;

            slen = 0;

            while (true)
            {
                Sleep(150);

                if (PeekNamedPipe(m_interpreter_command_state.hotpr, NULL, 0, NULL, &bavail, NULL) == TRUE)
                {
                    if (bavail != 0)
                    {
                        if (tlen + bavail >= reslen)
                        {
                            char* tmpr;

                            tmpr = qsc_memutils_realloc(result, reslen + bavail + sizeof(char));

                            if (tmpr != NULL)
                            {
                                result = tmpr;
                                reslen += bavail + sizeof(char);
                            }
                            else
                            {
                                break;
                            }
                        }

                        if (ReadFile(m_interpreter_command_state.hotpr, result + tlen, (DWORD)(reslen - tlen), &bread, NULL) == TRUE)
                        {
                            tlen += bread;
                        }
                        else
                        {
                            break;
                        }

                        Sleep(10);
                    }
                    else
                    {
                        break;
                    }
                }
                else
                {
                    break;
                }
            }
        }
    }

#else

    FILE *fp;
    char rbuf[PQS_INTERPRETER_COMMAND_BUFFER_SIZE] = { 0 };
    size_t slen;

    fp = NULL;
    slen = 0;

    if (m_interpreter_command_state.active == true && parameter != NULL && result != NULL && reslen > 0)
    {
        fp = popen(parameter, "rt");

        if (fp != NULL)
        {
            while (true)
            {
                slen = fread(rbuf, sizeof(uint8_t), PQS_INTERPRETER_COMMAND_BUFFER_SIZE, fp);

                if (slen != 0)
                {
                    if (tlen + slen > reslen)
                    {
                        char* tmpr;

                        tmpr = qsc_memutils_realloc(result, reslen + slen + sizeof(char));

                        if (tmpr != NULL)
                        {
                            result = tmpr;
                            reslen += slen + sizeof(char);
                        }
                        else
                        {
                            break;
                        }
                    }

                    qsc_memutils_copy(result + tlen, rbuf, slen);
                    qsc_memutils_clear(rbuf, slen);
                    tlen += slen;
                }
                else
                {
                    break;
                }
            };

            if (tlen == 0)
            {
                const char emsg[] = " is not recognized as an internal or external command, operable program or batch file.";

                tlen = qsc_stringutils_copy_string(result, reslen, parameter);
                tlen += qsc_stringutils_concat_strings(result + tlen, reslen - tlen, emsg);
            }

            pclose(fp);
        }
    }

#endif

    return tlen;
}

void pqs_interpreter_cleanup() 
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
    if (m_interpreter_command_state.active) 
    {
        TerminateProcess(m_interpreter_command_state.hproc, 0);
        CloseHandle(m_interpreter_command_state.hinpw);
        CloseHandle(m_interpreter_command_state.hotpr);
        CloseHandle(m_interpreter_command_state.hproc);
        m_interpreter_command_state.active = false;
    }
#endif
}

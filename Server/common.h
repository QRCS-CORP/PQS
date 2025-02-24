#ifndef PQS_MASTER_COMMON_H
#define PQS_MASTER_COMMON_H

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "../../QSC/QSC/common.h"


/*!
\def PQS_DLL_API
* \brief Enables the dll api exports
*/
#if defined(_DLL)
#	define PQS_DLL_API
#endif
/*!
\def PQS_EXPORT_API
* \brief The api export prefix
*/
#if defined(PQS_DLL_API)
#	if defined(QSC_SYSTEM_COMPILER_MSC)
#		if defined(PQS_DLL_IMPORT)
#			define PQS_EXPORT_API __declspec(dllimport)
#		else
#			define PQS_EXPORT_API __declspec(dllexport)
#		endif
#	elif defined(QSC_SYSTEM_COMPILER_GCC)
#		if defined(PQS_DLL_IMPORT)
#		define PQS_EXPORT_API __attribute__((dllimport))
#		else
#		define PQS_EXPORT_API __attribute__((dllexport))
#		endif
#	else
#		if defined(__SUNPRO_C)
#			if !defined(__GNU_C__)
#				define PQS_EXPORT_API __attribute__ (visibility(__global))
#			else
#				define PQS_EXPORT_API __attribute__ __global
#			endif
#		elif defined(_MSG_VER)
#			define PQS_EXPORT_API extern __declspec(dllexport)
#		else
#			define PQS_EXPORT_API __attribute__ ((visibility ("default")))
#		endif
#	endif
#else
#	define PQS_EXPORT_API
#endif


#endif

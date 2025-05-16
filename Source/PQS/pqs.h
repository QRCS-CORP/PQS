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

#ifndef PQS_H
#define PQS_H

#include "common.h"
#include "../../QSC/QSC/dilithium.h"
#include "../../QSC/QSC/kyber.h"
#include "../../QSC/QSC/sha3.h"
#include "../../QSC/QSC/socketbase.h"

/**
 * \file pqs.h
 * \brief PQS support header.
 *
 * \details
 * This header defines the common parameters, macros, data structures, enumerations, and function
 * prototypes used by both the PQS client and server implementations. PQS (Post Quantum Shell)
 * implements a one-way trust, client-server key-exchange model designed for efficiency and 256-bit
 * post-quantum security. The underlying cryptographic primitives are provided by the QSC library,
 * using combinations of the Dilithium (for signatures) and Kyber (for key encapsulation) schemes.
 * 
 * The protocol configuration is determined at compile-time by preprocessor definitions (such as
 * QSC_DILITHIUM_S1P2544, QSC_KYBER_S1P1632, etc.) defined in the QSC library's common.h file. Although
 * library defaults are used by default, the parameter sets may be changed to suit different security or
 * performance requirements.
 *
 * The file also defines the structures for network packets, connection state, and key containers,
 * along with function prototypes for operations such as connection management, encryption/decryption,
 * logging, public key encoding/decoding, and key generation.
 *
 * \note
 * This header does not include any test functions. The test routines (if implemented elsewhere)
 * validate operations such as key generation, packet encryption/decryption, and error handling.
 *
 * \par Project Description:
 * The PQS exchange is a one-way trust, client-server key-exchange model in which the client trusts
 * the server, and a single shared secret is securely shared between them. Designed for efficiency,
 * the Simplex exchange is fast and lightweight, while providing 256-bit post-quantum security, ensuring
 * protection against future quantum-based threats. This protocol is versatile and applicable to a wide
 * range of secure communications and key distribution scenarios.
 */

/*=============================================================================
                              Macros and Constants
=============================================================================*/

/*!
* \def PQS_USE_RCS_ENCRYPTION
* \brief If the RCS encryption option is chosen SKDP uses the more modern RCS stream cipher with KMAC/QMAC authentication.
* The default symmetric cipher/authenticator is AES-256/GCM (GMAC Counter Mode) NIST standardized per SP800-38a.
*/
//#define PQS_USE_RCS_ENCRYPTION

#if defined(PQS_USE_RCS_ENCRYPTION)
#	include "../../QSC/QSC/rcs.h"
#	define pqs_cipher_state qsc_rcs_state
#	define pqs_cipher_dispose qsc_rcs_dispose
#	define pqs_cipher_initialize qsc_rcs_initialize
#	define pqs_cipher_keyparams qsc_rcs_keyparams
#	define pqs_cipher_set_associated qsc_rcs_set_associated
#	define pqs_cipher_transform qsc_rcs_transform
#else
#	include "../../QSC/QSC/aes.h"
#	define pqs_cipher_state qsc_aes_gcm256_state
#	define pqs_cipher_dispose qsc_aes_gcm256_dispose
#	define pqs_cipher_initialize qsc_aes_gcm256_initialize
#	define pqs_cipher_keyparams qsc_aes_keyparams
#	define pqs_cipher_set_associated qsc_aes_gcm256_set_associated
#	define pqs_cipher_transform qsc_aes_gcm256_transform
#endif

/*!
 * \def PQS_CONFIG_SIZE
 * \brief The size in bytes of the protocol configuration string.
 *
 * This constant defines the fixed length (48 bytes) of the configuration string that
 * specifies the selected cryptographic primitive parameter set.
 */
#define PQS_CONFIG_SIZE 48

/*!
 * \def PQS_CONFIG_STRING
 * \brief The PQS cryptographic primitive configuration string.
 *
 * \details
 * Depending on the compile-time defined parameters, this statically allocated string
 * represents the selected combination of the Dilithium and Kyber algorithms. The possible
 * values include:
 *
 * - "dilithium-s1_kyber-s1_sha3_rcs"
 * - "dilithium-s1_kyber-s3_sha3_rcs"
 * - "dilithium-s1_kyber-s5_sha3_rcs"
 * - "dilithium-s1_kyber-s6_sha3_rcs"
 * - "dilithium-s3_kyber-s1_sha3_rcs"
 * - "dilithium-s3_kyber-s3_sha3_rcs"
 * - "dilithium-s3_kyber-s5_sha3_rcs"
 * - "dilithium-s3_kyber-s6_sha3_rcs"
 * - "dilithium-s5_kyber-s1_sha3_rcs"
 * - "dilithium-s5_kyber-s3_sha3_rcs"
 * - "dilithium-s5_kyber-s5_sha3_rcs"
 * - "dilithium-s5_kyber-s6_sha3_rcs"
 *
 * The value is chosen via a set of nested preprocessor directives based on the defined
 * parameter sets.
 */
#if defined(QSC_DILITHIUM_S1P2544)
#	if defined(QSC_KYBER_S1P1632)
static const char PQS_CONFIG_STRING[PQS_CONFIG_SIZE] = "dilithium-s1_kyber-s1_sha3_rcs";
#	elif defined(QSC_KYBER_S3P2400)
static const char PQS_CONFIG_STRING[PQS_CONFIG_SIZE] = "dilithium-s1_kyber-s3_sha3_rcs";
#	elif defined(QSC_KYBER_S5P3168)
static const char PQS_CONFIG_STRING[PQS_CONFIG_SIZE] = "dilithium-s1_kyber-s5_sha3_rcs";
#	elif defined(QSC_KYBER_S6P3936)
static const char PQS_CONFIG_STRING[PQS_CONFIG_SIZE] = "dilithium-s1_kyber-s6_sha3_rcs";
#	else
#		error Invalid parameter set!
#	endif
#elif defined(QSC_DILITHIUM_S3P4016)
#	if defined(QSC_KYBER_S1P1632)
static const char PQS_CONFIG_STRING[PQS_CONFIG_SIZE] = "dilithium-s3_kyber-s1_sha3_rcs";
#	elif defined(QSC_KYBER_S3P2400)
static const char PQS_CONFIG_STRING[PQS_CONFIG_SIZE] = "dilithium-s3_kyber-s3_sha3_rcs";
#	elif defined(QSC_KYBER_S5P3168)
static const char PQS_CONFIG_STRING[PQS_CONFIG_SIZE] = "dilithium-s3_kyber-s5_sha3_rcs";
#	elif defined(QSC_KYBER_S6P3936)
static const char PQS_CONFIG_STRING[PQS_CONFIG_SIZE] = "dilithium-s3_kyber-s6_sha3_rcs";
#	else
#		error Invalid parameter set!
#	endif
#elif defined(QSC_DILITHIUM_S5P4880)
#	if defined(QSC_KYBER_S1P1632)
static const char PQS_CONFIG_STRING[PQS_CONFIG_SIZE] = "dilithium-s5_kyber-s1_sha3_rcs";
#	elif defined(QSC_KYBER_S3P2400)
static const char PQS_CONFIG_STRING[PQS_CONFIG_SIZE] = "dilithium-s5_kyber-s3_sha3_rcs";
#	elif defined(QSC_KYBER_S5P3168)
static const char PQS_CONFIG_STRING[PQS_CONFIG_SIZE] = "dilithium-s5_kyber-s5_sha3_rcs";
#	elif defined(QSC_KYBER_S6P3936)
static const char PQS_CONFIG_STRING[PQS_CONFIG_SIZE] = "dilithium-s5_kyber-s6_sha3_rcs";
#	else
#		error Invalid parameter set!
#	endif
#else
#	error Invalid parameter set!
#endif

/*!
 * \def PQS_ASYMMETRIC_CIPHER_TEXT_SIZE
 * \brief The size in bytes of the asymmetric cipher-text array.
 *
 * This macro is defined as the value of QSC_KYBER_CIPHERTEXT_SIZE, representing the
 * output size for the Kyber key encapsulation mechanism.
 */
#define PQS_ASYMMETRIC_CIPHER_TEXT_SIZE (QSC_KYBER_CIPHERTEXT_SIZE)

/*!
 * \def PQS_ASYMMETRIC_PRIVATE_KEY_SIZE
 * \brief The size in bytes of the asymmetric cipher private-key array.
 *
 * This is defined in terms of QSC_KYBER_PRIVATEKEY_SIZE.
 */
#define PQS_ASYMMETRIC_PRIVATE_KEY_SIZE (QSC_KYBER_PRIVATEKEY_SIZE)

/*!
 * \def PQS_ASYMMETRIC_PUBLIC_KEY_SIZE
 * \brief The size in bytes of the asymmetric cipher public-key array.
 *
 * This value is taken from QSC_KYBER_PUBLICKEY_SIZE.
 */
#define PQS_ASYMMETRIC_PUBLIC_KEY_SIZE (QSC_KYBER_PUBLICKEY_SIZE)

/*!
 * \def PQS_ASYMMETRIC_SIGNING_KEY_SIZE
 * \brief The size in bytes of the asymmetric signature signing-key array.
 *
 * This value corresponds to QSC_DILITHIUM_PRIVATEKEY_SIZE.
 */
#define PQS_ASYMMETRIC_SIGNING_KEY_SIZE (QSC_DILITHIUM_PRIVATEKEY_SIZE)

/*!
 * \def PQS_ASYMMETRIC_VERIFY_KEY_SIZE
 * \brief The size in bytes of the asymmetric signature verification-key array.
 *
 * This value corresponds to QSC_DILITHIUM_PUBLICKEY_SIZE.
 */
#define PQS_ASYMMETRIC_VERIFY_KEY_SIZE (QSC_DILITHIUM_PUBLICKEY_SIZE)

/*!
 * \def PQS_ASYMMETRIC_SIGNATURE_SIZE
 * \brief The size in bytes of the asymmetric signature array.
 *
 * This value is defined as QSC_DILITHIUM_SIGNATURE_SIZE.
 */
#define PQS_ASYMMETRIC_SIGNATURE_SIZE (QSC_DILITHIUM_SIGNATURE_SIZE)

/*!
 * \def PQS_PUBKEY_ENCODING_SIZE
 * \brief The size in bytes of the encoded PQS public-key.
 *
 * The encoding size varies depending on the selected Dilithium parameter set.
 */
#if defined(QSC_DILITHIUM_S1P2544)
#	define PQS_PUBKEY_ENCODING_SIZE 1752
#elif defined(QSC_DILITHIUM_S3P4016)
#	define PQS_PUBKEY_ENCODING_SIZE 2604
#elif defined(QSC_DILITHIUM_S5P4880)
#	define PQS_PUBKEY_ENCODING_SIZE 3456
#else
#	error invalid dilithium parameter!
#endif

/*!
 * \def PQS_PUBKEY_STRING_SIZE
 * \brief The size in bytes of the serialized PQS client-key structure.
 *
 * This defines the length of the string produced when encoding a public key.
 */
#if defined(QSC_DILITHIUM_S1P2544)
#	define PQS_PUBKEY_STRING_SIZE 2014
#elif defined(QSC_DILITHIUM_S3P4016)
#	define PQS_PUBKEY_STRING_SIZE 2879
#elif defined(QSC_DILITHIUM_S5P4880)
#	define PQS_PUBKEY_STRING_SIZE 3745
#else
#	error invalid dilithium parameter!
#endif

/*!
 * \def PQS_CLIENT_PORT
 * \brief The default port number for PQS client connections.
 */
#define PQS_CLIENT_PORT 33118

/*!
 * \def PQS_CONNECTIONS_INIT
 * \brief The initial size of the PQS connection queue.
 *
 * This value is used when initializing the connection state.
 */
#define PQS_CONNECTIONS_INIT 1000

/*!
 * \def PQS_CONNECTIONS_MAX
 * \brief The maximum number of concurrent PQS connections.
 *
 * This is calculated based on an approximate memory footprint per connection. For example,
 * with a 256GB DRAM system, the maximum may be set to 50,000 connections.
 */
#define PQS_CONNECTIONS_MAX 50000

/*!
 * \def PQS_CONNECTION_MTU
 * \brief The maximum transmission unit (MTU) size for a PQS packet.
 */
#define PQS_CONNECTION_MTU 1500

/*!
 * \def PQS_ERROR_SEQUENCE
 * \brief The sequence number used to indicate an error in a packet.
 */
#define PQS_ERROR_SEQUENCE 0xFF00000000000000ULL

/*!
 * \def PQS_ERROR_MESSAGE_SIZE
 * \brief The size in bytes of the error message contained in a packet.
 */
#define PQS_ERROR_MESSAGE_SIZE 1

/*!
 * \def PQS_FLAG_SIZE
 * \brief The size in bytes of the packet flag.
 */
#define PQS_FLAG_SIZE 1

/*!
 * \def PQS_HASH_SIZE
 * \brief The output size in bytes of the Simplex 256-bit hash function.
 */
#define PQS_HASH_SIZE 32

/*!
 * \def PQS_HEADER_SIZE
 * \brief The size in bytes of a PQS packet header.
 */
#define PQS_HEADER_SIZE 21

/*!
 * \def PQS_KEEPALIVE_TIMEOUT
 * \brief The timeout period (in milliseconds) for keep-alive messages.
 *
 * The default value is 2 minutes.
 */
#define PQS_KEEPALIVE_TIMEOUT (120 * 1000)

/*!
 * \def PQS_KEYID_SIZE
 * \brief The size in bytes of a PQS key identity.
 */
#define PQS_KEYID_SIZE 16

/*!
 * \def PQS_MACTAG_SIZE
 * \brief The size in bytes of the MAC tag for the Simplex 256-bit MAC.
 */
#if defined(PQS_USE_RCS_ENCRYPTION)
#	define PQS_MACTAG_SIZE 32
#else
#	define PQS_MACTAG_SIZE 16
#endif

/*!
 * \def PQS_MESSAGE_MAX
 * \brief The maximum allowed message size (in bytes) during the key exchange.
 *
 * This value is approximately 1 GB.
 */
#define PQS_MESSAGE_MAX 0x3D090000

/*!
 * \def PQS_MSGLEN_SIZE
 * \brief The size in bytes of the packet message length field.
 */
#define PQS_MSGLEN_SIZE 4

/*!
 * \def PQS_NONCE_SIZE
 * \brief The size in bytes of the nonce used in symmetric encryption.
 */
#if defined(PQS_USE_RCS_ENCRYPTION)
#	define PQS_NONCE_SIZE 32
#else
#	define PQS_NONCE_SIZE 16
#endif

/*!
 * \def PQS_NETWORK_BUFFER_SIZE
 * \brief The size in bytes of the network buffer.
 */
#define PQS_NETWORK_BUFFER_SIZE 1280

/*!
 * \def PQS_PACKET_TIME_THRESHOLD
 * \brief The maximum time (in seconds) a packet is considered valid.
 *
 * This threshold can be tuned based on network conditions. For interior networks with
 * synchronized clocks, it might be as low as 1 second; for exterior networks, it may be higher.
 */
#define PQS_PACKET_TIME_THRESHOLD 60

/*!
 * \def PQS_PUBKEY_DURATION_DAYS
 * \brief The validity duration (in days) of a public key.
 */
#define PQS_PUBKEY_DURATION_DAYS 365

/*!
 * \def PQS_PUBKEY_DURATION_SECONDS
 * \brief The validity duration (in seconds) of a public key.
 *
 * Calculated from PQS_PUBKEY_DURATION_DAYS.
 */
#define PQS_PUBKEY_DURATION_SECONDS (PQS_PUBKEY_DURATION_DAYS * 24 * 60 * 60)

/*!
 * \def PQS_PUBKEY_LINE_LENGTH
 * \brief The maximum number of characters per line in a printed PQS public key.
 */
#define PQS_PUBKEY_LINE_LENGTH 64

/*!
 * \def PQS_SCHASH_SIZE
 * \brief The size in bytes of the Simplex 256-bit session token hash.
 */
#define PQS_SCHASH_SIZE 32

/*!
 * \def PQS_SECRET_SIZE
 * \brief The size in bytes of the shared secret for each communication channel.
 */
#define PQS_SECRET_SIZE 32

/*!
 * \def PQS_SEQUENCE_SIZE
 * \brief The size in bytes of the packet sequence number.
 */
#define PQS_SEQUENCE_SIZE 8

/*!
 * \def PQS_SEQUENCE_TERMINATOR
 * \brief The sequence number that indicates a packet which closes a connection.
 */
#define PQS_SEQUENCE_TERMINATOR 0xFFFFFFFFUL

/*!
 * \def PQS_SERVER_LISTEN_BACKLOG
 * \brief The backlog size for the server listen socket.
 *
 * Set to zero since concurrent connections are disallowed at the listen level.
 */
#define PQS_SERVER_LISTEN_BACKLOG 0

/*!
 * \def PQS_SERVER_PORT
 * \brief The default port number for PQS server connections.
 */
#define PQS_SERVER_PORT 3119

/*!
 * \def PQS_SYMMETRIC_KEY_SIZE
 * \brief The size in bytes of the Simplex 256-bit symmetric cipher key.
 */
#define PQS_SYMMETRIC_KEY_SIZE 32

/*!
 * \def PQS_TIMESTAMP_SIZE
 * \brief The size in bytes of the key expiration timestamp.
 */
#define PQS_TIMESTAMP_SIZE 8

/*!
 * \def PQS_SIGKEY_ENCODED_SIZE
 * \brief The size in bytes of the encoded secret signature key structure.
 *
 * The encoded key consists of the key identity, timestamp, configuration string, public key hash,
 * signature key, and verification key.
 */
#define PQS_SIGKEY_ENCODED_SIZE (PQS_KEYID_SIZE + PQS_TIMESTAMP_SIZE + PQS_CONFIG_SIZE + \
	PQS_HASH_SIZE + PQS_ASYMMETRIC_SIGNING_KEY_SIZE + PQS_ASYMMETRIC_VERIFY_KEY_SIZE)

/*----------------------------------------------------------------------------
   PQS algorithm function aliases
   These macros provide aliases to the underlying QSC library functions.
-----------------------------------------------------------------------------*/
/*!
 * \def pqs_cipher_generate_keypair
 * \brief Generate an asymmetric cipher key-pair
 */
#define pqs_cipher_generate_keypair qsc_kyber_generate_keypair
/*!
 * \def pqs_cipher_decapsulate
 * \brief Decapsulate a shared-secret with the asymmetric cipher
 */
#define pqs_cipher_decapsulate qsc_kyber_decapsulate
/*!
 * \def pqs_cipher_encapsulate
 * \brief Encapsulate a shared-secret with the asymmetric cipher
 */
#define pqs_cipher_encapsulate qsc_kyber_encapsulate
/*!
 * \def pqs_signature_generate_keypair
 * \brief Generate an asymmetric signature key-pair
 */
#define pqs_signature_generate_keypair qsc_dilithium_generate_keypair
/*!
 * \def pqs_signature_sign
 * \brief Sign a message with the asymmetric signature scheme
 */
#define pqs_signature_sign qsc_dilithium_sign
/*!
 * \def pqs_signature_verify
 * \brief Verify a message with the asymmetric signature scheme
 */
#define pqs_signature_verify qsc_dilithium_verify

/*----------------------------------------------------------------------------
   Public key encoding constants
   These constants are used to format the textual representation of the PQS public key.
-----------------------------------------------------------------------------*/
/** \cond DOXYGEN_IGNORE */
static const char PQS_PUBKEY_HEADER[] = "------BEGIN PQS PUBLIC KEY BLOCK------";
static const char PQS_PUBKEY_VERSION[] = "Version: PQS v1.0";
static const char PQS_PUBKEY_CONFIG_PREFIX[] = "Configuration: ";
static const char PQS_PUBKEY_KEYID_PREFIX[] = "Host ID: ";
static const char PQS_PUBKEY_EXPIRATION_PREFIX[] = "Expiration: ";
static const char PQS_PUBKEY_FOOTER[] = "------END PQS PUBLIC KEY BLOCK------";
/** \endcond DOXYGEN_IGNORE
* 
/*----------------------------------------------------------------------------
   Error code string parameters
-----------------------------------------------------------------------------*/

/** \cond DOXYGEN_IGNORE */
#define PQS_ERROR_STRING_DEPTH 32
#define PQS_ERROR_STRING_WIDTH 128
#define PQS_MESSAGE_STRING_DEPTH 21
#define PQS_MESSAGE_STRING_WIDTH 128
/** \endcond DOXYGEN_IGNORE */

/** \cond DOXYGEN_IGNORE
 * Internal arrays of error and message strings. These are used by the logging and error
 * reporting functions and are not intended for external use.
 */
static const char PQS_MESSAGE_STRINGS[PQS_ERROR_STRING_DEPTH][PQS_ERROR_STRING_WIDTH] =
{
	"The operation completed succesfully.",
	"The socket server accept function failed.",
	"The listener socket listener could not connect.",
	"The listener socket could not bind to the address.",
	"The listener socket could not be created.",
	"The server is connected to remote host - ",
	"The socket receive function failed - ",
	"The server had a memory allocation failure.",
	"The key exchange has experienced a failure.",
	"The server has disconnected from the remote host - ",
	"The server has disconnected the client due to an error - ",
	"The server has had a socket level error.",
	"The server has reached the maximum number of connections",
	"The server listener socket has failed.",
	"The server has run out of socket connections",
	"The message decryption has failed - ",
	"The keepalive function has failed - ",
	"The keepalive period has been exceeded",
	"The connection failed or was interrupted - ",
	"The function received an invalid request - ",
	"The remote host is busy and refused the connection - "
};

static const char PQS_ERROR_STRINGS[PQS_ERROR_STRING_DEPTH][PQS_ERROR_STRING_WIDTH] =
{
	"No error was detected",
	"The socket accept function returned an error",
	"The symmetric cipher had an authentication failure",
	"The keep alive check failed",
	"The communications channel has failed",
	"The device could not make a connection to the remote host",
	"The transmission failed at the KEX connection phase",
	"The asymmetric cipher failed to decapsulate the shared secret",
	"The decryption authentication has failed",
	"The transmission failed at the KEX establish phase",
	"The transmission failed at the KEX exchange phase",
	"The public - key hash is invalid",
	"The server has run out of socket connections",
	"The expected input was invalid",
	"The packet flag was unexpected",
	"The keep alive has expired with no response",
	"The decryption authentication has failed",
	"The PQS public key has expired ",
	"The key identity is unrecognized",
	"The ratchet operation has failed",
	"The listener function failed to initialize",
	"The server has run out of memory",
	"The packet was received out of sequence",
	"The random generator has failed",
	"The receiver failed at the network layer",
	"The transmitter failed at the network layer",
	"The protocol string was not recognized",
	"The expected data could not be verified",
	"The client received an authentication failure response",
	"The client received an authentication success response",
	"The packet valid time has expired",
	"The connection was refused by the remote server"
};
/** \endcond DOXYGEN_IGNORE */

/*=============================================================================
                              Enumerations
=============================================================================*/

/*!
 * \enum pqs_client_commands
 * \brief Enumeration of client commands in the PQS protocol.
 *
 * These commands are used by the client to indicate the desired operation.
 */
PQS_EXPORT_API typedef enum pqs_client_commands
{
	pqs_client_command_none = 0x00,         /*!< No command was specified */
	pqs_client_command_cprint = 0x01,       /*!< The certificate print command */
	pqs_client_command_execute = 0x02,      /*!< The execute command */
	pqs_client_command_quit = 0x03,         /*!< The quit command */
} pqs_client_commands;

/*!
 * \enum pqs_errors
 * \brief Enumeration of error codes returned by PQS functions.
 *
 * These error values indicate various failure conditions encountered during
 * connection establishment, encryption/decryption, key exchange, and other operations.
 */
PQS_EXPORT_API typedef enum pqs_errors
{
	pqs_error_none = 0x00,                  /*!< No error was detected */
	pqs_error_accept_fail = 0x01,           /*!< The socket accept function returned an error */
	pqs_error_authentication_failure = 0x02,/*!< The symmetric cipher had an authentication failure */
	pqs_error_bad_keep_alive = 0x03,        /*!< The keep alive check failed */
	pqs_error_channel_down = 0x04,          /*!< The communications channel has failed */
	pqs_error_connection_failure = 0x05,    /*!< The device could not make a connection to the remote host */
	pqs_error_connect_failure = 0x06,       /*!< The transmission failed at the KEX connection phase */
	pqs_error_decapsulation_failure = 0x07, /*!< The asymmetric cipher failed to decapsulate the shared secret */
	pqs_error_decryption_failure = 0x08,    /*!< The decryption authentication has failed */
	pqs_error_establish_failure = 0x09,     /*!< The transmission failed at the KEX establish phase */
	pqs_error_exchange_failure = 0x0A,      /*!< The transmission failed at the KEX exchange phase */
	pqs_error_hash_invalid = 0x0B,          /*!< The public-key hash is invalid */
	pqs_error_hosts_exceeded = 0x0C,        /*!< The server has run out of socket connections */
	pqs_error_invalid_input = 0x0D,         /*!< The expected input was invalid */
	pqs_error_invalid_request = 0x0E,       /*!< The packet flag was unexpected */
	pqs_error_keepalive_expired = 0x0F,     /*!< The keep alive has expired with no response */
	pqs_error_keepalive_timeout = 0x10,     /*!< The decryption authentication has failed */
	pqs_error_key_expired = 0x11,           /*!< The PQS public key has expired  */
	pqs_error_key_unrecognized = 0x12,      /*!< The key identity is unrecognized */
	pqs_error_keychain_fail = 0x13,         /*!< The ratchet operation has failed */
	pqs_error_listener_fail = 0x14,         /*!< The listener function failed to initialize */
	pqs_error_memory_allocation = 0x15,     /*!< The server has run out of memory */
	pqs_error_packet_unsequenced = 0x16,    /*!< The packet was received out of sequence */
	pqs_error_random_failure = 0x17,        /*!< The random generator has failed */
	pqs_error_receive_failure = 0x18,       /*!< The receiver failed at the network layer */
	pqs_error_transmit_failure = 0x19,      /*!< The transmitter failed at the network layer */
	pqs_error_unknown_protocol = 0x1A,      /*!< The protocol string was not recognized */
	pqs_error_verify_failure = 0x1B,        /*!< The expected data could not be verified */
	pqs_error_login_failure = 0x1C,         /*!< The client received an authentication failure response */
	pqs_error_login_success = 0x1D,         /*!< The client received an authentication success response */
	pqs_error_message_time_invalid = 0x1E,  /*!< The packet valid time has expired */
	pqs_error_connection_refused = 0x1F,    /*!< The connection was refused by the remote server */
} pqs_errors;

/*!
 * \enum pqs_flags
 * \brief Enumeration of packet flags used in the PQS protocol.
 *
 * The flags indicate the type or purpose of a packet (e.g., connection requests,
 * key exchange phases, keep alive messages, error conditions, etc.).
 */
PQS_EXPORT_API typedef enum pqs_flags
{
	pqs_flag_none = 0x00,                           /*!< No flag was specified */
	pqs_flag_connect_request = 0x01,                /*!< The PQS key-exchange client connection request flag  */
	pqs_flag_connect_response = 0x02,               /*!< The PQS key-exchange server connection response flag */
	pqs_flag_connection_terminate = 0x03,           /*!< The connection is to be terminated */
	pqs_flag_encrypted_message = 0x04,              /*!< The message has been encrypted */
	pqs_flag_exstart_request = 0x05,                /*!< The PQS key-exchange client exstart request flag */
	pqs_flag_exstart_response = 0x06,               /*!< The PQS key-exchange server exstart response flag */
	pqs_flag_exchange_request = 0x07,               /*!< The PQS key-exchange client exchange request flag */
	pqs_flag_exchange_response = 0x08,              /*!< The PQS key-exchange server exchange response flag */
	pqs_flag_establish_request = 0x09,              /*!< The PQS key-exchange client establish request flag */
	pqs_flag_establish_response = 0x0A,             /*!< The PQS key-exchange server establish response flag */
	pqs_flag_keep_alive_request = 0x0B,             /*!< The packet contains a keep alive request */
	pqs_flag_keep_alive_response = 0x0C,            /*!< The packet contains a keep alive response */
	pqs_flag_remote_connected = 0x0E,               /*!< The remote host is connected flag */
	pqs_flag_remote_terminated = 0x0F,              /*!< The remote host has terminated the connection */
	pqs_flag_session_established = 0x10,            /*!< The exchange is in the established state */
	pqs_flag_session_establish_verify = 0x11,       /*!< The exchange is in the established verify state */
	pqs_flag_unrecognized_protocol = 0x12,          /*!< The protocol string is not recognized */
	pqs_flag_asymmetric_ratchet_request = 0x13,     /*!< The host has received an asymmetric key ratchet request */
	pqs_flag_asymmetric_ratchet_response = 0x14,    /*!< The host has received an asymmetric key ratchet request */
	pqs_flag_symmetric_ratchet_request = 0x15,      /*!< The host has received a symmetric key ratchet request */
	pqs_flag_transfer_request = 0x16,               /*!< Reserved - The host has received a transfer request */
	pqs_flag_error_condition = 0xFF,                /*!< The connection experienced an error */
} pqs_flags;

/*!
 * \enum pqs_messages
 * \brief Enumeration of logging and status messages used by PQS.
 *
 * These messages correspond to various events and errors occurring within the
 * protocol, and are used for diagnostic logging.
 */
PQS_EXPORT_API typedef enum pqs_messages
{
	pqs_messages_none = 0x00,             /*!< No configuration was specified */
	pqs_messages_accept_fail = 0x01,      /*!< The socket accept failed */
	pqs_messages_listen_fail = 0x02,      /*!< The listener socket could not connect */
	pqs_messages_bind_fail = 0x03,        /*!< The listener socket could not bind to the address */
	pqs_messages_create_fail = 0x04,      /*!< The listener socket could not be created */
	pqs_messages_connect_success = 0x05,  /*!< The server connected to a host */
	pqs_messages_receive_fail = 0x06,     /*!< The socket receive function failed */
	pqs_messages_allocate_fail = 0x07,    /*!< The server memory allocation request has failed */
	pqs_messages_kex_fail = 0x08,         /*!< The key exchange has experienced a failure */
	pqs_messages_disconnect = 0x09,       /*!< The server has disconnected the client */
	pqs_messages_disconnect_fail = 0x0A,  /*!< The server has disconnected the client due to an error */
	pqs_messages_socket_message = 0x0B,   /*!< The server has had a socket level error */
	pqs_messages_queue_empty = 0x0C,      /*!< The server has reached the maximum number of connections */
	pqs_messages_listener_fail = 0x0D,    /*!< The server listener socket has failed */
	pqs_messages_sockalloc_fail = 0x0E,   /*!< The server has run out of socket connections */
	pqs_messages_decryption_fail = 0x0F,  /*!< The message decryption has failed */
	pqs_messages_keepalive_fail = 0x10,   /*!< The keepalive function has failed */
	pqs_messages_keepalive_timeout = 0x11,/*!< The keepalive period has been exceeded */
	pqs_messages_connection_fail = 0x12,  /*!< The connection failed or was interrupted */
	pqs_messages_invalid_request = 0x13,  /*!< The function received an invalid request */
	pqs_messages_connection_refused = 0x14, /*!< The remote host is busy and refused the connection */
} pqs_messages;

/*=============================================================================
                              Structures
=============================================================================*/

/*!
 * \struct pqs_asymmetric_cipher_keypair
 * \brief Container for an asymmetric cipher key pair.
 *
 * This structure holds the private and public keys for the key encapsulation mechanism
 * (Kyber). The private key is kept secret, while the public key is distributed.
 */
PQS_EXPORT_API typedef struct pqs_asymmetric_cipher_keypair
{
	uint8_t prikey[PQS_ASYMMETRIC_PRIVATE_KEY_SIZE];  /*!< The private key array */
	uint8_t pubkey[PQS_ASYMMETRIC_PUBLIC_KEY_SIZE];     /*!< The public key array */
} pqs_asymmetric_cipher_keypair;

/*!
 * \struct pqs_asymmetric_signature_keypair
 * \brief Container for an asymmetric signature key pair.
 *
 * This structure holds the signing key and the corresponding verification key
 * used by the Dilithium signature scheme.
 */
PQS_EXPORT_API typedef struct pqs_asymmetric_signature_keypair
{
	uint8_t sigkey[PQS_ASYMMETRIC_SIGNING_KEY_SIZE];    /*!< The secret signing key */
	uint8_t verkey[PQS_ASYMMETRIC_VERIFY_KEY_SIZE];       /*!< The public verification key */
} pqs_asymmetric_signature_keypair;

/*!
 * \struct pqs_network_packet
 * \brief Represents a network packet in the PQS protocol.
 *
 * The packet contains a flag indicating its type, the length of the payload,
 * a sequence number, a timestamp, and a pointer to the message buffer.
 */
PQS_EXPORT_API typedef struct pqs_network_packet
{
	uint8_t flag;         /*!< The packet flag */
	uint32_t msglen;      /*!< The length in bytes of the message payload */
	uint64_t sequence;    /*!< The packet sequence number */
	uint64_t utctime;     /*!< The UTC timestamp when the packet was created (in seconds) */
	uint8_t* pmessage;    /*!< Pointer to the packet's message buffer */
} pqs_network_packet;

/*!
 * \struct pqs_client_verification_key
 * \brief Structure holding a PQS client public key.
 *
 * This structure is used to distribute the public key used for verifying digital
 * signatures. It contains the key expiration time, the configuration string,
 * a key identity, and the asymmetric verification key.
 */
PQS_EXPORT_API typedef struct pqs_client_verification_key
{
	uint64_t expiration;                           /*!< The expiration time (in seconds from epoch) */
	uint8_t config[PQS_CONFIG_SIZE];               /*!< The cryptographic configuration string */
	uint8_t keyid[PQS_KEYID_SIZE];                 /*!< The key identity string */
	uint8_t verkey[PQS_ASYMMETRIC_VERIFY_KEY_SIZE];  /*!< The public verification key for signatures */
} pqs_client_verification_key;

/*!
 * \struct pqs_server_signature_key
 * \brief Structure holding a PQS server secret signature key.
 *
 * This structure contains both the secret signing key and the public verification key,
 * along with metadata such as expiration, configuration, key identity, and a remote login key hash.
 */
PQS_EXPORT_API typedef struct pqs_server_signature_key
{
	uint64_t expiration;                             /*!< The expiration time (in seconds from epoch) */
	uint8_t config[PQS_CONFIG_SIZE];                 /*!< The cryptographic configuration string */
	uint8_t keyid[PQS_KEYID_SIZE];                   /*!< The key identity string */
	uint8_t sigkey[PQS_ASYMMETRIC_SIGNING_KEY_SIZE];   /*!< The secret signing key */
	uint8_t verkey[PQS_ASYMMETRIC_VERIFY_KEY_SIZE];    /*!< The public verification key */
	uint8_t rkhash[PQS_HASH_SIZE];                   /*!< The remote login key hash */
} pqs_server_signature_key;

/*!
 * \struct pqs_keep_alive_state
 * \brief Maintains the state for a keep-alive mechanism.
 *
 * This structure tracks the target socket, the epoch time of the keep-alive, a sequence
 * counter, and whether a keep-alive response was received.
 */
PQS_EXPORT_API typedef struct pqs_keep_alive_state
{
	qsc_socket target;  /*!< The target socket for keep-alive messages */
	uint64_t etime;     /*!< The epoch time associated with the keep-alive state */
	uint64_t seqctr;    /*!< The keep-alive packet sequence counter */
	bool recd;          /*!< Flag indicating if a keep-alive response was received */
} pqs_keep_alive_state;

/*!
 * \struct pqs_connection_state
 * \brief Maintains the state for a PQS socket connection.
 *
 * This structure encapsulates the socket, the transmit and receive cipher states,
 * packet sequence numbers for both directions, a connection identifier, and additional
 * flags used during key exchange.
 */
PQS_EXPORT_API typedef struct pqs_connection_state
{
	qsc_socket target;       /*!< The target socket structure */
	pqs_cipher_state rxcpr;  /*!< The receive channel cipher state */
	pqs_cipher_state txcpr;  /*!< The transmit channel cipher state */
	uint64_t rxseq;          /*!< The receive channel packet sequence number */
	uint64_t txseq;          /*!< The transmit channel packet sequence number */
	uint32_t cid;            /*!< The connection instance count */
	pqs_flags exflag;        /*!< The key exchange stage flag */
	bool receiver;           /*!< True if the connection was initialized in listener mode */
} pqs_connection_state;

/*=============================================================================
                              Function Prototypes
=============================================================================*/

/*!
 * \brief Closes the network connection between hosts.
 *
 * \details
 * If the connection is active, this function optionally sends a disconnect notification.
 * In the case of a normal disconnect (no error), a simple disconnect packet is transmitted.
 * If an error has occurred, an error packet is encrypted and sent before closing the connection.
 *
 * \param cns A pointer to the connection state structure.
 * \param err The error code to be reported (if any).
 * \param notify Set to true to notify the remote host of the connection closure.
 */
PQS_EXPORT_API void pqs_connection_close(pqs_connection_state* cns, pqs_errors err, bool notify);

/*!
 * \brief Resets and disposes of the connection state.
 *
 * \details
 * This function disposes of the internal cipher states and clears the socket and sequence
 * information in the connection state structure.
 *
 * \param cns A pointer to the connection state structure to dispose.
 */
PQS_EXPORT_API void pqs_connection_state_dispose(pqs_connection_state* cns);

/*!
 * \brief Retrieves the description string for a given message enumeration.
 *
 * \param emsg The message enumeration value.
 * \return A pointer to the corresponding message string, or NULL if invalid.
 */
PQS_EXPORT_API const char* pqs_error_description(pqs_messages emsg);

/*!
 * \brief Converts an error code to its corresponding string description.
 *
 * \param error The error code.
 * \return A pointer to the error description string, or NULL if invalid.
 */
PQS_EXPORT_API const char* pqs_error_to_string(pqs_errors error);

/*!
 * \brief Generates a PQS key pair.
 *
 * \details
 * This function creates a new asymmetric signature key pair for the server. The expiration
 * time is set to the current UTC time plus the public key duration. The configuration string
 * and key identity are copied to the server key structure, and the generated verification key
 * is also copied to the client public key structure.
 *
 * \param pubkey A pointer to the client public key structure (output).
 * \param prikey A pointer to the server secret key structure (output).
 * \param keyid A pointer to a key identity string (input).
 */
PQS_EXPORT_API void pqs_generate_keypair(pqs_client_verification_key* pubkey, pqs_server_signature_key* prikey, const uint8_t keyid[PQS_KEYID_SIZE]);

/*!
 * \brief Logs an error message along with socket error details.
 *
 * \details
 * This function writes an error message based on the provided message enumeration and
 * appends additional error information from the socket exception if present.
 *
 * \param emsg The message enumeration indicating the error type.
 * \param err The socket exception value.
 * \param msg A constant string providing additional context (input).
 */
PQS_EXPORT_API void pqs_log_error(pqs_messages emsg, qsc_socket_exceptions err, const char* msg);

/*!
 * \brief Logs a message based on the provided message enumeration.
 *
 * \param emsg The message enumeration to be logged.
 */
PQS_EXPORT_API void pqs_log_message(pqs_messages emsg);

/*!
 * \brief Logs a message with an accompanying description.
 *
 * \param emsg The message enumeration.
 * \param msg A constant string containing additional information.
 */
PQS_EXPORT_API void pqs_log_write(pqs_messages emsg, const char* msg);

/*!
 * \brief Clears the state of a network packet.
 *
 * \details
 * Resets the packet flag, message length, and sequence number to default values.
 * If the packet contains a message payload, it is cleared.
 *
 * \param packet A pointer to the packet structure to clear.
 */
PQS_EXPORT_API void pqs_packet_clear(pqs_network_packet* packet);

/*!
 * \brief Decrypts an incoming packet's payload.
 *
 * \details
 * This function verifies the packet sequence number and timestamp before attempting
 * to decrypt the payload using the associated receive cipher state. The decrypted
 * message is copied to the output buffer.
 *
 * \param cns A pointer to the connection state structure.
 * \param message An output buffer for the decrypted message.
 * \param msglen A pointer to a size variable to receive the length of the decrypted message.
 * \param packetin A constant pointer to the input packet structure.
 * \return A pqs_errors value indicating the status of the decryption operation.
 */
PQS_EXPORT_API pqs_errors pqs_packet_decrypt(pqs_connection_state* cns, uint8_t* message, size_t* msglen, const pqs_network_packet* packetin);

/*!
 * \brief Encrypts a message and constructs an output packet.
 *
 * \details
 * This function increments the transmit sequence number, creates a packet header,
 * and sets the associated data for the transmit cipher state before encrypting the
 * provided message payload.
 *
 * \param cns A pointer to the connection state structure.
 * \param packetout A pointer to the output packet structure to be populated.
 * \param message A constant pointer to the input message to encrypt.
 * \param msglen The length in bytes of the input message.
 * \return A pqs_errors value indicating the status of the encryption operation.
 */
PQS_EXPORT_API pqs_errors pqs_packet_encrypt(pqs_connection_state* cns, pqs_network_packet* packetout, const uint8_t* message, size_t msglen);

/*!
 * \brief Populates a packet structure with an error message.
 *
 * \details
 * Sets the packet flag to indicate an error, assigns a predefined sequence number,
 * and writes the error code into the message payload.
 *
 * \param packet A pointer to the packet structure (output).
 * \param error The error code to embed in the packet.
 */
PQS_EXPORT_API void pqs_packet_error_message(pqs_network_packet* packet, pqs_errors error);

/*!
 * \brief Creates and populates a packet header.
 *
 * \details
 * This function sets the flag, sequence number, and message length in the packet header,
 * and assigns the current UTC time as the creation timestamp.
 *
 * \param packetout A pointer to the output packet structure.
 * \param flag The packet flag indicating the packet type.
 * \param sequence The packet sequence number.
 * \param msglen The length in bytes of the message payload.
 */
PQS_EXPORT_API void pqs_packet_header_create(pqs_network_packet* packetout, pqs_flags flag, uint64_t sequence, uint32_t msglen);

/*!
 * \brief Deserializes a byte array into a packet header.
 *
 * \param header A constant pointer to the byte array representing the packet header.
 * \param packet A pointer to the packet structure to populate.
 */
PQS_EXPORT_API void pqs_packet_header_deserialize(const uint8_t* header, pqs_network_packet* packet);

/*!
 * \brief Serializes a packet header into a byte array.
 *
 * \param packet A constant pointer to the packet structure to serialize.
 * \param header A pointer to the byte array that will receive the serialized header.
 */
PQS_EXPORT_API void pqs_packet_header_serialize(const pqs_network_packet* packet, uint8_t* header);

/*!
 * \brief Validates a packet header and its associated timestamp.
 *
 * \details
 * Checks that the packet's message length, sequence number, flag, and timestamp are as expected.
 * If the packet carries an error flag, the error code is extracted from the payload.
 *
 * \param cns A pointer to the connection state structure.
 * \param packetin A pointer to the input packet structure.
 * \param kexflag The expected key exchange stage flag.
 * \param pktflag The expected packet flag.
 * \param sequence The expected packet sequence number.
 * \param msglen The expected length of the message payload.
 * \return A pqs_errors value indicating the result of the validation.
 */
PQS_EXPORT_API pqs_errors pqs_header_validate(pqs_connection_state* cns, const pqs_network_packet* packetin, pqs_flags kexflag, pqs_flags pktflag, uint64_t sequence, uint32_t msglen);

/*!
 * \brief Sets the packet's UTC timestamp to the current time.
 *
 * \param packet A pointer to the network packet whose timestamp is to be set.
 */
PQS_EXPORT_API void pqs_packet_time_set(pqs_network_packet* packet);

/*!
 * \brief Validates the timestamp of a packet against the local UTC time.
 *
 * \details
 * Ensures that the packet's timestamp is within the acceptable time threshold
 * (PQS_PACKET_TIME_THRESHOLD) relative to the current UTC time.
 *
 * \param packet A constant pointer to the network packet.
 * \return True if the packet timestamp is valid; otherwise, false.
 */
PQS_EXPORT_API bool pqs_packet_time_validate(const pqs_network_packet* packet);

/*!
 * \brief Serializes a full packet (header and payload) into a byte stream.
 *
 * \param packet A constant pointer to the packet structure to serialize.
 * \param pstream A pointer to the output byte array.
 * \return The total number of bytes written to the byte stream.
 */
PQS_EXPORT_API size_t pqs_packet_to_stream(const pqs_network_packet* packet, uint8_t* pstream);

/*!
 * \brief Decodes an encoded public key string into a client verification key structure.
 *
 * \details
 * This function parses the encoded string (which includes header, configuration, key identity,
 * expiration timestamp, and base64-encoded verification key) and populates the client key structure.
 *
 * \param pubk A pointer to the output client verification key structure.
 * \param enck A constant encoded public key string.
 * \return True if decoding and parsing were successful; otherwise, false.
 */
PQS_EXPORT_API bool pqs_public_key_decode(pqs_client_verification_key* pubk, const char enck[PQS_PUBKEY_STRING_SIZE]);

/*!
 * \brief Encodes a client public key structure into a printable string.
 *
 * \details
 * The encoded string includes the header, version, configuration, key identity, expiration
 * timestamp, and a base64-encoded verification key, formatted with line breaks.
 *
 * \param enck A pointer to the output encoded public key string.
 * \param pubkey A constant pointer to the client verification key structure.
 */
PQS_EXPORT_API void pqs_public_key_encode(char enck[PQS_PUBKEY_STRING_SIZE], const pqs_client_verification_key* pubkey);

/*!
 * \brief Computes a hash of a public key structure.
 *
 * \details
 * Uses the SHA3/Keccak hash function to compute a 256-bit hash over the public key's configuration,
 * expiration, key identity, and verification key.
 *
 * \param hash An output array to receive the hash (must be at least PQS_HASH_SIZE bytes).
 * \param pubk A constant pointer to the client verification key structure.
 */
PQS_EXPORT_API void pqs_public_key_hash(uint8_t* hash, const pqs_client_verification_key* pubk);

/*!
 * \brief Deserializes an encoded secret signature key into a server signature key structure.
 *
 * \param kset A pointer to the output server signature key structure.
 * \param serk A constant array containing the encoded secret key.
 */
PQS_EXPORT_API void pqs_signature_key_deserialize(pqs_server_signature_key* kset, const uint8_t serk[PQS_SIGKEY_ENCODED_SIZE]);

/*!
 * \brief Serializes a server secret signature key structure into an encoded array.
 *
 * \param serk A pointer to the output encoded key array.
 * \param kset A constant pointer to the server signature key structure.
 */
PQS_EXPORT_API void pqs_signature_key_serialize(uint8_t serk[PQS_SIGKEY_ENCODED_SIZE], const pqs_server_signature_key* kset);

/*!
 * \brief Deserializes a byte stream into a network packet structure.
 *
 * \param pstream A constant pointer to the input byte stream.
 * \param packet A pointer to the packet structure to populate.
 */
PQS_EXPORT_API void pqs_stream_to_packet(const uint8_t* pstream, pqs_network_packet* packet);

#endif

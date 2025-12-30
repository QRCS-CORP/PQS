/* 2025-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef PQS_DOXYMAIN_H
#define PQS_DOXYMAIN_H

/**
 * \mainpage Post Quantum Shell (PQS) Project Documentation
 *
 * \section intro_sec Introduction
 *
 * The Post Quantum Shell (PQS) project implements a secure, post-quantum key exchange protocol based on a one-way trust model.
 * In this model, the client trusts the server, and a single shared secret is securely established between them. PQS is designed for efficiency,
 * using the Simplex exchange that is both fast and lightweight while providing 256-bit post-quantum security. This ensures robust protection
 * against future quantum-based threats.
 *
 * \section protocol_sec Protocol Description
 *
 * The PQS exchange is a one-way trust, client-to-server key-exchange model in which the client trusts the server, and a single shared secret is securely
 * shared between them. Designed for efficiency, the Simplex exchange is fast and lightweight, while providing 256-bit post-quantum security.
 * This protocol is versatile and can be used in a wide range of applications, such as:
 *
 * - Client registration on networks
 * - Secure cloud storage
 * - Hub-and-spoke model communications
 * - Commodity trading
 * - Electronic currency exchange
 *
 * Essentially, PQS is applicable to any scenario where an encrypted tunnel using strong, quantum-safe cryptography is required.
 *
 * The server in this model is implemented as a multi-threaded communications platform capable of generating a uniquely keyed encrypted tunnel
 * for each connected client. With a lightweight state footprint of less than 4 kilobytes per client, a single server instance can handle
 * potentially hundreds of thousands of simultaneous connections. The cipher encapsulation keys used during each key exchange are ephemeral
 * and unique, ensuring that every key exchange remains secure and independent of previous sessions.
 *
 * The server distributes a public signature verification key to its clients. This key is used to authenticate the server's public cipher
 * encapsulation key during the key exchange process. The public verification key can be securely distributed via various channels, such as during
 * a registration event, pre-embedded in client software, or through other secure methods.
 *
 * \section crypto_sec Cryptographic Primitives
 *
 * PQS relies on a suite of cryptographic primitives designed to be resilient against both classical and quantum-based attacks.
 * These primitives form the foundation for PQS's encryption, key exchange, and authentication processes.
 *
 * \subsection asym_sec Asymmetric Cryptographic Primitives
 *
 * PQS employs post-quantum secure asymmetric algorithms to ensure both the integrity and confidentiality of key exchanges,
 * as well as to enable robust digital signature functionality. The primary asymmetric primitives used include:
 *
 * - \b Kyber: An IND-CCA secure lattice-based key encapsulation mechanism that provides secure and efficient key exchange resistant
 *   to quantum attacks. Kyber is highly valued for its balance between computational speed and cryptographic strength.
 *
 * - \b McEliece: A code-based cryptosystem that leverages the difficulty of decoding general linear codes, offering strong security even
 *   against advanced quantum decryption techniques.
 *
 * - \b Dilithium: A lattice-based digital signature scheme based on MLWE and MSIS problems, providing fast signing and verification
 *   while maintaining robust security guarantees against quantum attacks.
 *
 * - \b Sphincs+: A stateless hash-based signature scheme that delivers long-term security without reliance on specific problem structures,
 *   ensuring resilience against future cryptographic advancements.
 *
 * \subsection sym_sec Symmetric Cryptographic Primitives
 *
 * PQS employs the Rijndael Cryptographic Stream (RCS) for symmetric encryption. RCS is an adaptation of the AES symmetric cipher,
 * modified to meet post-quantum security requirements. Key features of RCS include:
 *
 * - \b Wide-Block Cipher Design: Extends the original AES design by increasing the block size (from 128 to 256 bits) and the number of transformation
 *   rounds (from 14 to 21 for a 256-bit key, and 30 rounds for a 512-bit key), thereby enhancing resistance to differential and linear cryptanalysis.
 *
 * - \b Enhanced Key Schedule: Utilizes a strong key expansion function based on Keccak (cSHAKE) to generate keys that are resistant to algebraic,
 *   differential, and other forms of cryptanalysis.
 *
 * - \b Authenticated Encryption with Associated Data (AEAD): Integrates with KMAC (a Keccak-based Message Authentication Code) to provide both encryption
 *   and message authentication in a single operation, ensuring data integrity alongside confidentiality.
 *
 * RCS is optimized for high-performance environments and leverages AES-NI instructions present in modern CPUs.
 *
 * \subsection hash_sec Hash Functions and Key Derivation
 *
 * Hash functions and key derivation functions (KDFs) are critical in transforming raw cryptographic data into secure keys and hashes.
 * The primitives employed in PQS include:
 *
 * - \b SHA-3: Serves as the primary hash function for PQS, providing secure, collision-resistant hashing.
 *
 * - \b SHAKE: A Keccak-based extendable output function (XOF) used for deriving symmetric keys from shared secrets, ensuring each session key is
 *   uniquely generated and unpredictable.
 *
 * - \b KMAC: A SHA-3-based keyed hashing function that provides post-quantum resistant message authentication.
 *
 * \subsection library_dependencies Cryptographic Dependencies
 * QSTP uses the QSC cryptographic library: <a href="https://github.com/QRCS-CORP/QSC">The QSC Library</a>
 * 
 * QRCS-PL private License. See license file for details.
 * All rights reserved by QRCS Corporation, copyrighted and patents pending.
 * 
 * \author John G. Underhill
 * \date 2025-02-10
 */

#endif
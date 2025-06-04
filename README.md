# Post Quantum Shell (PQS) Project Documentation

The Post Quantum Shell Protocol

## Introduction

[![Build](https://github.com/QRCS-CORP/PQS/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/QRCS-CORP/PQS/actions/workflows/build.yml)
[![CodeQL](https://github.com/QRCS-CORP/PQS/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/QRCS-CORP/PQS/actions/workflows/codeql-analysis.yml)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20macOS%20|%20Windows-blue)](#)
[![docs](https://img.shields.io/badge/docs-online-brightgreen)](https://qrcs-corp.github.io/PQS/)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](https://github.com/QRCS-CORP/PQS/security/policy)  

The Post Quantum Shell (PQS) project implements a secure, post-quantum key exchange protocol based on a one-way trust model. In this model, the client trusts the server, and a single shared secret is securely established between them. PQS is designed for efficiency, using the Simplex exchange that is both fast and lightweight while providing 256-bit post-quantum security. This ensures robust protection against future quantum-based threats.

[PQS Help Documentation](https://qrcs-corp.github.io/PQS/)  
[PQS Protocol Specification](https://qrcs-corp.github.io/PQS/pdf/PQS_Specification.pdf)  
[PQS Summary Document](https://qrcs-corp.github.io/PQS/pdf/PQS_Summary.pdf)  


## Protocol Description

The PQS exchange is a one-way trust, client-to-server key-exchange model in which the client trusts the server, and a single shared secret is securely shared between them. Designed for efficiency, the key exchange is fast and lightweight, while providing 256-bit post-quantum security. This protocol is versatile and can be used in a wide range of applications, such as:

- Client registration on networks
- Secure cloud storage
- Hub-and-spoke model communications
- Commodity trading
- Electronic currency exchange

Essentially, PQS is applicable to any scenario where an encrypted tunnel using strong, quantum-safe cryptography is required.

The server in this model is implemented as a multi-threaded communications platform capable of generating a uniquely keyed encrypted tunnel for each connected client. With a lightweight state footprint of less than 4 kilobytes per client, a single server instance can handle potentially hundreds of thousands of simultaneous connections. The cipher encapsulation keys used during each key exchange are ephemeral and unique, ensuring that every key exchange remains secure and independent of previous sessions.

The server distributes a public signature verification key to its clients. This key is used to authenticate the server's public cipher encapsulation key during the key exchange process. The public verification key can be securely distributed via various channels, such as during a registration event, pre-embedded in client software, or through other secure methods.

## Cryptographic Primitives

PQS relies on a suite of cryptographic primitives designed to be resilient against both classical and quantum-based attacks. These primitives form the foundation for PQS's encryption, key exchange, and authentication processes.

### Asymmetric Cryptographic Primitives

PQS employs post-quantum secure asymmetric algorithms to ensure both the integrity and confidentiality of key exchanges, as well as to enable robust digital signature functionality. The primary asymmetric primitives used include:

- **Kyber:** An IND-CCA secure lattice-based key encapsulation mechanism that provides secure and efficient key exchange resistant to quantum attacks. Kyber is highly valued for its balance between computational speed and cryptographic strength. Kyber has been updated to the FIPS 203 standard.
- **McEliece:** A code-based cryptosystem that leverages the difficulty of decoding general linear codes, offering strong security even against advanced quantum decryption techniques.
- **Dilithium:** A lattice-based digital signature scheme based on MLWE and MSIS problems, providing fast signing and verification while maintaining robust security guarantees against quantum attacks. Dilithium has been updated to the FIPS 204 standard.
- **Sphincs+:** A stateless hash-based signature scheme that delivers long-term security without reliance on specific problem structures, ensuring resilience against future cryptographic advancements. SPHINCS+ has been updated to the FIPS 205 standard.

### Symmetric Cryptographic Primitives

PQS employs the Rijndael Cryptographic Stream (RCS) for symmetric encryption. RCS is an adaptation of the AES symmetric cipher, modified to meet post-quantum security requirements. Key features of RCS include:

- **Wide-Block Cipher Design:** Extends the original AES design by increasing the block size (from 128 to 256 bits) and the number of transformation rounds (from 14 to 21 for a 256-bit key, and 30 rounds for a 512-bit key), thereby enhancing resistance to differential and linear cryptanalysis.
- **Enhanced Key Schedule:** Utilizes a strong key expansion function based on Keccak (cSHAKE) to generate keys that are resistant to algebraic, differential, and other forms of cryptanalysis.
- **Authenticated Encryption with Associated Data (AEAD):** Integrates with KMAC (a Keccak-based Message Authentication Code) or QMAC (a post quantum strength GMAC with GF(2^256)) to provide both encryption and message authentication in a single operation, ensuring data integrity alongside confidentiality.

RCS is optimized for high-performance environments and leverages AES-NI instructions present in modern CPUs.

### Hash Functions and Key Derivation

Hash functions and key derivation functions (KDFs) are critical in transforming raw cryptographic data into secure keys and hashes. The primitives employed in PQS include:

- **SHA-3:** Serves as the primary hash function for PQS, providing secure, collision-resistant hashing.
- **SHAKE:** A Keccak-based extendable output function (XOF) used for deriving symmetric keys from shared secrets, ensuring each session key is uniquely generated and unpredictable.
- **KMAC:** A SHA-3-based keyed hashing function that provides post-quantum resistant message authentication.

### Cryptographic Dependencies

PQS uses the QSC cryptographic library. More details can be found on [The QSC Library](https://github.com/QRCS-CORP/QSC).

## Compilation

PQS uses the QSC cryptographic library. QSC is a standalone, portable, and MISRA-aligned cryptographic library written in C. It supports platform-optimized builds across **Windows**, **macOS**, and **Linux** via [CMake](https://cmake.org/), and includes support for modern hardware acceleration such as AES-NI, AVX2/AVX-512, and RDRAND.

### Prerequisites

- **CMake**: 3.15 or newer
- **Windows**: Visual Studio 2022 or newer
- **macOS**: Clang via Xcode or Homebrew
- **Ubuntu**: GCC or Clang  

### Building PQS library and the Client/Server projects

#### Windows (MSVC)

Use the Visual Studio solution to create the library and the Server and Client projects: PQS, Server, and Client.
Extract the files, and open the Server and Client projects. The PQS library has a default location in a folder parallel to the Server and Client project folders.  
The server and client projects additional files folder are set to: **$(SolutionDir)PQS** and **$(SolutionDir)..\QSC\QSC**, if this is not the location of the library files, change it by going to server/client project properties **Configuration Properties->C/C++->General->Additional Include Directories** and set the library files location.  
Ensure that the **[server/client]->References** property contains a reference to the PQS library, and that the PQS library contains a valid reference to the QSC library.  
QSC and PQS support every AVX instruction family (AVX/AVX2/AVX-512).  
Set the QSC and PQS libries and every server/client project to the same AVX family setting in **Configuration Properties->C/C++->All Options->Enable Enhanced Instruction Set**.  
Set both QSC and PQS to the same instruction set in Debug and Release Solution Configurations.  
Compile the QSC library (right-click and choose build), build the PQS library, then build the Server and Client projects.

#### MacOS / Ubuntu (Eclipse)

The QSC and the PQS library projects, along with the Server and Client projects have been tested using the Eclipse IDE on Ubuntu and MacOS.  
In the Eclipse folder there are subfolders for Ubuntu and MacOS that contain the **.project**, **.cproject**, and **.settings** Eclipse files.  Copy those files directly into the folders containing the code files; move the files in the **Eclipse\Ubuntu\project-name** or **Eclipse\MacOS\project-name** folder to the folder containing the project's header and implementation files for PQS and the Server and Client projects.  
Create a new project for QSC, select C/C++ project, and then **Create an empty project** with the same name as the folder with the files, 'QSC'. Repeat for each additional project.  
Eclipse should load the project with all of the settings into the project view window. The same proceedure is true for **MacOS and Ubuntu**, but some settings are different (GCC/Clang), so choose the project files that correspond to the operating system.  
The default projects use minimal flags, but are set to use AVX2, AES-NI, and RDRand by default.

Sample flag sets and their meanings:  
-**AVX Support**: -msse2 -mavx -maes -mpclmul -mrdrnd -mbmi2  
-**msse2**        # baseline for x86_64  
-**mavx**         # 256-bit FP/SIMD  
-**maes**         # AES-NI (128-bit AES rounds)  
-**mpclmul**      # PCLMUL (carry-less multiply)  
-**mrdrnd**       # RDRAND (hardware RNG)  
-**mbmi2**        # BMI2 (PEXT/PDEP, bit-manipulation)  

-**AVX2 Support**: -msse2 -mavx -mavx2 -mpclmul -maes -mrdrnd -mbmi2  
-**msse2**        # baseline for x86_64  
-**mavx**         # AVX baseline  
-**mavx2**        # 256-bit integer + FP SIMD  
-**mpclmul**      # PCLMUL (carry-less multiply for AES-GCM, GHASH, etc.)  
-**maes**         # AES-NI (128-bit AES rounds)  
-**mrdrnd**       # RDRAND (hardware RNG)  
-**mbmi2**        # BMI2 (PEXT/PDEP, bit-manipulation)  

-**AVX-512 Support**: -msse2 -mavx -mavx2 -mavx512f -mavx512bw -mvaes -mpclmul -mrdrnd -mbmi2 -maes  
-**msse2**        # baseline for x86_64  
-**mavx**         # AVX baseline  
-**mavx2**        # AVX2 baseline (implied by AVX-512 but explicit is safer)  
-**mavx512f**     # 512-bit Foundation instructions  
-**mavx512bw**    # 512-bit Byte/Word integer instructions  
-**mvaes**        # Vector-AES (VAES) in 512-bit registers  
-**mpclmul**      # PCLMUL (carry-less multiply for GF(2ⁿ))  
-**mrdrnd**       # RDRAND (hardware RNG)  
-**mbmi2**        # BMI2 (PEXT/PDEP, bit-manipulation)  
-**maes**         # AES-NI (128-bit AES rounds; optional if VAES covers your AES use)  


## License

ACQUISITION INQUIRIES:
QRCS is currently seeking a corporate acquirer for this technology.
Parties interested in exclusive licensing or acquisition should contact:
john.underhill@protonmail.com  

PATENT NOTICE:
One or more patent applications (provisional and/or non-provisional) covering aspects of this software have been filed with the United States Patent and 
Trademark Office (USPTO). Unauthorized use may result in patent infringement liability.  

QRCS-PL private License. See license file for details.  
Software is copyrighted and PQS is patent pending.
Written by John G. Underhill, under the QRCS-PL license, see the included license file for details. 
Not to be redistributed or used commercially without the author's expressed written permission. 
_All rights reserved by QRCS Corp. 2025._

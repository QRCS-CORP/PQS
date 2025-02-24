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

#ifndef PQS_CONNECTIONS_H
#define PQS_CONNECTIONS_H

#include "common.h"
#include "pqs.h"

/**
 * \file connections.h
 * \brief The server connection collection.
 *
 * \details
 * This header defines a collection of functions for managing the server connection states in the PQS
 * implementation. These functions are internal (non-exportable) and are used to maintain an array (or
 * collection) of connection state objects. The functions allow for initialization, addition, retrieval,
 * reset, and disposal of connection states, as well as performing a self-test of the collection functionality.
 *
 * The collection is implemented as a dynamically allocated array of connection state structures along with
 * a parallel array of booleans to indicate which entries are active.
 */

/**
 * \brief Check if a collection member is set to active.
 *
 * \details
 * This function checks if the connection state at the given index in the collection is marked as active.
 * If the index is within bounds, the function returns the boolean flag from the internal active array.
 * Otherwise, it returns false.
 *
 * \param index The socket index number within the collection.
 *
 * \return Returns true if the connection at the specified index is active; otherwise, false.
 */
bool pqs_connections_active(size_t index);

/**
 * \brief Add an item to the connection collection and set it to active.
 *
 * \details
 * This function adds a new connection state to the collection if the current number of entries
 * plus one does not exceed the maximum allowed. It reallocates the internal arrays as needed,
 * initializes the new connection state, sets its connection identifier (cid) to its index, and marks
 * it as active.
 *
 * \return Returns a pointer to the new connection state item or NULL if the maximum capacity is reached
 *         or a memory allocation failure occurs.
 */
pqs_connection_state* pqs_connections_add(void);

/**
 * \brief Get the number of available (inactive) connection states in the collection.
 *
 * \details
 * This function iterates through the connection collection and counts the number of entries that are
 * currently marked as inactive.
 *
 * \return Returns the number of available (inactive) connection states.
 */
size_t pqs_connections_available(void);

/**
 * \brief Get a connection state pointer from a given instance number.
 *
 * \details
 * The function searches through the connection collection for a connection state whose connection
 * identifier (cid) matches the provided instance number.
 *
 * \param instance The socket instance number.
 *
 * \return Returns the pointer to the connection state if found; otherwise, returns NULL.
 */
pqs_connection_state* pqs_connections_get(uint32_t instance);

/**
 * \brief Initialize the connection collection.
 *
 * \details
 * This function allocates and initializes the internal connection collection with the specified
 * number of connection states. A minimum of one connection state is created, and the maximum number
 * of connection states is set to the provided value. Each connection state is initialized by setting
 * its connection identifier (cid) to its index and marking it as inactive.
 *
 * \param count The number of initial connection states to allocate (minimum of one).
 * \param maximum The maximum number of connection states allowed (must be greater than or equal to count).
 */
void pqs_connections_initialize(size_t count, size_t maximum);

/**
 * \brief Erase (clear) all the connection collection members.
 *
 * \details
 * This function clears the memory for all connection state structures in the collection and resets
 * each active flag to false. It also resets the connection identifier (cid) of each state to its index.
 */
void pqs_connections_clear(void);

/**
 * \brief Dispose of the connection collection state.
 *
 * \details
 * This function frees all memory allocated for the connection state array and the corresponding active
 * flag array. It also resets the collection length and maximum capacity to zero.
 */
void pqs_connections_dispose(void);

/**
 * \brief Get a connection state pointer by its collection index.
 *
 * \details
 * This function returns a pointer to the connection state located at the specified index in the
 * internal connection collection, provided the index is within bounds.
 *
 * \param index The index number within the connection collection.
 *
 * \return Returns a pointer to the connection state at the given index, or NULL if the index is out of range.
 */
pqs_connection_state* pqs_connections_index(size_t index);

/**
 * \brief Check if the connection collection is full.
 *
 * \details
 * The function iterates through the active flags in the connection collection. If every entry is
 * marked as active, the collection is considered full.
 *
 * \return Returns true if all connection state entries are active; otherwise, false.
 */
bool pqs_connections_full(void);

/**
 * \brief Get the next available connection state.
 *
 * \details
 * This function searches for the first inactive connection state in the collection and marks it as active.
 * If the collection is already full, it attempts to add a new connection state (subject to the maximum capacity).
 *
 * \return Returns a pointer to the next available (or newly added) connection state, or NULL if none are available.
 */
pqs_connection_state* pqs_connections_next(void);

/**
 * \brief Reset a connection in the collection.
 *
 * \details
 * This function finds the connection state with the specified connection identifier (cid) and resets it.
 * The connection state is cleared, its connection identifier is reset to its index, and its active flag is set to false.
 *
 * \param instance The socket instance number (connection identifier) of the connection to reset.
 */
void pqs_connections_reset(uint32_t instance);

/**
 * \brief Get the total number of connection state items in the collection.
 *
 * \details
 * This function returns the current number of connection state items in the internal connection collection.
 *
 * \return Returns the total number of connection state items.
 */
size_t pqs_connections_size(void);

/**
 * \brief Run the self-test for the connection collection.
 *
 * \details
 * This function performs a series of tests on the connection collection to verify correct behavior:
 *
 * - Initializes the collection with one connection state and sets the maximum to 10.
 * - Adds nine additional connection states using pqs_connections_next(), resulting in a full collection.
 * - Checks that the number of available connections is zero and that the collection is full.
 * - Resets several connection states (instances 1, 3, 5, 7, and 9) to simulate connection closure.
 * - Verifies that the collection is no longer full.
 * - Reclaims five connection states by calling pqs_connections_next() and confirms that the collection is full again.
 * - Attempts to add an extra connection state beyond the maximum capacity.
 * - Verifies that the collection size remains at the maximum (10).
 * - Finally, clears and disposes of the collection.
 *
 * This self-test is intended for internal diagnostic purposes to ensure the integrity and proper operation
 * of the connection management functions.
 */
void pqs_connections_self_test(void);

#endif

#include "connections.h"
#include "../../QSC/QSC/common.h"
#include "../../QSC/QSC/memutils.h"

/**
 * \struct pqs_connection_set
 * \brief Internal structure to manage the collection of connection states.
 *
 * \details
 * This structure holds:
 * - an array of connection state structures (\c conset),
 * - an array of boolean flags (\c active) that indicate whether each corresponding connection
 *   state is active,
 * - the current number of connection states allocated (\c length),
 * - and the maximum allowed number of connection states (\c maximum).
 *
 * The structure is aligned for SIMD operations as required.
 */
typedef struct pqs_connection_set
{
    pqs_connection_state* conset;  /*!< Pointer to the array of connection state structures */
    bool* active;                  /*!< Pointer to the array of active flags for each connection */
    size_t maximum;                /*!< The maximum number of connection states allowed */
    size_t length;                 /*!< The current number of connection states in the collection */
} pqs_connection_set;

/** 
 * \brief Static internal variable holding the connection collection.
 *
 * \details
 * This variable is used internally to maintain the state of the server connection collection.
 * It is allocated and managed by the functions declared in this header.
 */
static pqs_connection_set m_connection_set;

bool pqs_connections_active(size_t index)
{
	bool res;

	res = false;

	if (index < m_connection_set.length)
	{
		res = m_connection_set.active[index];
	}

	return res;
}

pqs_connection_state* pqs_connections_add()
{
	pqs_connection_state* cns;

	cns = NULL;

	if ((m_connection_set.length + 1) <= m_connection_set.maximum)
	{
		m_connection_set.conset = qsc_memutils_realloc(m_connection_set.conset, (m_connection_set.length + 1) * sizeof(pqs_connection_state));
		m_connection_set.active = qsc_memutils_realloc(m_connection_set.active, (m_connection_set.length + 1) * sizeof(bool));

		if (m_connection_set.conset != NULL && m_connection_set.active != NULL)
		{
			qsc_memutils_clear(&m_connection_set.conset[m_connection_set.length], sizeof(pqs_connection_state));
			m_connection_set.conset[m_connection_set.length].cid = (uint32_t)m_connection_set.length;
			m_connection_set.active[m_connection_set.length] = true;
			cns = &m_connection_set.conset[m_connection_set.length];
			++m_connection_set.length;
		}
	}

	return cns;
}

size_t pqs_connections_available()
{
	size_t count;

	count = 0;

	for (size_t i = 0; i < m_connection_set.length; ++i)
	{
		if (m_connection_set.active[i] == false)
		{
			++count;
		}
	}
	
	return count;
}

void pqs_connections_clear()
{
	qsc_memutils_clear(m_connection_set.conset, sizeof(pqs_connection_state) * m_connection_set.length);

	for (size_t i = 0; i < m_connection_set.length; ++i)
	{
		m_connection_set.active[i] = false;
		m_connection_set.conset[i].cid = (uint32_t)i;
	}
}

void pqs_connections_dispose()
{
	if (m_connection_set.conset != NULL)
	{
		pqs_connections_clear();

		if (m_connection_set.conset != NULL)
		{
			qsc_memutils_alloc_free(m_connection_set.conset);
			m_connection_set.conset = NULL;
		}
	}

	if (m_connection_set.active != NULL)
	{
		qsc_memutils_alloc_free(m_connection_set.active);
		m_connection_set.active = NULL;
	}

	m_connection_set.length = 0;
	m_connection_set.maximum = 0;
}

pqs_connection_state* pqs_connections_index(size_t index)
{
	pqs_connection_state* res;

	res = NULL;

	if (index < m_connection_set.length)
	{
		res = &m_connection_set.conset[index];
	}

	return res;
}

bool pqs_connections_full()
{
	bool res;

	res = true;

	for (size_t i = 0; i < m_connection_set.length; ++i)
	{
		if (m_connection_set.active[i] == false)
		{
			res = false;
			break;
		}
	}

	return res;
}

pqs_connection_state* pqs_connections_get(uint32_t instance)
{
	pqs_connection_state* res;

	res = NULL;

	for (size_t i = 0; i < m_connection_set.length; ++i)
	{
		if (m_connection_set.conset[i].cid == instance)
		{
			res = &m_connection_set.conset[i];
		}
	}

	return res;
}

void pqs_connections_initialize(size_t count, size_t maximum)
{
	assert(count != 0);
	assert(maximum != 0);
	assert(count <= maximum);
	
	if (count != 0 && maximum != 0 && count <= maximum)
	{
		m_connection_set.length = count;
		m_connection_set.maximum = maximum;
		m_connection_set.conset = (pqs_connection_state*)qsc_memutils_malloc(sizeof(pqs_connection_state) * m_connection_set.length);
		m_connection_set.active = (bool*)qsc_memutils_malloc(sizeof(bool) * m_connection_set.length);

		if (m_connection_set.conset != NULL && m_connection_set.active != NULL)
		{
			qsc_memutils_clear(m_connection_set.conset, sizeof(pqs_connection_state) * m_connection_set.length);

			for (size_t i = 0; i < count; ++i)
			{
				m_connection_set.conset[i].cid = (uint32_t)i;
				m_connection_set.active[i] = false;
			}
		}
	}
}

pqs_connection_state* pqs_connections_next()
{
	pqs_connection_state* res;

	res = NULL;

	if (pqs_connections_full() == false)
	{
		for (size_t i = 0; i < m_connection_set.length; ++i)
		{
			if (m_connection_set.active[i] == false)
			{
				res = &m_connection_set.conset[i];
				m_connection_set.active[i] = true;
				break;
			}
		}
	}
	else
	{
		res = pqs_connections_add();
	}

	return res;
}

void pqs_connections_reset(uint32_t instance)
{
	for (size_t i = 0; i < m_connection_set.length; ++i)
	{
		if (m_connection_set.conset[i].cid == instance)
		{
			qsc_memutils_clear(&m_connection_set.conset[i], sizeof(pqs_connection_state));
			m_connection_set.conset[i].cid = (uint32_t)i;
			m_connection_set.active[i] = false;
			break;
		}
	}
}

size_t pqs_connections_size()
{
	return m_connection_set.length;
}

void pqs_connections_self_test()
{
	pqs_connection_state* xn[20] = { 0 };
	size_t cnt;
	bool full;

	pqs_connections_initialize(1, 10); /* init with 1 */

	for (size_t i = 1; i < 10; ++i)
	{
		xn[i] = pqs_connections_next(); /* init next 9 */
	}

	cnt = pqs_connections_available(); /* expected 0 */
	full = pqs_connections_full(); /* expected true */

	pqs_connections_reset(1); /* release 5 */
	pqs_connections_reset(3);
	pqs_connections_reset(5);
	pqs_connections_reset(7);
	pqs_connections_reset(9);

	full = pqs_connections_full(); /* expected false */

	xn[11] = pqs_connections_next(); /* reclaim 5 */
	xn[12] = pqs_connections_next();
	xn[13] = pqs_connections_next();
	xn[14] = pqs_connections_next();
	xn[15] = pqs_connections_next();

	full = pqs_connections_full(); /* expected true */

	xn[16] = pqs_connections_next(); /* should exceed max */

	cnt = pqs_connections_size(); /* expected 10 */

	pqs_connections_clear();
	pqs_connections_dispose();
}

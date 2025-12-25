/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 *
 *
 * Author: Miralem Mehic <miralem.mehic@etf.unsa.ba>
 */

#ifndef QKD_TOTAL_GRAPH_H
#define QKD_TOTAL_GRAPH_H

#include <fstream>
#include "ns3/object.h"
#include "ns3/gnuplot.h"
#include "ns3/core-module.h"
#include "ns3/node-list.h"
#include <sstream>

namespace ns3 {

/**
 * @ingroup qkd
 * @class QKDTotalGraph
 * @brief QKDTotalGraph is implemented to allow easier access to the state of
 *  ALL QBuffers and easier monitoring of the overall key material consumption.
 *
 * @note QKDTotalGraph is used to show the overall consumption of key material in QKD Network.
 *	QKD Total Graph is updated each time when key material is generated or consumed on a
 *	network link. Only one QKDTotalGraph in the whole simulation is allowed!
 */
class QKDTotalGraph : public Object
{
public:

    /**
    * @brief Get the type ID.
    * @return the object TypeId
    */
    static TypeId GetTypeId();

    /**
    * 	@brief Constructor
    */
	QKDTotalGraph();

    /**
    * 	@brief Constructor
    *	@param std::string graphTitle
    *	@param std::string graphType
    */
	QKDTotalGraph(
		std::string graphName,
		std::string graphType
	);

    /**
    * @brief Initialized function used in constructor
    */
	void Init(
		std::string graphName,
		std::string graphType
	);

    /**
    * @brief Destructor
    */
	~QKDTotalGraph() override;

    /**
    * @brief Print the graph
    */
	void PrintGraph();
 
    /**
    * @brief MCurrent value of the QBuffer changed, so plot it on the graph
    *	@param uint32_t value
    *	@param char signToBePloted
    */
	void ProcessMCurrent(uint32_t value, char sign);

private:

	uint32_t     		m_keymCurrent; //!< get some boundaries for the graph
	uint32_t     		m_keymThreshold;  //!< get some boundaries for the graph
    uint32_t            m_keymMax; //!< get some boundaries for the graph

	std::string			m_plotFileName; //!< output filename
	std::string			m_plotFileType; //png or svg
	double				m_simulationTime; //!< time value, x-axis

	Gnuplot				m_gnuplot;
    Gnuplot2dDataset 	m_dataset; 
};
}

#endif /* QKDTotalGraph */

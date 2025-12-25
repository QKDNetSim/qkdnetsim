/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 *
 *
 * Author: Miralem Mehic <miralem.mehic@etf.unsa.ba>
 */

#ifndef QKD_GRAPH_MANAGER_H
#define QKD_GRAPH_MANAGER_H

#include <fstream>
#include <sstream>
#include <vector>
#include "ns3/object.h"
#include "ns3/gnuplot.h"
#include "ns3/core-module.h"
#include "ns3/node-list.h"
#include "qkd-graph.h"
#include "qkd-control.h"
#include "qkd-total-graph.h"

namespace ns3 {

/**
 * @ingroup qkd
 * @class QKDGraphManager
 * @brief QKDGraphManager.
 *
 *  @brief QKDGraphManager is a signleton class used to connect QKDGraphs and
 *  QKDTotalGraph. It uses TraceSources to make connection and make printing
 *  of graphs easier, all graphs are printed using a single function "PrintGraphs".
 */

class QKDGraph;

class QKDGraphManager : public Object
{
public:

    /**
    * @brief Get the type ID.
    * @return the object TypeId
    */
    static TypeId GetTypeId();

    /**
    * 	@brief Destructor
    */
	~QKDGraphManager() override;

    /**
    * 	@brief Signelton getInstance function
    */
	static QKDGraphManager* getInstance();

    /**
    * 	@brief Print graphs
    */
	void 	PrintGraphs();

    /**
    *   @brief Connect new QBuffer/Sbuffer to QKDTotalGraph
    *   @param Ptr<Node>    src
    *   @param Ptr<Node>    dst
    *   @param uint32_t     bufferID
    *   @param uint32_t     srcKMSApplicationIndex
    *   @param std::string  graphTitle
    *   @param std::string  graphType
    */
    void CreateGraphForBuffer(
        Ptr<Node> srcKMSNode,
        Ptr<Node> dstKMSNode,
        uint32_t bufferID,
        uint32_t srcKMSApplicationIndex,
        std::string graphName,
        std::string graphType,
        Ptr<QBuffer> buff
    );

    /**
    * @brief Mcur value changed, so plot it on the graph
    *	@param std::string context
    *	@param uint32_t value
    */
	static void ProcessCurrentChange(std::string context, uint32_t value);

    /**
    * @brief Status changed, so plot it on the graph
    *	@param std::string context
    *	@param uint32_t value
    */
	static void ProcessStatusChange(std::string context, uint32_t value);

    /**
    * @brief Mthr value changed, so plot it on the graph
    *	@param std::string context
    *	@param uint32_t value
    */
	static void ProcessThresholdChange(std::string context, uint32_t value);

	// FOR QKD TOTAL GRAPH

    /**
    * @brief Mcur value increase, so plot it on the graph
    *	@param std::string context
    *	@param uint32_t value
    */
	static void ProcessCurrentIncrease(std::string context, uint32_t value);

    /**
    * @brief Mcur value decreased, so plot it on the graph
    *	@param std::string context
    *	@param uint32_t value
    */
	static void ProcessCurrentDecrease(std::string context, uint32_t value);

    /**
    * @brief Mthr value increased, so plot it on the graph
    *	@param std::string context
    *	@param uint32_t value
    */
	static void ProcessThresholdIncrease(std::string context, uint32_t value);

    /**
    * @brief Mthr value decreased, so plot it on the graph
    *	@param std::string context
    *	@param uint32_t value
    */
	static void ProcessThresholdDecrease(std::string context, uint32_t value);

    /**
    * @brief Temp function, forward value form trace source to the graph in the list
    *	@param uint32_t& nodeID
    *	@param uint32_t& bufferID
    *	@param uint32_t& value
    */
	void SendStatusValueToGraph(const uint32_t& nodeID, const uint32_t& bufferID, const uint32_t& value);

    /**
    * @brief Temp function, forward value form trace source to the graph in the list
    *	@param uint32_t& nodeID
    *	@param uint32_t& bufferID
    *	@param uint32_t& value
    */
	void SendCurrentChangeValueToGraph(const uint32_t& nodeID, const uint32_t& bufferID, const uint32_t& value);

    /**
    * @brief Temp function, forward value form trace source to the graph in the list
    *	@param uint32_t& nodeID
    *	@param uint32_t& bufferID
    *	@param uint32_t& value
    */
	void SendThresholdValueToGraph(const uint32_t& nodeID, const uint32_t& bufferID, const uint32_t& value);

    /**
    * 	@brief Return Ptr to QKDTotalGraph
    *	@return Ptr<QKDTotalGraph>
    */
	Ptr<QKDTotalGraph> GetTotalGraph();

private:

	QKDGraphManager(){};

	static bool instanceFlag; //!< check whether object exists

	static QKDGraphManager *single;

	static Ptr<QKDTotalGraph> m_totalGraph; //!< Ptr to QKDTotalGraph

	std::vector<std::vector<Ptr<QKDGraph > > > m_graphs; //vector of nodes-device-channels
};
}
#endif /* QKD_GRAPH_MANAGER */

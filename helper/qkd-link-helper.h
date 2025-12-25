/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 *
 *
 * Author: Miralem Mehic <miralem.mehic@etf.unsa.ba>
 */

#ifndef QKD_HELPER_H
#define QKD_HELPER_H

#include <string>
#include <queue>

#include "ns3/object-factory.h"
#include "ns3/net-device-container.h"
#include "ns3/node-container.h"
#include "ns3/trace-helper.h"
#include "ns3/ipv4-interface-address.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"

//#include "ns3/qkd-control.h"
#include "ns3/qcen-control.h" 
#include "ns3/qkd-graph-manager.h"

namespace ns3 {

class NetDevice;
class Node;

/**
 * @ingroup qkd
 * @class QKDLinkHelper
 * @brief Build a set of QKDNetDevice objects such as QKD buffers
 * QKD encryptors and QKD graphs.
 *
 */
class QKDLinkHelper
{
public:

    /**
    * Create a QKDLinkHelper to make life easier when creating point to
    * point networks.
    */
    QKDLinkHelper();
    virtual ~QKDLinkHelper() {}

    void AddGraphs();

	void AddGraph(Ptr<Node> src, Ptr<Node> dst);

	void AddGraph(Ptr<Node> src, Ptr<Node> dst, std::string graphName);

    void AddGraph(Ptr<Node> src, Ptr<Node> dst, std::string graphName, std::string graphType);

    void PrintGraphs();

    /**
     * @brief Install QKDN controller on node
     * @param node smart pointer on node
     * @return Ptr<QKDControl> smart pointer on QKDN controller
     */
    Ptr<QKDControl> InstallQKDNController(Ptr<Node> node);
    //QKDControlContainer InstallQKDNController(NodeContainer& n);

    Ptr<QCenController> InstallQCenController(Ptr<Node> node);

    void CreateTopologyGraph(std::vector<Ptr<QKDControl> > controllers, uint32_t reroute = 0);

    void PopulateRoutingTables();

    /**
     * @brief Configure all Q buffers(default conf). Mandatory function!
     * @param controllers vector of all QKDN controllers
     * @param Mmin minimum amount(bits) of key material QKD buffer should maintain
     * @param Mmax maximum amount(bits) of key material QKD buffer can store
     * @param Mthr thresold amount(bits) of key material
     * @param Mcurr current amount(bits) of key material QKD buffer maintain
     * @param defaultKeysize default size of stored keys
     */
    void ConfigureQBuffers(
        std::vector<Ptr<QKDControl> > controllers,
        uint32_t Mmin,
        uint32_t Mthr,
        uint32_t Mmax,
        uint32_t Mcurr,
        uint32_t defaultKeySize
    );

    /**
     * @brief Configure all Q buffers(default conf). Mandatory function!
     * @param controllers vector of all QKDN controllers
     * @param Mmin minimum amount(bits) of key material QKD buffer should maintain
     * @param Mthr thresold amount(bits) of key material
     * @param Mmax maximum amount(bits) of key material QKD buffer can store
     */
    void ConfigureQBuffers(
        std::vector<Ptr<QKDControl> > controllers,
        uint32_t Mmin,
        uint32_t Mthr,
        uint32_t Mmax,
        uint32_t defaultKeySize
    );

    void ConfigureRSBuffers(
        std::vector<Ptr<QKDControl> > controllers,
        uint32_t Mmin,
        uint32_t Mthr,
        uint32_t Mmax,
        uint32_t Mcurr,
        uint32_t defaultKeySize
    );

    void ConfigureRSBuffers(
        std::vector<Ptr<QKDControl> > controllers,
        uint32_t Mmin,
        uint32_t Mthr,
        uint32_t Mmax,
        uint32_t defaultKeySize
    );

    bool     m_useRealStorages;

    /**
    * @brief create an object from its TypeId and aggregates it to the node
    * @param node the node
    * @param typeId the object TypeId
    */
    static void CreateAndAggregateObjectFromTypeId(Ptr<Node> node, const std::string typeId);

private:

    // map KMNodeId -> internal index (0..N-1)
    std::unordered_map<uint32_t, uint32_t> m_kmNodeIdToIndex;
    // vector index -> KMNodeId (reverse mapping)
    std::vector<uint32_t> m_indexToKmNodeId;
    
    uint32_t GetColumn(uint32_t nodeId);

    uint32_t ReverseColumn(uint32_t position);

    std::vector< std::pair<uint32_t, uint32_t> > DijkstraSP(
        std::vector< std::vector<std::pair<uint32_t, uint32_t> > > adjList,
        uint32_t start
    );

    Ptr<QCenController> m_cen_controller; //!< Centralized control for rerouting.

    std::map<uint32_t, Ptr<QKDControl> > m_controllers; //<! a pair of KMNodeId and respective QKDControl

    std::vector< std::vector<std::pair<uint32_t, uint32_t> > > m_adjList; //<! adjecent List, used for dijkstraSP!

    ObjectFactory m_qkdbufferFactory;        //!< Device Factory

};
} // namespace ns3

#endif /* QKD_HELPER_H */

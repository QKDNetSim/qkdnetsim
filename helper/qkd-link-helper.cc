/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 * Author: Miralem Mehic <miralem.mehic@etf.unsa.ba>
 */

#include "ns3/abort.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/queue.h"
#include "ns3/config.h"
#include "ns3/packet.h"
#include "ns3/object.h"
#include "ns3/names.h"
#include "ns3/internet-module.h"
#include "ns3/random-variable-stream.h"
#include "ns3/trace-helper.h"
#include "ns3/traffic-control-module.h"

#include "qkd-link-helper.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("QKDLinkHelper");
const uint32_t INF = 1000000007u;

QKDLinkHelper::QKDLinkHelper()
{
    m_useRealStorages = false;
    m_controllers.clear();
    m_adjList.clear();
}

/**
*   @brief ADD QKDGraph
*   @param  Ptr<Node>       src
*   @param  Ptr<Node>       dst
*/
void
QKDLinkHelper::AddGraphs()
{
    std::cout << "ADD GRAPHS! " << std::endl;
    int32_t nNodes = NodeList::GetNNodes();
    for(int32_t i = 0; i < nNodes; ++i)
    {
        Ptr<Node> node = NodeList::GetNode(i);
        Ptr<QKDKeyManagerSystemApplication> kms;
        uint32_t applicationIndex = 0;
        for(uint32_t i = 0; i < node->GetNApplications(); ++i)
        {
            kms = node->GetApplication(i)->GetObject <QKDKeyManagerSystemApplication>();
            applicationIndex = i;
            if(kms) break;
        }

        if(kms)
        {
            QKDGraphManager *QKDGraphManager = QKDGraphManager::getInstance();

            std::vector<Ptr<QBuffer> > Qbuffers = kms->GetQBuffersVector();
            for(const auto& buffer : Qbuffers)
            {
                buffer->SetSrcKMSApplicationIndex(applicationIndex);
                NS_LOG_FUNCTION(this << buffer << buffer->GetState() << buffer->GetIndex() );
 
                uint32_t dstNodeId = buffer->GetRemoteNodeId();
                Ptr<Node> dstKmsNode = NodeList::GetNode(dstNodeId);

                std::string graphTitle = "";
                if(
                    buffer->GetInstanceTypeId().GetName() == "ns3::SBuffer"
                ){ 

                    Ptr<SBuffer> sbuffer = DynamicCast<SBuffer>(buffer);
                    std::string bufferDescription = sbuffer->GetDescription();
                    if(sbuffer->GetType() == SBuffer::LOCAL_SBUFFER)
                    {
                        std::ostringstream temp1;
                        temp1 << "SBUFFER (LOCAL) between " << node->GetId() << " and " << dstKmsNode->GetId();
                        graphTitle = temp1.str();

                    }else if(sbuffer->GetType() == SBuffer::RELAY_SBUFFER)
                    {
                        std::ostringstream temp1;
                        temp1 << "SBUFFER (RELAY) between " << node->GetId() << " and " << dstKmsNode->GetId();
                        graphTitle = temp1.str();
                    }else if(sbuffer->GetType() == SBuffer::STREAM_SBUFFER)
                    {
                        std::ostringstream temp1;
                        temp1 << "SBUFFER (STREAM) between " << node->GetId() << " and " << dstKmsNode->GetId();
                        graphTitle = temp1.str();
                    }

                    if(!bufferDescription.empty())
                        graphTitle = graphTitle + "_" + bufferDescription;
                }

                NS_LOG_FUNCTION(this << "BufferTitle: " << graphTitle);

                QKDGraphManager->CreateGraphForBuffer(
                    node, 
                    dstKmsNode,
                    buffer->GetIndex(), 
                    buffer->GetSrcKMSApplicationIndex(), 
                    graphTitle, 
                    "png",
                    buffer
                ); 
            }
        }
    }
}

/**
*   @brief ADD QKDGraph
*   @param  Ptr<Node>       src
*   @param  Ptr<Node>       dst
*/
void
QKDLinkHelper::AddGraph(
    Ptr<Node> src,
    Ptr<Node> dst
) {
    AddGraph(src, dst, "", "png");
}

/**
*   @brief ADD QKDGraph
*   @param  Ptr<Node>       src
*   @param  Ptr<Node>       dst
*   @param  std::string     graphName
*/
void
QKDLinkHelper::AddGraph(
    Ptr<Node> src,
    Ptr<Node> dst,
    std::string graphName
){
    AddGraph(src, dst, graphName, "png");
}

/**
*   @brief ADD QKDGraph
*   @param  Ptr<QKDControl> QKDControl
*   @param  Ptr<Node>       src
*   @param  Ptr<Node>       dst
*   @param  std::string     graphName
*   @param  std::string     graphType
*/
void
QKDLinkHelper::AddGraph(
    Ptr<Node> srcKMSNode,
    Ptr<Node> dstKmsNode,
    std::string graphName,
    std::string graphType
) {

    NS_LOG_FUNCTION(this);

    Ptr<QKDKeyManagerSystemApplication> kms;
    uint32_t applicationIndex = 0;
    for(uint32_t i = 0; i < srcKMSNode->GetNApplications(); ++i){
        kms = srcKMSNode->GetApplication(i)->GetObject <QKDKeyManagerSystemApplication>();
        applicationIndex = i;
        if(kms) break;
    }
    NS_ASSERT(kms);

    Ptr<QBuffer> buffer = kms->GetQBuffer( dstKmsNode->GetId(), "ns3::QBuffer" );
    NS_ASSERT(buffer);

    buffer->SetSrcKMSApplicationIndex(applicationIndex);
    NS_LOG_FUNCTION(this << buffer << buffer->GetState() << buffer->GetIndex() );

    QKDGraphManager *QKDGraphManager = QKDGraphManager::getInstance();
    QKDGraphManager->CreateGraphForBuffer(srcKMSNode, dstKmsNode, buffer->GetIndex(), buffer->GetSrcKMSApplicationIndex(), graphName, graphType, buffer);
}

/**
*   @brief Print QKDGraphs
*/
void
QKDLinkHelper::PrintGraphs()
{
    NS_LOG_FUNCTION(this);

    QKDGraphManager *QKDGraphManager = QKDGraphManager::getInstance();
    QKDGraphManager->PrintGraphs();
}

Ptr<QKDControl>
QKDLinkHelper::InstallQKDNController(Ptr<Node> n)
{
    NS_LOG_FUNCTION(this);

    Ptr<QKDControl> controller = n->GetObject<QKDControl>();
    if(!controller){
        ObjectFactory factory;
        factory.SetTypeId("ns3::QKDControl");
        controller = factory.Create <QKDControl>();
        controller->SetNode(n);
        n->AggregateObject(controller);
    }
    return controller;
}

Ptr<QCenController>
QKDLinkHelper::InstallQCenController(Ptr<Node> node)
{
    NS_LOG_FUNCTION(this);

    Ptr<QCenController> controller = node->GetObject<QCenController>();
    if(!controller){
        ObjectFactory factory;
        factory.SetTypeId("ns3::QCenController");
        controller = factory.Create <QCenController>();
        controller->SetNode(node);
        node->AggregateObject(controller);
    }

    m_cen_controller = controller;
    return controller;
}

void
QKDLinkHelper::ConfigureQBuffers(
    std::vector<Ptr<QKDControl> > controllers,
    uint32_t Mmin,
    uint32_t Mthr,
    uint32_t Mmax,
    uint32_t defaultKeySize
)
{
    NS_LOG_FUNCTION(this);
    return ConfigureQBuffers(controllers, Mmin, Mthr, Mmax, 0, defaultKeySize);
}

void
QKDLinkHelper::ConfigureQBuffers(
    std::vector<Ptr<QKDControl> > controllers,
    uint32_t Mmin,
    uint32_t Mthr,
    uint32_t Mmax,
    uint32_t Mcurr,
    uint32_t defaultKeySize
)
{
    NS_LOG_FUNCTION(this);

    for(auto controller : controllers)
        controller->ConfigureQBuffers(Mmin, Mthr, Mmax, Mcurr, defaultKeySize);
}

void
QKDLinkHelper::ConfigureRSBuffers(
    std::vector<Ptr<QKDControl> > controllers,
    uint32_t Mmin,
    uint32_t Mthr,
    uint32_t Mmax,
    uint32_t Mcurr,
    uint32_t defaultKeySize
)
{
    for(auto controller : controllers)
        controller->ConfigureRSBuffers(Mmin, Mthr, Mmax, Mcurr, defaultKeySize);
}

void
QKDLinkHelper::ConfigureRSBuffers(
    std::vector<Ptr<QKDControl> > controllers,
    uint32_t Mmin,
    uint32_t Mthr,
    uint32_t Mmax,
    uint32_t defaultKeySize
)
{
    return ConfigureRSBuffers(controllers, Mmin, Mthr, Mmax, 0, defaultKeySize);
}

void
QKDLinkHelper::CreateAndAggregateObjectFromTypeId(Ptr<Node> node, const std::string typeId)
{
    ObjectFactory factory;
    factory.SetTypeId(typeId);
    Ptr<Object> protocol = factory.Create <Object>();
    node->AggregateObject(protocol);
}

uint32_t
QKDLinkHelper::GetColumn(uint32_t nodeId)
{
    auto it = m_kmNodeIdToIndex.find(nodeId);
    if (it == m_kmNodeIdToIndex.end())
    {
        NS_LOG_ERROR("GetColumn: unknown KMNodeId " << nodeId);
        return uint32_t(-1); // caller should avoid using this
    }
    return it->second;
}

uint32_t
QKDLinkHelper::ReverseColumn(uint32_t position)
{
    if (position >= m_indexToKmNodeId.size())
    {
        NS_LOG_ERROR("ReverseColumn: invalid position " << position);
        return uint32_t(-1);
    }
    return m_indexToKmNodeId[position];
}

void
QKDLinkHelper::CreateTopologyGraph(std::vector<Ptr<QKDControl>> controllers,
                                   uint32_t reroute)
{
    NS_LOG_FUNCTION(this);

    // -------- Centralized controller --------
    if (reroute != 0)
    {
        m_cen_controller->RegisterDControllers(controllers);
        return;
    }

    // -------- Reset previous state --------
    m_adjList.clear();
    m_controllers.clear();
    m_kmNodeIdToIndex.clear();
    m_indexToKmNodeId.clear();

    // -------- Insert controllers sorted by KMNodeId --------
    for (auto const& c : controllers)
    {
        m_controllers.emplace(c->GetLocalKMNodeId(), c);
    }

    uint32_t count = m_controllers.size();
    NS_ASSERT(count > 0);

    m_adjList.resize(count);

    // -------- Authoritative KMNodeId <-> index mapping --------
    uint32_t idx = 0;
    for (auto const& entry : m_controllers)
    {
        uint32_t kmId = entry.first;

        m_kmNodeIdToIndex[kmId] = idx;
        m_indexToKmNodeId.push_back(kmId);

        NS_LOG_INFO("Mapping KMNodeId " << kmId << " -> index " << idx);
        ++idx;
    }

    // -------- Build adjacency list (UNDIRECTED GRAPH) --------
    idx = 0;
    for (auto const& entry : m_controllers)
    {
        uint32_t srcKmId   = entry.first;
        auto     srcCtrl   = entry.second;

        NS_LOG_INFO("Building adjacency for KMNodeId " << srcKmId
                     << " (index " << idx << ")");

        std::vector<uint32_t> neighbors = srcCtrl->GetRemoteKmNodeIds();

        for (uint32_t remoteKmId : neighbors)
        {
            auto it = m_kmNodeIdToIndex.find(remoteKmId);

            if (it == m_kmNodeIdToIndex.end())
            {
                NS_LOG_WARN("KMNodeId " << srcKmId << " references remote "
                             << remoteKmId << " which is not in controller list. Skipping.");
                continue;
            }

            uint32_t dstIdx = it->second;

            // Skip accidental self-loop
            if (dstIdx == idx)
            {
                NS_LOG_WARN("Self-link detected at KMNodeId "
                             << srcKmId << "; ignoring.");
                continue;
            }

            // Prevent duplicate edges
            auto& row = m_adjList[idx];
            bool exists = false;
            for (auto& e : row)
                if (e.first == dstIdx) exists = true;

            if (!exists)
            {
                NS_LOG_INFO("  + Edge: " << idx << " <-> " << dstIdx
                             << " (KM " << srcKmId << " <-> " << remoteKmId << ")");

                // ADD UNDIRECTED EDGES
                row.emplace_back(dstIdx, 1);
                m_adjList[dstIdx].emplace_back(idx, 1);
            }
        }

        ++idx;
    }

    NS_LOG_INFO("Topology graph complete. Nodes: " << m_adjList.size());
}




// Given an Adjacency List, find all shortest paths from "start" to all other vertices. 
std::vector< std::pair<uint32_t, uint32_t> >
QKDLinkHelper::DijkstraSP(
    std::vector< std::vector<std::pair<uint32_t, uint32_t> > > adjList,
    uint32_t start)
{
    std::vector<std::pair<uint32_t, uint32_t> > dist; // First = dist, Second = previous node.

    // Initialize all source->vertex as "infinite".
    const uint32_t INF = 1000000007u;
    int n = adjList.size();
    dist.reserve(n);
    for(int i = 0; i < n; i++)
    {
        dist.push_back(std::make_pair(INF, uint32_t(i))); // previous defaults to itself
    }

    // Priority queue of (distance, vertex) so it orders by distance.
    std::priority_queue<
        std::pair<int, int>,
        std::vector<std::pair<int, int> >,
        std::greater<std::pair<int, int> >
    > pq;

    // Add source to pq with distance 0.
    if (start >= uint32_t(n)) {
        // invalid start; return dist (all INF)
        return dist;
    }
    dist[start] = std::make_pair(uint32_t(0), start);
    pq.push(std::make_pair(0, int(start)));

    while (!pq.empty())
    {
        // pq.top() is (distance, vertex)
        auto top = pq.top();
        pq.pop();
        int currDist = top.first;
        int u = top.second;

        // Skip stale entries: we only process when distances match
        if (uint32_t(currDist) != dist[u].first) continue;

        // Visit all neighbors of u.
        int listSize = adjList[u].size();
        for(int i = 0; i < listSize; i++)
        {
            uint32_t v = adjList[u][i].first;
            uint32_t weight = adjList[u][i].second;

            // If the distance to v is shorter by going through u...
            if (dist[v].first > dist[u].first + weight)
            {
                // Update distance and previous.
                dist[v].first = dist[u].first + weight;
                dist[v].second = uint32_t(u);
                // Insert v into the pq with the new distance.
                pq.push(std::make_pair(int(dist[v].first), int(v)));
            }
        }
    }

    return dist;
}



void
QKDLinkHelper::PopulateRoutingTables()
{
    NS_LOG_FUNCTION(this << m_controllers.size());

    if (m_controllers.empty())
        return;


    for (auto const& srcEntry : m_controllers)
    {
        uint32_t srcKmId = srcEntry.first;
        Ptr<QKDControl> srcCtrl = srcEntry.second;

        uint32_t srcIdx = GetColumn(srcKmId);

        NS_LOG_INFO("=== ROUTING FOR SRC KM " << srcKmId
                     << " (index " << srcIdx << ") ===");

        // Run Dijkstra from this source
        auto dist = DijkstraSP(m_adjList, srcIdx);

        int N = dist.size();

        for (int dstIdx = 0; dstIdx < N; dstIdx++)
        {
            uint32_t d = dist[dstIdx].first;

            // ---- Skip source itself ----
            if (dstIdx == int(srcIdx))
                continue;

            // ---- Skip if no path ----
            if (d >= INF/2)
            {
                NS_LOG_WARN("No path from " << srcKmId
                             << " to index " << dstIdx << "; skipping.");
                continue;
            }

            // ---- Reconstruct path ----
            std::vector<uint32_t> pathIndices;
            uint32_t cur = dstIdx;

            while (cur != srcIdx)
            {
                pathIndices.push_back(cur);
                uint32_t prev = dist[cur].second;

                // safety: if stuck, break
                if (prev == cur)
                {
                    NS_LOG_ERROR("Broken Dijkstra predecessor chain at index "
                                 << cur << "; skipping route.");
                    pathIndices.clear();
                    break;
                }
                cur = prev;
            }

            if (pathIndices.empty())
                continue;

            // Insert source to complete path
            pathIndices.push_back(srcIdx);

            // Reverse path so it is: [src → ... → dst]
            std::reverse(pathIndices.begin(), pathIndices.end());

            if (pathIndices.size() < 2)
            {
                NS_LOG_ERROR("Reconstructed path of invalid length.");
                continue;
            }

            // Next hop = second element in path
            uint32_t nextIdx = pathIndices[1];

            uint32_t nextHopKmId = ReverseColumn(nextIdx);
            uint32_t dstKmId     = ReverseColumn(dstIdx);

            Ipv4Address nextHopAddr =
                m_controllers.find(nextHopKmId)->second->GetLocalKMAddress();

            Ipv4Address dstAddr =
                m_controllers.find(dstKmId)->second->GetLocalKMAddress();

            std::string dstKmString =
                m_controllers.find(dstKmId)->second->GetLocalKMId();

            QKDLocationRegisterEntry entry(
                nextHopKmId,
                nextHopAddr,
                d,          // number of hops
                dstKmId,
                dstAddr,
                dstKmString
            );

            NS_LOG_INFO("ADD ROUTE: SRC " << srcKmId
                         << " → DST " << dstKmId
                         << " via nextHop KM " << nextHopKmId
                         << " hops=" << d);

            srcCtrl->AddRouteEntry(entry);
        }
    }
}


} // namespace ns3

/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 *
 *
 * Authors:  Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 *           Miralem Mehic <miralem.mehic@etf.unsa.ba>
 */

#include <string>
#include <queue>

#include <cmath>
#include <algorithm>
#include <numeric>
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/log.h"
#include "ns3/boolean.h"
#include "ns3/double.h"
#include "ns3/uinteger.h"

#include "qcen-control.h"
//#include "ns3/qkd-control.h"
//#include "ns3/qkd-control-container.h"
//#include "ns3/qkd-location-register-entry.h"

namespace ns3 {

    NS_LOG_COMPONENT_DEFINE("QCenController");

    TypeId
    QCenController::GetTypeId()
    {
      static TypeId tid = TypeId("ns3::QCenController")
        .SetParent<Object>()
        .AddConstructor<QCenController>()
        ;
      return tid;
    }

    QCenController::QCenController()
    {
        NS_LOG_FUNCTION(this);
    }

    QCenController::QCenController(std::vector<Ptr<QKDControl>> controllers)
    {
        NS_LOG_FUNCTION(this);

        m_controllerList = controllers;
        //Code adjusted from: https://www.srcmake.com/home/cpp-shortest-path-dijkstra
        for(size_t i = 0; i < controllers.size(); i++)
        {
            // Create a vector to represent a row, and add it to the adjList.
            std::vector<std::pair<uint32_t, uint32_t> > row;
            m_adjList.push_back(row);
        }

        //Read inputs into sorted map entries where key is KMNodeId and value is QKDControl
        for(auto el : controllers)
            m_controllers.insert(std::make_pair(el->GetLocalKMNodeId(), el));
        //Algorithm uses nodes from 0 to size. Our nodes have other numbers!
        //We use this map to transit from position(0 to size) to actual node Id

        uint32_t elNum = m_controllers.size();
        NS_ASSERT(elNum != 0);
    }

    QCenController::~QCenController()
    {

    }

    void
    QCenController::RegisterDControllers(std::vector<Ptr<QKDControl>> controllers)
    {
        NS_LOG_FUNCTION(this);

        m_controllerList = controllers;
        //Code adjusted from: https://www.srcmake.com/home/cpp-shortest-path-dijkstra
        for(size_t i = 0; i < controllers.size(); i++)
        {
            // Create a vector to represent a row, and add it to the adjList.
            std::vector<std::pair<uint32_t, uint32_t> > row;
            m_adjList.push_back(row);
        }

        //Read inputs into sorted map entries where key is KMNodeId and value is QKDControl
        for(auto el : controllers)
            m_controllers.insert(std::make_pair(el->GetLocalKMNodeId(), el));
        //Algorithm uses nodes from 0 to size. Our nodes have other numbers!
        //We use this map to transit from position(0 to size) to actual node Id

        uint32_t elNum = m_controllers.size();
        NS_ASSERT(elNum != 0);


        //We use are automated procedure to fill adjList!
        uint32_t row = 0;
        for(auto const& el : m_controllers) //For each controller
        {
            NS_LOG_FUNCTION(this << "KMNodeId: " << el.first << "Row: " << row);
            //Get connecting remote KM node IDs
            std::vector<uint32_t> remoteKmNodeIds = el.second->GetRemoteKmNodeIds();
            //Go through all remote KM node IDs and fill the graph
            for(auto const& kmNodeId : remoteKmNodeIds)
            {
                NS_LOG_FUNCTION(this << "Connected to: " << kmNodeId << "Column: " << GetColumn(kmNodeId));
                m_adjList[row].emplace_back(GetColumn(kmNodeId), 100u); //weight is set to 100 for all links, as they are down
            }

            ++row;
        }

        PopulateRoutingTables();
    }

    void
    QCenController::SetNode(Ptr<Node> node)
    {
        m_node = node;
    }

    uint32_t
    QCenController::GetColumn(uint32_t nodeId)
    {
        uint32_t output = 0;
        for(auto const& el : m_controllers)
        {
            if(el.first == nodeId)
                break;
            output++;
        }

        return output;
    }

    uint32_t
    QCenController::ReverseColumn(uint32_t position)
    {
        auto it = std::next(std::begin(m_controllers), position);
        if(it == m_controllers.end())
            NS_LOG_ERROR(this);

        return it->first;
    }

    void
    QCenController::LinkDown(uint32_t source, uint32_t destination)
    {
        NS_LOG_FUNCTION(this << source << destination);
        uint32_t rc1 {GetColumn(source)};
        uint32_t rc2 {GetColumn(destination)};
        for(auto it = m_adjList[rc1].begin(); it != m_adjList[rc1].end(); ++it)
            if(it->first == rc2){
                it->second = 100;
                break;
            }

        for(auto it = m_adjList[rc2].begin(); it != m_adjList[rc2].end(); ++it)
            if(it->first == rc1){
                it->second = 100;
                break;
            }

        PopulateRoutingTables();
    }

    void
    QCenController::LinkUp(uint32_t source, uint32_t destination)
    {
        NS_LOG_FUNCTION(this << source << destination);
        uint32_t rc1 {GetColumn(source)};
        uint32_t rc2 {GetColumn(destination)};
        for(auto it = m_adjList[rc1].begin(); it != m_adjList[rc1].end(); ++it)
            if(it->first == rc2){
                it->second = 1;
                break;
            }
        for(auto it = m_adjList[rc2].begin(); it != m_adjList[rc2].end(); ++it)
            if(it->first == rc1){
                it->second = 1;
                break;
            }

        PopulateRoutingTables();
    }


    // Given an Adjacency List, find all shortest paths from "start" to all other vertices.
    std::vector< std::pair<uint32_t, uint32_t> >
    QCenController::DijkstraSP(
        std::vector< std::vector<std::pair<uint32_t, uint32_t> > > adjList,
        uint32_t start)
    {
        std::vector<std::pair<uint32_t, uint32_t> > dist; // First int is dist, second is the previous node.

        // Initialize all source->vertex as infinite.
        int n = adjList.size();
        for(int i = 0; i < n; i++)
        {
            //dist.push_back(std::make_pair(uint32_t(1000000007), uint32_t(i))); // Define "infinity" as necessary by constraints.
            dist.emplace_back(1000000007u, static_cast<uint32_t>(i));

        }

        // Create a PQ.
        std::priority_queue<std::pair<int, int>, std::vector< std::pair<int, int> >, std::greater<std::pair<int, int> > > pq;

        // Add source to pq, where distance is 0.
        pq.emplace(int(start), 0);
        dist[start] = std::make_pair(uint32_t(0), start);

        // While pq isn't empty...
        while(!pq.empty())
        {
            // Get min distance vertex from pq.(Call it u.)
            int u = pq.top().first;
            pq.pop();

            // Visit all of u's friends. For each one(called v)....
            int listSize = adjList[u].size();
            for(int i = 0; i < listSize; i++)
            {
                uint32_t v = adjList[u][i].first;
                uint32_t weight = adjList[u][i].second;

                // If the distance to v is shorter by going through u...
                if(dist[v].first > dist[u].first + weight)
                {
                    // Update the distance of v.
                    dist[v].first = dist[u].first + weight;
                    // Update the previous node of v.
                    dist[v].second = u;
                    // Insert v into the pq.
                    pq.push(std::make_pair(v, dist[v].first));
                }
            }
        }

        return dist;
    }


    void
    QCenController::PopulateRoutingTables()
    {
        NS_LOG_FUNCTION(this);

        std::vector<std::pair<uint32_t, uint32_t> > dist; // First int is dist, second is the previous node.
        for(auto el : m_controllers)
        {
            el.second->ClearRoutingTable();
            dist = DijkstraSP(m_adjList, GetColumn(el.first));
            NS_LOG_FUNCTION(this << dist.size() << GetColumn(el.first));
            int distSize = dist.size();
            for(int i = 0; i < distSize; i++)
            {
                int currnode = i;
                std::vector<uint32_t> path;
                while(currnode != int(GetColumn(el.first)))
                {
                    path.push_back(currnode);
                    currnode = dist[currnode].second;
                }
                /*
                    path is empty if the node is the node!
                    the first element in path is destination node!
                    the last element in path is the next hop!
                    GetColumn(el.fist) is the source node!
                    dist[i].first is number of hops
                    i is source node as well
                */
                uint32_t hops = dist[i].first;
                if(hops >= 1){ //Populate routing table
                    uint32_t nextHop = ReverseColumn(path[path.size()-1]);
                    Ipv4Address nextHopAddress = m_controllers.find(nextHop)->second->GetLocalKMAddress();
                    uint32_t dstNodeId = ReverseColumn(uint32_t(i));
                    Ipv4Address dstNodeAddress = m_controllers.find(dstNodeId)->second->GetLocalKMAddress();
                    std::string dstKmId = m_controllers.find(dstNodeId)->second->GetLocalKMId();
                    QKDLocationRegisterEntry newEntry(
                            nextHop,//nextHop KM node ID
                            nextHopAddress, //nextHop KM address
                            hops, // Dirrect p2p connection(number of hops)
                            dstNodeId, //Destination KM node ID
                            dstNodeAddress, //Destination KM address
                            dstKmId
                    );
                    el.second->AddRouteEntry(newEntry);
                }

            }

        }
    }


} // namespace ns3

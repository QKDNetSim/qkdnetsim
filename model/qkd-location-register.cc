/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 * Author:  Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 *          Miralem Mehic <miralem.mehic@etf.unsa.ba>
 */
#include "ns3/log.h"
#include "ns3/address.h"
#include "ns3/node.h"
#include "ns3/nstime.h"
#include "ns3/simulator.h"
#include "ns3/uinteger.h"
#include "ns3/trace-source-accessor.h"
#include <iostream>
#include <fstream>
#include <string>

#include "qkd-location-register.h"
#include "qkd-location-register-entry.h"

namespace ns3 {

    NS_LOG_COMPONENT_DEFINE("QKDLocationRegister");

    NS_OBJECT_ENSURE_REGISTERED(QKDLocationRegister);
 
    TypeId
    QKDLocationRegister::GetTypeId()
    {
      static TypeId tid = TypeId("ns3::QKDLocationRegister")
        .SetParent<Object>()
        .SetGroupName("QKDLocationRegister")
        .AddConstructor<QKDLocationRegister>()
        ;
      return tid;
    }
 
    QKDLocationRegister::QKDLocationRegister()
    {}

    QKDLocationRegister::QKDLocationRegister(Ptr<Node> n)
    {
        SetNode(n);
        
        Ptr<QKDKeyManagerSystemApplication> kms;
        for(uint32_t i = 0; i < m_node->GetNApplications(); i++ ){
            Ptr<Application> app = m_node->GetApplication( i );
            kms = app->GetObject<QKDKeyManagerSystemApplication>();
            if(kms) break;
        }
        NS_ASSERT(kms);
        SetAddress(kms->GetAddress());

    }

    bool
    QKDLocationRegister::AddEntry(QKDLocationRegisterEntry & rt)
    {
        NS_LOG_FUNCTION(this << m_id << rt.GetDestinationKmNodeId() << rt.GetNextHopKMNodeId());

        if(m_id == rt.GetDestinationKmNodeId() && m_id == rt.GetNextHopKMNodeId())
            return false;

        std::pair<std::map<uint32_t, QKDLocationRegisterEntry>::iterator, bool> result = m_locationEntites.insert(
            std::make_pair(rt.GetDestinationKmNodeId(),rt)
        );
        return result.second;
    }

    bool
    QKDLocationRegister::DeleteEntry(uint32_t dstSaeId)
    {
        NS_LOG_FUNCTION(this);
        return (m_locationEntites.erase(dstSaeId) != 0);
    }

    bool
    QKDLocationRegister::Lookup(uint32_t id, QKDLocationRegisterEntry & rt)
    {
        NS_LOG_FUNCTION(this << m_id << id << m_locationEntites.size());

        if(m_locationEntites.empty())
            return false;

        for(auto i = m_locationEntites.begin(); i != m_locationEntites.end(); ++i)
            NS_LOG_FUNCTION(this << "PRINT:" << m_id << i->first << id);

        auto i = m_locationEntites.find(id);

        if(i == m_locationEntites.end())
            return false;

        rt = i->second;
        return true;
    }

    bool
    QKDLocationRegister::LookupByKms(Ipv4Address dstKmsAddress, QKDLocationRegisterEntry & rt)
    {
        NS_LOG_FUNCTION(this << dstKmsAddress );
        for(auto i = m_locationEntites.begin(); i != m_locationEntites.end(); ++i)
        {
            if( i->second.GetDestinationKmsAddress() == dstKmsAddress ){
                rt = i->second;
                return true;
            }
        }
        return false;

    }

    void
    QKDLocationRegister::GetListOfAllEntries(std::map<uint32_t, QKDLocationRegisterEntry> & allRoutes)
    {
      for(auto i = m_locationEntites.begin(); i != m_locationEntites.end(); ++i)
        {
            allRoutes.insert(std::make_pair(i->first,i->second));
        }
    }

    void
    QKDLocationRegister::GetListOfDestinationWithNextHop(uint32_t nextHop,
                                                   std::map<uint32_t, QKDLocationRegisterEntry> & unreachable)
    {
      unreachable.clear();
      for(auto i = m_locationEntites.begin(); i
           != m_locationEntites.end(); ++i)
        {
          if(i->second.GetNextHop() == nextHop)
            {
              unreachable.insert(std::make_pair(i->first,i->second));
            }
        }
    }

    uint32_t
    QKDLocationRegister::GetSize()
    {
        return m_locationEntites.size();
    }


    std::vector<std::pair<uint32_t, uint32_t>>
    QKDLocationRegister::DijkstraSP(uint32_t start)
    {
        NS_LOG_FUNCTION(this << m_id << " DijkstraSP start=" << start);

        const uint32_t INF = 1000000;

        // Determine max node id
        uint32_t maxNode = start;
        for (auto const& el : m_adjList)
            maxNode = std::max(maxNode, el.first);

        std::vector<std::pair<uint32_t, uint32_t>> dist(maxNode + 1);

        // Init
        for (uint32_t i = 0; i <= maxNode; ++i)
            dist[i] = { INF, i };

        dist[start] = { 0, start };

        // (distance, node)
        std::priority_queue<
            std::pair<uint32_t,uint32_t>,
            std::vector<std::pair<uint32_t,uint32_t>>,
            std::greater<>
        > pq;

        pq.emplace(0, start);

        while (!pq.empty())
        {
            auto [du, u] = pq.top();
            pq.pop();

            if (du > dist[u].first)
                continue;

            // Scan ALL edges, pick those originating from u
            for (auto const& el : m_adjList)
            {
                uint32_t v      = el.first;
                uint32_t weight = el.second;

                if (u == v)
                    continue;

                if (dist[v].first > dist[u].first + weight)
                {
                    dist[v].first  = dist[u].first + weight;
                    dist[v].second = u;
                    pq.emplace(dist[v].first, v);
                }
            }
        }

        return dist;
    }



    void
    QKDLocationRegister::PopulateRoutingTables()
    {
        NS_LOG_FUNCTION(this << m_id);

        for (auto const& srcPair : m_controllers)
        {
            uint32_t sourceNode = srcPair.first;
            Ptr<QKDControl> srcCtrl = srcPair.second;

            srcCtrl->ClearRoutingTable();

            // Run Dijkstra from sourceNode
            auto dist = DijkstraSP(sourceNode);

            for (uint32_t dstNode = 0; dstNode < dist.size(); ++dstNode)
            {
                // Skip self
                if (dstNode == sourceNode)
                    continue;

                uint32_t distance = dist[dstNode].first;
                uint32_t prev     = dist[dstNode].second;

                // Unreachable
                if (distance >= 1000000 || prev == dstNode)
                    continue;

                // Walk back to find NEXT HOP
                uint32_t nextHop = dstNode;
                uint32_t parent  = prev;

                while (parent != sourceNode)
                {
                    nextHop = parent;
                    parent  = dist[parent].second;

                    // Safety guard (broken chain)
                    if (parent == dist[parent].second)
                        break;
                }

                // Must be directly reachable from source
                if (m_controllers.find(nextHop) == m_controllers.end())
                    continue;

                // Build route entry
                Ptr<QKDControl> nextHopCtrl = m_controllers[nextHop];
                Ptr<QKDControl> dstCtrl     = m_controllers[dstNode];

                QKDLocationRegisterEntry entry(
                    nextHop,
                    nextHopCtrl->GetLocalKMAddress(),
                    distance,
                    dstNode,
                    dstCtrl->GetLocalKMAddress(),
                    dstCtrl->GetLocalKMId()
                );

                AddEntry(entry);

                NS_LOG_INFO(
                    "Route installed: src=" << sourceNode
                    << " dst=" << dstNode
                    << " nextHop=" << nextHop
                    << " hops=" << distance
                );
            }
        }
    }


} // namespace ns3

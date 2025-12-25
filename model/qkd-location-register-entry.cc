/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 *
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

#include "qkd-location-register-entry.h"

namespace ns3 {

    NS_LOG_COMPONENT_DEFINE("QKDLocationRegisterEntry");

    NS_OBJECT_ENSURE_REGISTERED(QKDLocationRegisterEntry);

    TypeId
    QKDLocationRegisterEntry::GetTypeId()
    {
      static TypeId tid = TypeId("ns3::QKDLocationRegisterEntry")
        .SetParent<Object>()
        .SetGroupName("QKDLocationRegisterEntry")
        .AddConstructor<QKDLocationRegisterEntry>()
        ;
      return tid;
    } 

    QKDLocationRegisterEntry::QKDLocationRegisterEntry(){

    }

    QKDLocationRegisterEntry::QKDLocationRegisterEntry(
      uint32_t nextHopKmNodeId,
      Ipv4Address nextHopKmNodeAddress,
      uint32_t hops,
      uint32_t dstKmNodeId,
      Ipv4Address dstKmAddress,
      std::string dstKmId
    )
      : m_nextHop(nextHopKmNodeId),
        m_nextHopAddress(nextHopKmNodeAddress),
        m_hops(hops),
        m_dstKmNodeId(dstKmNodeId),
        m_dstAddress(dstKmAddress),
        m_dstKmId(dstKmId)
    {
      NS_LOG_FUNCTION(this << nextHopKmNodeId << hops << dstKmNodeId);
    }

    std::string
    QKDLocationRegisterEntry::GetKmId()
    {
      return m_dstKmId;
    }

    QKDLocationRegisterEntry::~QKDLocationRegisterEntry()
    {
    }

    void
    QKDLocationRegisterEntry::PrintRegistryInfo()
    {
        NS_LOG_FUNCTION( this << m_srcAppId << m_dstAppId << m_nextHop << m_hops << m_dstKmNodeId << m_dstAddress );
    }

    void
    QKDLocationRegisterEntry::Print(Ptr<OutputStreamWrapper> stream) const
    {
      *stream->GetStream() << GetSourceAppId() << "\t\t"
                            << GetRemoteAppId() << "\t\t"
                            << GetNextHop() << "\n";
    }

} // namespace ns3

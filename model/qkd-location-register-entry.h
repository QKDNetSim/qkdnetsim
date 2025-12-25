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
#ifndef QKD_LOCATION_REGISTER_ENTRY_H
#define QKD_LOCATION_REGISTER_ENTRY_H

#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/data-rate.h"
#include "ns3/traced-callback.h"
#include "ns3/output-stream-wrapper.h"
#include "ns3/packet.h"
#include "ns3/object.h"
#include "ns3/traced-value.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/node.h"
#include "ns3/core-module.h"
#include "ns3/log.h"

#include "ns3/qkd-key-manager-system-application.h"

#include <map>
#include <iostream>
#include <sstream>

namespace ns3 {

class QKDKeyManagerSystemApplication;

/**
 * @ingroup applications
 * @class QKD QKDLocationRegister
 * @brief QKD QKDLocationRegister is a class used to
 * keep details about distant QKD nodes and their connectivity.
 *
 * @note QKDNetSim KMS implements a location register table that is used
 * to define paths to distant node. It is a early version of routing table
 * that will be updated via routing protocol.
 */
class QKDLocationRegisterEntry : public Object
{
  public:

    /**
    * @brief Get the type ID.
    * @return the object TypeId
    */
    static TypeId GetTypeId();

    QKDLocationRegisterEntry();

    QKDLocationRegisterEntry(
      uint32_t nextHopKmNodeId,
      Ipv4Address nextHopKmNodeAddress,
      uint32_t hops,
      uint32_t dstKmNodeId,
      Ipv4Address dstKmAddress,
      std::string dstKmId
    );

    ~QKDLocationRegisterEntry() override;

    std::string
    GetRemoteAppId() const
    {
      return m_dstAppId;
    }

    std::string
    GetSourceAppId() const
    {
      return m_srcAppId;
    }

    /**
     * Get destination KMS Address
     * @returns the destination KMS Address
     */
    Ipv4Address
    GetDestinationKmsAddress() const
    {
      return m_dstAddress;
    }

    uint32_t GetDestinationKmNodeId() const
    {
      return m_dstKmNodeId;
    }

    uint32_t GetNextHopKMNodeId() const
    {
      return m_nextHop;
    }

    /**
     * Set next hop
     * @param nextHop the ID of the next hop
     */
    void
    SetNextHop(uint32_t nextHop)
    {
      m_nextHop = nextHop;
    }
    /**
     * Get next hop
     * @returns the ID of the next hop
     */
    uint32_t
    GetNextHop() const
    {
      return m_nextHop;
    }

    Ipv4Address
    GetNextHopAddress() const
    {
      return m_nextHopAddress;
    }

    std::string GetKmId();

    /**
     * Set hop
     * @param hopCount the hop count
     */
    void
    SetHop(uint32_t hopCount)
    {
      m_hops = hopCount;
    }
    /**
     * Get hop
     * @returns the hop count
     */
    uint32_t
    GetHop() const
    {
      return m_hops;
    }
    /**
     * @brief Print registry info
     */
    void
    PrintRegistryInfo();
    /**
     * Print routing table entry
     * @param stream the output stream
     */
    void
    Print(Ptr<OutputStreamWrapper> stream) const;

  private:
    std::string     m_srcAppId;
    std::string     m_dstAppId;
    uint32_t        m_nextHop;
    Ipv4Address     m_nextHopAddress;
    uint32_t        m_hops;
    uint32_t        m_dstKmNodeId;
    Ipv4Address     m_dstAddress;
    std::string     m_dstKmId;
};



} // namespace ns3

#endif /* QKD_LOCATION_REGISTER_ENTRY_H */


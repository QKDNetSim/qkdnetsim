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
#ifndef QKD_LOCATION_REGISTER_H
#define QKD_LOCATION_REGISTER_H

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
#include "ns3/socket.h"

#include "qkd-location-register-entry.h"
#include "qkd-control.h"

#include <map>
#include <iostream>
#include <sstream>

namespace ns3 {

class QKDControl;
class QKDLocationRegisterEntry;

/**
 * @ingroup applications
 * @class QKDLocationRegister
 * @brief QKDLocationRegister is a class used to
 * keep details about distant QKD nodes and their connectivity.
 *
 * @note QKDNetSim KMS implements a location register table that is used
 * to define paths to distant node. It is a early version of routing table
 * that will be updated via routing protocol.
 */

class QKDLocationRegister : public Object
{
  public:

    /**
    * @brief Get the type ID.
    * @return the object TypeId
    */
    static TypeId GetTypeId();

    /// c-tor
    QKDLocationRegister();

    QKDLocationRegister(Ptr<Node> n);
    /**
     * Add location table entry if it doesn't yet exist in location table
     * @param r location table entry
     * @return true in success
     */
    bool
    AddEntry(QKDLocationRegisterEntry & r);
    /**
     * Delete location table entry with destination address dst, if it exists.
     * @param dst destination address
     * @return true on success
     */
    bool
    DeleteEntry(uint32_t dst);
    /**
     * Lookup location table entry with destination address dst
     * @param dst destination application ID
     * @param rt entry with destination address dst, if exists
     * @return true on success
     */
    bool
    Lookup(uint32_t dstSaeId, QKDLocationRegisterEntry & rt);
    /**
     * Lookup location table entry with destination address dst KMS Id
     * @Ipv4Address destination KMS Ipv4Address
     * @param rt entry with destination address dst, if exists
     * @return true on success
     */
    bool
    LookupByKms(Ipv4Address dstKmsId, QKDLocationRegisterEntry & rt);
    /**
     * Lookup list of addresses for which nxtHp is the next Hop address
     * @param nxtHp nexthop's address for which we want the list of destinations
     * @param dstList is the list that will hold all these destination addresses
     */
    void
    GetListOfDestinationWithNextHop(uint32_t nxtHp, std::map<uint32_t, QKDLocationRegisterEntry> & dstList);
    /**
     * Lookup list of all addresses in the location table
     * @param allRoutes is the list that will hold all these addresses present in the nodes location table
     */
    void
    GetListOfAllEntries(std::map<uint32_t, QKDLocationRegisterEntry> & allRoutes);
    /**
     * Print location table
     * @param stream the output stream
     */
    void
    Print(Ptr<OutputStreamWrapper> stream) const;
    /**
     * Provides the number of routes present in that nodes location table.
     * @returns the number of routes
     */
    uint32_t GetSize(); 

    Ptr<Node> GetNode() { return m_node; }

    void SetNode(Ptr<Node> n) { m_node = n; m_id = n->GetId(); }

    Ipv4Address GetAddress(){ return m_address; }

    void SetAddress(Ipv4Address addr) { m_address = addr; } 

  private:

    void PopulateRoutingTables();
 
    std::vector< std::pair<uint32_t, uint32_t> > DijkstraSP(
      uint32_t start
    );
 
    std::map<uint32_t, QKDLocationRegisterEntry> m_locationEntites;

    uint32_t m_id;

    std::vector<std::pair<uint32_t, uint32_t> > m_adjList; //<! adjecent List, used for dijkstraSP! It is a topology graph!
  
    std::map<uint32_t, Ptr<QKDControl> > m_controllers; //<! a pair of KMNodeId and respective QKDControl
  
    Ipv4Address m_address;
    
    Ptr<Node> m_node;
};

} // namespace ns3

#endif /* QKD_LOCATION_REGISTER_H */


/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 *
 * Authors: Miralem Mehic <miralem.mehic@etf.unsa.ba>
 *          Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 */

#ifndef QCENCONTROLLER_H
#define QCENCONTROLLER_H

#include "ns3/object.h"
#include "ns3/traced-value.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/node.h"

#include "qkd-control.h"
//class QKDControl;
//class QKDLocationRegister;

namespace ns3 {

  /**
   * @defgroup qkd Quantum Key Distribution(QKD)
   * This section documents the API of the ns-3 QKD Network Simulation Module(QKDNetSim).
   *
   * Be sure to read the manual BEFORE going down to the API.
   */

  /**
   * @ingroup qkd
   * @class QCenController
   * @brief QCenController is a centralized controller used for re-routing.
   *
   * @note  Distributed QControllers in every QKD node inform QCenController about the
   * state of QKD Links. If the QKD Link is EMPTY, a notification is sent, and QCenController
   * updates routing tables for every QController. It has two routing tables, one default, starting
   * and one working table.
   *
   *
   */
  class QCenController: public Object {
    public:

      static TypeId GetTypeId();

      QCenController();

      QCenController(std::vector<Ptr<QKDControl>> controllers);

      ~QCenController() override;

      void RegisterDControllers(std::vector<Ptr<QKDControl>> controllers);

      void SetNode(Ptr<Node> node);

      uint32_t GetColumn(uint32_t nodeId);

      uint32_t ReverseColumn(uint32_t position);

      void LinkDown(uint32_t source, uint32_t destination);

      void LinkUp(uint32_t source, uint32_t destination);

      std::vector< std::pair<uint32_t, uint32_t> >  DijkstraSP(std::vector< std::vector<std::pair<uint32_t, uint32_t> > > adjList, uint32_t start);

      void PopulateRoutingTables();

    private:

      std::map<uint32_t, Ptr<QKDControl> > m_controllers; //<! a pair of KMNodeId and respective QKDControl

      std::vector< std::vector<std::pair<uint32_t, uint32_t> > > m_adjList; //<! adjecent List, used for dijkstraSP! It is a topology graph!

      std::vector<Ptr<QKDControl> >           m_controllerList;   //!< List of all controllers.

      Ptr<QKDLocationRegister>                m_routingTable;     //!< Routing Table

      Ptr<Node> m_node;

  };
}

#endif /* QCENCONTROLLER_H */

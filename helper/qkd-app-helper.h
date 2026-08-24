/*
 * Copyright (c) 2020 DOTFEESA www.tk.etf.unsa.ba
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 *
 *
 * Author: Miralem Mehic <miralem.mehic@etf.unsa.ba>
 */

#ifndef QKD_APP_HELPER_H
#define QKD_APP_HELPER_H

#include <stdint.h> 
#include <string>
#include "ns3/object-factory.h"
#include "ns3/address.h"
#include "ns3/attribute.h"
#include "ns3/net-device.h"
#include "ns3/net-device-container.h"
#include "ns3/node-container.h"
#include "ns3/application-container.h"
#include "ns3/qkd-postprocessing-application.h" 
#include "ns3/qcen-control.h"
#include "ns3/qkd-app-014.h"
#include "ns3/qkd-app-004.h"
#include "ns3/uuid.h"

namespace ns3 {

/**
 * @ingroup qkd
 * @brief A helper to make it easier to instantiate an ns3::QKDAppApplication
 * on a set of nodes.
 */
class QKDAppHelper  
{
public:
  /**
   * Create an QKDAppHelper to make it easier to work with QKD Applications (KMS, Post-processing and other)
   *
   */ 
  QKDAppHelper ();

  /**
   * Helper function used to set the underlying application attributes,
   * _not_ the socket attributes.
   *
   * @param name the name of the application attribute to set
   * @param value the value of the application attribute to set
   */
  void SetAttribute (std::string mFactoryName, std::string name, const AttributeValue &value);
  
  /**
   * @brief Install key manager
   * @param node node to install KM
   * @param kmsAddress KM Ipv4 address
   * @param port listening port
   * @param controller competent controller's node
   */
  void InstallKeyManager (Ptr<Node> node, Ipv4Address kmsAddress, uint32_t port, Ptr<QKDControl> controller);
 
  /**
   * @brief Install key manager
   * @param node node to install KM
   * @param kmsAddress KM Ipv4 address
   * @param port listening port
   * @param controller competent controller's node
   */
  void InstallKeyManager (Ptr<Node> node, Ipv4Address kmsAddress, uint32_t port, Ptr<QKDControl> controller, Ptr<QCenController> cenController);

  ApplicationContainer InstallPostProcessing (
    Ptr<Node> node1,
    Ptr<Node> node2,
    Address     masterAddress,
    Address     slaveAddress,
    Ptr<Node>   control1,
    Ptr<Node>   control2,
    uint32_t    keySize,
    DataRate    keyRate,
    uint32_t    packetSize,
    DataRate    dataRate,
    std::string masterUUID,
    std::string slaveUUID
  );

  ApplicationContainer InstallPostProcessing (
    Ptr<Node> node1,
    Ptr<Node> node2,
    Address     masterAddress,
    Address     slaveAddress,
    Ptr<Node>   control1,
    Ptr<Node>   control2,
    uint32_t    keySize,
    DataRate    keyRate,
    uint32_t    packetSize,
    DataRate    dataRate
  );

  /**
   * @brief Install a pair of cryptographic applications to consume keys
   * @param node1 master application node
   * @param node2 slave application node
   * @param masterAddress master application address
   * @param slaveAddress slave application address
   * @param control1 QKDN controller node at site of master application
   * @param control2 QKDN controller node at site of slave application
   * @param connectionType connection type
   * @param packetSize the size of data packets
   * @param dataRate data rate
   * @param applicationType the type of the application (etsi014 or etsi004)
   * @return Container of Ptr to the applications installed
   */
  ApplicationContainer InstallQKDApplication (
    Ptr<Node> node1,
    Ptr<Node> node2,
    Address   masterAddress,
    Address   slaveAddress,
    Ptr<Node> control1,
    Ptr<Node> control2,
    std::string connectionType,
    uint32_t packetSize,
    DataRate dataRate,
    std::string applicationType,
    std::string masterUUID,
    std::string slaveUUID
  );

  /**
   * @brief Install a pair of cryptographic applications to consume keys
   * @param node1 master application node
   * @param node2 slave application node
   * @param masterAddress master application address
   * @param slaveAddress slave application address
   * @param control1 QKDN controller node at site of master application
   * @param control2 QKDN controller node at site of slave application
   * @param connectionType connection type
   * @param packetSize the size of data packets
   * @param dataRate data rate
   * @param applicationType the type of the application (etsi014 or etsi004)
   * @return Container of Ptr to the applications installed
   */
  ApplicationContainer InstallQKDApplication (
    Ptr<Node> node1,
    Ptr<Node> node2,
    Address   masterAddress,
    Address   slaveAddress,
    Ptr<Node> control1,
    Ptr<Node> control2,
    std::string connectionType,
    uint32_t packetSize,
    DataRate dataRate,
    std::string applicationType
  );

private: 

  ObjectFactory m_factory_kms_app; //!< Object factory.
  ObjectFactory m_factory_qkd004_app; //!< Object factory.
  ObjectFactory m_factory_qkd014_app; //!< Object factory.
  ObjectFactory m_factory_postprocessing_app; //!< Object factory. 

};

} // namespace ns3

#endif /* QKD_APP_HELPER_H */


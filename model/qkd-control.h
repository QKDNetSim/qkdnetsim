/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 *
 * Authors: Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 *          Miralem Mehic <miralem.mehic@etf.unsa.ba>
 */

#ifndef QKDCONTROL_H
#define QKDCONTROL_H

#include <queue>
#include <vector>
#include <map>
#include <string>

#include "ns3/packet.h"
#include "ns3/object.h"
#include "ns3/ipv4-header.h"
#include "ns3/traced-value.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/event-id.h"
#include "qkd-key.h"
#include "ns3/node.h"
#include "ns3/qkd-key-manager-system-application.h"

#include "ns3/tag.h"
#include "ns3/net-device.h"
#include "ns3/traffic-control-layer.h"

#include "qkd-encryptor.h"
#include "q-buffer.h"
#include "s-buffer.h"

#include "ns3/object-factory.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-interface-address.h"

namespace ns3 {

    class QKDKeyManagerSystemApplication;
    class QKDLocationRegisterEntry;
    class QKDLocationRegister;
    /**
     * @ingroup qkd
     * @class QKDControl
     *
     * @brief As described in OPENQKD deliverable D6.1(section 5),
     * the QKD control is a network component with the knowledge of the
     * network status. It should perform network management through distributed
     * protocols or centralized entities.
     *
     * @note In the current version of QKDNetSim, QKDControl can be installed
     * on an independent node without a direct QKD connection. It is in charge
     * of establishing QKD links, and it contains a list of QKD links with
     * associated QKD buffers implemented in a QKD network.
     */
    class QKDControl : public Object
    {
    public:

        /**
         * Describes QKD modules at site
         */
        struct QKDModule
        {
            Ptr<Node>       node;
            Ptr<Node>       remoteNode;
            std::string     id;
            std::string     remoteId;
            Ptr<Node>       kmNode;
            Ptr<Node>       remoteKmNode;
        };

        struct QKDLink
        {
            Ptr<Node>               alice;
            Ptr<Node>               bob;
            Ptr<QBuffer>            qkdBufferAlice;
            Ptr<QBuffer>            qkdBufferBob;
            double                  publicChannelMetric;
            double                  quantumChannelMetric;
        };

        /**
        * @brief Get the type ID.
        * @return the object TypeId
        */
        static TypeId GetTypeId(); 

        /**
        * @brief Constructor
        */
        QKDControl();

        /**
        * @brief Destructor
        */
        ~QKDControl() override;

        /**
        * Destroy a QKDControl
        *
        * This is the pre-destructor function of the QKDControl.
        */
        void Dispose();

        /**
        *   @brief Return QKDQBuffer for plotting
        *   @param  Ptr<Node> src, Ptr<Node> dst
        *   @return Ptr<QBuffer>
        */
        Ptr<QBuffer> GetBufferByDestinationNode(Ptr<Node>, Ptr<Node>);

        Ptr<Node> GetNode() const;

        void SetNode(Ptr<Node>);

        /**
         * @brief Assign key manager
         * @param n key manager's node
         */
        void AssignKeyManager(Ptr<Node> n);

        /**
         * @brief Get Key Manager System Application from node
         * @param n node
         * @return key manager system application
         */
        Ptr<QKDKeyManagerSystemApplication> GetKeyManagerSystemApplication(Ptr<Node> n) const;

        Ptr<Node> GetLocalKMNode() const;

        uint32_t GetLocalKMNodeId() const;

        std::string GetLocalKMId() const;

        Ipv4Address GetLocalKMAddress() const;

        std::vector<uint32_t> GetRemoteKmNodeIds() const;

        /**
         * @brief Register QKD Module / PP application pair
         * @param moduleLocal local QKD module node
         * @param moduleRemote remote QKD module node
         * @param idLocal local QKD module ID
         * @param idRemote remote QKD module ID
         * @param kmLocal local key manager node
         * @param kmRemote remote key manager node
         */
        void RegisterQKDModulePair(
            Ptr<Node>   moduleLocal,
            Ptr<Node>   moduleRemote,
            std::string idLocal,
            std::string idRemote,
            Ptr<Node>   kmLocal,
            Ptr<Node>   kmRemote
        );

        /**
         * @brief register a pair of QKD applications
         * @param localAppId ID of local QKD application
         * @param remoteAppId ID of remote QKD application
         * @param remoteKmNode remote KM node
         */
        void RegisterQKDApplicationPair(
            std::string localAppId,
            std::string remoteAppId,
            Ptr<Node> remoteKmNode
        );

        /**
         * @brief Get local application ID based on the remote application ID
         * @param peerAppId remote application ID
         * @return string local application ID
         */
        std::string GetApplicationId(std::string peerAppId);

        /**
         * @brief Configure all buffers(default conf). Mandatory function!
         * @param Mmin minimum amount(bits) of key material QKD buffer should maintain
         * @param Mmax maximum amount(bits) of key material QKD buffer can store
         * @param Mthr thresold amount(bits) of key material
         * @param Mcurr current amount(bits) of key material QKD buffer maintain
         * @param defaultKeySize default size of stored keys
         */
        void ConfigureQBuffers(
            uint32_t Mmin,
            uint32_t Mthr,
            uint32_t Mmax,
            uint32_t Mcurr,
            uint32_t defaultKeySize
        ); //add intance of same function with input remoteKM -> configure this buffer connection, and one with vector<KMs>

        void ConfigureRSBuffers(
            uint32_t Mmin,
            uint32_t Mthr,
            uint32_t Mmax,
            uint32_t Mcurr,
            uint32_t defaultKeySize
        );

        Ptr<SBuffer> CreateRSBuffer(uint32_t remoteId);

        Ptr<QBuffer>   GetQBufferConf(uint32_t remoteId);

        void ClearRoutingTable();

        void AddRouteEntry(QKDLocationRegisterEntry entry);

        QKDLocationRegisterEntry GetRoute(std::string remoteAppId);

        QKDLocationRegisterEntry GetRoute(uint32_t remoteKmId);


    protected:
        /**
        * The dispose method. Subclasses must override this method
        * and must chain up to it by calling Node::DoDispose at the
        * end of their own DoDispose method.
        */
        void DoDispose() override;

        /**
        *   @briefInitialization function
        */
        void DoInitialize() override;

    private:


        Ptr<Node>                   m_node;

        std::vector<Ptr<Node> >     m_remote_km_nodes;       //!< Remote Key Manager Node(s)(direct QKD connection!)

        std::vector<QKDModule>      m_qkd_modules;           //!< Registered QKD modules

        //std::vector<Ptr<QKDControl> >     m_conn_qkdn_controllers; //!< Connecting QKDN controllers

        Ptr<QBuffer>                            m_qbuffer_config;    //!< Default QKD buffer configuration

        Ptr<QBuffer>                            m_rsbuffer_config;

        std::map<uint32_t, Ptr<QBuffer> >       m_qbuffers_conf;  //!< Dedicaded QKD buffer configuration

        std::vector<std::string>                m_local_qkdapps;    //!< Vector of all the apps(IDs) connecting to local KM node

        std::map<std::string, std::string>      m_qkdapp_pairs;      //!<QKDapp pair(remoteApp, localApp)

        std::map<std::string, uint32_t >        m_remote_qkdapps;   //!< All remote apps(IDs) and their KM nodes(must keep nodes to get remote KM address in QKD network)

        Ptr<QKDLocationRegister>                m_routingTable;     //!< Routing Table

    };
}
// namespace ns3

#endif /* QKDCONTROL_H */

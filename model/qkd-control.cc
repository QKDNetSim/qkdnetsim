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

#include <cmath>
#include <algorithm>
#include <numeric>
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/log.h"
#include "ns3/boolean.h"
#include "ns3/double.h"
#include "ns3/uinteger.h"

#include "qkd-control.h"

namespace ns3 {

    NS_LOG_COMPONENT_DEFINE("QKDControl");

    NS_OBJECT_ENSURE_REGISTERED(QKDControl);

    TypeId
    QKDControl::GetTypeId()
    {
      static TypeId tid = TypeId("ns3::QKDControl")
        .SetParent<Object>()
        .SetGroupName("QKDControl")
        .AddConstructor<QKDControl>();
      return tid;
    } 
    
    QKDControl::QKDControl()
      : Object()
    {
        NS_LOG_FUNCTION_NOARGS();
    }

    QKDControl::~QKDControl()
    {
    }

    void
    QKDControl::DoDispose()
    {
        Object::DoDispose();
    }

    void
    QKDControl::DoInitialize()
    {
        NS_LOG_FUNCTION(this);
        Object::DoInitialize();
    }

    Ptr<QBuffer>
    QKDControl::GetBufferByDestinationNode(Ptr<Node> src, Ptr<Node> dst) {

        NS_LOG_FUNCTION(this << src->GetId() << dst->GetId() );

        Ptr<QKDKeyManagerSystemApplication> kms;
        for(uint32_t i = 0; i < src->GetNApplications(); ++i){
            kms = src->GetApplication(i)->GetObject <QKDKeyManagerSystemApplication>();
            if(kms) break;
        }

        Ptr<QBuffer> buffer = kms->GetQBuffer( dst->GetId() );
        NS_ASSERT(buffer);

        return buffer;
    }

    Ptr<Node>
    QKDControl::GetNode() const {
        return m_node;
    }

    void
    QKDControl::SetNode(Ptr<Node> node) {
        m_node = node;
    }

    void
    QKDControl::AssignKeyManager(Ptr<Node> n)
    {
        NS_LOG_FUNCTION(this);
        SetNode(n);
        m_routingTable = CreateObject<QKDLocationRegister>(GetNode()); //Initialize Routing Table
        m_routingTable->SetNode( GetNode() );
        m_routingTable->SetAddress( GetLocalKMAddress() );
    }

    Ptr<QKDKeyManagerSystemApplication>
    QKDControl::GetKeyManagerSystemApplication(Ptr<Node> n) const
    {
        NS_LOG_FUNCTION(this);
        Ptr<QKDKeyManagerSystemApplication> lkm;
        for(uint32_t i = 0; i < n->GetNApplications(); ++i){
            lkm = n->GetApplication(i)->GetObject <QKDKeyManagerSystemApplication>();
            if(lkm) break;
        }
        //NS_ASSERT(lkm);

        return lkm;
    }

    Ipv4Address
    QKDControl::GetLocalKMAddress() const {
        return GetKeyManagerSystemApplication( GetLocalKMNode() )->GetAddress();
    }

    Ptr<Node>
    QKDControl::GetLocalKMNode() const {
        return GetNode();
    }

    uint32_t
    QKDControl::GetLocalKMNodeId() const {
        return GetLocalKMNode()->GetId();
    }

    std::string
    QKDControl::GetLocalKMId() const {
        return GetKeyManagerSystemApplication( GetLocalKMNode() )->GetId();
    }

    std::vector<uint32_t>
    QKDControl::GetRemoteKmNodeIds() const
    {
        std::vector<uint32_t> output;
        for(auto el : m_remote_km_nodes)
            output.push_back(el->GetId());

        return output;
    }

    void
    QKDControl::RegisterQKDModulePair(
        Ptr<Node> moduleLocal,
        Ptr<Node> moduleRemote,
        std::string idLocal,
        std::string idRemote,
        Ptr<Node> kmLocal,
        Ptr<Node> kmRemote
    )
    {
        NS_LOG_FUNCTION(this);
        //Assign QKD module in m_qkd_modules(currently is not necessary to record all entries)
        QKDModule localQKDModule;
        localQKDModule.node = moduleLocal;
        localQKDModule.remoteNode = moduleRemote;
        localQKDModule.id = idLocal;
        localQKDModule.remoteId = idRemote;
        localQKDModule.kmNode = kmLocal;
        localQKDModule.remoteKmNode = kmRemote;
        m_qkd_modules.push_back(localQKDModule);
        //m_conn_qkdn_controllers.push_back(GetKeyManagerSystemApplication(kmRemote)->GetController()); //Add connecting QKDNController

        //Check if we have the same connecting KM in m_remote_km_nodes. If not, add this one!
        bool registered {false};
        for(auto kmNodes : m_remote_km_nodes)
            if(kmRemote->GetId() == kmNodes->GetId()){
                registered = true;
                break;
            }

        //Tell local KM to establish QKD buffer for this connection!
        //If QKD buffer exists KM will do nothing, exept remember a pair modulId and matching modulId
        if(!registered){
            m_remote_km_nodes.push_back(kmRemote);
            NS_LOG_FUNCTION(this << "New remote KM added");
            //Instruct Key Manager to establish QBuffer for this connection with kmRemote!
            GetKeyManagerSystemApplication( GetLocalKMNode() )->CreateQBuffer(
                kmRemote->GetId(),
                GetQBufferConf( kmRemote->GetId() )
            );
            GetKeyManagerSystemApplication( GetLocalKMNode() )->SetPeerKmAddress(
                kmRemote->GetId(),
                GetKeyManagerSystemApplication( kmRemote )->GetAddress()
            );
        }

        //Each QKD buffer should have corresponding moduleIds so KM knows where to put keys
        GetKeyManagerSystemApplication( GetLocalKMNode() )->RegisterQKDModule(
            kmRemote->GetId(),
            idLocal
        );

        GetKeyManagerSystemApplication( GetLocalKMNode() )->EstablishKMLinkSockets(
            GetKeyManagerSystemApplication( kmRemote )->GetAddress()
        );
        GetKeyManagerSystemApplication( kmRemote )->EstablishKMLinkSockets(
            GetKeyManagerSystemApplication( GetLocalKMNode() )->GetAddress()
        );
    }

    void
    QKDControl::RegisterQKDApplicationPair(
        std::string localAppId,
        std::string remoteAppId,
        Ptr<Node> remoteKmNode
    )
    {
        NS_LOG_FUNCTION(this << localAppId << remoteAppId);
        m_local_qkdapps.push_back(localAppId);
        m_remote_qkdapps.insert(std::make_pair(remoteAppId, remoteKmNode->GetId()));
        m_qkdapp_pairs.insert(std::make_pair(remoteAppId, localAppId));

        /*for(auto remoteKm : m_remote_km_nodes) {
            if(remoteKm->GetId() == remoteKmNode->GetId()) { //This is direct connection to remoteApp!
                QKDLocationRegisterEntry newEntry(
                    localAppId,
                    remoteAppId,
                    remoteKmNode->GetId(),//nextHop KM node ID
                    GetKeyManagerSystemApplication(remoteKmNode)->GetAddress(), //nextHop KM address
                    1, // Dirrect p2p connection(number of hops)
                    remoteKmNode->GetId(), //Destination KM node ID
                    GetKeyManagerSystemApplication(remoteKmNode)->GetAddress(), //Destination KM address
                    GetKeyManagerSystemApplication(remoteKmNode)->GetId()
                );
                m_routingTable->AddEntry(newEntry);
                break;
            }
        }*/
    }

    std::string
    QKDControl::GetApplicationId(std::string peerAppId)
    {
        NS_LOG_FUNCTION(this << peerAppId);
        std::string appId;
        auto it = m_qkdapp_pairs.find(peerAppId);
        if(it != m_qkdapp_pairs.end())
            appId = it->second;
        else
            NS_LOG_ERROR(this << "Peer application ID not registered!");
        return appId;
    }

    void
    QKDControl::ConfigureQBuffers(
        uint32_t Mmin,
        uint32_t Mthr,
        uint32_t Mmax,
        uint32_t Mcurr,
        uint32_t defaultKeySize
    )
    {
        NS_LOG_FUNCTION(this << "\tMmin:" << Mmin << "\tMthr:" << Mthr << "\tMmax:" << Mmax << "\tMcurr:" << Mcurr);
        m_qbuffer_config = CreateObject<QBuffer>();
        m_qbuffer_config->Configure(Mmin, Mthr, Mmax, Mcurr, defaultKeySize);
    }

    Ptr<QBuffer>
    QKDControl::GetQBufferConf(uint32_t remoteId)
    {
        NS_LOG_FUNCTION(this);

        auto it = m_qbuffers_conf.find(remoteId);
        if(it == m_qbuffers_conf.end()){
            NS_LOG_LOGIC(this << "\tDefault configuration selected");
            return m_qbuffer_config;
        }else{
            NS_LOG_LOGIC(this << "\tCustom buffer configuration selected");
            return it->second;
        }
    }

    void
    QKDControl::ConfigureRSBuffers(
        uint32_t Mmin,
        uint32_t Mthr,
        uint32_t Mmax,
        uint32_t Mcurr,
        uint32_t defaultKeySize
    )
    {
        NS_LOG_FUNCTION(this << "\tMmin:" << Mmin << "\tMthr:" << Mthr << "\tMmax:" << Mmax << "\tMcurr:" << Mcurr);
        m_rsbuffer_config = CreateObject<QBuffer>();
        m_rsbuffer_config->Configure(Mmin, Mthr, Mmax, Mcurr, defaultKeySize);
    }

    Ptr<SBuffer>
    QKDControl::CreateRSBuffer(uint32_t remoteId)
    {
        NS_LOG_FUNCTION(this << remoteId);
        Ptr<SBuffer> sBuffer = CreateObject<SBuffer>();
        sBuffer->Init(
            remoteId,
            m_rsbuffer_config->GetMmin(),
            m_rsbuffer_config->GetMthr(),
            m_rsbuffer_config->GetMmax(),
            m_rsbuffer_config->GetBitCount(),
            m_rsbuffer_config->GetKeySize()
        );
        //@toDo QKDNController holds a pointer to S-Buffer and monitors it to control thr, max values!
        return sBuffer;
    }

    QKDLocationRegisterEntry
    QKDControl::GetRoute(std::string remoteAppId)
    {
        NS_LOG_FUNCTION(this << "remoteAppId:" << remoteAppId);
        QKDLocationRegisterEntry routeInfo;
        auto it = m_remote_qkdapps.find(remoteAppId);
        if(it!=m_remote_qkdapps.end()){
            routeInfo = GetRoute(it->second);
        }else{
            NS_LOG_ERROR(this << "\t Remote SAE not known to QKDN controller!" <<remoteAppId);
        }
        return routeInfo;
    }

    QKDLocationRegisterEntry
    QKDControl::GetRoute(uint32_t remoteKmId)
    {
        NS_LOG_FUNCTION(this << "remoteKmId:" << remoteKmId);
        QKDLocationRegisterEntry routeInfo;
        if(!m_routingTable->Lookup(remoteKmId, routeInfo))
            NS_LOG_ERROR(this << "\t Route to remoteKME " << remoteKmId << " not found!");
        return routeInfo;
    }

    void
    QKDControl::ClearRoutingTable()
    {
        //m_routingTable = null;
    }

    void
    QKDControl::AddRouteEntry(QKDLocationRegisterEntry entry)
    {
        NS_LOG_FUNCTION(this);
        m_routingTable->AddEntry(entry);
    }


} // namespace ns3

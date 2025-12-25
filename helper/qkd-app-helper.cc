/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 * Author: Miralem Mehic <miralem.mehic@etf.unsa.ba>
 */

#include "ns3/core-module.h"
#include "ns3/inet-socket-address.h"
#include "ns3/packet-socket-address.h"
#include "ns3/socket.h"
#include "ns3/string.h"
#include "ns3/names.h"
#include "ns3/uinteger.h"
#include "qkd-app-helper.h"
#include "ns3/qkd-key-manager-system-application.h"
#include "ns3/qkd-location-register.h"

NS_LOG_COMPONENT_DEFINE ("QKDAppHelper");

namespace ns3 {

uint32_t QKDAppHelper::appCounter = 0;

QKDAppHelper::QKDAppHelper ()
{
    m_factory_qkd_app.SetTypeId ("ns3::QKDApp014");

    Address sinkAddress (InetSocketAddress (Ipv4Address::GetAny (), 80));
    m_factory_kms_app.SetTypeId ("ns3::QKDKeyManagerSystemApplication");
    m_factory_lr_app.SetTypeId ("ns3::QKDLocationRegister");
    m_factory_postprocessing_app.SetTypeId ("ns3::QKDPostprocessingApplication");
}

QKDAppHelper::QKDAppHelper (std::string protocol, Ipv4Address master, Ipv4Address slave, uint32_t keyRate)
{
    SetSettings(protocol, master, slave, keyRate);
}

void
QKDAppHelper::SetSettings ( std::string protocol, Ipv4Address master, Ipv4Address slave, uint32_t keyRate)
{
    uint16_t port;

    /*************************
    //      MASTER
    **************************/
    port = 80;
    Address sinkAddress (InetSocketAddress (Ipv4Address::GetAny (), port));
    Address masterAppRemoteAddress (InetSocketAddress (master, port));
    Address slaveAppRemoteAddress (InetSocketAddress (slave, port));
    m_factory_kms_app.SetTypeId ("ns3::QKDKeyManagerSystemApplication");

    m_protocol = protocol;

}


void
QKDAppHelper::SetAttribute ( std::string mFactoryName, std::string name, const AttributeValue &value)
{
    if(mFactoryName == "kms") {
        m_factory_kms_app.Set (name, value);
    } else if(mFactoryName == "postprocessing") {
        m_factory_postprocessing_app.Set (name, value);
    } else if(mFactoryName == "app") {
        m_factory_qkd_app.Set (name, value);
    }
}

void
QKDAppHelper::InstallKeyManager (Ptr<Node> node, Ipv4Address kmsAddress, uint32_t port, Ptr<QKDControl> controller)
{
    NS_LOG_FUNCTION(this << "Node ID" << node->GetId() << "Controller ID" << controller->GetNode()->GetId());
    Ptr<Application> appKMS = m_factory_kms_app.Create <Application> ();
    node->AddApplication (appKMS);

    Ptr<QKDKeyManagerSystemApplication> kms = appKMS->GetObject<QKDKeyManagerSystemApplication> ();
    kms->SetId(UUID::Sequential().string()); //Assign a unique identifier (UUID v1)
    kms->SetNode(node);
    kms->SetAddress(kmsAddress);
    kms->SetPort(port);
    kms->SetController(controller);
}

void
QKDAppHelper::InstallKeyManager (Ptr<Node> node, Ipv4Address kmsAddress, uint32_t port, Ptr<QKDControl> controller, Ptr<QCenController> cenController)
{
    NS_LOG_FUNCTION(this << "Node ID" << node->GetId() << "Controller ID" << controller->GetNode()->GetId());
    Ptr<Application> appKMS = m_factory_kms_app.Create <Application> ();
    node->AddApplication (appKMS);

    Ptr<QKDKeyManagerSystemApplication> kms = appKMS->GetObject<QKDKeyManagerSystemApplication> ();
    kms->SetId(UUID::Sequential().string()); //Assign a unique identifier (UUID v1)
    kms->SetNode(node);
    kms->SetAddress(kmsAddress);
    kms->SetPort(port);
    kms->SetController(controller);
    kms->SetCenController(cenController);
}

ApplicationContainer
QKDAppHelper::InstallPostProcessing (
    Ptr<Node>   node1,
    Ptr<Node>   node2,
    Address     masterAddress,
    Address     slaveAddress,
    Ptr<Node>   control1,
    Ptr<Node>   control2,
    uint32_t    keySize,
    DataRate    keyRate,
    uint32_t    packetSize,
    DataRate    dataRate
)
{
    return InstallPostProcessing(
        node1,
        node2,
        masterAddress,
        slaveAddress,
        control1,
        control2,
        keySize,
        keyRate,
        packetSize,
        dataRate,
        "",
        ""
    );
}

ApplicationContainer
QKDAppHelper::InstallPostProcessing (
    Ptr<Node>   node1,
    Ptr<Node>   node2,
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
)
{
    /**
    *   UDP Protocol is used for sifting (implementation detail)
    */
    TypeId m_tid    = TypeId::LookupByName ("ns3::TcpSocketFactory");
    TypeId udp_tid  = TypeId::LookupByName ("ns3::UdpSocketFactory");

    /**
     * Obtain KM addresses from the QKDN Controller!
     */
    Ipv4Address km1Address {control1->GetObject<QKDControl> ()->GetLocalKMAddress()};
    Ipv4Address km2Address {control2->GetObject<QKDControl> ()->GetLocalKMAddress()};
    NS_LOG_FUNCTION(this << "KM addresses" << km1Address << km2Address);

    /**************
    //  MASTER - Post-Processing running at node A
    ***************/
    m_factory_postprocessing_app.Set ("Local", AddressValue (masterAddress));
    m_factory_postprocessing_app.Set ("Local_Sifting", AddressValue (masterAddress));
    m_factory_postprocessing_app.Set ("Local_KMS", AddressValue (InetSocketAddress (km1Address, 80)));
    m_factory_postprocessing_app.Set ("Remote", AddressValue (slaveAddress));
    m_factory_postprocessing_app.Set ("Remote_Sifting", AddressValue (slaveAddress));

    m_factory_postprocessing_app.Set ("KeySize", UintegerValue (keySize));
    m_factory_postprocessing_app.Set ("KeyRate", DataRateValue (keyRate));
    m_factory_postprocessing_app.Set ("PacketSize", UintegerValue (packetSize));
    m_factory_postprocessing_app.Set ("DataRate", DataRateValue (dataRate));


    Ptr<Application> appMaster = m_factory_postprocessing_app.Create<Application> ();
    node1->AddApplication (appMaster);

    DynamicCast<QKDPostprocessingApplication> (appMaster)->SetSrc (node1);
    DynamicCast<QKDPostprocessingApplication> (appMaster)->SetDst (node2);

    //POST-processing sockets
    Ptr<Socket> sckt1 = Socket::CreateSocket (node1, m_tid);
    Ptr<Socket> sckt2 = Socket::CreateSocket (node1, m_tid);
    DynamicCast<QKDPostprocessingApplication> (appMaster)->SetSocket ("send", sckt1, true);
    DynamicCast<QKDPostprocessingApplication> (appMaster)->SetSocket ("sink", sckt2, true);
    //SIFTING
    Ptr<Socket> sckt1_sifting = Socket::CreateSocket (node1, udp_tid);
    Ptr<Socket> sckt2_sifting = Socket::CreateSocket (node1, udp_tid);
    DynamicCast<QKDPostprocessingApplication> (appMaster)->SetSiftingSocket ("send", sckt1_sifting);
    DynamicCast<QKDPostprocessingApplication> (appMaster)->SetSiftingSocket ("sink", sckt2_sifting);

    /**************
    //  SLAVE - Post-Processing running at node B
    ***************/
    m_factory_postprocessing_app.Set ("Local", AddressValue (slaveAddress));
    m_factory_postprocessing_app.Set ("Local_Sifting", AddressValue (slaveAddress));
    m_factory_postprocessing_app.Set ("Local_KMS", AddressValue (InetSocketAddress (km2Address, 80)));
    m_factory_postprocessing_app.Set ("Remote", AddressValue (masterAddress));
    m_factory_postprocessing_app.Set ("Remote_Sifting", AddressValue (masterAddress));

    m_factory_postprocessing_app.Set ("KeySize", UintegerValue (keySize));
    m_factory_postprocessing_app.Set ("KeyRate", DataRateValue (keyRate));
    m_factory_postprocessing_app.Set ("PacketSize", UintegerValue (packetSize));
    m_factory_postprocessing_app.Set ("DataRate", DataRateValue (dataRate));

    Ptr<Application> appSlave = m_factory_postprocessing_app.Create<Application> ();
    node2->AddApplication (appSlave);

    DynamicCast<QKDPostprocessingApplication> (appSlave)->SetSrc (node2);
    DynamicCast<QKDPostprocessingApplication> (appSlave)->SetDst (node1);

    //POST-processing sockets
    Ptr<Socket> sckt3 = Socket::CreateSocket (node2, m_tid);
    Ptr<Socket> sckt4 = Socket::CreateSocket (node2, m_tid);
    DynamicCast<QKDPostprocessingApplication> (appSlave)->SetSocket ("send", sckt3, false);
    DynamicCast<QKDPostprocessingApplication> (appSlave)->SetSocket ("sink", sckt4, false);
    //SIFTING
    Ptr<Socket> sckt3_sifting = Socket::CreateSocket (node2, udp_tid);
    Ptr<Socket> sckt4_sifting = Socket::CreateSocket (node2, udp_tid);
    DynamicCast<QKDPostprocessingApplication> (appSlave)->SetSiftingSocket ("send", sckt3_sifting);
    DynamicCast<QKDPostprocessingApplication> (appSlave)->SetSiftingSocket ("sink", sckt4_sifting);

    //Generate UUIDs

    std::string masterModuleId {UUID::Sequential().string()};
    std::string slaveModuleId {UUID::Sequential().string()};

    if(!masterUUID.empty() && !slaveUUID.empty()){
        masterModuleId = masterUUID;
        slaveModuleId = slaveUUID;
    }

    /*std::cout << "\nQKD MODULES INSTALLED\n" << "\tMaster ID:\t" << masterModuleId << "\n\tSlave ID:\t" << slaveModuleId
            << "\n\tConnecting:\t" << control1->GetObject<QKDControl>()->GetLocalKMNodeId() << "\t<-->\t"
            << control2->GetObject<QKDControl>()->GetLocalKMNodeId() << "\n\tKey rate:\t" << keyRate;*/
    //Assign UUIDs
    DynamicCast<QKDPostprocessingApplication> (appMaster)->SetId (masterModuleId);
    DynamicCast<QKDPostprocessingApplication> (appMaster)->SetPeerId (slaveModuleId);
    DynamicCast<QKDPostprocessingApplication> (appSlave)->SetId (slaveModuleId);
    DynamicCast<QKDPostprocessingApplication> (appSlave)->SetPeerId (masterModuleId);

    //Register QKD modules / PP applications at QKDN controller!
    control1->GetObject<QKDControl> ()->RegisterQKDModulePair (
        node1,          //Local QKD Module Node
        node2,          //Remote QKD Module Node
        masterModuleId, //Local QKD Module ID
        slaveModuleId,  //Remote QKD Module ID
        control1->GetObject<QKDControl> ()->GetLocalKMNode(), //Local KM Node
        control2->GetObject<QKDControl> ()->GetLocalKMNode()  //Remote KM Node
    );
    control2->GetObject<QKDControl> ()->RegisterQKDModulePair (
        node2,          //Local QKD Module Node
        node1,          //Remote QKD Module Node
        slaveModuleId,  //Local QKD Module ID
        masterModuleId, //Remote QKD Module ID
        control2->GetObject<QKDControl> ()->GetLocalKMNode(), //Local KM Node
        control1->GetObject<QKDControl> ()->GetLocalKMNode()  //Remote KM Node
    );

    ApplicationContainer apps;
    apps.Add(appMaster);
    apps.Add(appSlave);

    return apps;
}

ApplicationContainer
QKDAppHelper::InstallQKDApplication (
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
)
{
    return InstallQKDApplication(
        node1,
        node2,
        masterAddress,
        slaveAddress,
        control1,
        control2,
        connectionType,
        packetSize,
        dataRate,
        applicationType,
        "",
        ""
    );
}


ApplicationContainer
QKDAppHelper::InstallQKDApplication
(
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
)
{
    ApplicationContainer apps;

    /**
     * Obtain KM addresses from the QKDN Controller!
     */
    Ipv4Address km1Address {control1->GetObject<QKDControl> ()->GetLocalKMAddress()};
    Ipv4Address km2Address {control2->GetObject<QKDControl> ()->GetLocalKMAddress()};

    /**
     * Create unique identifiers
     */
    std::string aliceId {UUID::Sequential().string()};
    std::string bobId {UUID::Sequential().string()};
    if(!masterUUID.empty() && !slaveUUID.empty()){
        aliceId = masterUUID;
        bobId = slaveUUID;
    }

    std::cout << "\n\nCRYPTOGRAPHIC APPLICATION PAIR INSTALLED\n"
            << "\tMaster ID:\t" << aliceId << "\tLocal KMS node:\t" << control1->GetObject<QKDControl> ()->GetLocalKMNodeId()
            << "\n\tSlave ID:\t" << bobId << "\tLocal KMS node:\t" << control2->GetObject<QKDControl> ()->GetLocalKMNodeId()
            << "\n\tData rate:\t" << dataRate << "\tPacket size:\t" << packetSize;

    NS_LOG_FUNCTION(this << "\n\nCRYPTOGRAPHIC APPLICATION PAIR INSTALLED\n"
            << "\tMaster ID:\t" << aliceId << "\tLocal KMS node:\t" << control1->GetObject<QKDControl> ()->GetLocalKMNodeId()
            << "\n\tSlave ID:\t" << bobId << "\tLocal KMS node:\t" << control2->GetObject<QKDControl> ()->GetLocalKMNodeId()
            << "\n\tData rate:\t" << dataRate << "\tPacket size:\t" << packetSize;
    );

    if(applicationType == "etsi014"){

        Ptr<QKDApp014> appAlice = CreateObject<QKDApp014> ();
        Ptr<QKDApp014> appBob = CreateObject<QKDApp014> ();
        appAlice->Setup(
            connectionType,
            aliceId,    //This application ID
            bobId,   //Peer application ID
            masterAddress,
            slaveAddress,
            InetSocketAddress (km1Address, 80),
            packetSize,
            DataRate (dataRate),
            "alice"
        );
        node1->AddApplication (appAlice);

        appBob->Setup(
            connectionType,
            bobId,  //This application ID
            aliceId, //Peer application ID
            slaveAddress,
            masterAddress,
            InetSocketAddress (km2Address, 80),
            "bob"
        );
        node2->AddApplication (appBob);

        control1->GetObject<QKDControl> ()->RegisterQKDApplicationPair (
            aliceId,
            bobId,
            control2->GetObject<QKDControl> ()->GetLocalKMNode() //KM on which Bob is connected!
        );
        control2->GetObject<QKDControl> ()->RegisterQKDApplicationPair (
            bobId,
            aliceId,
            control1->GetObject<QKDControl> ()->GetLocalKMNode() //KM on which Alice is connected!
        );


        apps.Add(appAlice);
        apps.Add(appBob);

    }else if(applicationType == "etsi004"){

        Ptr<QKDApp004> appAlice = CreateObject<QKDApp004> ();
        Ptr<QKDApp004> appBob = CreateObject<QKDApp004> ();
        appAlice->Setup(
            connectionType,
            aliceId,    //This application ID
            bobId,   //Peer application ID
            masterAddress,
            slaveAddress,
            InetSocketAddress (km1Address, 80),
            packetSize,
            DataRate (dataRate),
            "alice"
        );
        node1->AddApplication (appAlice);

        appBob->Setup(
            connectionType,
            bobId,  //This application ID
            aliceId, //Peer application ID
            slaveAddress,
            masterAddress,
            InetSocketAddress (km2Address, 80),
            "bob"
        );
        node2->AddApplication (appBob);

        control1->GetObject<QKDControl> ()->RegisterQKDApplicationPair (
            aliceId,
            bobId,
            control2->GetObject<QKDControl> ()->GetLocalKMNode() //KM on which Bob is connected!
        );
        control2->GetObject<QKDControl> ()->RegisterQKDApplicationPair (
            bobId,
            aliceId,
            control1->GetObject<QKDControl> ()->GetLocalKMNode() //KM on which Alice is connected!
        );


        apps.Add(appAlice);
        apps.Add(appBob);

    }else
        std::cout << "ERROR: Unknown application type!";

    return apps;
}


} // namespace ns3


/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 * Author:  Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 *          Miralem Mehic <miralem.mehic@etf.unsa.ba>
 */

// Network topology

//       n7 ---------p2p-------- n8 (app)
//        |                       | 
//       n3 (kms) -- p2p ------- n4 (kms)
//       |                      |
//       n0 ---p2p-- n1 --p2p-- n2 (app)
//        |<----qkd--x----------->|

//
//        n5(QKDControl)
//        n6(QKDControl)
//
// - 1 QKD link (n0-n2)
// - 2 KMSs on nodes n3 and n4 
// - 1 ETSI 014 UDP application on nodes n7 (master) and n8 (slave)

#include <fstream>
#include "ns3/core-module.h"
#include "ns3/applications-module.h"
#include "ns3/internet-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/mobility-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/gnuplot.h"

#include "ns3/qkd-link-helper.h"
#include "ns3/qkd-app-helper.h"
#include "ns3/qkd-app-014.h"

#include "ns3/network-module.h"
#include "ns3/internet-apps-module.h"
#include "ns3/netanim-module.h" 
#include "ns3/fd-net-device-module.h" 

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("QKD_ETSI014");

uint32_t showKeyAdded = 0;
uint32_t showKeyServed = 0;
 
std::map<std::string, std::map<std::string, uint32_t> > m_generatedKeys;
std::map<std::string, std::map<std::string, uint32_t> > m_servedKeys;

std::map<std::string, std::pair<uint32_t, uint32_t> > m_dataAppSent;
std::map<std::string, std::pair<uint32_t, uint32_t> > m_dataAppReveived;
std::map<std::string, std::pair<uint32_t, uint32_t> > m_dataSigSent;
std::map<std::string, std::pair<uint32_t, uint32_t> > m_dataSigReceived;
std::map<std::string, std::pair<uint32_t, uint32_t> > m_dataKmSent;
std::map<std::string, std::pair<uint32_t, uint32_t> > m_dataKmReceived;
std::map<std::string, uint32_t> m_missedSendPacketCalls;

void
KeyGenerated(std::string context, const std::string& appId, const std::string& keyId, const uint32_t& amountInBits)
{   
    m_generatedKeys[appId][keyId] += amountInBits;    
}

void
KeyServed (std::string context, const std::string& appId, const std::string& keyId, const uint32_t& amountInBits)
{ 
    m_servedKeys[appId][keyId] += amountInBits;
}

void
SentPacket(std::string context, const std::string& appId, Ptr<const Packet> p){

    auto it = m_dataAppSent.find(appId);
    if(it == m_dataAppSent.end())
        m_dataAppSent.insert(std::make_pair(appId, std::make_pair(1, p->GetSize() )) );
    else{
        it->second.first++;
        it->second.second += p->GetSize();
    }
}

void MissedSendPacketCall (std::string context, const std::string& appId, Ptr<const Packet> p){

    auto it = m_missedSendPacketCalls.find(appId);
    if(it == m_missedSendPacketCalls.end())
        m_missedSendPacketCalls.insert(std::make_pair(appId, 1));
    else
        it->second++;
}

void
ReceivedPacket(std::string context, const std::string& appId, Ptr<const Packet> p){

    auto it = m_dataAppReveived.find(appId);
    if(it == m_dataAppReveived.end())
        m_dataAppReveived.insert(std::make_pair(appId, std::make_pair(1, p->GetSize())) );
    else{
        it->second.first++;
        it->second.second += p->GetSize();
    }
}

void
SentPacketSig(std::string context, const std::string& appId, Ptr<const Packet> p){

    auto it = m_dataSigSent.find(appId);
    if(it == m_dataSigSent.end())
        m_dataSigSent.insert(std::make_pair(appId, std::make_pair(1, p->GetSize())) );
    else{
        it->second.first++;
        it->second.second += p->GetSize();
    }
}

void
ReceivedPacketSig(std::string context, const std::string& appId, Ptr<const Packet> p){

    auto it = m_dataSigReceived.find(appId);
    if(it == m_dataSigReceived.end())
        m_dataSigReceived.insert(std::make_pair(appId, std::make_pair(1, p->GetSize())) );
    else{
        it->second.first++;
        it->second.second += p->GetSize();
    }
}

void
SentPacketToKMS(std::string context, const std::string& appId, Ptr<const Packet> p){

    auto it = m_dataKmSent.find(appId);
    if(it == m_dataKmSent.end())
        m_dataKmSent.insert(std::make_pair(appId, std::make_pair(1, p->GetSize())) );
    else{
        it->second.first++;
        it->second.second += p->GetSize();
    }
}

void
ReceivedPacketFromKMS(std::string context, const std::string& appId, Ptr<const Packet> p){

    auto it = m_dataKmReceived.find(appId);
    if(it == m_dataKmReceived.end())
        m_dataKmReceived.insert(std::make_pair(appId, std::make_pair(1, p->GetSize())) );
    else{
        it->second.first++;
        it->second.second += p->GetSize();
    }
}

void
Ratio(){
    std::cout << "\n\nAPPLICATION STATS:\n";
    std::cout << "\n\tAPP-APP Data Packets Sent:";
    for(const auto &el: m_dataAppSent)
        std::cout << "\n\t\tApplication ID:\t" << el.first
        << "\tNumber:\t" << el.second.first << "\t\tBytes:\t" << el.second.second;
    std::cout << "\n\n\tAPP-APP Data Packets Received:";
    for(const auto &el: m_dataAppReveived)
        std::cout << "\n\t\tApplication ID:\t" << el.first
        << "\tNumber:\t" << el.second.first << "\t\tBytes:\t" << el.second.second;
    std::cout << "\n\n\tMissed Send Packet Calls:";
    for(const auto &el: m_missedSendPacketCalls)
        std::cout << "\n\t\tApplication ID:\t" << el.first << "\tNumber:\t" << el.second;
    std::cout << "\n\n\tAPP-APP Signaling Packets Sent:";
    for(const auto &el: m_dataSigSent)
        std::cout << "\n\t\tApplication ID:\t" << el.first
        << "\tNumber:\t" << el.second.first << "\t\tBytes:\t" << el.second.second;
    std::cout << "\n\n\tAPP-APP Signaling Packets Received:";
    for(const auto &el: m_dataSigReceived)
        std::cout << "\n\t\tApplication ID:\t" << el.first
        << "\tNumber:\t" << el.second.first << "\t\tBytes:\t" << el.second.second;
    std::cout << "\n\n\tAPP-KM Packets Sent:";
    for(const auto &el: m_dataKmSent)
        std::cout << "\n\t\tApplication ID:\t" << el.first
        << "\tNumber:\t" << el.second.first << "\t\tBytes:\t" << el.second.second;
    std::cout << "\n\n\tAPP-KM Packets Received:";
    for(const auto &el: m_dataKmReceived)
        std::cout << "\n\t\tApplication ID:\t" << el.first
        << "\tNumber:\t" << el.second.first << "\t\tBytes:\t" << el.second.second;

    std::cout << "\n\nQKD LINK STATS:\n";
    for (const auto &el: m_generatedKeys){
        for(const auto &el1 : el.second)
            std::cout << "\n\tLink (" << el.first << "-"<< el1.first << ")\tGenerated (bits):" << el1.second;
    }

    std::cout << "\n\nSERVICE STATS:\n";
    for(auto const &el: m_servedKeys){
        std::cout << "\n\tApplication ID:\t" << el.first;
        for(auto const &el1: el.second)   
            std::cout << "\n\t\tKey ID:\t" << el1.first << "\t\tServed (bits):\t" << el1.second;
        std::cout << "\n";
    }

}

int main (int argc, char *argv[])
{
    Packet::EnablePrinting();
    PacketMetadata::Enable ();
    //
    // Explicitly create the nodes required by the topology (shown above).
    //
    NS_LOG_INFO ("Create nodes.");

    NodeContainer n; 

    double  appHoldTime = 0.5;
    uint16_t simulationTime = 5000;
    uint16_t appStartTime = 50;
    uint16_t appStopTime = 5000;
    uint16_t qkdStartTime = 0;
    uint16_t qkdStopTime = 5000;
    uint32_t encryptionType = 1; //0-unencrypted, 1-OTP, 2-AES256
    uint32_t numberOfKeyToFetchFromKMS = 3;
    uint32_t aesLifetime = 10000; //In bytes! 64GB = 68719476736B
    uint32_t keyBufferLengthEncryption = 3;
    uint32_t authenticationType = 1; //0-unauthenticated, 1-VMAC, 2,3-MD5,SHA1
    uint32_t keyBufferLengthAuthentication = 6;
    uint32_t useCrypto = 0;
    NS_LOG_DEBUG(appHoldTime);
    NS_LOG_DEBUG(simulationTime);
    NS_LOG_DEBUG(encryptionType);
    NS_LOG_DEBUG(numberOfKeyToFetchFromKMS);
    NS_LOG_DEBUG(aesLifetime);
    NS_LOG_DEBUG(keyBufferLengthEncryption);
    NS_LOG_DEBUG(authenticationType);
    NS_LOG_DEBUG(keyBufferLengthAuthentication);
    NS_LOG_DEBUG(useCrypto);

    uint32_t appRate = 10; //In bps
    uint32_t appPacketSize =  800; //In bytes
    uint32_t ppKeyRate = 10000; //In bps
    uint32_t ppKeySize = 8192; //In bytes
    uint32_t ppPacketSize = 100; //In bytes
    uint32_t ppRate = 1000;
    NS_LOG_DEBUG(appRate);
    NS_LOG_DEBUG(appPacketSize);
    NS_LOG_DEBUG(ppKeyRate);
    NS_LOG_DEBUG(ppKeySize);
    NS_LOG_DEBUG(ppPacketSize);
    NS_LOG_DEBUG(ppRate);

    bool trace = false;
    n.Create (9); 

    uint32_t stream = 15;
    uint32_t seed = 100;

    ns3::RngSeedManager::SetSeed(seed);
    RngSeedManager::SetRun (stream);
    srand( stream ); //seeding for the first time only!

    // Configure command line parameters
    CommandLine cmd;
    cmd.AddValue ("simTime", "Simulation time (seconds)", simulationTime);
    cmd.AddValue ("appHoldTime", "How long (seconds) should QKDApp004 wait to close socket to KMS after receiving REST response?", appHoldTime);
    cmd.AddValue ("appStartTime", "Application start time (seconds)", appStartTime);
    cmd.AddValue ("appStopTime", "Application stop time (seconds)", appStopTime);
    cmd.AddValue ("qkdStartTime", "QKD start time (seconds)", qkdStartTime);
    cmd.AddValue ("qkdStopTime", "QKD stop time (seconds)", qkdStopTime);
    cmd.AddValue ("encryptionType", "Type of encryption to be used", encryptionType);
    cmd.AddValue ("authenticationType", "Type of authentication to be used", authenticationType);
    cmd.AddValue ("aesLifetime", "How many packets to encrypt with the same AES key?", aesLifetime);
    cmd.AddValue ("numberOfKeyToFetchFromKMS", "How many keys to fetch from KMS in a query?", numberOfKeyToFetchFromKMS);
    cmd.AddValue ("keyBufferLengthEncryption", "How many keys to store in local buffer of QKDApp004 for encryption?", keyBufferLengthEncryption);
    cmd.AddValue ("keyBufferLengthAuthentication", "How many keys to store in local buffer of QKDApp004 for authentication?", keyBufferLengthAuthentication);
    cmd.AddValue ("useCrypto", "Perform crypto functions?", useCrypto);
    cmd.AddValue ("seed", "Random seed value", seed);
    cmd.AddValue ("trace", "Enable datapath stats and pcap traces", trace);
    cmd.Parse (argc, argv);

    NodeContainer n0n1 = NodeContainer (n.Get(0), n.Get (1));
    NodeContainer n1n2 = NodeContainer (n.Get(1), n.Get (2));
    NodeContainer n0n3 = NodeContainer (n.Get(0), n.Get (3));
    NodeContainer n7n3 = NodeContainer (n.Get(7), n.Get (3));
    NodeContainer n2n4 = NodeContainer (n.Get(2), n.Get (4));
    NodeContainer n8n4 = NodeContainer (n.Get(8), n.Get (4));
    NodeContainer n3n4 = NodeContainer (n.Get(3), n.Get (4));

    InternetStackHelper internet;
    internet.Install (n);

    // Set Mobility for all nodes
    MobilityHelper mobility;
    Ptr<ListPositionAllocator> positionAlloc = CreateObject <ListPositionAllocator>();
    positionAlloc ->Add(Vector(0,   0, 0));     // node0 //Install PPApps and QKDApps
    positionAlloc ->Add(Vector(200, 0, 0));     // node1 // optional
    positionAlloc ->Add(Vector(400, 0, 0));     // node2 //Install PPApps and QKDApps
    positionAlloc ->Add(Vector(0,   100, 0));   // node3 //KM node 1
    positionAlloc ->Add(Vector(400, 100, 0));   // node4 //KM node 2
    positionAlloc ->Add(Vector(0,   200, 0));   // node5 //Controller 1
    positionAlloc ->Add(Vector(400, 200, 0));   // node6 //Controller 2
    positionAlloc ->Add(Vector(0,   50,  0));   // test-PPApp - slave!
    positionAlloc ->Add(Vector(400, 50,  0));   // test-PPApp - master!
    mobility.SetPositionAllocator(positionAlloc);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(n);
 

    EmuFdNetDeviceHelper emuDevice;
    emuDevice.SetDeviceName ("enp0s31f6");

    //------------------ NODE 3 - KMS Emulated interface
    NetDeviceContainer tempDevNode3 = emuDevice.Install (n.Get(3));
    Ptr<NetDevice> device_emu_node3 = tempDevNode3.Get (0);
    std::string macStringTempNode3 ("00:00:00:00:00:81");
    Mac48Address macTempNode3(macStringTempNode3.c_str());
    device_emu_node3->SetAttribute ("Address", Mac48AddressValue (macTempNode3)); 

    Ptr<Ipv4> ipv4_node3 = n.Get(3)->GetObject<Ipv4> ();
    uint32_t interface_emu_node3 = ipv4_node3->AddInterface (device_emu_node3);
    Ipv4InterfaceAddress address_emu_node3 = Ipv4InterfaceAddress (Ipv4Address("100.100.129.81"), Ipv4Mask("255.255.255.0"));
    ipv4_node3->AddAddress (interface_emu_node3, address_emu_node3);
    ipv4_node3->SetMetric (interface_emu_node3, 1);
    ipv4_node3->SetUp (interface_emu_node3);
 
    //------------------ NODE 4 - KMS Emulated interface
    NetDeviceContainer tempDevNode4 = emuDevice.Install (n.Get(4));
    Ptr<NetDevice> device_emu_node4 = tempDevNode4.Get (0);
    std::string macStringTempNode4 ("00:00:00:00:00:82");
    Mac48Address macTempNode4(macStringTempNode4.c_str());
    device_emu_node4->SetAttribute ("Address", Mac48AddressValue (macTempNode4)); 

    Ptr<Ipv4> ipv4_node4 = n.Get(4)->GetObject<Ipv4> ();
    uint32_t interface_emu_node4 = ipv4_node4->AddInterface (device_emu_node4);
    Ipv4InterfaceAddress address_emu_node4 = Ipv4InterfaceAddress (Ipv4Address("100.100.129.82"), Ipv4Mask("255.255.255.0"));
    ipv4_node4->AddAddress (interface_emu_node4, address_emu_node4);
    ipv4_node4->SetMetric (interface_emu_node4, 1);
    ipv4_node4->SetUp (interface_emu_node4);


    // We create the channels first without any IP addressing information
    NS_LOG_INFO ("Create channels.");
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute ("DataRate", StringValue ("50Mbps"));
    p2p.SetChannelAttribute ("Delay", StringValue ("2ms"));

    NetDeviceContainer d0d1 = p2p.Install (n0n1);
    NetDeviceContainer d1d2 = p2p.Install (n1n2);
    NetDeviceContainer d0d3 = p2p.Install (n0n3);
    NetDeviceContainer d7d3 = p2p.Install (n7n3);
    NetDeviceContainer d2d4 = p2p.Install (n2n4);
    NetDeviceContainer d8d4 = p2p.Install (n8n4);
    NetDeviceContainer d3d4 = p2p.Install (n3n4);

    //
    // We've got the "hardware" in place.  Now we need to add IP addresses.
    //
    NS_LOG_INFO ("Assign IP Addresses.");
    Ipv4AddressHelper ipv4;

    ipv4.SetBase ("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer i0i1 = ipv4.Assign (d0d1);
    ipv4.SetBase ("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer i1i2 = ipv4.Assign (d1d2);
    ipv4.SetBase ("10.1.3.0", "255.255.255.0");
    Ipv4InterfaceContainer i0i3 = ipv4.Assign (d0d3);
    ipv4.SetBase ("10.1.4.0", "255.255.255.0");
    Ipv4InterfaceContainer i2i4 = ipv4.Assign (d2d4);
    ipv4.SetBase ("10.1.5.0", "255.255.255.0");
    Ipv4InterfaceContainer i3i4 = ipv4.Assign (d3d4);  
    ipv4.SetBase ("10.1.6.0", "255.255.255.0");
    Ipv4InterfaceContainer i7i3 = ipv4.Assign (d7d3);
    ipv4.SetBase ("10.1.7.0", "255.255.255.0");
    Ipv4InterfaceContainer i8i4 = ipv4.Assign (d8d4);

    QKDAppHelper QAHelper;
    QKDLinkHelper QLinkHelper;

    //  install QKD Control the node 5 and 6
    Ptr<QKDControl> controlSiteA = QLinkHelper.InstallQKDNController ( n.Get(5) );
    Ptr<QKDControl> controlSiteB = QLinkHelper.InstallQKDNController ( n.Get(6) );
    QLinkHelper.ConfigureQBuffers ( //Configure Q-Buffers
        {controlSiteA, controlSiteB}, 
        1024,       //min_bits
        1800,      //thr_bits
        500000000,  //max_bits
        512         //default key size in bits
    );
    
    //Config::SetDefault ("ns3::QKDKeyManagerSystemApplication::SBufferMaxSizeBits", UintegerValue (3000));

    //  install KMs on nodes 3 and 4
    QAHelper.InstallKeyManager(//Install key manager for site A
        n.Get(3),           //Node KM-A
        i3i4.GetAddress(0), //IP address KM-A
        80,                 //Port
        controlSiteA        //Assigned controller A
    );
    QAHelper.InstallKeyManager( //Install key manager for site B
        n.Get(4),           //Node KM-B
        i3i4.GetAddress(1), //IP address KM-B
        80,                 //Port
        controlSiteB        //Assigned controller B
    );

    NS_LOG_INFO ("Create Applications.");

    std::cout << "SrcNode: " << n.Get(0)->GetId() << " Source IP address: " << i0i1.GetAddress(0) << std::endl;
    std::cout << "DstNode: " << n.Get(2)->GetId() << " Destination IP address: " << i1i2.GetAddress(1) << std::endl;
    std::cout << "SrcKMSNode: " << n.Get(3)->GetId() << " Destination KMS IP address: " << i3i4.GetAddress(0) << std::endl;
    std::cout << "DstKMSNode: " << n.Get(4)->GetId() << " Destination KMS IP address: " << i3i4.GetAddress(1) << std::endl;

    //Create APP to generate keys
    ApplicationContainer postprocessingApplications;
    postprocessingApplications.Add(
        QAHelper.InstallPostProcessing(
            n.Get(0),   //QKD module A
            n.Get(2),   //QKD module B
            InetSocketAddress (i0i1.GetAddress(0), 102),    //Address A
            InetSocketAddress (i1i2.GetAddress(1), 102),    //Address B
            n.Get(5),  //Controller-A
            n.Get(6),  //Controller-B
            ppKeySize,   //size of key to be added to QKD buffer
            DataRate (ppKeyRate), //average QKD key rate
            ppPacketSize,    //average data packet size
            DataRate (ppRate) //average data traffic rate
        )
    );
    postprocessingApplications.Start (Seconds (qkdStartTime));
    postprocessingApplications.Stop (Seconds (qkdStopTime));

    //Set default values for applications created below
    Config::SetDefault ("ns3::QKDApp014::NumberOfKeyToFetchFromKMS", UintegerValue (numberOfKeyToFetchFromKMS));//Number of keys to obtain per request!
    Config::SetDefault ("ns3::QKDApp014::AuthenticationType", UintegerValue (authenticationType)); //(0-unauthenticated, 1-VMAC, 2-MD5, 3-SHA1)
    Config::SetDefault ("ns3::QKDApp014::EncryptionType", UintegerValue (encryptionType)); //(0-unencrypted, 1-OTP, 2-AES)
    Config::SetDefault ("ns3::QKDApp014::AESLifetime", UintegerValue (aesLifetime));
    Config::SetDefault ("ns3::QKDApp014::UseCrypto", UintegerValue (useCrypto));

    uint16_t communicationPort = 8081;
    ApplicationContainer cryptographicApplications; 
    cryptographicApplications.Add(
        QAHelper.InstallQKDApplication(
            n.Get(8),
            n.Get(7),
            InetSocketAddress (i8i4.GetAddress(0), communicationPort),    //Address A
            InetSocketAddress (i7i3.GetAddress(0), communicationPort),    //Address B
            n.Get(6),  //Controller-A
            n.Get(5),  //Controller-B
            "tcp",      //Connection type
            appPacketSize, //Payload size
            DataRate (appRate), //Data rate
            "etsi014",   //Application type
            "aaac7de9-5826-11ef-8057-9b39f247aaa",
            "bbbc7de9-5826-11ef-8057-9b39f247bbb"
        )
    );
    cryptographicApplications.Start (Seconds (appStartTime));
    cryptographicApplications.Stop (Seconds (appStopTime));


    Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

    QLinkHelper.CreateTopologyGraph({controlSiteA, controlSiteB});
    QLinkHelper.PopulateRoutingTables();
    QLinkHelper.AddGraphs();


    //We are interested to connect to n6 and n11 so we spefiy routing for them
    Ipv4StaticRoutingHelper ipv4RoutingHelper;
    Ptr<Ipv4StaticRouting> staticRouting = ipv4RoutingHelper.GetStaticRouting (ipv4_node3); 
    staticRouting->SetDefaultRoute(Ipv4Address("100.100.128.1"),interface_emu_node3,1);
    
    Ptr<Ipv4StaticRouting> staticRouting0 = ipv4RoutingHelper.GetStaticRouting (ipv4_node4); 
    staticRouting0->SetDefaultRoute(Ipv4Address("100.100.128.1"),interface_emu_node4,1);


    //////////////////////////////////////
    ////         STATISTICS
    //////////////////////////////////////

    //Connect Traces for QKD Cryptographic Applications
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp014/Tx", MakeCallback(&SentPacket));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp014/Rx", MakeCallback(&ReceivedPacket));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp014/Mx", MakeCallback(&MissedSendPacketCall));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp014/TxSig", MakeCallback(&SentPacketSig));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp014/RxSig", MakeCallback(&ReceivedPacketSig));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp014/TxKMS", MakeCallback(&SentPacketToKMS));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp014/RxKMS", MakeCallback(&ReceivedPacketFromKMS));

    //Connect Traces for KM key statistics
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDKeyManagerSystemApplication/KeyServed", MakeCallback(&KeyServed));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDKeyManagerSystemApplication/QKDKeyGenerated", MakeCallback(&KeyGenerated));

    if(trace){
        //if we need we can create pcap files
        AsciiTraceHelper ascii;
        p2p.EnableAsciiAll (ascii.CreateFileStream ("qkd_etis014_emulation.tr"));
        p2p.EnablePcapAll ("qkd_etis014_emulation");
        AnimationInterface anim ("qkd_etis014_emulation.xml");  // where "animation.xml" is any arbitrary filename
    }

    Simulator::Stop (Seconds (simulationTime));
    Simulator::Run ();

    //Finally print the graphs
    QLinkHelper.PrintGraphs();

    std::cout << "simTime:\t" << simulationTime << "\n";
    std::cout << "appStartTime:\t" << appStartTime << "\n";
    std::cout << "appStopTime:\t" << appStopTime << "\n";
    std::cout << "qkdStartTime:\t" << qkdStartTime << "\n";
    std::cout << "qkdStopTime:\t" << qkdStopTime << "\n";
    std::cout << "encryptionType:\t" << encryptionType << "\n";
    std::cout << "authenticationType:\t" << authenticationType << "\n";
    std::cout << "aesLifetime:\t" << aesLifetime << "\n";
    std::cout << "useCrypto:\t" << useCrypto << "\n";
    std::cout << "trace:\t" << trace << "\n";

    Ratio();
    Simulator::Destroy ();
}

/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 * Author:  Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 *          Miralem Mehic <miralem.mehic@etf.unsa.ba>
 */ 

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
#include "ns3/qkd-app-004.h"

#include "ns3/network-module.h"
#include "ns3/internet-apps-module.h"
#include "ns3/netanim-module.h"


using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("QKD_ETSI004");

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
            std::cout << "\n\t QKDSystem link: " << el.first << "\t keyId: "<< el1.first << "\t Size: " << el1.second / 2 << " (bits)";
    }

    std::cout << "\n\nSERVICE STATS:\n";
    for(auto const &el: m_servedKeys){
        std::cout << "\n\tApplication ID:\t" << el.first;
        for(auto const &el1: el.second)   
            std::cout << "\n\t\tKey ID:\t" << el1.first << "\t Size: " << el1.second << " (bits)";
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
    uint16_t simulationTime = 500;
    uint16_t appStartTime = 50;
    uint16_t appStopTime = 500;
    uint16_t qkdStartTime = 0;
    uint16_t qkdStopTime = 500;
    uint32_t authenticationType = 1; //0-unauthenticated, 1-VMAC, 2,3-MD5,SHA1
    uint32_t encryptionType = 1; //0-unencrypted, 1-OTP, 2-AES256
    uint32_t numberOfKeyToFetchFromKMS = 3;
    uint32_t aesLifetime = 10000; //In bytes! 64GB = 68719476736B
    uint32_t keyBufferLengthEncryption = 3;
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

    uint32_t appRate = 100000; //In bps
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
    n.Create (18);

    uint32_t stream = 15;
    uint32_t seed = 100;

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
    cmd.AddValue ("keyBufferLengthEncryption", "How many keys to store in local buffer of QKDApp004 for encryption?", keyBufferLengthEncryption);
    cmd.AddValue ("keyBufferLengthAuthentication", "How many keys to store in local buffer of QKDApp004 for authentication?", keyBufferLengthAuthentication);
    cmd.AddValue ("useCrypto", "Perform crypto functions?", useCrypto);
    cmd.AddValue ("seed", "Random seed value", seed);
    cmd.AddValue ("trace", "Enable datapath stats and pcap traces", trace);
    cmd.Parse (argc, argv);

    ns3::RngSeedManager::SetSeed(seed);
    RngSeedManager::SetRun (stream);
    srand( stream ); //seeding for the first time only!

    NodeContainer n0n2 = NodeContainer (n.Get(0), n.Get (2));
    NodeContainer n0n1 = NodeContainer (n.Get(0), n.Get (1));
    NodeContainer n1n3 = NodeContainer (n.Get(1), n.Get (3));
    NodeContainer n2n3 = NodeContainer (n.Get(2), n.Get (3));

    NodeContainer n2n4 = NodeContainer (n.Get(2), n.Get (4));
    NodeContainer n2n6 = NodeContainer (n.Get(2), n.Get (6));
    NodeContainer n3n5 = NodeContainer (n.Get(3), n.Get (5));
    NodeContainer n3n7 = NodeContainer (n.Get(3), n.Get (7));

    NodeContainer n4n5 = NodeContainer (n.Get(4), n.Get (5));
    NodeContainer n4n8 = NodeContainer (n.Get(4), n.Get (8));
    NodeContainer n5n9 = NodeContainer (n.Get(5), n.Get (9));
    NodeContainer n6n7 = NodeContainer (n.Get(6), n.Get (7));
    NodeContainer n6n8 = NodeContainer (n.Get(6), n.Get (8));
    NodeContainer n7n9 = NodeContainer (n.Get(7), n.Get (9));

    NodeContainer n8n10 = NodeContainer (n.Get(8), n.Get (10));
    NodeContainer n8n9 = NodeContainer (n.Get(8), n.Get (9));
    NodeContainer n9n11 = NodeContainer (n.Get(9), n.Get (11));
    NodeContainer n10n11 = NodeContainer (n.Get(10), n.Get (11));  

    InternetStackHelper internet; 
    internet.Install (n);

    // Set Mobility for all nodes
    MobilityHelper mobility;
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(n);

    // We create the channels first without any IP addressing information
    NS_LOG_INFO ("Create channels.");
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute ("DataRate", StringValue ("50Mbps"));
    p2p.SetChannelAttribute ("Delay", StringValue ("2ms"));

    NetDeviceContainer d0d2 = p2p.Install (n0n2);
    NetDeviceContainer d0d1 = p2p.Install (n0n1);
    NetDeviceContainer d1d3 = p2p.Install (n1n3);
    NetDeviceContainer d2d3 = p2p.Install (n2n3);

    NetDeviceContainer d2d4 = p2p.Install (n2n4);
    NetDeviceContainer d2d6 = p2p.Install (n2n6);
    NetDeviceContainer d3d5 = p2p.Install (n3n5);
    NetDeviceContainer d3d7 = p2p.Install (n3n7);

    NetDeviceContainer d4d5 = p2p.Install (n4n5);
    NetDeviceContainer d4d8 = p2p.Install (n4n8);
    NetDeviceContainer d5d9 = p2p.Install (n5n9);
    NetDeviceContainer d6d7 = p2p.Install (n6n7);
    NetDeviceContainer d6d8 = p2p.Install (n6n8);
    NetDeviceContainer d7d9 = p2p.Install (n7n9);

    NetDeviceContainer d8d10 = p2p.Install (n8n10);
    NetDeviceContainer d8d9 = p2p.Install (n8n9);
    NetDeviceContainer d9d11 = p2p.Install (n9n11);
    NetDeviceContainer d10d11 = p2p.Install (n10n11);

    //
    // We've got the "hardware" in place.  Now we need to add IP addresses.
    //
    NS_LOG_INFO ("Assign IP Addresses.");
    Ipv4AddressHelper ipv4;

    ipv4.SetBase ("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer i0i2 = ipv4.Assign (d0d2);
    ipv4.SetBase ("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer i0i1 = ipv4.Assign (d0d1);
    ipv4.SetBase ("10.1.3.0", "255.255.255.0");
    Ipv4InterfaceContainer i1i3 = ipv4.Assign (d1d3);
    ipv4.SetBase ("10.1.4.0", "255.255.255.0");
    Ipv4InterfaceContainer i2i3 = ipv4.Assign (d2d3);

    ipv4.SetBase ("10.1.5.0", "255.255.255.0");
    Ipv4InterfaceContainer i2i4 = ipv4.Assign (d2d4);
    ipv4.SetBase ("10.1.6.0", "255.255.255.0");
    Ipv4InterfaceContainer i2i6 = ipv4.Assign (d2d6);
    ipv4.SetBase ("10.1.7.0", "255.255.255.0");
    Ipv4InterfaceContainer i3i5 = ipv4.Assign (d3d5);
    ipv4.SetBase ("10.1.8.0", "255.255.255.0");
    Ipv4InterfaceContainer i3i7 = ipv4.Assign (d3d7);

    ipv4.SetBase ("10.1.9.0", "255.255.255.0");
    Ipv4InterfaceContainer i4i5 = ipv4.Assign (d4d5);
    ipv4.SetBase ("10.1.10.0", "255.255.255.0");
    Ipv4InterfaceContainer i4i8 = ipv4.Assign (d4d8);
    ipv4.SetBase ("10.1.11.0", "255.255.255.0");
    Ipv4InterfaceContainer i5i9 = ipv4.Assign (d5d9);
    ipv4.SetBase ("10.1.12.0", "255.255.255.0");
    Ipv4InterfaceContainer i6i7 = ipv4.Assign (d6d7);
    ipv4.SetBase ("10.1.13.0", "255.255.255.0");
    Ipv4InterfaceContainer i6i8 = ipv4.Assign (d6d8);
    ipv4.SetBase ("10.1.14.0", "255.255.255.0");
    Ipv4InterfaceContainer i7i9 = ipv4.Assign (d7d9);

    ipv4.SetBase ("10.1.15.0", "255.255.255.0");
    Ipv4InterfaceContainer i8i10 = ipv4.Assign (d8d10);
    ipv4.SetBase ("10.1.16.0", "255.255.255.0");
    Ipv4InterfaceContainer i8i9 = ipv4.Assign (d8d9);
    ipv4.SetBase ("10.1.17.0", "255.255.255.0");
    Ipv4InterfaceContainer i9i11 = ipv4.Assign (d9d11);
    ipv4.SetBase ("10.1.18.0", "255.255.255.0");
    Ipv4InterfaceContainer i10i11 = ipv4.Assign (d10d11);

    QKDAppHelper QAHelper;
    QKDLinkHelper QLinkHelper;

    //  install QKD Control the node 5 and 6
    Ptr<QKDControl> controlSiteA = QLinkHelper.InstallQKDNController ( n.Get(12) );
    Ptr<QKDControl> controlSiteB = QLinkHelper.InstallQKDNController ( n.Get(13) );
    Ptr<QKDControl> controlSiteC = QLinkHelper.InstallQKDNController ( n.Get(14) );
    Ptr<QKDControl> controlSiteD = QLinkHelper.InstallQKDNController ( n.Get(15) );
    Ptr<QKDControl> controlSiteE = QLinkHelper.InstallQKDNController ( n.Get(16) );
    Ptr<QKDControl> controlSiteF = QLinkHelper.InstallQKDNController ( n.Get(17) );
    QLinkHelper.ConfigureQBuffers ( //Configure Q-Buffers
        {controlSiteA, controlSiteB, controlSiteC, controlSiteD, controlSiteE, controlSiteF},
        1024,       //min_bits
        1800,       //thr_bits
        500000000,  //max_bits
        512         //default key size in bits
    );
    QLinkHelper.ConfigureRSBuffers ( //Configure S-Buffers for relay (RBuffers)!
        {controlSiteA, controlSiteB, controlSiteC, controlSiteD, controlSiteE, controlSiteF},
        0,     //min_bits
        16000, //thr_bits
        64000, //max_bits
        512    //default key size in bits
    );

    //  install KMs on nodes 3 and 4
    QAHelper.InstallKeyManager(//Install key manager for site A
        n.Get(1),           //Node KM-A
        i1i3.GetAddress(0), //IP address KM-A
        80,                 //Port
        controlSiteA        //Assigned controller A
    );
    QAHelper.InstallKeyManager( //Install key manager for site B
        n.Get(3),           //Node KM-B
        i1i3.GetAddress(1), //IP address KM-B
        80,                 //Port
        controlSiteB        //Assigned controller B
    );
    QAHelper.InstallKeyManager(
        n.Get(5),
        i3i5.GetAddress(1),
        80,
        controlSiteC
    );
    QAHelper.InstallKeyManager(
        n.Get(7),
        i3i7.GetAddress(1),
        80,
        controlSiteD
    );
    QAHelper.InstallKeyManager(
        n.Get(9),
        i9i11.GetAddress(0),
        80,
        controlSiteE
    );
    QAHelper.InstallKeyManager(
        n.Get(11),
        i9i11.GetAddress(1),
        80,
        controlSiteF
    );

    NS_LOG_INFO ("Create Applications.");

    std::cout << "QKDsiteA: " << n.Get(0)->GetId() << " IP address: " << i0i2.GetAddress(0) << std::endl;
    std::cout << "QKDsiteB: " << n.Get(2)->GetId() << " IP address: " << i0i2.GetAddress(1) << std::endl;
    std::cout << "QKDsiteC: " << n.Get(4)->GetId() << " IP address: " << i2i4.GetAddress(1) << std::endl;
    std::cout << "KMsiteA: "  << n.Get(1)->GetId() << " IP address: " << i1i3.GetAddress(0) << std::endl;
    std::cout << "KMsiteB: "  << n.Get(3)->GetId() << " IP address: " << i1i3.GetAddress(1) << std::endl;
    std::cout << "KMsiteC: "  << n.Get(5)->GetId() << " IP address: " << i3i5.GetAddress(1) << std::endl;

    ApplicationContainer postprocessingApplications;
    postprocessingApplications.Add(
        QAHelper.InstallPostProcessing(
            n.Get(0),   //QKD module A
            n.Get(2),   //QKD module B
            InetSocketAddress (i0i2.GetAddress(0), 102),    //Address A
            InetSocketAddress (i0i2.GetAddress(1), 102),    //Address B
            n.Get(12),  //Controller-A
            n.Get(13),  //Controller-B
            ppKeySize,   //size of key to be added to QKD buffer
            DataRate (ppKeyRate), //average QKD key rate
            ppPacketSize,    //average data packet size
            DataRate (ppRate) //average data traffic rate
        )
    );
    postprocessingApplications.Add(
        QAHelper.InstallPostProcessing(
            n.Get(2),
            n.Get(4),
            InetSocketAddress (i2i4.GetAddress(0), 104),
            InetSocketAddress (i2i4.GetAddress(1), 104),
            n.Get(13),
            n.Get(14),
            ppKeySize,
            DataRate (ppKeyRate),
            ppPacketSize,
            DataRate (ppRate)
        )
    );
    postprocessingApplications.Add(
        QAHelper.InstallPostProcessing(
            n.Get(2),
            n.Get(6),
            InetSocketAddress (i2i6.GetAddress(0), 106),
            InetSocketAddress (i2i6.GetAddress(1), 106),
            n.Get(13),
            n.Get(15),
            ppKeySize,
            DataRate (ppKeyRate),
            ppPacketSize,
            DataRate (ppRate)
        )
    );
    postprocessingApplications.Add(
        QAHelper.InstallPostProcessing(
            n.Get(4),
            n.Get(8),
            InetSocketAddress (i4i8.GetAddress(0), 108),
            InetSocketAddress (i4i8.GetAddress(1), 108),
            n.Get(14),
            n.Get(16),
            ppKeySize,
            DataRate (7000), //@testing relay errors, use different ppKeyRate: e.g., 7000
            ppPacketSize,
            DataRate (ppRate)
        )
    );
    postprocessingApplications.Add(
        QAHelper.InstallPostProcessing(
            n.Get(6),
            n.Get(8),
            InetSocketAddress (i6i8.GetAddress(0), 110),
            InetSocketAddress (i6i8.GetAddress(1), 110),
            n.Get(15),
            n.Get(16),
            ppKeySize,
            DataRate (ppKeyRate),
            ppPacketSize,
            DataRate (ppRate)
        )
    );
    postprocessingApplications.Add(
        QAHelper.InstallPostProcessing(
            n.Get(8),
            n.Get(10),
            InetSocketAddress (i8i10.GetAddress(0), 112),
            InetSocketAddress (i8i10.GetAddress(1), 112),
            n.Get(16),
            n.Get(17),
            ppKeySize,
            DataRate (ppKeyRate),
            ppPacketSize,
            DataRate (ppRate)
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
            n.Get(0),   //Source Node
            n.Get(10),   //Destination Node
            InetSocketAddress (i0i2.GetAddress(0), communicationPort), //Source address
            InetSocketAddress (i8i10.GetAddress(1), communicationPort), //Destination address
            n.Get(12),   //Controller 1
            n.Get(17),   //Controller 2
            "tcp",      //Connection type
            appPacketSize, //Payload size
            DataRate (appRate), //Data rate
            "etsi014"   //Application type
        )
    );
    cryptographicApplications.Start (Seconds (appStartTime));
    cryptographicApplications.Stop (Seconds (appStopTime));

    Ipv4GlobalRoutingHelper::PopulateRoutingTables ();
    QLinkHelper.CreateTopologyGraph({controlSiteA, controlSiteB, controlSiteC, controlSiteD, controlSiteE, controlSiteF});
    QLinkHelper.PopulateRoutingTables();
    QLinkHelper.AddGraphs();

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
        p2p.EnableAsciiAll (ascii.CreateFileStream ("qkd_secoqc.tr"));
        p2p.EnablePcapAll ("qkd_secoqc");
        AnimationInterface anim ("qkd_secoqc.xml");  // where "animation.xml" is any arbitrary filename
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

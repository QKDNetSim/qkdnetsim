/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/* 
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 * Author:  Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 *          Miralem Mehic <miralem.mehic@etf.unsa.ba>
 */

// IEEE Netork emulation script (without Qiskit)
// Mehic, Miralem, et al. "Virtual Quantum Key Distribution Network Ecosystem: The National Czech QKD Network." IEEE network (2025).
// DOI: 10.1109/MNET.2025.3540705
//
//      PRAGUE                               BRNO                       OSTRAVA
//       n6 (kms) -- n7(kms) --- n8 (kms) ---- n9 (kms) --- n10 (kms) --- n11 (kms)
//       |             |          |            |            |            |
//       n0 ---qkd -- n1 --qkd -- n2 -- qkd -- n3 -- qkd --n4  -- qkd --n5
//
//       n12          n13         n14          n15          n16          n17
//    (control)    (control)    (control)   (control)     (control)    (control)
//
// - udp flows from n0 to n5

#include <fstream>
#include "ns3/core-module.h" 
#include "ns3/applications-module.h"
#include "ns3/internet-module.h" 
#include "ns3/flow-monitor-module.h" 
#include "ns3/mobility-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/gnuplot.h" 
#include "ns3/traffic-control-module.h"

#include "ns3/qkd-link-helper.h" 
#include "ns3/qkd-app-helper.h"
#include "ns3/qkd-app-014.h"

#include "ns3/network-module.h" 
#include "ns3/internet-apps-module.h"
#include "ns3/netanim-module.h" 

#include "ns3/abort.h"
#include "ns3/fd-net-device-module.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/ipv4-list-routing-helper.h"

#include "ns3/internet-apps-module.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/ipv4-list-routing-helper.h"


#include "ns3/virtual-net-device-module.h"
#include "ns3/virtual-net-device.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("QKD_ETSI014");
   
std::map<uint32_t, std::map<uint32_t, std::map<uint32_t, uint32_t>> > m_relayTrace;
std::map<uint32_t, uint32_t> m_wasteTrace;

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
    auto it = m_generatedKeys.find(appId);
    if(it == m_generatedKeys.end())
    {
        
        std::map<std::string, uint32_t> map0 {{keyId, amountInBits}};
        m_generatedKeys.insert(std::make_pair(appId, map0)); 

    }else{
                
        auto it2 = it->second.find(keyId);
        if(it2 != it->second.end()){
            it2->second += amountInBits;
        } else {
            it->second.insert(std::make_pair(keyId, amountInBits)); 
        }
    } 
}

void
KeyServed (std::string context, const std::string& appId, const std::string& keyId, const uint32_t& amountInBits)
{ 
    auto it = m_servedKeys.find(appId);
    if(it == m_servedKeys.end()){
        std::map<std::string, uint32_t> map0 {{keyId, amountInBits}};
        m_servedKeys.insert(std::make_pair(appId, map0)); 
    }else{
        auto it2 = it->second.find(keyId);
        if(it2 != it->second.end()){
            it2->second += amountInBits;
        } else {
            it->second.insert(std::make_pair(keyId, amountInBits)); 
        }
    }       
}

void
RelayKeyTrace(
    std::string context, 
    const uint32_t& nodeId, 
    const uint32_t& srcNodeId,
    const uint32_t& dstNodeId,
    const uint32_t& amount
){
    std::map<uint32_t, uint32_t> map0 {{dstNodeId, amount}};
    std::map<uint32_t, std::map<uint32_t, uint32_t> > map1 {{srcNodeId, map0}};

    auto it = m_relayTrace.find(nodeId);
    if(it == m_relayTrace.end())
        m_relayTrace.insert( std::make_pair(nodeId, map1) );
    else{
        auto it1 = it->second.find(srcNodeId);
        if(it1 == it->second.end())
            it->second.insert(std::make_pair(srcNodeId, map0) );
        else{
            auto it2 = it1->second.find(dstNodeId);
            if(it2 == it1->second.end())
                it1->second.insert(std::make_pair(dstNodeId, amount));
            else
                it2->second += amount;
        }
    }

}

void
WasteKeyTrace (std::string, const uint32_t& srcNodeId, const uint32_t& dstNodeId, const uint32_t& amountInBits){
    auto it = m_wasteTrace.find(srcNodeId);
    if(it == m_wasteTrace.end())
        m_wasteTrace.insert( std::make_pair(srcNodeId, amountInBits) );
    else
        it->second += amountInBits;
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

    std::cout << "\n\nKEY RELAY STATS:\n";
    for (const auto &el: m_relayTrace){
        uint32_t totalKeysRelayed {0};
        std::cout << "\n\tNode ID:\t" << el.first;
        for (const auto &el1: el.second){
            for(const auto &el2: el1.second){
                std::cout << "\n\t\tFrom:" << el1.first << "\tTo:" << el2.first << "\tAmount (bits):" << el2.second;
                totalKeysRelayed += el2.second;
            }
        }
        std::cout << "\n\t\tTotal amount (bits):\t" << totalKeysRelayed;
    }
    if(m_relayTrace.empty())
        std::cout << "\n\tNONE";

    std::cout << "\n\nWasted key material (source and intermidiate nodes)";
    for (const auto &el: m_wasteTrace)
        std::cout << "\n\tNode ID:\t" << el.first
        << "\n\t\tWasted amount:\t" << el.second;
    if(m_wasteTrace.empty())
        std::cout << "\n\tNONE";

    std::cout << "\n\nQKD LINK STATS:\n";
    for (const auto &el: m_generatedKeys){
        for(const auto &el1 : el.second)
            std::cout << "\n\tLink (" << el.first << "-"<< el1.first << ")\tGenerated (bits):" << el1.second;
    }

    std::cout << "\n\nSERVICE STATS:\n";
    for(auto const &el: m_servedKeys){
        std::cout << "\n\tNode ID:\t" << el.first;
        for(auto const &el1: el.second)   
            std::cout << "\n\t\tApplication ID:\t" << el1.first << "\t\tServed (bits):\t" << el1.second;
    }

}

bool PromiscRx(Ptr<NetDevice> device, Ptr<const Packet> packet, uint16_t protocol, const Address &src, const Address &dst, NetDevice::PacketType packetType)
{
    std::cout << "Promicious mode packet received! \t" << protocol << "\t" <<  src << "\t" << dst << "\t" << packet->GetSize() << std::endl;
    return true;
}

int main (int argc, char *argv[])
{
    //Packet::EnablePrinting(); 
    //PacketMetadata::Enable ();

    //
    // Since we are using a real piece of hardware we need to use the realtime
    // simulator.
    //
    GlobalValue::Bind ("SimulatorImplementationType", StringValue ("ns3::RealtimeSimulatorImpl"));

    //
    // Since we are going to be talking to real-world machines, we need to enable
    // calculation of checksums in our protocols.
    //
    GlobalValue::Bind ("ChecksumEnabled", BooleanValue (true));
    Config::SetDefault ("ns3::TcpSocketBase::Timestamp", BooleanValue (false));

    //
    // Explicitly create the nodes required by the topology (shown above).
    //
    NS_LOG_INFO ("Create nodes.");
    NodeContainer n;
    uint32_t simulationTime = 100000;
    uint16_t appStartTime = 10;
    uint16_t appStopTime = 15;    
    uint16_t qkdStartTime = 5;
    uint16_t qkdStopTime = 15000;    
    uint32_t encryptionType = 1;
    uint32_t numberOfKeyToFetchFromKMS = 2;
    uint32_t authenticationType = 0;
    uint32_t aesLifetime = 300000; //In bytes! 64GB = 68719476736B
    uint32_t appPacketLimit = 0;
    uint32_t useCrypto = 0;

    uint32_t appRate = 1;
    uint32_t appPacketSize = 32; //bytes
    uint32_t ppKeyRate = 10000;
    uint32_t ppKeySize = 32; //Key in bytes!!!
    uint32_t ppPacketSize = 100;
    uint32_t ppRate = 1000;

    bool trace = false;
    n.Create (18);

    // Configure command line parameters
    CommandLine cmd;

    cmd.AddValue ("appPacketLimit", "The number of application packets to exchange. Used to limit the communication if needed.", appPacketLimit); 
    cmd.AddValue ("appPacketSize", "The traffic rate of application that consumes keys", appPacketSize); 
    cmd.AddValue ("appRate", "The traffic rate of application that consumes keys", appRate); 
    
    cmd.AddValue ("keyRate", "QKD Key rate", ppKeyRate); 
    cmd.AddValue ("keySize", "The size of generated keys", ppKeySize); 

    cmd.AddValue ("showKeyServed", "Show trace when a key is served from KMS", showKeyServed); 
    cmd.AddValue ("showKeyAdded", "Show trace when a key is generated", showKeyAdded);  

    cmd.AddValue ("ppPacketSize", "QKD Post-processing packet size", ppPacketSize);
    cmd.AddValue ("ppRate", "QKD Post-processing traffic rate", ppRate);

    cmd.AddValue ("simTime", "Simulation time (seconds)", simulationTime); 
    cmd.AddValue ("appStartTime", "Application start time (seconds)", appStartTime); 
    cmd.AddValue ("appStopTime", "Application stop time (seconds)", appStopTime); 
    cmd.AddValue ("qkdStartTime", "QKD start time (seconds)", qkdStartTime); 
    cmd.AddValue ("qkdStopTime", "QKD stop time (seconds)", qkdStopTime); 

    cmd.AddValue ("encryptionType", "Type of encryption to be used", encryptionType); 
    cmd.AddValue ("authenticationType", "Type of authentication to be used", authenticationType); 
    cmd.AddValue ("numberOfKeyToFetchFromKMS", "How may key to fetch from KMS?", numberOfKeyToFetchFromKMS); 
    cmd.AddValue ("aesLifetime", "How many packets to encrypt with the same AES key?", aesLifetime);
    cmd.AddValue ("useCrypto", "Perform crypto functions?", useCrypto);
    cmd.AddValue ("trace", "Enable datapath stats and pcap traces", trace);
    cmd.Parse (argc, argv);

    NodeContainer n0n1 = NodeContainer (n.Get(0), n.Get (1));
    NodeContainer n1n2 = NodeContainer (n.Get(1), n.Get (2));
    NodeContainer n2n3 = NodeContainer (n.Get(2), n.Get (3));
    NodeContainer n3n4 = NodeContainer (n.Get(3), n.Get (4));
    NodeContainer n4n5 = NodeContainer (n.Get(4), n.Get (5));
    
    NodeContainer n6n7 = NodeContainer (n.Get(6), n.Get (7));
    NodeContainer n7n8 = NodeContainer (n.Get(7), n.Get (8));
    NodeContainer n8n9 = NodeContainer (n.Get(8), n.Get (9));
    NodeContainer n9n10 = NodeContainer (n.Get(9), n.Get (10));
    NodeContainer n10n11 = NodeContainer (n.Get(10), n.Get (11));

    NodeContainer n0n6 = NodeContainer (n.Get(0), n.Get (6));
    NodeContainer n1n7 = NodeContainer (n.Get(1), n.Get (7));
    NodeContainer n2n8 = NodeContainer (n.Get(2), n.Get (8));
    NodeContainer n3n9 = NodeContainer (n.Get(3), n.Get (9));
    NodeContainer n4n10 = NodeContainer (n.Get(4), n.Get (10));
    NodeContainer n5n11 = NodeContainer (n.Get(5), n.Get (11));


    InternetStackHelper internet;
    internet.Install (n);

    // Set Mobility for all nodes
    MobilityHelper mobility;
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(n);
       
    EmuFdNetDeviceHelper emuDevice;
    emuDevice.SetDeviceName ("eth0");

    //------------------ NODE 0 - QKD PRAGUE
    NetDeviceContainer tempDevNode0 = emuDevice.Install (n.Get(0));
    Ptr<NetDevice> device_emu_node0 = tempDevNode0.Get (0);
    std::string macStringTempNode0 ("00:00:00:00:00:20");
    Mac48Address macTempNode0(macStringTempNode0.c_str());
    device_emu_node0->SetAttribute ("Address", Mac48AddressValue (macTempNode0));

    Ptr<Ipv4> ipv4_node0 = n.Get(0)->GetObject<Ipv4> ();
    uint32_t interface_emu_node0 = ipv4_node0->AddInterface (device_emu_node0);
    Ipv4InterfaceAddress address_emu_node0 = Ipv4InterfaceAddress (Ipv4Address("172.17.0.20"), Ipv4Mask("255.255.255.0"));
    ipv4_node0->AddAddress (interface_emu_node0, address_emu_node0);
    ipv4_node0->SetMetric (interface_emu_node0, 1);
    ipv4_node0->SetUp (interface_emu_node0); 

    //------------------ NODE 1 - QKD PRAGUE1
    NetDeviceContainer tempDevNode1 = emuDevice.Install (n.Get(1));
    Ptr<NetDevice> device_emu_node1 = tempDevNode1.Get (0);
    std::string macStringTempNode1 ("00:00:00:00:00:21");
    Mac48Address macTempNode1(macStringTempNode1.c_str());
    device_emu_node1->SetAttribute ("Address", Mac48AddressValue (macTempNode1));

    Ptr<Ipv4> ipv4_node1 = n.Get(1)->GetObject<Ipv4> ();
    uint32_t interface_emu_node1 = ipv4_node1->AddInterface (device_emu_node1);
    Ipv4InterfaceAddress address_emu_node1 = Ipv4InterfaceAddress (Ipv4Address("172.17.0.21"), Ipv4Mask("255.255.255.0"));
    ipv4_node1->AddAddress (interface_emu_node1, address_emu_node1);
    ipv4_node1->SetMetric (interface_emu_node1, 1);
    ipv4_node1->SetUp (interface_emu_node1); 

    //------------------ NODE 2 - QKD PRAGUE2
    NetDeviceContainer tempDevNode2 = emuDevice.Install (n.Get(2));
    Ptr<NetDevice> device_emu_node2 = tempDevNode2.Get (0);
    std::string macStringTempNode2 ("00:00:00:00:00:21");
    Mac48Address macTempNode2(macStringTempNode2.c_str());
    device_emu_node2->SetAttribute ("Address", Mac48AddressValue (macTempNode2));

    Ptr<Ipv4> ipv4_node2 = n.Get(2)->GetObject<Ipv4> ();
    uint32_t interface_emu_node2 = ipv4_node2->AddInterface (device_emu_node2);
    Ipv4InterfaceAddress address_emu_node2 = Ipv4InterfaceAddress (Ipv4Address("172.17.0.22"), Ipv4Mask("255.255.255.0"));
    ipv4_node2->AddAddress (interface_emu_node2, address_emu_node2);
    ipv4_node2->SetMetric (interface_emu_node2, 1);
    ipv4_node2->SetUp (interface_emu_node2); 

    //------------------ NODE 6 - KMS PRAGUE
    NetDeviceContainer tempDevNode6 = emuDevice.Install (n.Get(6));
    Ptr<NetDevice> device_emu_node6 = tempDevNode6.Get (0);
    std::string macStringTempNode6 ("00:00:00:00:00:22");
    Mac48Address macTempNode6(macStringTempNode6.c_str());
    device_emu_node6->SetAttribute ("Address", Mac48AddressValue (macTempNode6));
    //device_emu_node6->SetAttribute ("Address", Mac48AddressValue (Mac48Address::Allocate ()));

    Ptr<Ipv4> ipv4_node6 = n.Get(6)->GetObject<Ipv4> ();
    uint32_t interface_emu_node6 = ipv4_node6->AddInterface (device_emu_node6);
    Ipv4InterfaceAddress address_emu_node6 = Ipv4InterfaceAddress (Ipv4Address("172.17.0.26"), Ipv4Mask("255.255.255.0"));
    ipv4_node6->AddAddress (interface_emu_node6, address_emu_node6);
    ipv4_node6->SetMetric (interface_emu_node6, 1);
    ipv4_node6->SetUp (interface_emu_node6); 

    //------------------ NODE 3 - QKD BRNO1
    NetDeviceContainer tempDevNode3 = emuDevice.Install (n.Get(3));
    Ptr<NetDevice> device_emu_node3 = tempDevNode3.Get (0);
    std::string macStringTempNode3 ("00:00:00:00:00:23");
    Mac48Address macTempNode3(macStringTempNode3.c_str());
    device_emu_node3->SetAttribute ("Address", Mac48AddressValue (macTempNode3));
    //device_emu_node3->SetAttribute ("Address", Mac48AddressValue (Mac48Address::Allocate ()));

    Ptr<Ipv4> ipv4_node3 = n.Get(3)->GetObject<Ipv4> ();
    uint32_t interface_emu_node3 = ipv4_node3->AddInterface (device_emu_node3);
    Ipv4InterfaceAddress address_emu_node3 = Ipv4InterfaceAddress (Ipv4Address("172.17.0.23"), Ipv4Mask("255.255.255.0"));
    ipv4_node3->AddAddress (interface_emu_node3, address_emu_node3);
    ipv4_node3->SetMetric (interface_emu_node3, 1);
    ipv4_node3->SetUp (interface_emu_node3);
 
    //------------------ NODE 4 - QKD BRNO2
    NetDeviceContainer tempDevNode4 = emuDevice.Install (n.Get(4));
    Ptr<NetDevice> device_emu_node4 = tempDevNode4.Get (0);
    std::string macStringTempNode4 ("00:00:00:00:00:24");
    Mac48Address macTempNode4(macStringTempNode4.c_str());
    device_emu_node4->SetAttribute ("Address", Mac48AddressValue (macTempNode4));
    //device_emu_node4->SetAttribute ("Address", Mac48AddressValue (Mac48Address::Allocate ()));

    Ptr<Ipv4> ipv4_node4 = n.Get(4)->GetObject<Ipv4> ();
    uint32_t interface_emu_node4 = ipv4_node4->AddInterface (device_emu_node4);
    Ipv4InterfaceAddress address_emu_node4 = Ipv4InterfaceAddress (Ipv4Address("172.17.0.24"), Ipv4Mask("255.255.255.0"));
    ipv4_node4->AddAddress (interface_emu_node4, address_emu_node4);
    ipv4_node4->SetMetric (interface_emu_node4, 1);
    ipv4_node4->SetUp (interface_emu_node4);

    //------------------ NODE 9 - KMS BRNO
    NetDeviceContainer tempDevNode9 = emuDevice.Install (n.Get(9));
    Ptr<NetDevice> device_emu_node9 = tempDevNode9.Get (0);
    std::string macStringTempNode9 ("00:00:00:00:00:29");
    Mac48Address macTempNode9(macStringTempNode9.c_str());
    device_emu_node9->SetAttribute ("Address", Mac48AddressValue (macTempNode9));
    //device_emu_node9->SetAttribute ("Address", Mac48AddressValue (Mac48Address::Allocate ()));

    Ptr<Ipv4> ipv4_node9 = n.Get(9)->GetObject<Ipv4> ();
    uint32_t interface_emu_node9 = ipv4_node9->AddInterface (device_emu_node9);
    Ipv4InterfaceAddress address_emu_node9 = Ipv4InterfaceAddress (Ipv4Address("172.17.0.29"), Ipv4Mask("255.255.255.0"));
    ipv4_node9->AddAddress (interface_emu_node9, address_emu_node9);
    ipv4_node9->SetMetric (interface_emu_node9, 1);
    ipv4_node9->SetUp (interface_emu_node9); 


    //------------------ NODE 5 - QKD OSTRAVA
    NetDeviceContainer tempDevNode5 = emuDevice.Install (n.Get(5));
    Ptr<NetDevice> device_emu_node5 = tempDevNode5.Get (0);
    std::string macStringTempNode5 ("00:00:00:00:00:25");
    Mac48Address macTempNode5(macStringTempNode5.c_str());
    device_emu_node5->SetAttribute ("Address", Mac48AddressValue (macTempNode5));
    //device_emu_node5->SetAttribute ("Address", Mac48AddressValue (Mac48Address::Allocate ()));

    Ptr<Ipv4> ipv4_node5 = n.Get(5)->GetObject<Ipv4> ();
    uint32_t interface_emu_node5 = ipv4_node5->AddInterface (device_emu_node5);
    Ipv4InterfaceAddress address_emu_node5 = Ipv4InterfaceAddress (Ipv4Address("172.17.0.25"), Ipv4Mask("255.255.255.0"));
    ipv4_node5->AddAddress (interface_emu_node5, address_emu_node5);
    ipv4_node5->SetMetric (interface_emu_node5, 1);
    ipv4_node5->SetUp (interface_emu_node5); 

    //------------------ NODE 11 - KMS OSTRAVA
    NetDeviceContainer tempDevNode11 = emuDevice.Install (n.Get(11));
    Ptr<NetDevice> device_emu_node11 = tempDevNode11.Get (0);
    std::string macStringTempNode11 ("00:00:00:00:00:28");
    Mac48Address macTempNode11(macStringTempNode11.c_str());
    device_emu_node11->SetAttribute ("Address", Mac48AddressValue (macTempNode11));
    //device_emu_node11->SetAttribute ("Address", Mac48AddressValue (Mac48Address::Allocate ()));

    Ptr<Ipv4> ipv4_node11 = n.Get(11)->GetObject<Ipv4> ();
    uint32_t interface_emu_node11 = ipv4_node11->AddInterface (device_emu_node11);
    Ipv4InterfaceAddress address_emu_node11 = Ipv4InterfaceAddress (Ipv4Address("172.17.0.31"), Ipv4Mask("255.255.255.0"));
    ipv4_node11->AddAddress (interface_emu_node11, address_emu_node11);
    ipv4_node11->SetMetric (interface_emu_node11, 1);
    ipv4_node11->SetUp (interface_emu_node11); 


    //------------------ NODE 7 - KMS2
    NetDeviceContainer tempDevnode7 = emuDevice.Install (n.Get(7));
    Ptr<NetDevice> device_emu_node7 = tempDevnode7.Get (0);
    std::string macStringTempnode7 ("00:00:00:00:00:27");
    Mac48Address macTempnode7(macStringTempnode7.c_str());
    device_emu_node7->SetAttribute ("Address", Mac48AddressValue (macTempnode7));
    //device_emu_node7->SetAttribute ("Address", Mac48AddressValue (Mac48Address::Allocate ()));

    Ptr<Ipv4> ipv4_node7 = n.Get(7)->GetObject<Ipv4> ();
    uint32_t interface_emu_node7 = ipv4_node7->AddInterface (device_emu_node7);
    Ipv4InterfaceAddress address_emu_node7 = Ipv4InterfaceAddress (Ipv4Address("172.17.0.27"), Ipv4Mask("255.255.255.0"));
    ipv4_node7->AddAddress (interface_emu_node7, address_emu_node7);
    ipv4_node7->SetMetric (interface_emu_node7, 1);
    ipv4_node7->SetUp (interface_emu_node7); 

    //------------------ NODE 8 - KMS3
    NetDeviceContainer tempDevnode8 = emuDevice.Install (n.Get(8));
    Ptr<NetDevice> device_emu_node8 = tempDevnode8.Get (0);
    std::string macStringTempnode8 ("00:00:00:00:00:28");
    Mac48Address macTempnode8(macStringTempnode8.c_str());
    device_emu_node8->SetAttribute ("Address", Mac48AddressValue (macTempnode8));
    //device_emu_node8->SetAttribute ("Address", Mac48AddressValue (Mac48Address::Allocate ()));

    Ptr<Ipv4> ipv4_node8 = n.Get(8)->GetObject<Ipv4> ();
    uint32_t interface_emu_node8 = ipv4_node8->AddInterface (device_emu_node8);
    Ipv4InterfaceAddress address_emu_node8 = Ipv4InterfaceAddress (Ipv4Address("172.17.0.28"), Ipv4Mask("255.255.255.0"));
    ipv4_node8->AddAddress (interface_emu_node8, address_emu_node8);
    ipv4_node8->SetMetric (interface_emu_node8, 1);
    ipv4_node8->SetUp (interface_emu_node8); 

    

    // We create the channels first without any IP addressing information
    NS_LOG_INFO ("Create channels.");
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute ("DataRate", StringValue ("10Gbps"));
    p2p.SetChannelAttribute ("Delay", StringValue ("1ms")); 

    NetDeviceContainer d0d1 = p2p.Install (n0n1);
    NetDeviceContainer d1d2 = p2p.Install (n1n2);
    NetDeviceContainer d2d3 = p2p.Install (n2n3);
    //NetDeviceContainer d3d4 = p2p.Install (n3n4);
    //NetDeviceContainer d4d5 = p2p.Install (n4n5);

    NetDeviceContainer d6d7 = p2p.Install (n6n7);
    NetDeviceContainer d7d8 = p2p.Install (n7n8);
    NetDeviceContainer d8d9 = p2p.Install (n8n9);
    NetDeviceContainer d9d10 = p2p.Install (n9n10);
    NetDeviceContainer d10d11 = p2p.Install (n10n11);

    NetDeviceContainer d0d6 = p2p.Install (n0n6);
    NetDeviceContainer d1d7 = p2p.Install (n1n7);
    NetDeviceContainer d2d8 = p2p.Install (n2n8);
    NetDeviceContainer d3d9 = p2p.Install (n3n9);
    NetDeviceContainer d4d10 = p2p.Install (n4n10);
    NetDeviceContainer d5d11 = p2p.Install (n5n11);

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
    Ipv4InterfaceContainer i2i3 = ipv4.Assign (d2d3);
    //ipv4.SetBase ("10.1.4.0", "255.255.255.0");
    //Ipv4InterfaceContainer i3i4 = ipv4.Assign (d3d4);
    //ipv4.SetBase ("10.1.5.0", "255.255.255.0");
    //Ipv4InterfaceContainer i4i5 = ipv4.Assign (d4d5);

    ipv4.SetBase ("10.1.6.0", "255.255.255.0");
    Ipv4InterfaceContainer i6i7 = ipv4.Assign (d6d7);
    ipv4.SetBase ("10.1.7.0", "255.255.255.0");
    Ipv4InterfaceContainer i7i8 = ipv4.Assign (d7d8);
    ipv4.SetBase ("10.1.8.0", "255.255.255.0");
    Ipv4InterfaceContainer i8i9 = ipv4.Assign (d8d9);
    ipv4.SetBase ("10.1.9.0", "255.255.255.0");
    Ipv4InterfaceContainer i9i10 = ipv4.Assign (d9d10);
    ipv4.SetBase ("10.1.10.0", "255.255.255.0");
    Ipv4InterfaceContainer i10i11 = ipv4.Assign (d10d11);

    ipv4.SetBase ("10.1.11.0", "255.255.255.0");
    Ipv4InterfaceContainer i0i6 = ipv4.Assign (d0d6);
    ipv4.SetBase ("10.1.12.0", "255.255.255.0");
    Ipv4InterfaceContainer i1i7 = ipv4.Assign (d1d7);
    ipv4.SetBase ("10.1.13.0", "255.255.255.0");
    Ipv4InterfaceContainer i2i8 = ipv4.Assign (d2d8);
    ipv4.SetBase ("10.1.14.0", "255.255.255.0");
    Ipv4InterfaceContainer i3i9 = ipv4.Assign (d3d9);
    ipv4.SetBase ("10.1.15.0", "255.255.255.0");
    Ipv4InterfaceContainer i4i10 = ipv4.Assign (d4d10);
    ipv4.SetBase ("10.1.16.0", "255.255.255.0");
    Ipv4InterfaceContainer i5i11 = ipv4.Assign (d5d11);
    
    QKDAppHelper QAHelper; 
    QKDLinkHelper QLinkHelper;  
    
    //  install QKD Control the nodes 12,13,14,15,16,17
    Ptr<QKDControl> controlSite_Prague1 = QLinkHelper.InstallQKDNController ( n.Get(12) );
    Ptr<QKDControl> controlSite_Prague2 = QLinkHelper.InstallQKDNController ( n.Get(13) );
    Ptr<QKDControl> controlSite_Prague3 = QLinkHelper.InstallQKDNController ( n.Get(14) );
    Ptr<QKDControl> controlSite_Brno1 = QLinkHelper.InstallQKDNController ( n.Get(15) ); 

    QLinkHelper.ConfigureQBuffers ( //Configure Q-Buffers
        {
            controlSite_Prague1, 
            controlSite_Prague2, 
            controlSite_Prague3,
            controlSite_Brno1
        },
        1024,       //min
        51200,      //thr
        500000000,  //max
        0,          //current
        512         //default key size in bits
    );
    QLinkHelper.ConfigureRSBuffers ( //Configure S-Buffers for relay (RBuffers)!
        {
            controlSite_Prague1, 
            controlSite_Prague2, 
            controlSite_Prague3,
            controlSite_Brno1
        },
        0,
        16000, //Treshold
        64000, //Mmax
        0,
        512
    );

    //  install KMs on nodes 6,7,8,9,10,11

    //KMS - Prague1
    QAHelper.InstallKeyManager(//Install key manager for Prague1
        n.Get(6),           //Node KM-A
        i6i7.GetAddress(0), //IP address KM-A
        80,                 //Port
        controlSite_Prague1 //Assigned controlSite_Prague1
    ); 
    //KMS - Prague2
    QAHelper.InstallKeyManager(//Install key manager for Prague2
        n.Get(7),           //Node KM-A
        i6i7.GetAddress(1), //IP address KM-A
        80,                 //Port
        controlSite_Prague2 //Assigned controlSite_Prague2
    ); 
    //KMS - Prague3
    QAHelper.InstallKeyManager(//Install key manager for Prague3
        n.Get(8),           //Node KM-A
        i7i8.GetAddress(1), //IP address KM-A
        80,                 //Port
        controlSite_Prague3 //Assigned controlSite_Prague3
    ); 
    //KMS - Brno1
    QAHelper.InstallKeyManager(//Install key manager for Brno1
        n.Get(9),            //Node KM-A
        i9i10.GetAddress(0), //IP address KM-A
        80,                  //Port
        controlSite_Brno1    //Assigned controlSite_Brno1
    );  

    NS_LOG_INFO ("Create Applications.");

    std::cout << "QKD Prague1: " << n.Get(0)->GetId() << " IP address: " << i0i1.GetAddress(0) << std::endl;
    std::cout << "QKD Prague2: " << n.Get(1)->GetId() << " IP address: " << i1i2.GetAddress(0) << std::endl;
    std::cout << "QKD Prague3: " << n.Get(2)->GetId() << " IP address: " << i2i3.GetAddress(0) << std::endl;
    std::cout << "QKD Brno1: " << n.Get(3)->GetId() << " IP address: " << i2i3.GetAddress(1) << std::endl; 

    std::cout << "KMS Prague1: "  << n.Get(6)->GetId() << " IP address: " << i6i7.GetAddress(0) << std::endl;
    std::cout << "KMS Prague2: "  << n.Get(7)->GetId() << " IP address: " << i6i7.GetAddress(1) << std::endl;
    std::cout << "KMS Prague3: "  << n.Get(8)->GetId() << " IP address: " << i7i8.GetAddress(0) << std::endl;
    std::cout << "KMS Brno1: "  << n.Get(9)->GetId() << " IP address: " << i7i8.GetAddress(1) << std::endl;

    //Create APP to generate keys
    ApplicationContainer postprocessingApplications;
    postprocessingApplications.Add( 
        QAHelper.InstallPostProcessing(
            n.Get(0),   //QKD module A
            n.Get(1),   //QKD module B
            InetSocketAddress (i0i1.GetAddress(0), 102),    //Address A
            InetSocketAddress (i0i1.GetAddress(1), 102),    //Address B
            n.Get(12),  //Controller-A
            n.Get(13),  //Controller-B
            ppKeySize,   //size of key to be added to QKD buffer
            DataRate ("85.083kbps"), //average QKD key rate
            ppPacketSize,    //average data packet size
            DataRate (ppRate), //average data traffic rate
            "ad9c7de9-5826-11ef-8057-9b39f2479ea",
            "bd9c7de9-5826-11ef-8057-9b39f2479eb"
        )
    );

    postprocessingApplications.Add(
        QAHelper.InstallPostProcessing(
            n.Get(1),
            n.Get(2),
            InetSocketAddress (i1i2.GetAddress(0), 103),
            InetSocketAddress (i1i2.GetAddress(1), 103),
            n.Get(13),
            n.Get(14),
            ppKeySize,
            DataRate ("85.083kbps"), //average QKD key rate
            ppPacketSize,
            DataRate (ppRate),
            "cd9c7de9-5826-11ef-8057-9b39f2479ec",
            "dd9c7de9-5826-11ef-8057-9b39f2479ed"
        )
    );
    postprocessingApplications.Add(
        QAHelper.InstallPostProcessing(
            n.Get(2),
            n.Get(3),
            InetSocketAddress (i2i3.GetAddress(0), 104),
            InetSocketAddress (i2i3.GetAddress(1), 104),
            n.Get(14),
            n.Get(15),
            ppKeySize,
            DataRate ("85.083kbps"), //average QKD key rate
            ppPacketSize,
            DataRate (ppRate),
            "cd9c7de9-5826-11ef-8057-9b39f2479ee",
            "dd9c7de9-5826-11ef-8057-9b39f2479ef"
        )
    );


    postprocessingApplications.Add(
        QAHelper.InstallPostProcessing(
            n.Get(0),
            n.Get(3),
            InetSocketAddress (i0i1.GetAddress(0), 105),
            InetSocketAddress (i2i3.GetAddress(1), 105),
            n.Get(12),
            n.Get(15),
            ppKeySize,
            DataRate ("150kbps"), //average QKD key rate
            ppPacketSize,
            DataRate (ppRate),
            "cd9c7de9-5826-11ef-8057-9b39f2479eg",
            "dd9c7de9-5826-11ef-8057-9b39f2479eh"
        )
    );
     postprocessingApplications.Add(
        QAHelper.InstallPostProcessing(
            n.Get(0),
            n.Get(2),
            InetSocketAddress (i0i1.GetAddress(0), 106),
            InetSocketAddress (i1i2.GetAddress(1), 106),
            n.Get(12),
            n.Get(14),
            ppKeySize,
            DataRate ("150kbps"), //average QKD key rate
            ppPacketSize,
            DataRate (ppRate),
            "cd9c7de9-5826-11ef-8057-9b39f2479ei",
            "dd9c7de9-5826-11ef-8057-9b39f2479ej"
        )
    );

     postprocessingApplications.Add(
        QAHelper.InstallPostProcessing(
            n.Get(1),
            n.Get(3),
            InetSocketAddress (i1i2.GetAddress(0), 107),
            InetSocketAddress (i2i3.GetAddress(1), 107),
            n.Get(13),
            n.Get(15),
            ppKeySize,
            DataRate ("150kbps"), //average QKD key rate
            ppPacketSize,
            DataRate (ppRate),
            "cd9c7de9-5826-11ef-8057-9b39f2479eh",
            "dd9c7de9-5826-11ef-8057-9b39f2479ez"
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
    communicationPort = 8081;
    cryptographicApplications.Add(
        QAHelper.InstallQKDApplication(
            n.Get(0),   //Source Node 
            n.Get(1),   //Destination Node
            InetSocketAddress (i0i1.GetAddress(0), communicationPort), //Source address
            InetSocketAddress (i0i1.GetAddress(1), communicationPort), //Destination address
            n.Get(12),   //Controller 1
            n.Get(13),   //Controller 2
            "tcp",      //Connection type
            appPacketSize, //Payload size
            DataRate (appRate), //Data rate
            "etsi014",   //Application type
            "aaac7de9-5826-11ef-8057-9b39f247aaa",
            "bbbc7de9-5826-11ef-8057-9b39f247bbb"
        )
    );

    communicationPort = 8082;
    cryptographicApplications.Add(
        QAHelper.InstallQKDApplication(
            n.Get(0),   //Source Node 
            n.Get(2),   //Destination Node
            InetSocketAddress (i0i1.GetAddress(0), communicationPort), //Source address
            InetSocketAddress (i1i2.GetAddress(1), communicationPort), //Destination address
            n.Get(12),   //Controller 1
            n.Get(14),   //Controller 2
            "tcp",      //Connection type
            appPacketSize, //Payload size
            DataRate (appRate), //Data rate
            "etsi014",   //Application type
            "aaac7de9-5826-11ef-8057-9b39f247aac",
            "bbbc7de9-5826-11ef-8057-9b39f247bbd"
        )
    );

    communicationPort = 8083;
    cryptographicApplications.Add(
        QAHelper.InstallQKDApplication(
            n.Get(0),   //Source Node 
            n.Get(3),   //Destination Node
            InetSocketAddress (i0i1.GetAddress(0), communicationPort), //Source address
            InetSocketAddress (i2i3.GetAddress(1), communicationPort), //Destination address
            n.Get(12),   //Controller 1
            n.Get(15),   //Controller 2
            "tcp",      //Connection type
            appPacketSize, //Payload size
            DataRate (appRate), //Data rate
            "etsi014",   //Application type
            "aaac7de9-5826-11ef-8057-9b39f247aae",
            "bbbc7de9-5826-11ef-8057-9b39f247bbf"
        )
    );

    communicationPort = 8084;
    cryptographicApplications.Add(
        QAHelper.InstallQKDApplication(
            n.Get(1),   //Source Node 
            n.Get(2),   //Destination Node
            InetSocketAddress (i1i2.GetAddress(0), communicationPort), //Source address
            InetSocketAddress (i1i2.GetAddress(1), communicationPort), //Destination address
            n.Get(13),   //Controller 1
            n.Get(14),   //Controller 2
            "tcp",      //Connection type
            appPacketSize, //Payload size
            DataRate (appRate), //Data rate
            "etsi014",   //Application type
            "aaac7de9-5826-11ef-8057-9b39f247aag",
            "bbbc7de9-5826-11ef-8057-9b39f247bbh"
        )
    );

    communicationPort = 8085;
    cryptographicApplications.Add(
        QAHelper.InstallQKDApplication(
            n.Get(1),   //Source Node 
            n.Get(3),   //Destination Node
            InetSocketAddress (i1i2.GetAddress(0), communicationPort), //Source address
            InetSocketAddress (i2i3.GetAddress(1), communicationPort), //Destination address
            n.Get(13),   //Controller 1
            n.Get(15),   //Controller 2
            "tcp",      //Connection type
            appPacketSize, //Payload size
            DataRate (appRate), //Data rate
            "etsi014",   //Application type
            "aaac7de9-5826-11ef-8057-9b39f247aai",
            "bbbc7de9-5826-11ef-8057-9b39f247bbj"
        )
    );

    communicationPort = 8086;
    cryptographicApplications.Add(
        QAHelper.InstallQKDApplication(
            n.Get(2),   //Source Node 
            n.Get(3),   //Destination Node
            InetSocketAddress (i2i3.GetAddress(0), communicationPort), //Source address
            InetSocketAddress (i2i3.GetAddress(1), communicationPort), //Destination address
            n.Get(14),   //Controller 1
            n.Get(15),   //Controller 2
            "tcp",      //Connection type
            appPacketSize, //Payload size
            DataRate (appRate), //Data rate
            "etsi014",   //Application type
            "aaac7de9-5826-11ef-8057-9b39f247aak",
            "bbbc7de9-5826-11ef-8057-9b39f247bbl"
        )
    );
    cryptographicApplications.Start (Seconds (appStartTime));
    cryptographicApplications.Stop (Seconds (appStopTime));


    Ipv4GlobalRoutingHelper::PopulateRoutingTables ();
    QLinkHelper.CreateTopologyGraph(
        {
            controlSite_Prague1, 
            controlSite_Prague2, 
            controlSite_Prague3,
            controlSite_Brno1
        }
    );
    QLinkHelper.PopulateRoutingTables();

    //We are interested to connect to n6 and n11 so we spefiy routing for them
    Ipv4StaticRoutingHelper ipv4RoutingHelper;
    Ptr<Ipv4StaticRouting> staticRouting = ipv4RoutingHelper.GetStaticRouting (ipv4_node6);
    staticRouting->AddNetworkRouteTo (Ipv4Address("172.17.0.0"), Ipv4Mask("255.255.255.0"), interface_emu_node6, 1);
    staticRouting->AddHostRouteTo(Ipv4Address("172.17.0.5"),interface_emu_node6,1);
    
    Ptr<Ipv4StaticRouting> staticRouting0 = ipv4RoutingHelper.GetStaticRouting (ipv4_node11);
    staticRouting0->AddNetworkRouteTo (Ipv4Address("172.17.0.0"), Ipv4Mask("255.255.255.0"), interface_emu_node11, 1);
    staticRouting0->AddHostRouteTo(Ipv4Address("172.17.0.5"),interface_emu_node11,1);

    //////////////////////////////////////
    ////         STATISTICS
    ////////////////////////////////////// 

    //Connect Traces for KM key statistics
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDKeyManagerSystemApplication/KeyServed", MakeCallback(&KeyServed));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDKeyManagerSystemApplication/QKDKeyGenerated", MakeCallback(&KeyGenerated));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDKeyManagerSystemApplication/RelayConsumption", MakeCallback(&RelayKeyTrace));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDKeyManagerSystemApplication/WasteRelay", MakeCallback(&WasteKeyTrace)); 

    if(trace){
        //if we need we can create pcap files
        AsciiTraceHelper ascii;
        p2p.EnableAsciiAll (ascii.CreateFileStream ("qkd_etis014_network_emulation.tr"));
        p2p.EnablePcapAll ("qkd_etis014_network_emulation");  
        AnimationInterface anim ("qkd_etis014_network_emulation.xml");  // where "animation.xml" is any arbitrary filename
    }

    Simulator::Stop (Seconds (simulationTime));
    Simulator::Run ();
 
    //Finally print the graphs
    QLinkHelper.PrintGraphs();

    Ratio();
    Simulator::Destroy ();
}

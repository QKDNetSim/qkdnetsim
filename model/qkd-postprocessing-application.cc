/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 * Author: Miralem Mehic <miralem.mehic@etf.unsa.ba>
 */
#include <bitset>
#include <sstream>
#include <iomanip>
#include "ns3/address.h"
#include "ns3/node.h"
#include "ns3/nstime.h"
#include "ns3/socket.h"
#include "ns3/simulator.h"
#include "ns3/packet.h"
#include "ns3/uinteger.h"
#include "ns3/trace-source-accessor.h"
#include "http.h"
#include "qkd-postprocessing-application.h"
#include <iostream>
#include <fstream>
#include <string>
#include <random>

namespace ns3 {

  NS_LOG_COMPONENT_DEFINE("QKDPostprocessingApplication");


  NS_OBJECT_ENSURE_REGISTERED(QKDPostprocessingApplication);

  TypeId
  QKDPostprocessingApplication::GetTypeId()
  {
    static TypeId tid = TypeId("ns3::QKDPostprocessingApplication")
      .SetParent<Application>()
      .SetGroupName("Applications")
      .AddConstructor<QKDPostprocessingApplication>()
      .AddAttribute("KeySize", "The amount of data to be added to QKD Buffer(in bytes).",
                     UintegerValue(8092),
                     MakeUintegerAccessor(&QKDPostprocessingApplication::m_keySize),
                     MakeUintegerChecker<uint32_t>(1))
      .AddAttribute("KeyRate", "The average QKD key rate.",
                     DataRateValue(DataRate("100kbps")),
                     MakeDataRateAccessor(&QKDPostprocessingApplication::m_keyRate),
                     MakeDataRateChecker())
      .AddAttribute("DataRate", "The average data rate of communication.",
                     DataRateValue(DataRate("650kbps")), //3.3Mbps //10kbps
                     MakeDataRateAccessor(&QKDPostprocessingApplication::m_dataRate),
                     MakeDataRateChecker())
      .AddAttribute("PacketSize", "The size of packets sent in post-processing state",
                     UintegerValue(320), //280
                     MakeUintegerAccessor(&QKDPostprocessingApplication::m_pktSize),
                     MakeUintegerChecker<uint32_t>(1))
      .AddAttribute("MaxSiftingPackets", "The size of packets sent in sifting state",
                     UintegerValue(5), ///190
                     MakeUintegerAccessor(&QKDPostprocessingApplication::m_maxPackets_sifting),
                     MakeUintegerChecker<uint32_t>(1))

      .AddAttribute("Protocol", "The type of protocol to use(TCP by default).",
                     TypeIdValue(TcpSocketFactory::GetTypeId()),
                     MakeTypeIdAccessor(&QKDPostprocessingApplication::m_tid),
                     MakeTypeIdChecker())
      .AddAttribute("ProtocolSifting", "The type of protocol to use for sifting(UDP by default).",
                     TypeIdValue(UdpSocketFactory::GetTypeId()),
                     MakeTypeIdAccessor(&QKDPostprocessingApplication::m_tidSifting),
                     MakeTypeIdChecker())

      .AddAttribute("Remote", "The address of the destination",
                     AddressValue(),
                     MakeAddressAccessor(&QKDPostprocessingApplication::m_peer),
                     MakeAddressChecker())
      .AddAttribute("Local", "The local address on which to bind the listening socket.",
                     AddressValue(),
                     MakeAddressAccessor(&QKDPostprocessingApplication::m_local),
                     MakeAddressChecker())
      .AddAttribute("Remote_Sifting", "The address of the destination for sifting traffic.",
                     AddressValue(),
                     MakeAddressAccessor(&QKDPostprocessingApplication::m_peer_sifting),
                     MakeAddressChecker())
      .AddAttribute("Local_Sifting", "The local address on which to bind the listening sifting socket.",
                     AddressValue(),
                     MakeAddressAccessor(&QKDPostprocessingApplication::m_local_sifting),
                     MakeAddressChecker())
      .AddAttribute("Local_KMS", "The local KSM address.",
                     AddressValue(),
                     MakeAddressAccessor(&QKDPostprocessingApplication::m_kms),
                     MakeAddressChecker())
      .AddTraceSource("Tx", "A new packet is created and is sent",
                     MakeTraceSourceAccessor(&QKDPostprocessingApplication::m_txTrace),
                     "ns3::QKDPostprocessingApplication::Tx")
      .AddTraceSource("Rx", "A packet has been received",
                     MakeTraceSourceAccessor(&QKDPostprocessingApplication::m_rxTrace),
                     "ns3::QKDPostprocessingApplication::Rx")
      .AddTraceSource("TxKMS", "A new packet is created and is sent to LKMS",
                     MakeTraceSourceAccessor(&QKDPostprocessingApplication::m_txTraceKMS),
                     "ns3::QKDPostprocessingApplication::TxKMS")
      .AddTraceSource("RxKMS", "A packet has been received from LKMS",
                     MakeTraceSourceAccessor(&QKDPostprocessingApplication::m_rxTraceKMS),
                     "ns3::QKDPostprocessingApplication::RxLKMS")
    ;
    return tid;
  }

  uint32_t QKDPostprocessingApplication::m_applicationCounts = 0;

  QKDPostprocessingApplication::QKDPostprocessingApplication()
  {
    m_applicationCounts++;
    m_ppId = m_applicationCounts;
    m_connected = false;
    m_random = CreateObject<UniformRandomVariable>();
    m_packetNumber = 1;
    m_totalRx = 0;
    m_packetNumber_sifting = 0;
    m_encryptor = CreateObject<QKDEncryptor>(64); //64 bits long key IDs. Collisions->0
    GenerateRandomKeyId();
  }

  QKDPostprocessingApplication::~QKDPostprocessingApplication()
  {
    NS_LOG_FUNCTION(this);
  }


// Convert binary bits to byte string
std::string bitsToBytes(const std::string& bits) {
    std::string bytes;
    size_t padding =(8 -(bits.length() % 8)) % 8;
    std::string padded = bits + std::string(padding, '0');

    for(size_t i = 0; i < padded.length(); i += 8) {
        bytes += static_cast<char>(std::bitset<8>(padded.substr(i, 8)).to_ulong());
    }

    return bytes;
}

  void
  QKDPostprocessingApplication::GenerateRandomKeyId(){
    m_randomSeed = m_random->GetValue(0, 99999999);
  }


  uint32_t QKDPostprocessingApplication::GetTotalRx() const
  {
    NS_LOG_FUNCTION(this);
    return m_totalRx;
  }

  Ptr<Node>
  QKDPostprocessingApplication::GetSrc(){
    return m_src;
  }

  void
  QKDPostprocessingApplication::SetSrc(Ptr<Node> node){
    NS_LOG_FUNCTION(this << node->GetId());
    m_src = node;
  }

  Ptr<Node>
  QKDPostprocessingApplication::GetDst(){
    return m_dst;
  }

  void
  QKDPostprocessingApplication::SetDst(Ptr<Node> node){
    NS_LOG_FUNCTION(this << node->GetId());
    m_dst = node;
  }

  std::list<Ptr<Socket> >
  QKDPostprocessingApplication::GetAcceptedSockets() const
  {
    NS_LOG_FUNCTION(this);
    return m_sinkSocketList;
  }

  Ptr<Socket>
  QKDPostprocessingApplication::GetSinkSocket() const
  {
    NS_LOG_FUNCTION(this);
    return m_sinkSocket;
  }

  Ptr<Socket>
  QKDPostprocessingApplication::GetSendSocket() const
  {
    NS_LOG_FUNCTION(this);
    return m_sendSocket;
  }

  void
  QKDPostprocessingApplication::SetSocket(std::string type, Ptr<Socket> socket, bool isMaster)
  {
      NS_LOG_FUNCTION(this << type << socket << isMaster);
      if(type == "send")//send app
        m_sendSocket = socket;
      else // sink app
        m_sinkSocket = socket;

      m_master = isMaster;
  }

  void
  QKDPostprocessingApplication::SetSiftingSocket(std::string type, Ptr<Socket> socket)
  {
    NS_LOG_FUNCTION(this << type << socket);
    if(type == "send")//send app
      m_sendSocket_sifting = socket;
    else // sink app
      m_sinkSocket_sifting = socket;
  }

  void
  QKDPostprocessingApplication::DoDispose()
  {
    NS_LOG_FUNCTION(this);

    m_sendSocket = nullptr;
    m_sinkSocket = nullptr;
    m_sendSocket_sifting = nullptr;
    m_sinkSocket_sifting = nullptr;

    m_sinkSocketList.clear();
    Simulator::Cancel(m_sendEvent);
    // chain up
    Application::DoDispose();
  }

  // Application Methods
  void
  QKDPostprocessingApplication::StartApplication()
  {
    NS_LOG_FUNCTION(this << "\nQKD module ID:" << GetId() << ";\nMatching QKD module ID:" << GetPeerId());

    // SINK socket settings
    if(!m_sinkSocket) m_sinkSocket = Socket::CreateSocket(GetNode(), m_tid);
    InetSocketAddress sinkAddress = InetSocketAddress(
      Ipv4Address::GetAny(),
      InetSocketAddress::ConvertFrom(m_local).GetPort()
    );
    if(m_sinkSocket->Bind(sinkAddress) == -1) NS_FATAL_ERROR("Failed to bind socket " << m_local);
    m_sinkSocket->Listen();
    m_sinkSocket->ShutdownSend();
    m_sinkSocket->SetRecvCallback(MakeCallback(&QKDPostprocessingApplication::HandleRead, this));
    m_sinkSocket->SetAcceptCallback(
      MakeNullCallback<bool, Ptr<Socket>, const Address &>(),
      MakeCallback(&QKDPostprocessingApplication::HandleAccept, this)
    );
    m_sinkSocket->SetCloseCallbacks(
      MakeCallback(&QKDPostprocessingApplication::HandlePeerClose, this),
      MakeCallback(&QKDPostprocessingApplication::HandlePeerError, this)
    );

    // SEND socket settings
    if(!m_sendSocket) m_sendSocket = Socket::CreateSocket(GetNode(), m_tid);
    Ptr<Ipv4L3Protocol> ipv4 = GetNode()->GetObject<Ipv4L3Protocol>();
    uint32_t interface = ipv4->GetInterfaceForAddress( InetSocketAddress::ConvertFrom(m_local).GetIpv4() );
    Ptr<NetDevice> netDevice = ipv4->GetNetDevice(interface);
    //m_sendSocket->BindToNetDevice(netDevice);
    m_sendSocket->ShutdownRecv();
    m_sendSocket->SetConnectCallback(
      MakeCallback(&QKDPostprocessingApplication::ConnectionSucceeded, this),
      MakeCallback(&QKDPostprocessingApplication::ConnectionFailed, this)
    );
    m_sendSocket->SetDataSentCallback(
      MakeCallback(&QKDPostprocessingApplication::DataSend, this)
    );
    m_sendSocket->TraceConnectWithoutContext("RTT", MakeCallback(&QKDPostprocessingApplication::RegisterAckTime, this));
    m_sendSocket->Connect(m_peer);

    NS_LOG_FUNCTION(
      this <<
      "Connecting QKDApp(" <<
      InetSocketAddress::ConvertFrom(m_peer).GetIpv4() << " port " << InetSocketAddress::ConvertFrom(m_peer).GetPort() <<
      " from " <<
      InetSocketAddress::ConvertFrom(m_local).GetIpv4() << " port " << InetSocketAddress::ConvertFrom(m_local).GetPort()
    );


    /****   SIFTING SOCKETS    ****/
    // SINK socket settings
    if(!m_sinkSocket_sifting) m_sinkSocket_sifting = Socket::CreateSocket(GetNode(), m_tidSifting);
    if(m_sinkSocket_sifting->Bind(m_local_sifting) == -1) NS_FATAL_ERROR("Failed to bind SIFTING socket " << m_local_sifting);
    m_sinkSocket_sifting->Listen();
    m_sinkSocket_sifting->ShutdownSend();
    m_sinkSocket_sifting->SetRecvCallback(MakeCallback(&QKDPostprocessingApplication::HandleReadSifting, this));

    // SEND socket settings
    if(!m_sendSocket_sifting) m_sendSocket_sifting = Socket::CreateSocket(GetNode(), m_tidSifting);
    m_sendSocket_sifting->Connect(m_peer_sifting);
    m_sendSocket_sifting->ShutdownRecv();


    /****   QISKIT SOCKET    ****/

    NS_LOG_FUNCTION(
      this << "BIND QISKIT socket to port " <<
      InetSocketAddress::ConvertFrom(m_local).GetPort()+50
    );

    // SINK socket settings
    if(!m_sinkSocketQiskit) m_sinkSocketQiskit = Socket::CreateSocket(GetNode(), m_tid);
    InetSocketAddress sinkAddressQiskit = InetSocketAddress(
      Ipv4Address::GetAny(),
      //Ipv4Address("192.168.0.8"),
      InetSocketAddress::ConvertFrom(m_local).GetPort()+50
    );
    if(m_sinkSocketQiskit->Bind(sinkAddressQiskit) == -1) NS_FATAL_ERROR("Failed to bind QISKIT socket " << m_local);
    m_sinkSocketQiskit->Listen();
    m_sinkSocketQiskit->ShutdownSend();
    m_sinkSocketQiskit->SetRecvCallback(MakeCallback(&QKDPostprocessingApplication::HandleReadQiskit, this));
    m_sinkSocketQiskit->SetAcceptCallback(
      MakeNullCallback<bool, Ptr<Socket>, const Address &>(),
      MakeCallback(&QKDPostprocessingApplication::HandleAcceptQiskit, this)
    );
    m_sinkSocketQiskit->SetCloseCallbacks(
      MakeCallback(&QKDPostprocessingApplication::HandlePeerCloseQiskit, this),
      MakeCallback(&QKDPostprocessingApplication::HandlePeerErrorQiskit, this)
    );

    /****   KMS SOCKETS    ****/

    // SEND socket settings
    if(!m_sendSocketKMS) m_sendSocketKMS = Socket::CreateSocket(GetNode(), m_tid);
    Ipv4Address localIpv4 = InetSocketAddress::ConvertFrom(m_local).GetIpv4();
    /*InetSocketAddress senderKMS = InetSocketAddress(
      InetSocketAddress::ConvertFrom(m_kms).GetIpv4(), //destination address
      InetSocketAddress::ConvertFrom(m_kms).GetPort() //destination listening port
    ); */

    //m_sendSocketKMS->Bind(senderKMS);
    m_sendSocketKMS->Bind();
    m_sendSocketKMS->ShutdownRecv();
    m_sendSocketKMS->SetConnectCallback(
        MakeCallback(&QKDPostprocessingApplication::ConnectionSucceededKMS, this),
        MakeCallback(&QKDPostprocessingApplication::ConnectionFailedKMS, this));
    m_sendSocketKMS->SetDataSentCallback(
        MakeCallback(&QKDPostprocessingApplication::DataSendKMS, this));
    m_sendSocketKMS->TraceConnectWithoutContext("RTT", MakeCallback(&QKDPostprocessingApplication::RegisterAckTime, this));
    m_sendSocketKMS->Connect(m_kms);


    Address allocatedLocalAddress;
    m_sendSocketKMS->GetSockName(allocatedLocalAddress);
    // SINK socket settings
    Address localAddress = InetSocketAddress(
      InetSocketAddress::ConvertFrom(m_local).GetIpv4(),
      InetSocketAddress::ConvertFrom(allocatedLocalAddress).GetPort()+100
      //82+m_ppId
    );
    m_sinkSocketKMS = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId() );
    //if(!m_sinkSocketKMS) m_sinkSocketKMS = Socket::CreateSocket(GetNode(), m_tid);

    //uint32_t portKMS = InetSocketAddress::ConvertFrom(m_kms).GetPort();
    //if(m_sinkSocketKMS->Bind(m_kms) == -1) NS_FATAL_ERROR("Failed to bind socket");
    if(m_sinkSocketKMS->Bind(localAddress) == -1) NS_FATAL_ERROR("Failed to bind socket");
    m_sinkSocketKMS->Listen();
    m_sinkSocketKMS->ShutdownSend();
    m_sinkSocketKMS->SetRecvCallback(MakeCallback(&QKDPostprocessingApplication::HandleReadKMS, this));
    m_sinkSocketKMS->SetAcceptCallback(
        MakeNullCallback<bool, Ptr<Socket>, const Address &>(),
        MakeCallback(&QKDPostprocessingApplication::HandleAcceptKMS, this));
    m_sinkSocketKMS->SetCloseCallbacks(
        MakeCallback(&QKDPostprocessingApplication::HandlePeerCloseKMS, this),
        MakeCallback(&QKDPostprocessingApplication::HandlePeerErrorKMS, this));

    NS_LOG_FUNCTION(
      this <<
      "Connecting KMS(" <<
      InetSocketAddress::ConvertFrom(m_kms).GetIpv4() << " port " << InetSocketAddress::ConvertFrom(m_kms).GetPort() <<
      " from " <<
      localIpv4 << " port" << InetSocketAddress::ConvertFrom(allocatedLocalAddress).GetPort()
    );
  }

  void
  QKDPostprocessingApplication::StopApplication()
  {
    NS_LOG_FUNCTION(this << "\nQKD module ID:" << GetId() << ";\nMatching QKD module ID:" << GetPeerId());

    if(m_sendSocket)
      m_sendSocket->Close();
    else
      NS_LOG_WARN("QKDPostprocessingApplication found null socket to close in StopApplication()!");

    while(!m_sinkSocketList.empty()){ //these are accepted sockets, close them
      Ptr<Socket> acceptedSocket = m_sinkSocketList.front();
      m_sinkSocketList.pop_front();
      acceptedSocket->Close();
    }
    if(m_sinkSocket){
      m_sinkSocket->Close();
      m_sinkSocket->SetRecvCallback(MakeNullCallback<void, Ptr<Socket> >());
    }

    m_connected = false;
    Simulator::Cancel(m_sendEvent);//
  }

  void
  QKDPostprocessingApplication::ScheduleNextReset()
  {
    //Time nextTime(Seconds(round((m_keySize*8) / static_cast<double>(m_keyRate.GetBitRate())))); // Time till next QKD packet
    Time nextTime(Seconds((m_keySize*8) / static_cast<double>(m_keyRate.GetBitRate()))); // Time till next QKD packet
    Simulator::Schedule(nextTime, &QKDPostprocessingApplication::ResetCounter, this);

    NS_LOG_FUNCTION(this << nextTime);
  }

  void
  QKDPostprocessingApplication::ResetCounter()
  {
    NS_LOG_FUNCTION(this << "Reached packet number:" << m_packetNumber);

    if(m_master) m_packetNumber = 0;
    if(m_connected){
      SendSiftingPacket();
      SendData();
      ScheduleNextReset();
    }
  }

  void
  QKDPostprocessingApplication::SendData()
  {
    if(m_master)
      NS_LOG_FUNCTION(this << "********************** MASTER **********************");
    else
      NS_LOG_FUNCTION(this << "********************** SLAVE **********************");

    NS_LOG_DEBUG(this << "\tSending packet " << m_packetNumber);
    if(m_packetNumber > 0){
      nlohmann::json msgBody = {
        {"ACTION", "QKDPPS"},
        {"NUMBER", m_packetNumber}
      };
      std::string message = msgBody.dump();
      PrepareOutput(message, "qkdpps");

    }else{
      NS_LOG_FUNCTION(this << "m_lastUUID:\t" << m_lastUUID);

      std::string keyId;
      if(m_master){
        UUID keyIdRaw = UUID::Sequential();
        keyId = keyIdRaw.string();
      }else
        keyId = m_lastUUID;

      if(!keyId.empty())
      {
        GenerateRandomKeyId();
        nlohmann::json msgBody = {
          {"ACTION", "ADDKEY"},
          {"size", m_keySize},
          {"uuid", keyId},
          {"srid", m_randomSeed}
        };
        std::string message = msgBody.dump();
        PrepareOutput(message, "addkey");
        //ScheduleNextReset();

        if(m_master && m_connected)
        {

          // Convert to bytes
          std::string byteKey = GenerateRandomString(m_keySize);
          // Convert to Base64 for JSON storage
          std::string keyValue = m_encryptor->Base64Encode(byteKey);

          NS_LOG_FUNCTION(this << "ADDKEY:" << keyId);
          NS_LOG_FUNCTION(this << "m_keySize:" << m_keySize);
          NS_LOG_FUNCTION(this << "byteKey.size():" << byteKey.size());
          //NS_LOG_FUNCTION(this << "byteKey:" << byteKey);
          //NS_LOG_FUNCTION(this << "keyValue:" << keyValue);

          StoreKey(keyId, keyValue);

        }
      }

    }
    m_packetNumber++;

  }

  void
  QKDPostprocessingApplication::PrepareOutput(std::string value, std::string action)
  {
    NS_LOG_FUNCTION(this <<  Simulator::Now() << action);

    if(static_cast<double>(m_dataRate.GetBitRate()) > 0 && m_pktSize > 0)
    {
      std::ostringstream msg;
      msg << value << ";";
      //Playing with packet size to introduce some randomness
      msg << std::string(m_random->GetValue(m_pktSize, m_pktSize*1.1), '0');
      msg << '\0';

      Ptr<Packet> packet = Create<Packet>((uint8_t*) msg.str().c_str(), msg.str().length());
      NS_LOG_DEBUG(this << "\t!!!SENDING PACKET WITH CONTENT:" << value << " of size " << packet->GetSize());

      uint32_t bits = packet->GetSize() * 8;
      NS_LOG_LOGIC(this << "bits = " << bits);

      if(action == "qkdpps"){
        Time nextTime(Seconds(bits / static_cast<double>(m_dataRate.GetBitRate()))); // Time till next packet
        NS_LOG_FUNCTION(this << "CALCULATED NEXTTIME:" << bits / m_dataRate.GetBitRate());
        NS_LOG_LOGIC("nextTime = " << nextTime);
        m_sendEvent = Simulator::Schedule(nextTime, &QKDPostprocessingApplication::SendPacket, this, packet);

      }else if(action == "addkey")
        SendPacket(packet);
    }
  }


  void
  QKDPostprocessingApplication::SendPacket(Ptr<Packet> packet)
  {
      NS_LOG_FUNCTION(this << "\t" << packet << "PACKETID: " << packet->GetUid() << packet->GetSize());
      if(m_connected){
        m_txTrace(packet);
        m_sendSocket->Send(packet);
      }
  }

  void
  QKDPostprocessingApplication::StoreKey(std::string keyId, std::string keyValue)
  {
    NS_LOG_FUNCTION(this << keyId);
    nlohmann::json msgBody = {
      {"qkd_module_ID", GetId()},
      {"matching_qkd_module_ID", GetPeerId()},
      {"key_ID", keyId},
      {"key", keyValue}
    };
    std::string msg = msgBody.dump();

    std::string headerUri = "http://" + GetStringAddress(m_kms) + "/api/v1/keys/" + GetPeerId() + "/store_key";

    NS_LOG_FUNCTION(this <<"aaaa:" <<  headerUri);
    HTTPMessage httpMessage;
    httpMessage.CreateRequest(headerUri, "POST", msg);
    httpMessage.SetHeader("User-Agent", "QKDModule_" + GetId());
    std::string hMessage = httpMessage.ToString();
    Ptr<Packet> packet = Create<Packet>(
     (uint8_t*)(hMessage).c_str(),
      hMessage.size()
    );
    NS_ASSERT(packet);

    NS_LOG_FUNCTION(this << "Sending PACKETID: "
      << packet->GetUid()
      << " of size: " << packet->GetSize()
      << " method name:" << "store_key"
      << " key_id: " << keyId
      << " via socket " << m_sendSocketKMS
      << httpMessage.GetUri()
      << " of msg " << msg
      );

    m_txTraceKMS(packet);
    m_sendSocketKMS->Send(packet);

  }

  std::string
  QKDPostprocessingApplication::GetStringAddress(Address m_address)
  {
    NS_LOG_FUNCTION(this << m_address);
    Ipv4Address ipv4Adr = InetSocketAddress::ConvertFrom(m_address).GetIpv4();
    std::ostringstream ipv4AdrTemp;
    ipv4Adr.Print(ipv4AdrTemp); //IPv4Address to string

    return ipv4AdrTemp.str();
  }

  void
  QKDPostprocessingApplication::SendSiftingPacket()
  {
    NS_LOG_FUNCTION(this);

    Ptr<Packet> packet = Create<Packet>( uint32_t(800 + m_random->GetValue(100, 300)) );
    m_sendSocket_sifting->Send(packet);
    NS_LOG_FUNCTION(this << "Sending SIFTING packet" << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize());

    m_packetNumber_sifting++;
    if(m_packetNumber_sifting < m_maxPackets_sifting)
      Simulator::Schedule(MicroSeconds(400), &QKDPostprocessingApplication::SendSiftingPacket, this);
    else
      m_packetNumber_sifting = 0;
  }

  void
  QKDPostprocessingApplication::HandleReadKMS(Ptr<Socket> socket)
  {
    if(m_master)
      NS_LOG_FUNCTION(this << "--------------MASTER--------------");
    else
      NS_LOG_FUNCTION(this << "--------------SLAVE--------------");

    Ptr<Packet> packet;
    Address from;
    while((packet = socket->RecvFrom(from))){

      if(packet->GetSize() == 0) break; //EOF

      NS_LOG_FUNCTION(this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() );

      m_totalRx += packet->GetSize();
      if(InetSocketAddress::IsMatchingType(from))
        NS_LOG_FUNCTION(this << "At time " << Simulator::Now().GetSeconds()
          << "s packet sink received "
          <<  packet->GetSize() << " bytes from "
          << InetSocketAddress::ConvertFrom(from).GetIpv4()
          << " port " << InetSocketAddress::ConvertFrom(from).GetPort()
          << " total Rx " << m_totalRx << " bytes");
      m_rxTraceKMS(packet, from);

    }
  }

  void
  QKDPostprocessingApplication::HandleReadQiskit(Ptr<Socket> socket)
  {
    if(m_master)
      NS_LOG_FUNCTION(this << "--------------MASTER--------------");
    else
      NS_LOG_FUNCTION(this << "--------------SLAVE--------------");

    Ptr<Packet> packet;
    Address from;
    while((packet = socket->RecvFrom(from)))
    {
      if(packet->GetSize() == 0) break; //EOF

      NS_LOG_FUNCTION(this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() );
      PacketReceived(packet, from, socket);
    }
  }
void
QKDPostprocessingApplication::PacketReceived(const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << p->GetUid() << p->GetSize() << from);

  // Maintain per-sender buffer
  Ptr<Packet> &buffer = m_buffer[from];
  if (!buffer) buffer = Create<Packet>(0);
  buffer->AddAtEnd(p);
  NS_LOG_DEBUG("Buffer after append: " << buffer->GetSize());

  HTTPMessageParser parser;
  while (buffer->GetSize() > 0) {
    // Copy buffer to string
    std::string bufferStr(buffer->GetSize(), '\0');
    buffer->CopyData(reinterpret_cast<uint8_t*>(&bufferStr[0]), bufferStr.size());

    std::string httpMessageStr;
    size_t httpMessageSize = 0;

    if (!parser.TryExtractHttpMessage(bufferStr, httpMessageStr, httpMessageSize)) {
      NS_LOG_DEBUG("[DEBUG] Incomplete or fragmented HTTP message. Awaiting more data.");
      break;
    }

    // Parse HTTP message
    HTTPMessage request;
    parser.Parse(&request, httpMessageStr);

    if (request.IsFragmented() || request.GetSize() == 0) {
      NS_LOG_WARN("[WARN] Fragmented or malformed HTTP message. Waiting...");
      break;
    }

    // Process complete HTTP packet
    Ptr<Packet> completePacket = buffer->CreateFragment(0, static_cast<uint32_t>(httpMessageSize));
    buffer->RemoveAtStart(static_cast<uint32_t>(httpMessageSize));

    NS_LOG_DEBUG("[DEBUG] Processing Qiskit request, size: " << httpMessageSize);
    ProcessQiskitRequest(request, completePacket, socket);
  }
}




  void
  QKDPostprocessingApplication::ProcessQiskitRequest(HTTPMessage headerIn, Ptr<Packet> packet, Ptr<Socket> socket)
  {
    NS_LOG_FUNCTION(this << headerIn.GetUri() << packet->GetUid());
    NS_ASSERT(!headerIn.GetUri().empty());

    std::string payloadRaw = headerIn.GetMessageBodyString(); //Read payload
    if(!payloadRaw.empty()){
      std::string label;
      nlohmann::json jresponse;
      try{
        jresponse = nlohmann::json::parse(payloadRaw);
      }catch(...){
        NS_FATAL_ERROR(this << "JSON parse error!");
      }

      if(jresponse.contains("ACTION")) label = jresponse["ACTION"];
      NS_LOG_DEBUG(this << "\tLABEL:\t" << label << "\tPACKETVALUE:\t" << socket);

      if(label == "SAVEQISKITKEY")
      {
        //if(!m_master){

        std::string keyId;
        std::string keyValueBits;
        std::string keyValue;
        if(jresponse.contains("keyid")) keyId = jresponse["keyid"];
        if(jresponse.contains("keyvalue")) keyValueBits = jresponse["keyvalue"];

        NS_LOG_FUNCTION(this << "SAVEQISKITKEY" << keyId);

        // Convert to bytes
        std::string byteKey = bitsToBytes(keyValueBits);

        // Convert to Base64 for JSON storage
        keyValue = m_encryptor->Base64Encode(byteKey);

        if(!keyId.empty() && !keyValue.empty())
          StoreKey(keyId, keyValue);

        //create packet
        HTTPMessage httpMessage;
        httpMessage.CreateResponse(HTTPMessage::HttpStatus::Ok, "", {
          {"Content-Type", "application/json; charset=utf-8"},
          {"Request URI", headerIn.GetUri() }
        });
        std::string hMessage = httpMessage.ToString();
        Ptr<Packet> packetR = Create<Packet>(
         (uint8_t*)(hMessage).c_str(),
          hMessage.size()
        );
        socket->Send(packetR);


        //}
      }
    }
}












  void
  QKDPostprocessingApplication::HandleRead(Ptr<Socket> socket)
  {
    if(m_master)
      NS_LOG_FUNCTION(this << "--------------MASTER--------------");
    else
      NS_LOG_FUNCTION(this << "--------------SLAVE--------------");

    Ptr<Packet> packet;
    Address from;
    while((packet = socket->RecvFrom(from))){

        if(packet->GetSize() == 0) break; //EOF

        NS_LOG_FUNCTION(this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() );

        m_totalRx += packet->GetSize();
        if(InetSocketAddress::IsMatchingType(from))
          NS_LOG_FUNCTION(this << "At time " << Simulator::Now().GetSeconds()
            << "s packet sink received "
            <<  packet->GetSize() << " bytes from "
            << InetSocketAddress::ConvertFrom(from).GetIpv4()
            << " port " << InetSocketAddress::ConvertFrom(from).GetPort()
            << " total Rx " << m_totalRx << " bytes");


        m_rxTrace(packet, from);
        if(!m_master) ProcessIncomingPacket(packet);

    }
  }


  void
  QKDPostprocessingApplication::ProcessIncomingPacket(Ptr<Packet> packet)
  {
      /**
      *  POST PROCESSING
      */
      uint8_t *buffer = new uint8_t[packet->GetSize()];
      packet->CopyData(buffer, packet->GetSize());
      std::string s = std::string((char*)buffer);
      delete[] buffer;

      if(s.size() > 5){

        NS_LOG_FUNCTION(this << "payload:" << s);
        std::size_t pos = s.find(";");
        std::string payloadRaw = s.substr(0,pos); //remove padding zeros
        NS_LOG_FUNCTION(this << "payloadRaw:" << payloadRaw);

        std::string label;
        nlohmann::json jresponse;
        try{
          jresponse = nlohmann::json::parse(payloadRaw);
        }catch(...){
          NS_FATAL_ERROR(this << "JSON parse error!");
        }

        if(jresponse.contains("ACTION")) label = jresponse["ACTION"];
        NS_LOG_DEBUG(this << "\tLABEL:\t" <<  jresponse["ACTION"] << "\tPACKETVALUE:\t" << s);

        if(label == "ADDKEY"){

          if(!m_master){
            uint32_t keySize = m_keySize;
            if(jresponse.contains("size")) keySize = uint32_t(jresponse["size"]);
            if(jresponse.contains("uuid")) m_lastUUID = jresponse["uuid"];
            if(jresponse.contains("srid")) m_randomSeed = jresponse["srid"];

            NS_LOG_FUNCTION(this << "ADDKEY" << m_lastUUID);

            // Convert to bytes
            std::string byteKey = GenerateRandomString(keySize);
            // Convert to Base64 for JSON storage
            std::string keyValue = m_encryptor->Base64Encode(byteKey);

            StoreKey(m_lastUUID, keyValue);
            m_packetNumber = 0;
          }

        }
      }
      SendData();
  }

  void
  QKDPostprocessingApplication::HandleReadSifting(Ptr<Socket> socket)
  {
    NS_LOG_FUNCTION(this << socket);

    if(m_master)
      NS_LOG_FUNCTION(this << "***MASTER***" );
    else
      NS_LOG_FUNCTION(this << "!!!SLAVE!!!");

    Ptr<Packet> packet;
    packet = socket->Recv(65535, 0);
  }

  void
  QKDPostprocessingApplication::HandlePeerClose(Ptr<Socket> socket)
  {
    NS_LOG_FUNCTION(this << socket);
  }

  void
  QKDPostprocessingApplication::HandlePeerCloseKMS(Ptr<Socket> socket)
  {
    NS_LOG_FUNCTION(this << socket);
  }

  void
  QKDPostprocessingApplication::HandlePeerCloseQiskit(Ptr<Socket> socket)
  {
    NS_LOG_FUNCTION(this << socket);
  }

  void
  QKDPostprocessingApplication::HandlePeerError(Ptr<Socket> socket)
  {
    NS_LOG_FUNCTION(this << socket);
  }

  void
  QKDPostprocessingApplication::HandlePeerErrorQiskit(Ptr<Socket> socket)
  {
    NS_LOG_FUNCTION(this << socket);
  }


  void
  QKDPostprocessingApplication::HandlePeerErrorKMS(Ptr<Socket> socket)
  {
    NS_LOG_FUNCTION(this << socket);
  }

  void
  QKDPostprocessingApplication::HandleAccept(Ptr<Socket> s, const Address& from)
  {
    NS_LOG_FUNCTION(this << s << from);
    s->SetRecvCallback(MakeCallback(&QKDPostprocessingApplication::HandleRead, this));
    m_sinkSocketList.push_back(s);
  }

  void
  QKDPostprocessingApplication::HandleAcceptKMS(Ptr<Socket> s, const Address& from)
  {
    NS_LOG_FUNCTION(this << s << from);
    s->SetRecvCallback(MakeCallback(&QKDPostprocessingApplication::HandleReadKMS, this));
  }

  void
  QKDPostprocessingApplication::HandleAcceptQiskit(Ptr<Socket> s, const Address& from)
  {
    NS_LOG_FUNCTION(this << s << from);
    s->SetRecvCallback(MakeCallback(&QKDPostprocessingApplication::HandleReadQiskit, this));
  }

  void
  QKDPostprocessingApplication::HandleAcceptSifting(Ptr<Socket> s, const Address& from)
  {
    NS_LOG_FUNCTION(this << s << from);
    s->SetRecvCallback(MakeCallback(&QKDPostprocessingApplication::HandleReadSifting, this));
    m_sinkSocketList.push_back(s);
  }

  void
  QKDPostprocessingApplication::ConnectionSucceeded(Ptr<Socket> socket)
  {
      NS_LOG_FUNCTION(this << socket);
      NS_LOG_FUNCTION(this << "QKDPostprocessingApplication Connection succeeded");

      if(m_sendSocket == socket || m_sinkSocket == socket){
        m_connected = true;

        if(m_master){

          NS_LOG_FUNCTION(this << "m_master:" << m_master);
          NS_LOG_FUNCTION(this << "m_dataRate.GetBitRate():" << m_dataRate.GetBitRate());
          NS_LOG_FUNCTION(this << "m_pktSize:" << m_pktSize);

          if(static_cast<double>(m_dataRate.GetBitRate()) > 0 && m_pktSize > 0)
          {
            SendSiftingPacket();
            SendData();
            ScheduleNextReset();
          }
        }
      }
  }

  void
  QKDPostprocessingApplication::ConnectionSucceededSifting(Ptr<Socket> socket)
  {
      NS_LOG_FUNCTION(this << socket);
      NS_LOG_FUNCTION(this << "QKDPostprocessingApplication SIFTING Connection succeeded");
  }

  void
  QKDPostprocessingApplication::ConnectionFailed(Ptr<Socket> socket)
  {
    NS_LOG_FUNCTION(this << socket);
    NS_LOG_FUNCTION(this << "QKDPostprocessingApplication, Connection Failed");
  }

  void
  QKDPostprocessingApplication::DataSend(Ptr<Socket> socket, uint32_t value)
  {
      NS_LOG_FUNCTION(this);
  }

  void
  QKDPostprocessingApplication::ConnectionSucceededKMS(Ptr<Socket> socket)
  {
      NS_LOG_FUNCTION(this << socket);
      NS_LOG_FUNCTION(this << "QKDPostprocessingApplication-KMS Connection succeeded");
  }

  void
  QKDPostprocessingApplication::ConnectionFailedKMS(Ptr<Socket> socket)
  {
    NS_LOG_FUNCTION(this << socket);
    NS_LOG_FUNCTION(this << "QKDPostprocessingApplication-KMS Connection Failed");
  }

  void
  QKDPostprocessingApplication::DataSendKMS(Ptr<Socket> socket, uint32_t value)
  {
      NS_LOG_FUNCTION(this);
  }

  void
  QKDPostprocessingApplication::RegisterAckTime(Time oldRtt, Time newRtt)
  {
    NS_LOG_FUNCTION(this << oldRtt << newRtt);
    m_lastAck = Simulator::Now();
  }

  Time
  QKDPostprocessingApplication::GetLastAckTime()
  {
    NS_LOG_FUNCTION(this);
    return m_lastAck;
  }

  std::string
  QKDPostprocessingApplication::GenerateRandomString(const int len) {

      NS_LOG_FUNCTION( this << len );
      srand( m_randomSeed );

      std::string tmp_s;
      static const char alphanum[] =
          "0123456789"
          "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
          "abcdefghijklmnopqrstuvwxyz";
      //srand( m_internalID );
      for(int i = 0; i < len; ++i){
          tmp_s += alphanum[rand() %(sizeof(alphanum) - 1)];
      }
      return tmp_s;
  }

} // Namespace ns3

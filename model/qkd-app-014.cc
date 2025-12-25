/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 * Author:  Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 *          Miralem Mehic <miralem.mehic@etf.unsa.ba>
 */

#include "ns3/address.h"
#include "ns3/address-utils.h"
#include "ns3/log.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/node.h"
#include "ns3/socket.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/tcp-socket-factory.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/packet.h"
#include "ns3/trace-source-accessor.h"
#include "qkd-app-014.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("QKDApp014");

NS_OBJECT_ENSURE_REGISTERED(QKDApp014);

TypeId
QKDApp014::GetTypeId()
{
  static TypeId tid = TypeId("ns3::QKDApp014")
    .SetParent<Application>()
    .SetGroupName("Applications")
    .AddConstructor<QKDApp014>()
    .AddAttribute("Protocol", "The type of protocol to use.",
                   TypeIdValue(TcpSocketFactory::GetTypeId()),
                   MakeTypeIdAccessor(&QKDApp014::m_tid),
                   MakeTypeIdChecker())
    .AddAttribute("NumberOfKeyToFetchFromKMS",
                   "The total number of keys per request to LKMS(ESTI QKD 014)",
                   UintegerValue(3),
                   MakeUintegerAccessor(&QKDApp014::m_numberOfKeysKMS),
                   MakeUintegerChecker<uint32_t>())
    .AddAttribute("LengthOfAuthenticationTag",
                   "The default length of the authentication tag",
                   UintegerValue(256), //32 bytes
                   MakeUintegerAccessor(&QKDApp014::m_authTagSize),
                   MakeUintegerChecker<uint32_t>())
    .AddAttribute("EncryptionType",
                   "The type of encryption to be used(0-unencrypted, 1-OTP, 2-AES)",
                   UintegerValue(1),
                   MakeUintegerAccessor(&QKDApp014::m_encryption),
                   MakeUintegerChecker<uint32_t>())
    .AddAttribute("AuthenticationType",
                   "The type of authentication to be used(0-unauthenticated, 1-VMAC, 2-MD5, 3-SHA1)",
                   UintegerValue(0),
                   MakeUintegerAccessor(&QKDApp014::m_authentication),
                   MakeUintegerChecker<uint32_t>())
    .AddAttribute("AESLifetime",
                   "Lifetime of AES key expressed in number of packets",
                   UintegerValue(1),
                   MakeUintegerAccessor(&QKDApp014::m_aesLifetime),
                   MakeUintegerChecker<uint32_t>())
    .AddAttribute("UseCrypto",
                   "Should crypto functions be performed(0-No, 1-Yes)",
                   UintegerValue(0),
                   MakeUintegerAccessor(&QKDApp014::m_useCrypto),
                   MakeUintegerChecker<uint32_t>())
    .AddAttribute("WaitInsufficient","Penalty time(in seconds) when there is insufficient amount of key",
                   TimeValue(Seconds(0.3)),
                   MakeTimeAccessor(&QKDApp014::m_waitInsufficient),
                   MakeTimeChecker())

    .AddTraceSource("Tx", "A new packet is created and is sent",
                     MakeTraceSourceAccessor(&QKDApp014::m_txTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource("TxSig", "A new signaling packet is created and is sent",
                     MakeTraceSourceAccessor(&QKDApp014::m_txSigTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource("TxKMS", "A new packet is created and is sent to local KMS",
                     MakeTraceSourceAccessor(&QKDApp014::m_txKmsTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource("Rx", "A new packet is received",
                     MakeTraceSourceAccessor(&QKDApp014::m_rxTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource("RxSig", "A new signaling packet is received",
                     MakeTraceSourceAccessor(&QKDApp014::m_rxSigTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource("RxKMS", "A new packet is received from local KMS",
                     MakeTraceSourceAccessor(&QKDApp014::m_rxKmsTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource("StateTransition",
                     "Trace fired upon every QKDApp014 state transition.",
                     MakeTraceSourceAccessor(&QKDApp014::m_stateTransitionTrace),
                     "ns3::Application::StateTransitionCallback")
    .AddTraceSource("PacketEncrypted",
                    "The change trance for currenly ecrypted packet",
                     MakeTraceSourceAccessor(&QKDApp014::m_encryptionTrace),
                     "ns3::QKDCrypto::PacketEncrypted")
    .AddTraceSource("PacketDecrypted",
                    "The change trance for currenly decrypted packet",
                     MakeTraceSourceAccessor(&QKDApp014::m_decryptionTrace),
                     "ns3::QKDCrypto::PacketDecrypted")
    .AddTraceSource("PacketAuthenticated",
                    "The change trance for currenly authenticated packet",
                     MakeTraceSourceAccessor(&QKDApp014::m_authenticationTrace),
                     "ns3::QKDCrypto::PacketAuthenticated")
    .AddTraceSource("PacketDeAuthenticated",
                    "The change trance for currenly deauthenticated packet",
                     MakeTraceSourceAccessor(&QKDApp014::m_deauthenticationTrace),
                     "ns3::QKDCrypto::PacketDeAuthenticated")
    .AddTraceSource("Mx", "Missed send packet call",
                     MakeTraceSourceAccessor(&QKDApp014::m_mxTrace),
                     "ns3::Packet::TracedCallback")
  ;

  return tid;
}
//@toDo: add use fallback to AES when OTP is used(Y/N)

uint32_t QKDApp014::m_applicationCounts = 0;

/**
 * ********************************************************************************************

 *        SETUP

 * ********************************************************************************************
 */

QKDApp014::QKDApp014()
  : m_signalingSocketApp(nullptr),
    m_dataSocketApp(nullptr),
    m_socketToKMS(nullptr),
    m_state(NOT_STARTED),
    m_master(0),
    m_size(0),
    m_rate(0),
    m_encryptor(nullptr),
    m_sendEvent()
{
  m_applicationCounts++;

  m_transitionMatrix = {
    {"NOT_STARTED", "INITIALIZED"},
    {"INITIALIZED", "WAIT"},
    {"INITIALIZED", "READY"},
    {"WAIT", "READY"},
    {"READY", "WAIT"},
    {"READY", "SEND_DATA"},
    {"SEND_DATA", "READY"},
    {"READY", "DECRYPT_DATA"},
    {"DECRYPT_DATA", "READY"},
    {"DECRYPT_DATA", "STOPPED"},
    {"SEND_DATA", "STOPPED"},
    {"READY", "STOPPED"},
    {"WAIT", "STOPPED"},
  };
}

QKDApp014::~QKDApp014()
{
    NS_LOG_FUNCTION(this);
}

void
QKDApp014::DoDispose()
{
    NS_LOG_FUNCTION(this);

    //Data sockets
    m_dataSocketApp = nullptr;
    //Signaling sockets
    m_signalingSocketApp = nullptr;
    //KMS sockets
    m_socketToKMS = nullptr;

    Application::DoDispose();
}

void
QKDApp014::Setup(
  std::string socketType,
  std::string appId,
  std::string remoteAppId,
  const Address&  appAddress,
  const Address&  remoteAppAddress,
  const Address&  kmAddress,
  std::string type
){
  Setup(
    socketType,
    appId,
    remoteAppId,
    appAddress,
    remoteAppAddress,
    kmAddress,
    0,
    0,
    type
  );
}

void
QKDApp014::Setup(
  std::string socketType,
  std::string appId,
  std::string remoteAppId,
  const Address&  appAddress,
  const Address&  remoteAppAddress,
  const Address&  kmAddress,
  uint32_t packetSize,
  DataRate dataRate,
  std::string type
)
{
  NS_LOG_FUNCTION(this);
  if(type == "alice")
    m_master = 1;
  else
    m_master = 0;

  m_id = appId;
  m_dstId = remoteAppId;

  NS_LOG_FUNCTION(this << remoteAppAddress);
  if(!remoteAppAddress.IsInvalid())
      m_peer = remoteAppAddress;

  NS_LOG_FUNCTION(this << appAddress);
  if(!appAddress.IsInvalid())
      m_local = appAddress;

  NS_LOG_FUNCTION(this << kmAddress);
  if(!kmAddress.IsInvalid())
      m_kms = kmAddress;

  m_portSignaling = 9010+m_applicationCounts;

  NS_LOG_FUNCTION(this << "Peer IP " << InetSocketAddress::ConvertFrom(m_peer).GetIpv4() << " and port " << m_portSignaling );

  m_size = packetSize;
  m_rate = dataRate;
  m_socketType = socketType;

  m_internalAppWait = false; //No longer wait schedule required!
  InitKeyStores(); //Setup application key buffer!
  SwitchAppState(INITIALIZED);
}

/**
 * ********************************************************************************************

 *        SCHEDULE functions

 * ********************************************************************************************
 */
void
QKDApp014::ScheduleTx()
{
  NS_LOG_FUNCTION(this << GetAppStateString(GetState()));
  if(GetState() != STOPPED && GetState() != NOT_STARTED && !m_sendEvent.IsPending())
  {
    double delay = m_size * 8 / static_cast<double>(m_rate.GetBitRate());
    NS_LOG_FUNCTION(this << "schedule in" << Seconds(delay));
    m_sendEvent = Simulator::Schedule(Time(Seconds(delay)), &QKDApp014::SendDataPacket, this);
  }
}

void
QKDApp014::ScheduleAction(Time t, std::string action)
{
    NS_LOG_FUNCTION(this); 
    if(action == "ManageStores"){
        if(!m_scheduleManageStores.IsPending())
        {
            m_scheduleManageStores = Simulator::Schedule(t, &QKDApp014::ManageStores, this); 
            NS_LOG_FUNCTION(this << action << "scheduled in" << t); 
        }else
            NS_LOG_FUNCTION(this << action << "already scheduled");

    }else
        NS_FATAL_ERROR( this << "invalid action" << action );
}
 

/**
 * ********************************************************************************************

 *        SOCKET functions

 * ********************************************************************************************
 */

void
QKDApp014::PrepareSocketToKMS()
{
  NS_LOG_FUNCTION(this);
  if(!m_socketToKMS)
  {
    Address lkmsAddress = InetSocketAddress(
      InetSocketAddress::ConvertFrom(m_kms).GetIpv4(),
      InetSocketAddress::ConvertFrom(m_kms).GetPort()
    );
    m_socketToKMS = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId() );

    m_socketToKMS->SetConnectCallback(
      MakeCallback(&QKDApp014::ConnectionToKMSSucceeded, this),
      MakeCallback(&QKDApp014::ConnectionToKMSFailed, this));
    m_socketToKMS->SetDataSentCallback(
      MakeCallback(&QKDApp014::DataToKMSSend, this));
    m_socketToKMS->SetRecvCallback(MakeCallback(&QKDApp014::HandleReadFromKMS, this));
    m_socketToKMS->SetAcceptCallback(
      MakeCallback(&QKDApp014::ConnectionRequestedFromKMS, this),
      MakeCallback(&QKDApp014::HandleAcceptFromKMS, this)
    );
    m_socketToKMS->SetCloseCallbacks(
      MakeCallback(&QKDApp014::HandlePeerCloseFromKMS, this),
      MakeCallback(&QKDApp014::HandlePeerErrorFromKMS, this)
    );
    m_socketToKMS->Bind();
    m_socketToKMS->Connect( lkmsAddress );
    NS_LOG_FUNCTION(this << "send socket created" << m_socketToKMS);

  }else
     NS_LOG_FUNCTION(this << "socket exists" << m_socketToKMS);

}

void
QKDApp014::PrepareSocketToApp()
{
  NS_LOG_FUNCTION(this);

  ////////////////
  // SIGNALING SOCKET
  ////////////////

  if(!m_signalingSocketApp  || !m_isSignalingConnectedToApp)
  {

    InetSocketAddress m_peerSignaling = InetSocketAddress(
      InetSocketAddress::ConvertFrom(m_peer).GetIpv4(),
      m_portSignaling
    );

    InetSocketAddress m_localSignaling = InetSocketAddress(
      InetSocketAddress::ConvertFrom(m_local).GetIpv4(),
      m_portSignaling
    );

    NS_LOG_FUNCTION(this << m_peerSignaling << m_localSignaling);

    if(!m_signalingSocketApp)
    {
      NS_LOG_FUNCTION(this << "Let's create signaling socket to peer APP!");

      m_signalingSocketApp = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId() );
      m_signalingSocketApp->SetConnectCallback(
        MakeCallback(&QKDApp014::ConnectionSignalingToAppSucceeded, this),
        MakeCallback(&QKDApp014::ConnectionSignalingToAppFailed, this)
      );
      m_signalingSocketApp->SetRecvCallback(MakeCallback(&QKDApp014::HandleReadSignalingFromApp, this));
      m_signalingSocketApp->SetAcceptCallback(
        MakeCallback(&QKDApp014::ConnectionRequestedSignalingFromApp, this),
        MakeCallback(&QKDApp014::HandleAcceptSignalingFromApp, this)
      );
      m_signalingSocketApp->SetCloseCallbacks(
        MakeCallback(&QKDApp014::HandlePeerCloseSignalingFromApp, this),
        MakeCallback(&QKDApp014::HandlePeerErrorSignalingFromApp, this)
      );
      if(m_master)
        m_signalingSocketApp->Bind();
    }

    if(!m_isSignalingConnectedToApp)
    {
      if(m_master)
      {
        NS_LOG_FUNCTION(this << "Let's connect to peer!");

        const auto ret [[maybe_unused]] = m_signalingSocketApp->Connect(m_peerSignaling);
        NS_LOG_DEBUG(this << " Connect() return value= " << ret << " GetErrNo= " << m_signalingSocketApp->GetErrno()
                          << ".");
        NS_ASSERT_MSG(m_signalingSocketApp, "Failed creating socket.");

      }else{
        if(m_signalingSocketApp->Bind(m_localSignaling) == -1)
        {
            NS_FATAL_ERROR("Failed to bind socket");
        }
        NS_LOG_FUNCTION(this << "PEER Listen");
        m_signalingSocketApp->Listen();
      }
    }
  }

    ////////////////
    // DATA SOCKET
    ////////////////

  if(!m_dataSocketApp  || !m_isDataConnectedToApp)
  {

    InetSocketAddress m_peerData = InetSocketAddress(
      InetSocketAddress::ConvertFrom(m_peer).GetIpv4(),
      InetSocketAddress::ConvertFrom(m_peer).GetPort()
    );

    InetSocketAddress m_localData = InetSocketAddress(
      InetSocketAddress::ConvertFrom(m_local).GetIpv4(),
      InetSocketAddress::ConvertFrom(m_local).GetPort()
    );

    if(!m_dataSocketApp)
    {
      NS_LOG_FUNCTION(this << "Let's create DATA socket to peer APP!");

      if(m_socketType == "tcp")
        m_dataSocketApp = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId() );
      else
        m_dataSocketApp = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId() );

      m_dataSocketApp->SetConnectCallback(
        MakeCallback(&QKDApp014::ConnectionToAppSucceeded, this),
        MakeCallback(&QKDApp014::ConnectionToAppFailed, this)
      );
      m_dataSocketApp->SetRecvCallback(MakeCallback(&QKDApp014::HandleReadFromApp, this));
      m_dataSocketApp->SetAcceptCallback(
        MakeCallback(&QKDApp014::ConnectionRequestedFromApp, this),
        MakeCallback(&QKDApp014::HandleAcceptFromApp, this)
      );
      m_dataSocketApp->SetCloseCallbacks(
        MakeCallback(&QKDApp014::HandlePeerCloseFromApp, this),
        MakeCallback(&QKDApp014::HandlePeerErrorFromApp, this)
      );
      if(m_master)
        m_dataSocketApp->Bind();
    }

    if(!m_isDataConnectedToApp)
    {
      if(m_master)
      {
        NS_LOG_FUNCTION(this << "Let's connect to DATA peer!");

        const auto ret [[maybe_unused]] = m_dataSocketApp->Connect(m_peerData);
        NS_LOG_DEBUG(this << " Connect() return value= " << ret << " GetErrNo= " << m_dataSocketApp->GetErrno()
                          << ".");
        NS_ASSERT_MSG(m_dataSocketApp, "Failed creating DATA socket.");

      }else{
        if(m_dataSocketApp->Bind(m_localData) == -1)
        {
            NS_FATAL_ERROR("Failed to bind DATA socket");
        }
        NS_LOG_FUNCTION(this << "PEER DATA Listen");
        m_dataSocketApp->Listen();
      }
    }

  }else
    NS_LOG_FUNCTION(this << "sockets exists" << m_signalingSocketApp << m_dataSocketApp);

}


bool
QKDApp014::ConnectionRequestedSignalingFromApp(Ptr<Socket> socket, const Address &from)
{
  NS_LOG_FUNCTION(this << socket << from
    << InetSocketAddress::ConvertFrom(from).GetIpv4()
    << InetSocketAddress::ConvertFrom(from).GetPort()
  );
  NS_LOG_FUNCTION(this << "requested on socket " << socket);
  m_isSignalingConnectedToApp = true;

  return true;
}

bool
QKDApp014::ConnectionRequestedFromApp(Ptr<Socket> socket, const Address &from)
{
  NS_LOG_FUNCTION(this << socket << from
    << InetSocketAddress::ConvertFrom(from).GetIpv4()
    << InetSocketAddress::ConvertFrom(from).GetPort()
  );
  NS_LOG_FUNCTION(this << "requested on socket " << socket);
  m_isDataConnectedToApp = true;

  return true;
}

bool
QKDApp014::ConnectionRequestedFromKMS(Ptr<Socket> socket, const Address &from)
{
  NS_LOG_FUNCTION(this << socket << from
    << InetSocketAddress::ConvertFrom(from).GetIpv4()
    << InetSocketAddress::ConvertFrom(from).GetPort()
  );
  NS_LOG_FUNCTION(this << "requested on socket " << socket);

  return true;
}

void
QKDApp014::HandleAcceptFromKMS(Ptr<Socket> socket, const Address& from)
{
  NS_LOG_FUNCTION(this << socket << from
    << InetSocketAddress::ConvertFrom(from).GetIpv4()
    << InetSocketAddress::ConvertFrom(from).GetPort()
  );
  NS_LOG_FUNCTION(this << "accepted on socket " << socket);
  socket->SetRecvCallback(MakeCallback(&QKDApp014::HandleReadFromKMS, this));

}

void
QKDApp014::HandleAcceptFromApp(Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION(this << s << from
    << InetSocketAddress::ConvertFrom(from).GetIpv4()
    << InetSocketAddress::ConvertFrom(from).GetPort()
  );
  m_dataSocketApp = s;
  NS_LOG_FUNCTION(this << "accepted on socket " << s);
  s->SetRecvCallback(MakeCallback(&QKDApp014::HandleReadFromApp, this));

}

void
QKDApp014::HandleAcceptSignalingFromApp(Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION(this << s << from
    << InetSocketAddress::ConvertFrom(from).GetIpv4()
    << InetSocketAddress::ConvertFrom(from).GetPort()
  );
  m_signalingSocketApp = s;
  NS_LOG_FUNCTION(this << "accepted on socket " << s);
  s->SetRecvCallback(MakeCallback(&QKDApp014::HandleReadSignalingFromApp, this));

}

void
QKDApp014::ConnectionToKMSSucceeded(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket << "succeeded via socket " << socket);
}

void
QKDApp014::ConnectionToKMSFailed(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket << "failed via socket " << socket);
}
void
QKDApp014::ConnectionToAppFailed(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << "failed via socket " << socket);
}

void
QKDApp014::ConnectionSignalingToAppSucceeded(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << "succeeded via socket " << socket);
  m_isSignalingConnectedToApp = true;
}

void
QKDApp014::ConnectionToAppSucceeded(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << "succeeded via socket " << socket);
  m_isDataConnectedToApp = true;
}

void
QKDApp014::ConnectionSignalingToAppFailed(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << "failed via socket " << socket);
}

void
QKDApp014::HandlePeerCloseFromKMS(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);
}

void
QKDApp014::HandlePeerErrorFromKMS(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);
}

void
QKDApp014::HandlePeerCloseFromApp(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);
}
void
QKDApp014::HandlePeerErrorFromApp(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);
}

void
QKDApp014::HandlePeerCloseSignalingFromApp(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);
}

void
QKDApp014::HandlePeerErrorSignalingFromApp(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);
}

void
QKDApp014::HandleReadFromKMS(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);
  Ptr<Packet> packet;
  Address from;
  while((packet = socket->RecvFrom(from))){
      if(packet->GetSize() == 0) //EOF
        break;

      NS_LOG_FUNCTION(this
        << packet << "PACKETID: " << packet->GetUid()
        << " of size: " << packet->GetSize()
      );
      if(InetSocketAddress::IsMatchingType(from)){
          NS_LOG_FUNCTION("At time " << Simulator::Now().GetSeconds()
                   << "s packet from KMS received "
                   <<  packet->GetSize() << " bytes from "
                   << InetSocketAddress::ConvertFrom(from).GetIpv4()
                   << " port " << InetSocketAddress::ConvertFrom(from).GetPort()
          );

      }
      HttpPacketReceived(packet, from, socket);

  }
}

void
QKDApp014::HandleReadFromApp(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);
  Ptr<Packet> packet;
  Address from;
  while((packet = socket->RecvFrom(from))){
      if(packet->GetSize() == 0) //EOF
        break;

      NS_LOG_FUNCTION(this << packet
        << "PACKETID: " << packet->GetUid()
        << " of size: " << packet->GetSize()
      );
      if(InetSocketAddress::IsMatchingType(from)){
          NS_LOG_FUNCTION( this << "At time " << Simulator::Now().GetSeconds()
                   << "s packet from APP pair received "
                   <<  packet->GetSize() << " bytes from "
                   << InetSocketAddress::ConvertFrom(from).GetIpv4()
                   << " port " << InetSocketAddress::ConvertFrom(from).GetPort()
          );

      }
      QAppPacketReceived(packet, from, socket);

  }
}

void
QKDApp014::HandleReadSignalingFromApp(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);
  Ptr<Packet> packet;
  Address from;
  while((packet = socket->RecvFrom(from))){
      if(packet->GetSize() == 0) //EOF
        break;

      NS_LOG_FUNCTION(this << packet
        << "PACKETID: " << packet->GetUid()
        << " of size: " << packet->GetSize()
      );
      if(InetSocketAddress::IsMatchingType(from)){
          NS_LOG_FUNCTION( this << "At time " << Simulator::Now().GetSeconds()
                   << "s signaling packet from APP pair received "
                   <<  packet->GetSize() << " bytes from "
                   << InetSocketAddress::ConvertFrom(from).GetIpv4()
                   << " port " << InetSocketAddress::ConvertFrom(from).GetPort()
          );

      }
      HttpPacketReceived(packet, from, socket);

  }
}


void
QKDApp014::QAppPacketReceived(const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION( this << m_master << p->GetUid() << p->GetSize() << from );
  NS_ASSERT(!m_master);

  //Must be ready to receive data
  if(GetState() == READY)
  {
    QKDAppHeader header;
    Ptr<Packet> buffer;

    auto itBuffer = m_buffer_QKDApp014.find(from);
    if(itBuffer == m_buffer_QKDApp014.end())
      itBuffer = m_buffer_QKDApp014.insert(std::make_pair(from, Create<Packet>(0))).first;

    buffer = itBuffer->second;
    buffer->AddAtEnd(p);
    buffer->PeekHeader(header);
    NS_ABORT_IF(header.GetLength() == 0);

    while(buffer->GetSize() >= header.GetLength()){
      NS_LOG_DEBUG("Removing packet of size " << header.GetLength() << " from buffer of size " << buffer->GetSize());
      Ptr<Packet> completePacket = buffer->CreateFragment(0, static_cast<uint32_t>(header.GetLength()));
      buffer->RemoveAtStart(static_cast<uint32_t>(header.GetLength()));

      m_rxTrace(GetId(), completePacket);
      completePacket->RemoveHeader(header);
      NS_LOG_FUNCTION(this << "RECEIVED QKDApp014 HEADER: " << header);

      ProcessDataPacket(header, completePacket, socket);
      if(buffer->GetSize() > header.GetSerializedSize())
        buffer->PeekHeader(header);
      else
        break;

    }

  }else
      NS_LOG_DEBUG(this << "invalid state " << GetAppStateString());

}

void
QKDApp014::HttpPacketReceived(const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << p->GetUid() << p->GetSize() << from);

  // Maintain per-peer buffer
  Ptr<Packet> &buffer = m_buffer_kms[from];
  if (!buffer) buffer = Create<Packet>(0);
  buffer->AddAtEnd(p);

  HTTPMessageParser parser;
  while (buffer->GetSize() > 0) {
    // Convert buffer into string
    std::string bufferStr(buffer->GetSize(), '\0');
    buffer->CopyData(reinterpret_cast<uint8_t*>(&bufferStr[0]), bufferStr.size());

    std::string httpMsgStr;
    size_t httpMsgSize = 0;

    if (!parser.TryExtractHttpMessage(bufferStr, httpMsgStr, httpMsgSize)) {
      NS_LOG_DEBUG("[DEBUG] Fragmented or incomplete HTTP message. Awaiting more data.");
      break;
    }

    // Parse full HTTP message
    HTTPMessage request;
    parser.Parse(&request, httpMsgStr);

    if (request.IsFragmented() || request.GetSize() == 0) {
      NS_LOG_DEBUG("[DEBUG] Detected fragmented or malformed HTTP message. Waiting...");
      break;
    }

    // Process full packet
    Ptr<Packet> completePacket = buffer->CreateFragment(0, static_cast<uint32_t>(httpMsgSize));
    buffer->RemoveAtStart(static_cast<uint32_t>(httpMsgSize));

    Ipv4Address peerIp = GetPeerIp();
    Ipv4Address senderIp = InetSocketAddress::ConvertFrom(from).GetIpv4();

    NS_LOG_DEBUG("[DEBUG] Received from: " << senderIp << ", expected peer IP: " << peerIp);

    if (senderIp == peerIp) {
      m_rxSigTrace(GetId(), completePacket);
      ProcessSignalingPacketFromApp(request, completePacket, socket);
    } else {
      m_rxKmsTrace(GetId(), completePacket);
      ProcessResponseFromKMS(request, completePacket, socket);
    }

    NS_LOG_DEBUG("[DEBUG] Processed HTTP message: " << request.ToString());
    NS_LOG_DEBUG("[DEBUG] Remaining buffer size: " << buffer->GetSize());
  }
}



void
QKDApp014::DataToKMSSend(Ptr<Socket> socket, uint32_t)
{
    NS_LOG_FUNCTION(this << "sent via socket " << socket);
}


/**
 * ********************************************************************************************

 *        KEY BUFFER functions

 * ********************************************************************************************
 */
void
QKDApp014::InitKeyStores()
{
  NS_LOG_FUNCTION(this); //Initialize key stores!
  m_commonStore.clear();
  m_encStore.clear();
  m_authStore.clear();

}

void
QKDApp014::ManageStores()
{
    NS_LOG_FUNCTION(this);
    PrintStoreStats();
    if(m_internalAppWait) m_internalAppWait = false;
    if(m_master)
    { //Only at Primary application!
      if(GetEncryptionKeySize() != 0 && m_encStore.empty()) //Check the state of encryption key store
          GetKeysFromKMS("encryption"); // 0 - Encryption key
      if(GetAuthenticationKeySize() != 0 && m_authStore.empty()) //Check the state of authentication key store
          GetKeysFromKMS("authentication"); // 1 - Authentication key
      CheckAppState(); 
    }
}

Ptr<AppKey>
QKDApp014::GetLocalKey(std::string type, std::string keyId)
{
  NS_LOG_FUNCTION(this << m_master << type << keyId);
  Ptr<AppKey> localKey;
  if(m_master){ //master
    if(type == "encryption"){ //Get encryption key
      auto it = m_encStore.begin();
      if(it != m_encStore.end()){
        localKey = it->second;
        NS_LOG_FUNCTION(this << localKey->GetLifetime());
        if(m_encryptionType == QKDEncryptor::QKDCRYPTO_AES && localKey->GetLifetime() < 2*m_size ){
          NS_LOG_FUNCTION(this << "lifetime expired! key " << localKey->GetId() << " removed");
          m_encStore.erase(it);
        }else
          it->second->UseLifetime(m_size);

      }else
        NS_LOG_DEBUG(this << m_master << type << "store empty");

    }else{
      auto it = m_authStore.begin();
      if(it != m_authStore.end()){
        localKey = it->second;
        NS_LOG_FUNCTION(this << type << localKey->GetId());
        m_authStore.erase(it);
        NS_LOG_FUNCTION(this << "key removed" << localKey->GetId());
      }else
        NS_LOG_DEBUG(this << m_master << "store empty" << type);

    }

  }else{ //slave
    auto it = m_commonStore.find(keyId);
    if(it != m_commonStore.end()){
      localKey = it->second;
      if(localKey->GetType() == AppKey::ENCRYPTION){
        if(m_encryptionType == QKDEncryptor::QKDCRYPTO_AES && localKey->GetLifetime() < 2*m_size ){
          NS_LOG_FUNCTION(this << "lifetime expired! key " << localKey->GetId() << " removed");
          m_commonStore.erase(it);
        }else
          it->second->UseLifetime(m_size);

      }else{ //Authenticaiton key
        NS_LOG_FUNCTION(this << "key " << localKey->GetId() << " removed");
        m_commonStore.erase(it);

      }

    }else
      NS_LOG_DEBUG(this << m_master << "store empty" << type);

  }

  return localKey;
}

void
QKDApp014::PrintStoreStats()
{
  NS_LOG_FUNCTION(this << "encryption key count" << m_encStore.size()
                        << "authentication key count" <<  m_authStore.size()
                        << "inbound/temporary key count" << m_commonStore.size());
}

void
QKDApp014::CheckAppState()
{
  NS_LOG_FUNCTION(this << GetAppStateString());
  bool encryptionReady {true};
  bool authenticationReady {true};

  if(GetEncryptionKeySize() && m_encStore.empty())
    encryptionReady = false;

  if(GetAuthenticationKeySize() && m_authStore.empty())
    authenticationReady = false;

  NS_LOG_FUNCTION(this << GetAppStateString() << encryptionReady << authenticationReady );

  if(GetState() == WAIT && encryptionReady && authenticationReady)
    SwitchAppState(READY);

  else if(GetState() == READY && !(encryptionReady && authenticationReady))
    SwitchAppState(WAIT);

}

/**
 * ********************************************************************************************

 *        HTTP mapping

 * ********************************************************************************************
 */
void
QKDApp014::PushHttpKmsRequest(std::string input)
{
  NS_LOG_FUNCTION(this);
  if(input.empty()) NS_LOG_ERROR(this << "empty input");
  m_kmsHttpReqQueue.push_back(input);
}

void
QKDApp014::PushHttpAppRequest(std::vector<std::string> keyIds)
{
  NS_LOG_FUNCTION(this);
  if(keyIds.empty()) NS_LOG_ERROR(this << "empty input");
  m_appHttpReqQueue.push_back(keyIds);
}

std::string
QKDApp014::PopHttpKmsRequest()
{
  NS_LOG_FUNCTION(this);
  std::string output;
  if(m_kmsHttpReqQueue.empty())   NS_LOG_ERROR(this << "request queue is empty");
  auto it = m_kmsHttpReqQueue.begin();
  output = *it;
  m_kmsHttpReqQueue.erase(it);

  return output;
}

std::vector<std::string>
QKDApp014::PopHttpAppRequest()
{
  NS_LOG_FUNCTION(this);
  std::vector<std::string> keyIds {};
  if(m_appHttpReqQueue.empty())   NS_LOG_ERROR(this << "request queue is empty");
  auto it = m_appHttpReqQueue.begin();
  keyIds = *it;
  m_appHttpReqQueue.erase(it);

  return keyIds;
}


/**
 * ********************************************************************************************

 *        APPLICATION functions

 * ********************************************************************************************
 */
void
QKDApp014::StartApplication()
{
  NS_LOG_FUNCTION( this << m_local << m_peer << m_master );
  if(m_encryption < 0 || m_encryption > 2)
    NS_FATAL_ERROR("invalid encryption type" << m_encryption << "allowed values are(0-unencrypted, 1-OTP, 2-AES)");
  if(m_authentication < 0 || m_authentication > 3)
    NS_FATAL_ERROR("invalid authentication type" << m_authentication << "allowed values are(0-unauthenticated, 1-VMAC, 2-MD5, 3-SHA1)");

  if(m_aesLifetime < 0)
    NS_FATAL_ERROR("invalid key lifetime " << m_aesLifetime << "the value must be positive");
  else if(m_aesLifetime < m_size && m_aesLifetime != 0)
    NS_FATAL_ERROR("invalid key lifetime " << m_aesLifetime << "the value must be larger than packet size" << m_size);

  if(GetState() == INITIALIZED){
    SetCryptoSettings(
      m_encryption,
      m_authentication,
      m_authTagSize
    );
    AppTransitionTree(); //Transition states
    PrepareSocketToApp(); //Create sink sockets for peer QKD applications

  }else
    NS_FATAL_ERROR("invalid state" << GetAppStateString() << "for StartApplication().");

}

void
QKDApp014::StopApplication()
{
  NS_LOG_FUNCTION(this);
  if(m_sendEvent.IsPending()) Simulator::Cancel(m_sendEvent);

  //Close sockets
  if(m_dataSocketApp)        m_dataSocketApp->Close();
  if(m_signalingSocketApp)   m_signalingSocketApp->Close();
  if(m_socketToKMS)          m_socketToKMS->Close();

  InitKeyStores(); //Clear key stores
  SwitchAppState(STOPPED);

}

void
QKDApp014::SendDataPacket()
{
  NS_LOG_FUNCTION(this);

  if(!m_dataSocketApp  || !m_isDataConnectedToApp)
    PrepareSocketToApp();

  if(GetState() == READY) SwitchAppState(SEND_DATA); //Direct call from SceduleTx()

  if(GetState() == SEND_DATA){ //Send only if in SEND_DATA state!

    bool encrypted {m_encryptionType != 0};
    bool authenticated {m_authenticationType != 0};
    NS_LOG_FUNCTION(this << "enc/auth" << encrypted << authenticated);

    //Obtain secret keys!
    Ptr<AppKey> encKey;
    Ptr<AppKey> authKey;
    std::string encKeyDecoded;
    std::string authKeyDecoded;
    std::string confidentialMsg {GetPacketContent()};
    std::string encryptedMsg {confidentialMsg};
    std::string authTag;
    
    if(encrypted){
      encKey = GetLocalKey("encryption");
      encKeyDecoded = m_encryptor->Base64Decode(encKey->GetKeyString());
      if(m_useCrypto){
        encryptedMsg = m_encryptor->EncryptMsg(confidentialMsg, encKeyDecoded);
        NS_LOG_FUNCTION(this << "\n\tencryption key" << encKey->GetId() << encKeyDecoded
          << "\n\tencrypted message(Base64 print)" << m_encryptor->Base64Encode(encryptedMsg));

      }else{
        encryptedMsg = confidentialMsg;
        NS_LOG_FUNCTION(this << "\n\tencryption key" << encKey->GetId() << encKeyDecoded);

      }
    }

    if(GetAuthenticationKeySize()){
      authKey = GetLocalKey("authentication");
      authKeyDecoded = m_encryptor->Base64Decode(authKey->GetKeyString());
      if(m_useCrypto){
        authTag = m_encryptor->Authenticate(encryptedMsg, authKeyDecoded);
        NS_LOG_FUNCTION(this << "\n\tauthentication key" << authKey->GetId() << authKeyDecoded
          << "\n\tauthentication tag" << authTag);

      }else{
        authTag = GetPacketContent(32);
        NS_LOG_FUNCTION(this << "\n\tauthentication key" << authKey->GetId() << authKeyDecoded);

      }
    }

    //Create packet with protected/unprotected data
    std::string msg {encryptedMsg};
    Ptr<Packet> packet = Create<Packet>((uint8_t*) msg.c_str(), msg.length() );
    NS_ASSERT(packet);
    m_authenticationTrace(packet, authTag);

    //Add qkd header!
    QKDAppHeader qHeader;
    qHeader.SetEncrypted(m_encryptionType);
    if(encKey)  qHeader.SetEncryptionKeyId(CreateKeyIdField(encKey->GetId()));
    else        qHeader.SetEncryptionKeyId(std::string(32, '0'));
    qHeader.SetAuthenticated(m_authenticationType);
    if(authKey) qHeader.SetAuthenticationKeyId(CreateKeyIdField(authKey->GetId()));
    else        qHeader.SetAuthenticationKeyId(std::string(32, '0'));
    qHeader.SetAuthTag(authTag);
    qHeader.SetLength(packet->GetSize() + qHeader.GetSerializedSize());
    packet->AddHeader(qHeader);

    NS_LOG_FUNCTION(this << "sending data packet id" << packet->GetUid() << packet->GetSize());

    //Send packet!
    m_txTrace(GetId(), packet);
    m_dataSocketApp->Send(packet);

    SwitchAppState(READY); //Application is now ready
    ManageStores(); //Fill stores if necessary
    ScheduleTx(); //Schedule send data

  }else if(GetState() == WAIT){
    m_mxTrace(GetId(), nullptr);
    ScheduleTx();
    NS_LOG_FUNCTION(this << "unable to send" << GetAppStateString(GetState()));

    if(!m_scheduleManageStores.IsPending())
        ScheduleAction(Time(m_waitInsufficient), "ManageStores"); 
  }

}

void
QKDApp014::ProcessDataPacket(QKDAppHeader header, Ptr<Packet> packet, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this);
  NS_ASSERT(!m_master);
  uint8_t *buffer = new uint8_t[packet->GetSize()];
  packet->CopyData(buffer, packet->GetSize());
  std::string payload = std::string((char*)buffer, packet->GetSize());
  delete[] buffer;

  NS_LOG_FUNCTION(this << "\ndata received\n" << m_encryptor->Base64Encode(payload));
  SwitchAppState(DECRYPT_DATA);
  SetCryptoSettings(header.GetEncrypted(), header.GetAuthenticated(), m_authTagSize);
  std::string decryptedMsg;
  m_size = payload.length();

  if(GetAuthenticationKeySize()){ //Perform authentication first
    Ptr<AppKey> key {GetLocalKey("authentication", ReadKeyIdField(header.GetAuthenticationKeyId()))};
    if(m_useCrypto){
      std::string decodedKey {m_encryptor->Base64Decode(key->GetKeyString())}; //Decode key
      if(m_encryptor->CheckAuthentication(payload, header.GetAuthTag(), decodedKey)) //Check authTag
        NS_LOG_FUNCTION(this << "authentication successful");
      else
        NS_LOG_WARN(this << "authentication failed");

    }else //We assume packet is authenticated
        NS_LOG_FUNCTION(this << "authentication successful");

  }else if(header.GetAuthenticated()){
    if(m_useCrypto){
      if(m_encryptor->CheckAuthentication(payload, header.GetAuthTag(), ""))
        NS_LOG_FUNCTION(this << "authentication successful");
      else
        NS_LOG_WARN(this << "authentication failed");

    }else//We assume packet is authenticated
      NS_LOG_FUNCTION(this << "authentication successful");

  }

  if(header.GetEncrypted()){ //Perform decryption
    Ptr<AppKey> key {GetLocalKey("encryption", ReadKeyIdField(header.GetEncryptionKeyId()))};
    if(m_useCrypto){
      std::string decodedKey {m_encryptor->Base64Decode(key->GetKeyString())}; //Decode key
      NS_LOG_FUNCTION(this << "\n\tdecryption key" << decodedKey);
      decryptedMsg = m_encryptor->DecryptMsg(payload, decodedKey);
      NS_LOG_FUNCTION(this << "\n\tdecrypted message" << decryptedMsg);
    }else
      NS_LOG_FUNCTION(this << "packet decrypted");

  }else
    NS_LOG_FUNCTION(this << "Received message" << payload);

  SwitchAppState(READY);

}

/**
 * ********************************************************************************************

 *        KEY MANAGEMENT functions

 * ********************************************************************************************
 */

void
QKDApp014::GetStatusFromKMS()
{
  NS_LOG_FUNCTION(this);
  if(!m_socketToKMS)    PrepareSocketToKMS();

  //Create packet
  HTTPMessage httpMessage;
  httpMessage.CreateRequest("http://" + IpToString(GetKmsIp()) + "/api/v1/keys/" + m_dstId + "/status", "GET");
  httpMessage.SetHeader("User-Agent", "QKDApp014_" + GetId());
  std::string hMessage = httpMessage.ToString();
  Ptr<Packet> packet = Create<Packet>(
   (uint8_t*)(hMessage).c_str(),
    hMessage.size()
  );

  NS_ASSERT(packet);
  NS_LOG_FUNCTION(this << "GET STATUS URL: " << "http://" + IpToString(GetKmsIp()) + "/api/v1/keys/" + m_dstId + "/status");

  NS_LOG_FUNCTION(this << "Sending PACKETID: " << packet->GetUid()
    << " of size: " << packet->GetSize()
    << " via socket " << m_socketToKMS
  );

  m_txKmsTrace(GetId(), packet);
  m_socketToKMS->Send(packet);

}

void
QKDApp014::GetKeysFromKMS(std::string keyType)
{
  NS_LOG_FUNCTION(this << keyType);
  if(!m_socketToKMS)    PrepareSocketToKMS();

  uint32_t number {m_numberOfKeysKMS};
  uint32_t size {0};
  if(keyType == "encryption")
    size = GetEncryptionKeySize();
  else if(keyType == "authentication")
    size = GetAuthenticationKeySize();
  else
    NS_FATAL_ERROR(this << "invalid key type" << keyType);

  //Application basic check of user input!
  if(number <= 0)   NS_FATAL_ERROR(this << "invalid m_numberOfKeysKMS" << number);
  if(size <= 0)     NS_FATAL_ERROR(this << "invalid key_size" << size);

  std::vector<std::string> additional_slave_SAE_IDs {}; //No additional Replica SAEs
  bool useGet {true}; //Used GET(if possible)
  if(!additional_slave_SAE_IDs.empty())
    useGet = false;

  HTTPMessage httpMessage;
  std::string headerUri {"http://" + IpToString(GetKmsIp()) + "/api/v1/keys/" + m_dstId + "/enc_keys"};
  if(useGet){ //Update header URI
    headerUri += "/number/" + std::to_string(number) + "/size/" + std::to_string(size);
    httpMessage.CreateRequest(headerUri, "GET");
    httpMessage.SetHeader("User-Agent", "QKDApp014_" + GetId());

  }else
    NS_LOG_ERROR(this << "POST method disabled");

  std::string hMessage = httpMessage.ToString();
  Ptr<Packet> packet = Create<Packet>(
   (uint8_t*)(hMessage).c_str(),
    hMessage.size()
  );
  NS_ASSERT(packet);

  NS_LOG_FUNCTION(this << "Sending PACKETID: " << packet->GetUid()
    << " of size: " << packet->GetSize()
    << " via socket " << m_socketToKMS
    << " uri " << headerUri
  );

  PushHttpKmsRequest(keyType);
  m_txKmsTrace(GetId(), packet);
  m_socketToKMS->Send(packet);
}

void
QKDApp014::GetKeyWithKeyIDs(std::string keyIds)
{
  NS_LOG_FUNCTION(this);
  if(!m_socketToKMS)    PrepareSocketToKMS();

  //Create packet
  HTTPMessage httpMessage;
  httpMessage.CreateRequest("http://" + IpToString(GetKmsIp()) + "/api/v1/keys/" + m_dstId + "/dec_keys", "POST", keyIds);
  httpMessage.SetHeader("User-Agent", "QKDApp014_" + GetId());
  std::string hMessage = httpMessage.ToString();
  Ptr<Packet> packet = Create<Packet>(
   (uint8_t*)(hMessage).c_str(),
    hMessage.size()
  );
  NS_ASSERT(packet);

  NS_LOG_FUNCTION(this << "Sending PACKETID: " << packet->GetUid()
    << " of size: " << packet->GetSize()
    << " via socket " << m_socketToKMS
  );

  m_txKmsTrace(GetId(), packet);
  m_socketToKMS->Send(packet);
}

void
QKDApp014::ProcessResponseFromKMS(HTTPMessage& header, Ptr<Packet> packet, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << header.GetRequestUri() << header.GetStatus());

  std::string reqMethod = ReadUri(header.GetRequestUri())[5]; //Get method from request URI field!
  nlohmann::json responseBody;
  try{
    responseBody = nlohmann::json::parse(header.GetMessageBodyString());
  }catch(...){
    NS_FATAL_ERROR(this << "json parse error");
  }

  /**       status          **/
  if(reqMethod == "status"){
    if(header.GetStatus() == HTTPMessage::Ok)
      ManageStores();
    else
      NS_LOG_ERROR(this << "status error" << responseBody.dump());


  /**       enc_keys          **/
  }else if(reqMethod == "enc_keys"){
    if(header.GetStatus() == HTTPMessage::Ok){
      std::string keyType {PopHttpKmsRequest()};
      std::vector<std::string> keyIds; //Obtained keyIds
      for(nlohmann::json::iterator it = responseBody["keys"].begin(); it != responseBody["keys"].end(); ++it){
        Ptr<AppKey> key = CreateObject<AppKey>( std::string{(it.value())["key_ID"]}, std::string {(it.value())["key"]}, AppKey::ENCRYPTION, m_size );
        if(keyType == "encryption" && m_encryptionType == QKDEncryptor::QKDCRYPTO_AES)
          key->SetLifetime(m_aesLifetime);
        else if(keyType == "authentication")
          key->SetType(AppKey::AUTHENTICATION);

        m_commonStore.insert(std::make_pair(key->GetId(), key)); //Add keys to temporary key store
        keyIds.push_back(key->GetId());

      }
      SendKeyIds(keyIds); //send key ids to receiver App014

  }else{
    if(responseBody.contains("message"))
    {
      if(responseBody["message"] == std::string {"insufficient amount of key material"})
        ScheduleAction(Time(m_waitInsufficient), "ManageStores");
      else
        NS_FATAL_ERROR(this << "get_key error" << responseBody.dump());

    }else
      NS_FATAL_ERROR(this << "response data format error" << responseBody.dump());
  }
  /**       dec_keys          **/
  }else if(reqMethod == "dec_keys"){
    if(header.GetStatus() == HTTPMessage::HttpStatus::Ok){
      //Replica application directly stores the keys in application key buffer!
      for(nlohmann::json::iterator it = responseBody["keys"].begin(); it != responseBody["keys"].end(); ++it)
        m_commonStore.insert(
          std::make_pair((it.value())["key_ID"],
                          CreateObject<AppKey>( std::string{(it.value())["key_ID"]}, std::string{(it.value())["key"]}, AppKey::ENCRYPTION, m_aesLifetime )
          )
        );
    }else
      NS_LOG_ERROR(this << "error");

    SendKeyIds({}, header.GetStatus()); //Send response on key ids notification

  }else
      NS_FATAL_ERROR(this << "unknown method" << reqMethod);


}

void
QKDApp014::ProcessSignalingPacketFromApp(HTTPMessage& header, Ptr<Packet> packet, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << m_master << packet->GetSize() << packet->GetUid());

  //Sender App014 process response on KEY_IDS notification
  if(m_master)
  {
    std::vector<std::string> keyIds = PopHttpAppRequest(); //mapping of response to request

    //Sender App014 moves keys to outbound key store
    if(header.GetStatus() == HTTPMessage::Ok)
    {
      for(auto const& el: keyIds){
        auto it = m_commonStore.find(el);
        if(it == m_commonStore.end())
          NS_LOG_ERROR(this << "unknown key");
        else{
          if(it->second->GetType() == AppKey::ENCRYPTION){
            m_encStore.insert( std::make_pair(it->second->GetId(), it->second) );
            NS_LOG_DEBUG(this << "moved to encryption store\t" << it->second->GetId());
          }else if(it->second->GetType() == AppKey::AUTHENTICATION){
            m_authStore.insert( std::make_pair(it->second->GetId(), it->second) );
            NS_LOG_DEBUG(this << "moved to authentication store\t" << it->second->GetId());
          }else
            NS_LOG_ERROR(this << "unknown key type");

          NS_LOG_DEBUG(this << "key removed from common\t" << it->second->GetId());
          m_commonStore.erase(it);
        }
      }

      PrintStoreStats();
      CheckAppState();

    }else{ //Error
      NS_LOG_WARN(this << "unexpected KEY_IDS error");
      //auto keyIds = PopHttpAppRequest();
      AppKey::Type type {};
      for(auto const& el : keyIds){             //remove keys from temporary key store
        auto it = m_commonStore.find(el);
        if(it != m_commonStore.end()){
          type = it->second->GetType();
          m_commonStore.erase(it);
        }else
          NS_LOG_ERROR(this << "unknown key" << el);

      }
      if(!m_internalAppWait){
        if(type == AppKey::ENCRYPTION) GetKeysFromKMS("encryption");
        else GetKeysFromKMS("authentication");

      }

    }

  }else //Receiver App014 process KEY_IDS notification
    GetKeyWithKeyIDs(header.GetMessageBodyString());

}

void
QKDApp014::SendKeyIds(std::vector<std::string> keyIds, HTTPMessage::HttpStatus statusCode)
{
  NS_LOG_FUNCTION(this << m_master);

  if(!m_signalingSocketApp  || !m_isSignalingConnectedToApp)
    PrepareSocketToApp();

  if(m_master){ //Primary QKDApp014 sends proposal of keys to Replica QKDApp014
    nlohmann::json jKeyIds;
    for(uint i = 0; i < keyIds.size(); i++)
      jKeyIds["key_IDs"].push_back({ {"key_ID", keyIds[i]} });

    std::string reqUri {"http://" + IpToString(GetPeerIp()) + "/keys/key_ids"};
    HTTPMessage httpMessage;
    httpMessage.CreateRequest(reqUri, "POST", jKeyIds.dump());
    httpMessage.SetHeader("User-Agent", "QKDApp014_" + GetId());
    std::string hMessage = httpMessage.ToString();
    Ptr<Packet> packet = Create<Packet>( //Create packet
     (uint8_t*)(hMessage).c_str(),
      hMessage.size()
    );
    NS_ASSERT(packet);

    PushHttpAppRequest(keyIds);
    m_txSigTrace(GetId(), packet);
    m_signalingSocketApp->Send(packet);
    NS_LOG_FUNCTION(this << "proposal sent" << packet->GetUid() << packet->GetSize() << httpMessage.ToString());

  }else{ //Replica QKDApp014 sends response to Primary QKDApp014.
    HTTPMessage httpMessage;
    httpMessage.CreateResponse(statusCode, "", {
      {"Request URI", "http://"+ IpToString(GetIp()) +"/keys/key_ids"}
    });
    std::string hMessage = httpMessage.ToString();
    Ptr<Packet> packet = Create<Packet>(
     (uint8_t*)(hMessage).c_str(),
      hMessage.size()
    );
    NS_ASSERT(packet);

    NS_LOG_FUNCTION(this << "PEER Sending SIGNALING PACKETID: " << packet->GetUid()
      << " of size: " << packet->GetSize()
      << " via socket " << m_signalingSocketApp
    );

    m_txSigTrace(GetId(), packet);
    m_signalingSocketApp->Send(packet);

    NS_LOG_FUNCTION(this << "\n\n\n" << packet->GetUid() << packet->GetSize() << httpMessage.ToString());

  }

}



/**
 * ********************************************************************************************

 *        STATE functions

 * ********************************************************************************************
 */

/*
 * @brief QKD App state transitions(Data transmision)
 */
void
QKDApp014::AppTransitionTree()
{
  NS_LOG_FUNCTION( this  );

  if(m_master) //Data transmision state transition for Primary QKDApp014
  {

    if(GetState() == INITIALIZED) {
      NS_LOG_FUNCTION( this << GetEncryptionKeySize() << GetAuthenticationKeySize() );
      if(GetEncryptionKeySize() == 0 && GetAuthenticationKeySize() == 0) //No initial key material needed!
      {
        SwitchAppState(READY);
        PrepareSocketToApp();
        SendDataPacket(); //Imidiatly send packet
      } else { //Obtain status information from KMS, obtain initial key material!
        SwitchAppState(WAIT);
        PrepareSocketToKMS();
        GetStatusFromKMS(); //First call Get Status
        SendDataPacket(); //It will result in schedule
      }
    } else {
      NS_FATAL_ERROR( this << "Invalid entry state" << GetState() <<
                              "for AppTransitionTree()!");
    }

  } else if(!m_master) { //Data transmision state transition for Replica QKDApp014

    if(GetState() == INITIALIZED) {
      SwitchAppState(READY);
    } else {
      NS_FATAL_ERROR( this << "Invalid entry state" << GetState() <<
                              "for AppTransitionTree()!");
    }

  }
}


std::string
QKDApp014::GetAppStateString(QKDApp014::State state)
{
  switch(state)
    {
    case NOT_STARTED:
      return "NOT_STARTED";
      break;
    case INITIALIZED:
      return "INITIALIZED";
      break;
    case READY:
      return "READY";
      break;
    case WAIT:
      return "WAIT";
      break;
    case SEND_DATA:
      return "SEND_DATA";
      break;
    case DECRYPT_DATA:
      return "DECRYPT_DATA";
      break;
    case STOPPED:
      return "STOPPED";
      break;
    default:
      NS_FATAL_ERROR("Unknown state");
      return "FATAL_ERROR";
      break;
    }
}


std::string
QKDApp014::GetAppStateString() const
{
  return GetAppStateString(GetState());
}

void
QKDApp014::SwitchAppState(QKDApp014::State state)
{

  const std::string oldState = GetAppStateString();
  const std::string newState = GetAppStateString(state);


  bool found = false;
  for(auto iter = m_transitionMatrix.begin(); iter != m_transitionMatrix.end(); iter++)
  {
    if(iter->first == oldState && iter->second == newState){
      SetState(state);
      NS_LOG_DEBUG(this << " QKDApp014 " << oldState << " --> " << newState << ".");
      m_stateTransitionTrace(oldState, newState);
      found = true;
    }
  }

  if(!found) {
    NS_FATAL_ERROR("Unsupported transition from " << oldState << " to " << newState);
  }


}

/**
 * ********************************************************************************************

 *        ADDTIONAL functions

 * ********************************************************************************************
 */

void
QKDApp014::SetCryptoSettings(
  uint32_t encryptionType,
  uint32_t authenticationType,
  uint32_t authenticationTagLengthInBits
){

  NS_LOG_FUNCTION(this << encryptionType << authenticationType << authenticationTagLengthInBits);

  switch(encryptionType){
    case 0:
      m_encryptionType = QKDEncryptor::UNENCRYPTED;
      break;
    case 1:
      m_encryptionType = QKDEncryptor::QKDCRYPTO_OTP;
      break;
    case 2:
      m_encryptionType = QKDEncryptor::QKDCRYPTO_AES;
      break;
  }

  switch(authenticationType){
    case 0:
      m_authenticationType = QKDEncryptor::UNAUTHENTICATED;
      break;
    case 1:
      m_authenticationType = QKDEncryptor::QKDCRYPTO_AUTH_VMAC;
      break;
    case 2:
      m_authenticationType = QKDEncryptor::QKDCRYPTO_AUTH_MD5;
      break;
    case 3:
      m_authenticationType = QKDEncryptor::QKDCRYPTO_AUTH_SHA1;
      break;
  }

  if(!m_encryptor){
    m_encryptor = CreateObject<QKDEncryptor>(
      m_encryptionType,
      m_authenticationType,
      authenticationTagLengthInBits
    );
  }else{
    m_encryptor->ChangeSettings(
      m_encryptionType,
      m_authenticationType,
      authenticationTagLengthInBits
    );
  }

}

std::string
QKDApp014::GetPacketContent(uint32_t msgLength)
{
  NS_LOG_FUNCTION(this);

  if(msgLength == 0)
    msgLength = m_size;

  //Generate random string with same size as merged key string
  std::string confidentialMessage;
  static const char alphanum[] =
    "0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz";
  for(std::size_t i = 0; i < msgLength; ++i){
    confidentialMessage += alphanum[rand() %(sizeof(alphanum) - 1)];
  }

  return confidentialMessage;

}

std::string
QKDApp014::CreateKeyIdField(std::string keyId)
{
    keyId.erase(std::remove(keyId.begin(), keyId.end(), '-'), keyId.end());
    return keyId;
}

std::string
QKDApp014::ReadKeyIdField(std::string keyId)
{
    NS_LOG_FUNCTION(this << keyId);
    keyId.insert(8, "-");
    keyId.insert(13, "-");
    keyId.insert(18, "-");
    keyId.insert(23, "-");
    NS_LOG_FUNCTION(this << keyId);
    return keyId;
}

uint32_t
QKDApp014::GetEncryptionKeySize()
{

  NS_LOG_FUNCTION(this << m_size << CryptoPP::AES::MAX_KEYLENGTH << m_encryptionType);

  switch(m_encryptionType)
  {
    case QKDEncryptor::UNENCRYPTED:
      return 0;
      break;
    case QKDEncryptor::QKDCRYPTO_OTP:
      return m_size * 8; //This will work great for Primary QKDApp014, Replica QKDApp014 needs to calculate for itself this!
      break;
    case QKDEncryptor::QKDCRYPTO_AES:
      return CryptoPP::AES::MAX_KEYLENGTH * 8; //In bits 256!
      break;
  }

  return 0;

}

uint32_t
QKDApp014::GetAuthenticationKeySize()
{
  switch(m_authenticationType)
  {
    case QKDEncryptor::UNAUTHENTICATED:
      return 0;
      break;
    case QKDEncryptor::QKDCRYPTO_AUTH_VMAC:
      return CryptoPP::AES::BLOCKSIZE * 8; //In bits //Before: m_authTagSize - 32B?
      break;
    case QKDEncryptor::QKDCRYPTO_AUTH_MD5:
      return 0; //NoKey
      break;
    case QKDEncryptor::QKDCRYPTO_AUTH_SHA1:
      return 0; //NoKey
      break;
  }

  return 0;

}

std::vector<std::string>
QKDApp014::ReadUri(std::string s)
{
  NS_LOG_FUNCTION(this);

  std::string delimiter {"/"};
  std::string token;
  size_t pos = 0;
  std::vector<std::string> uriParams;
  while((pos = s.find(delimiter)) != std::string::npos){
    token = s.substr(0, pos);
    if(!token.empty())
      uriParams.push_back(token);

    s.erase(0, pos + delimiter.length());

  }
  if(!s.empty())
    uriParams.push_back(s);

  return uriParams;
}

Ipv4Address
QKDApp014::GetIp()
{
  NS_LOG_FUNCTION(this);
  return {InetSocketAddress::ConvertFrom(m_local).GetIpv4()};
}

Ipv4Address
QKDApp014::GetPeerIp()
{
  NS_LOG_FUNCTION(this);
  return {InetSocketAddress::ConvertFrom(m_peer).GetIpv4()};
}

Ipv4Address
QKDApp014::GetKmsIp()
{
  NS_LOG_FUNCTION(this);
  return {InetSocketAddress::ConvertFrom(m_kms).GetIpv4()};
}

std::string
QKDApp014::IpToString(Ipv4Address address)
{
  NS_LOG_FUNCTION(this);
  std::string sAddress;
  std::ostringstream peerkmsAddressTemp;
  address.Print(peerkmsAddressTemp); //IPv4Address to string
  return peerkmsAddressTemp.str();
}


} // Namespace ns3

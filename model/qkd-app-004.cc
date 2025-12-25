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
#include "qkd-app-004.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("QKDApp004");

NS_OBJECT_ENSURE_REGISTERED(QKDApp004);

TypeId
QKDApp004::GetTypeId()
{
  static TypeId tid = TypeId("ns3::QKDApp004")
    .SetParent<Application>()
    .SetGroupName("Applications")
    .AddConstructor<QKDApp004>()
    .AddAttribute("Protocol", "The type of protocol to use.",
                   TypeIdValue(TcpSocketFactory::GetTypeId()),
                   MakeTypeIdAccessor(&QKDApp004::m_tid),
                   MakeTypeIdChecker())
    .AddAttribute("LengthOfAuthenticationTag",
                   "The default length of the authentication tag",
                   UintegerValue(256), //32 bytes
                   MakeUintegerAccessor(&QKDApp004::m_authenticationTagLengthInBits),
                   MakeUintegerChecker<uint32_t>())
    .AddAttribute("EncryptionType",
                   "The type of encryption to be used(0-unencrypted, 1-OTP, 2-AES)",
                   UintegerValue(2),
                   MakeUintegerAccessor(&QKDApp004::m_encryption),
                   MakeUintegerChecker<uint32_t>())
    .AddAttribute("AuthenticationType",
                   "The type of authentication to be used(0-unauthenticated, 1-VMAC, 2-MD5, 3-SHA1)",
                   UintegerValue(3),
                   MakeUintegerAccessor(&QKDApp004::m_authentication),
                   MakeUintegerChecker<uint32_t>())
    .AddAttribute("AESLifetime",
                   "Lifetime of AES key expressed in number of packets",
                   UintegerValue(1),
                   MakeUintegerAccessor(&QKDApp004::m_aesLifetime),
                   MakeUintegerChecker<uint32_t>())
    .AddAttribute("UseCrypto",
                   "Should crypto functions be performed(0-No, 1-Yes)",
                   UintegerValue(0),
                   MakeUintegerAccessor(&QKDApp004::m_useCrypto),
                   MakeUintegerChecker<uint32_t>())
    .AddAttribute("LengthOfKeyBufferForEncryption",
                   "How many keys to store in local buffer of QKDApp004 for encryption?",
                   UintegerValue(10),
                   MakeUintegerAccessor(&QKDApp004::m_keyBufferLengthEncryption),
                   MakeUintegerChecker<uint32_t>())
    .AddAttribute("LengthOfKeyBufferForAuthentication",
                   "How many keys to store in local buffer of QKDApp004 for authentication?",
                   UintegerValue(10),
                   MakeUintegerAccessor(&QKDApp004::m_keyBufferLengthAuthentication),
                   MakeUintegerChecker<uint32_t>())
    .AddAttribute("SocketToKMSHoldTime","How long(seconds) should QKDApp004 wait to close socket to KMS after receiving REST response?",
                   TimeValue(Seconds(0.5)),
                   MakeTimeAccessor(&QKDApp004::m_holdTime),
                   MakeTimeChecker())

    .AddTraceSource("Tx", "A new packet is created and is sent",
                     MakeTraceSourceAccessor(&QKDApp004::m_txTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource("TxSig", "A new signaling packet is created and is sent",
                     MakeTraceSourceAccessor(&QKDApp004::m_txSigTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource("TxKMS", "A new packet is created and is sent to local KMS",
                     MakeTraceSourceAccessor(&QKDApp004::m_txKmsTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource("Rx", "A new packet is received",
                     MakeTraceSourceAccessor(&QKDApp004::m_rxTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource("RxSig", "A new signaling packet is received",
                     MakeTraceSourceAccessor(&QKDApp004::m_rxSigTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource("RxKMS", "A new packet is received from local KMS",
                     MakeTraceSourceAccessor(&QKDApp004::m_rxKmsTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource("StateTransition",
                     "Trace fired upon every QKDApp state transition.",
                     MakeTraceSourceAccessor(&QKDApp004::m_stateTransitionTrace),
                     "ns3::Application::StateTransitionCallback")
    .AddTraceSource("PacketEncrypted",
                    "The change trance for currenly ecrypted packet",
                     MakeTraceSourceAccessor(&QKDApp004::m_encryptionTrace),
                     "ns3::QKDCrypto::PacketEncrypted")
    .AddTraceSource("PacketDecrypted",
                    "The change trance for currenly decrypted packet",
                     MakeTraceSourceAccessor(&QKDApp004::m_decryptionTrace),
                     "ns3::QKDCrypto::PacketDecrypted")
    .AddTraceSource("PacketAuthenticated",
                    "The change trance for currenly authenticated packet",
                     MakeTraceSourceAccessor(&QKDApp004::m_authenticationTrace),
                     "ns3::QKDCrypto::PacketAuthenticated")
    .AddTraceSource("PacketDeAuthenticated",
                    "The change trance for currenly deauthenticated packet",
                     MakeTraceSourceAccessor(&QKDApp004::m_deauthenticationTrace),
                     "ns3::QKDCrypto::PacketDeAuthenticated")
    .AddTraceSource("Mx", "Missed send packet call",
                     MakeTraceSourceAccessor(&QKDApp004::m_mxTrace),
                     "ns3::Packet::TracedCallback")
  ;

  return tid;
}


uint32_t QKDApp004::m_applicationCounts = 0;

/**
 * ********************************************************************************************

 *        SETUP

 * ********************************************************************************************
 */

QKDApp004::QKDApp004()
  : m_signalingSocketApp(nullptr),
    m_dataSocketApp(nullptr),
    m_socketToKMS(nullptr),
    m_packetSize(0),
    m_dataRate(0),
    m_sendEvent(),
    m_packetsSent(0),
    m_dataSent(0),
    m_master(0),
    m_encryptor(0),
    m_state(NOT_STARTED)
{
  m_applicationCounts++;
}

QKDApp004::~QKDApp004()
{
  NS_LOG_FUNCTION(this);
}

void
QKDApp004::DoDispose()
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
QKDApp004::Setup(
  std::string socketType,
  std::string appId,
  std::string remoteAppId,
  const Address& appAddress,
  const Address& remoteAppAddress,
  const Address& kmAddress,
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
QKDApp004::Setup(
  std::string socketType,
  std::string appId,
  std::string remoteAppId,
  const Address& appAddress,
  const Address& remoteAppAddress,
  const Address& kmAddress,
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

  NS_LOG_FUNCTION(this << remoteAppAddress);
  if(!remoteAppAddress.IsInvalid())
      m_peer = remoteAppAddress;

  NS_LOG_FUNCTION(this << appAddress);
  if(!appAddress.IsInvalid())
      m_local = appAddress;

  NS_LOG_FUNCTION(this << kmAddress);
  if(!kmAddress.IsInvalid())
      m_kms = kmAddress;

  m_portSignaling = 7010+m_applicationCounts;
  NS_LOG_FUNCTION(this << "Peer IP " << InetSocketAddress::ConvertFrom(m_peer).GetIpv4() << " and port " << m_portSignaling );

  m_dstAppId = remoteAppId;
  m_appId = appId;

  m_packetSize = packetSize;
  m_dataRate = dataRate;
  m_socketType = socketType;

  //Initialize key stream sessions
  m_primaryQueueEstablished = false;
  m_replicaQueueEstablished = false;

  m_encStream = CreateObject<KeyStreamSession>();
  m_encStream->SetSize(m_keyBufferLengthEncryption);

  m_authStream = CreateObject<KeyStreamSession>();
  m_authStream->SetSize(m_keyBufferLengthAuthentication);
  m_authStream->SetType(KeyStreamSession::AUTHENTICATION);

  SetState(INITIALIZED);

}

/**
 * ********************************************************************************************

 *        SCHEDULE functions

 * ********************************************************************************************
 */
void
QKDApp004::ScheduleTx()
{
  NS_LOG_FUNCTION(this);
  if(GetState() != STOPPED && GetState() != NOT_STARTED){
    NS_LOG_FUNCTION(this << "is running!");
    double delay = m_packetSize * 8 / static_cast<double>(m_dataRate.GetBitRate());
    NS_LOG_FUNCTION(this << "scheduled in" << Seconds(delay) );
    Time tNext(Seconds(delay));
    m_sendEvent = Simulator::Schedule(tNext, &QKDApp004::SendPacket, this);

  }else
    NS_LOG_FUNCTION(this << "is" << GetAppStateString(GetState()));

}


/**
 * ********************************************************************************************

 *        SOCKET functions

 * ********************************************************************************************
 */

void
QKDApp004::PrepareSocketToKMS()
{
  NS_LOG_FUNCTION(this);
  if(!m_socketToKMS)
    m_socketToKMS = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId() );

  Address temp;
  if(m_socketToKMS->GetPeerName(temp) != 0 ) {
    Address lkmsAddress = InetSocketAddress(
      InetSocketAddress::ConvertFrom(m_kms).GetIpv4(),
      InetSocketAddress::ConvertFrom(m_kms).GetPort()
    );
    m_socketToKMS->SetRecvCallback(MakeCallback(&QKDApp004::HandleReadFromKMS, this));
    m_socketToKMS->SetAcceptCallback(
      MakeCallback(&QKDApp004::ConnectionRequestedFromKMS, this),
      MakeCallback(&QKDApp004::HandleAcceptFromKMS, this)
    );
    m_socketToKMS->SetCloseCallbacks(
      MakeCallback(&QKDApp004::HandlePeerCloseFromKMS, this),
      MakeCallback(&QKDApp004::HandlePeerErrorFromKMS, this)
    );
    m_socketToKMS->SetConnectCallback(
      MakeCallback(&QKDApp004::ConnectionToKMSSucceeded, this),
      MakeCallback(&QKDApp004::ConnectionToKMSFailed, this));
    m_socketToKMS->SetDataSentCallback(
      MakeCallback(&QKDApp004::DataToKMSSend, this));
    m_socketToKMS->SetCloseCallbacks(
      MakeCallback(&QKDApp004::HandlePeerCloseToKMS, this),
      MakeCallback(&QKDApp004::HandlePeerErrorToKMS, this)
    );
    m_socketToKMS->Bind();
    m_socketToKMS->Connect( lkmsAddress );
    m_socketToKMS->TraceConnectWithoutContext("RTT", MakeCallback(&QKDApp004::RegisterAckTime, this));
    NS_LOG_FUNCTION(this << "send socket created" << m_socketToKMS);

  }else
     NS_LOG_FUNCTION(this << "socket exists" << m_socketToKMS);

}


void
QKDApp004::PrepareSocketToApp()
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
        MakeCallback(&QKDApp004::ConnectionSignalingToAppSucceeded, this),
        MakeCallback(&QKDApp004::ConnectionSignalingToAppFailed, this)
      );
      m_signalingSocketApp->SetRecvCallback(MakeCallback(&QKDApp004::HandleReadSignalingFromApp, this));
      m_signalingSocketApp->SetAcceptCallback(
        MakeCallback(&QKDApp004::ConnectionRequestedSignalingFromApp, this),
        MakeCallback(&QKDApp004::HandleAcceptSignalingFromApp, this)
      );
      m_signalingSocketApp->SetCloseCallbacks(
        MakeCallback(&QKDApp004::HandlePeerCloseSignalingFromApp, this),
        MakeCallback(&QKDApp004::HandlePeerErrorSignalingFromApp, this)
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
        MakeCallback(&QKDApp004::ConnectionToAppSucceeded, this),
        MakeCallback(&QKDApp004::ConnectionToAppFailed, this)
      );
      m_dataSocketApp->SetRecvCallback(MakeCallback(&QKDApp004::HandleReadFromApp, this));
      m_dataSocketApp->SetAcceptCallback(
        MakeCallback(&QKDApp004::ConnectionRequestedFromApp, this),
        MakeCallback(&QKDApp004::HandleAcceptFromApp, this)
      );
      m_dataSocketApp->SetCloseCallbacks(
        MakeCallback(&QKDApp004::HandlePeerCloseFromApp, this),
        MakeCallback(&QKDApp004::HandlePeerErrorFromApp, this)
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
QKDApp004::ConnectionRequestedFromKMS(Ptr<Socket> socket, const Address &from)
{
  NS_LOG_FUNCTION(this << socket << from
    << InetSocketAddress::ConvertFrom(from).GetIpv4()
    << InetSocketAddress::ConvertFrom(from).GetPort()
  );
  NS_LOG_FUNCTION(this << "requested on" << socket);
  return true; //Accept the connection request
}


bool
QKDApp004::ConnectionRequestedSignalingFromApp(Ptr<Socket> socket, const Address &from)
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
QKDApp004::ConnectionRequestedFromApp(Ptr<Socket> socket, const Address &from)
{
  NS_LOG_FUNCTION(this << socket << from
    << InetSocketAddress::ConvertFrom(from).GetIpv4()
    << InetSocketAddress::ConvertFrom(from).GetPort()
  );
  NS_LOG_FUNCTION(this << "requested on socket " << socket);
  m_isDataConnectedToApp = true;

  return true;
}


void
QKDApp004::HandleAcceptFromKMS(Ptr<Socket> socket, const Address& from)
{
  Address peer;
  NS_LOG_FUNCTION(this << socket << from
    << InetSocketAddress::ConvertFrom(from).GetIpv4()
    << InetSocketAddress::ConvertFrom(from).GetPort()
  );
  NS_LOG_FUNCTION(this << "accepted on" << socket);
  socket->SetRecvCallback(MakeCallback(&QKDApp004::HandleReadFromKMS, this));
  ProcessPacketsToKMSFromQueue();

}

void
QKDApp004::HandleAcceptFromApp(Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION(this << s << from
    << InetSocketAddress::ConvertFrom(from).GetIpv4()
    << InetSocketAddress::ConvertFrom(from).GetPort()
  );
  m_dataSocketApp = s;
  NS_LOG_FUNCTION(this << "accepted on socket " << s);
  s->SetRecvCallback(MakeCallback(&QKDApp004::HandleReadFromApp, this));

}

void
QKDApp004::HandleAcceptSignalingFromApp(Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION(this << s << from
    << InetSocketAddress::ConvertFrom(from).GetIpv4()
    << InetSocketAddress::ConvertFrom(from).GetPort()
  );
  m_signalingSocketApp = s;
  NS_LOG_FUNCTION(this << "accepted on socket " << s);
  s->SetRecvCallback(MakeCallback(&QKDApp004::HandleReadSignalingFromApp, this));

}

void
QKDApp004::ConnectionToKMSSucceeded(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket << "succeeded via socket " << socket);
}

void
QKDApp004::ConnectionToKMSFailed(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket << "failed via socket " << socket);
}

void
QKDApp004::ConnectionToAppSucceeded(Ptr<Socket> s)
{
  NS_LOG_FUNCTION(this << s << "succeeded via socket " << s);
  m_isDataConnectedToApp = true;
}

void
QKDApp004::ConnectionToAppFailed(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket << "failed via socket " << socket);
}

void
QKDApp004::ConnectionSignalingToAppSucceeded(Ptr<Socket> s)
{
  NS_LOG_FUNCTION(this << s << "succeeded via socket " << s);
  m_isSignalingConnectedToApp = true;
}

void
QKDApp004::ConnectionSignalingToAppFailed(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket << "failed via socket " << socket);
}

void
QKDApp004::HandlePeerCloseFromKMS(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);
}

void
QKDApp004::HandlePeerErrorFromKMS(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);
}

void
QKDApp004::HandlePeerCloseToKMS(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);
  if(socket == m_socketToKMS){
    m_socketToKMS->SetConnectCallback(
      MakeNullCallback<void, Ptr<Socket> >(),
      MakeNullCallback<void, Ptr<Socket> >()
    );
    m_socketToKMS = nullptr;
  }
}

void
QKDApp004::HandlePeerErrorToKMS(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);
  if(socket == m_socketToKMS){
    m_socketToKMS->SetConnectCallback(
      MakeNullCallback<void, Ptr<Socket> >(),
      MakeNullCallback<void, Ptr<Socket> >()
    );
    m_socketToKMS = nullptr;

  }
}

void
QKDApp004::HandlePeerCloseFromApp(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);
}
void
QKDApp004::HandlePeerErrorFromApp(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);
}

void
QKDApp004::HandlePeerCloseSignalingFromApp(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);
}

void
QKDApp004::HandlePeerErrorSignalingFromApp(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);
}

void
QKDApp004::HandleReadFromKMS(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);
  if(GetState() == STOPPED) return;
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
      PacketReceivedFromKMS(packet, from, socket);
  }
  ProcessPacketsToKMSFromQueue();

}

void
QKDApp004::ProcessPacketsToKMSFromQueue()
{
  NS_LOG_FUNCTION(this << m_queue_kms.size());
  Address temp;

  //Check is the socket to KMS active and connected
  if(!m_socketToKMS || m_socketToKMS->GetPeerName(temp) != 0 )
  {
    PrepareSocketToKMS();
  }else{
    if(m_queue_kms.size() > 0){
      uint32_t c = 0;
      auto it = m_queue_kms.begin();
      while(it != m_queue_kms.end()){
        NS_LOG_FUNCTION(this << c << m_queue_kms.size() << GetSessionScope( it->scope ));
        PushHttpKmsRequest(it->uri, it->scope);
        if(it->packet ) {
          m_txKmsTrace(GetId(), it->packet);
          m_socketToKMS->Send(it->packet);

        }
        m_queue_kms.erase(it);
        c++;

      }
    }
  }
}

void
QKDApp004::PacketReceivedFromKMS(const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << p->GetUid() << p->GetSize() << from);

  // Initialize or retrieve buffer
  Ptr<Packet> &buffer = m_buffer_kms[from];
  if (!buffer) buffer = Create<Packet>(0);
  buffer->AddAtEnd(p);

  HTTPMessageParser parser;
  while (buffer->GetSize() > 0) {
    // Copy buffer to string for parsing
    std::string bufferStr(buffer->GetSize(), '\0');
    buffer->CopyData(reinterpret_cast<uint8_t*>(&bufferStr[0]), bufferStr.size());

    // Try to extract one complete HTTP message
    std::string httpMsgStr;
    size_t httpMsgSize = 0;
    if (!parser.TryExtractHttpMessage(bufferStr, httpMsgStr, httpMsgSize)) {
      NS_LOG_DEBUG("[DEBUG] Fragmented or incomplete HTTP message. Awaiting more data.");
      break;
    }

    // Parse HTTP message
    HTTPMessage request;
    parser.Parse(&request, httpMsgStr);

    if (request.IsFragmented() || request.GetSize() == 0) {
      NS_LOG_DEBUG("[DEBUG] Detected fragmented or invalid HTTP message. Waiting for more data...");
      break;
    }

    // Remove parsed message from buffer
    Ptr<Packet> completePacket = buffer->CreateFragment(0, static_cast<uint32_t>(httpMsgSize));
    buffer->RemoveAtStart(static_cast<uint32_t>(httpMsgSize));

    m_rxKmsTrace(GetId(), completePacket);
    ProcessResponseFromKMS(request, completePacket, socket);

    NS_LOG_DEBUG("[DEBUG] Processed HTTP message, UID: " << p->GetUid());
    NS_LOG_DEBUG("[DEBUG] Remaining buffer size: " << buffer->GetSize());
  }
}


void
QKDApp004::HandleReadFromApp(Ptr<Socket> socket)
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
                   << " port " << InetSocketAddress::ConvertFrom(from).GetPort() << "\n");

      }
      DataPacketReceived(packet, from, socket);
  }
}

void
QKDApp004::DataPacketReceived(const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION( this << m_master << p->GetUid() << p->GetSize() << from );
  NS_ASSERT(!m_master);

  if(GetState() == READY)
  { //Must be ready to receive data
    QKDAppHeader header;
    Ptr<Packet> buffer;

    auto itBuffer = m_buffer_qkdapp.find(from);
    if(itBuffer == m_buffer_qkdapp.end())
      itBuffer = m_buffer_qkdapp.insert(std::make_pair(from, Create<Packet>(0))).first;

    buffer = itBuffer->second;
    buffer->AddAtEnd(p);
    buffer->PeekHeader(header);
    NS_ABORT_IF(header.GetLength() == 0);

    while(buffer->GetSize() >= header.GetLength())
    {
      NS_LOG_DEBUG("Removing packet of size " << header.GetLength() << " from buffer of size " << buffer->GetSize());
      Ptr<Packet> completePacket = buffer->CreateFragment(0, static_cast<uint32_t>(header.GetLength()));
      buffer->RemoveAtStart(static_cast<uint32_t>(header.GetLength()));

      m_rxTrace(GetId(), completePacket);
      completePacket->RemoveHeader(header);
      NS_LOG_FUNCTION(this << "received qkdapp header" << header);

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
QKDApp004::HandleReadSignalingFromApp(Ptr<Socket> socket)
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
                   << " port " << InetSocketAddress::ConvertFrom(from).GetPort() << "\n");

      }
      SignalingPacketReceivedFromApp(packet, from, socket);
  }
}
void
QKDApp004::SignalingPacketReceivedFromApp(const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << p->GetUid() << p->GetSize() << from);

  // Maintain or create buffer for the sender
  Ptr<Packet> &buffer = m_buffer_sig[from];
  if (!buffer) buffer = Create<Packet>(0);
  buffer->AddAtEnd(p);

  HTTPMessageParser parser;
  HTTPMessage request;

  while (true) {
    if (buffer->GetSize() == 0)
      break;

    // Copy buffer content to a string
    std::string payload(buffer->GetSize(), '\0');
    buffer->CopyData(reinterpret_cast<uint8_t*>(&payload[0]), buffer->GetSize());

    parser.Parse(&request, payload);

    if (request.IsFragmented() || request.GetSize() == 0 ||
        buffer->GetSize() < request.GetSize() ||
        request.GetStatusMessage() == "Undefined")
    {
      NS_LOG_FUNCTION(this << "Incomplete/fragmented HTTP message, waiting for more data.");
      break;
    }

    Ptr<Packet> completePacket = buffer->CreateFragment(0, static_cast<uint32_t>(request.GetSize()));
    buffer->RemoveAtStart(static_cast<uint32_t>(request.GetSize()));

    m_rxSigTrace(GetId(), completePacket);
    ProcessSignalingPacketFromApp(request, socket);

    NS_LOG_DEBUG("Processed HTTP message: " << request.ToString());
    NS_LOG_DEBUG("Remaining in buffer: " << buffer->GetSize());
  }
}



void
QKDApp004::DataToKMSSend(Ptr<Socket> socket, uint32_t)
{
    NS_LOG_FUNCTION(this << "sent via socket " << socket);
}


/**
 * ********************************************************************************************

 *        KEY BUFFER functions

 * ********************************************************************************************
 */

void
QKDApp004::CheckStreamSessions()
{
  NS_LOG_FUNCTION(this);

  NS_ASSERT(m_master); //Only Sender QKDApp
  bool encStream {true}, authStream {true};
  NS_LOG_FUNCTION(this << m_encStream->GetId() << m_encStream->IsVerified() << m_authStream->GetId() << m_authStream->IsVerified());
  if(!m_encStream->GetId().empty() && !m_encStream->IsVerified())
    encStream = false;
  if(!m_authStream->GetId().empty() && !m_authStream->IsVerified())
    authStream = false;

  NS_LOG_FUNCTION(this << encStream << authStream);
  if(encStream && authStream && GetState() == ESTABLISHING_ASSOCIATIONS){
    NS_LOG_FUNCTION(this << "sessions establihed" << m_encStream->GetId() << m_authStream->GetId());
    SetState(ASSOCIATIONS_ESTABLISHED);
    AppTransitionTree();

  }else
    NS_LOG_FUNCTION(this << "key stream sessions are NOT established");

}

void
QKDApp004::CheckQueues()
{
    NS_LOG_FUNCTION(this);
    bool encQueueReady {false};
    bool authQueueReady {false};
    if(m_encStream->IsVerified() && m_encStream->GetKeyCount() < m_encStream->GetSize())
        GetKeyFromKMS(m_encStream->GetId());
    else
        encQueueReady = true;

    if(m_authStream->IsVerified() && m_authStream->GetKeyCount() < m_authStream->GetSize())
        GetKeyFromKMS(m_authStream->GetId());
    else
        authQueueReady = true;

    if(authQueueReady && encQueueReady){
        if(!m_master){
            NS_LOG_FUNCTION(this << m_master << "queues established");
            SetState(KEY_QUEUES_ESTABLISHED);
            AppTransitionTree();

        }else if(m_master){
            if(m_replicaQueueEstablished){
                NS_LOG_FUNCTION(this << "both sides establihed queues");
                SetState(KEY_QUEUES_ESTABLISHED);
                AppTransitionTree();

            }else{
                NS_LOG_FUNCTION(this << m_master << "queues established");
                m_primaryQueueEstablished = true;

            }
        }
    }else if(!authQueueReady && encQueueReady){
      NS_LOG_FUNCTION(this << "authQueueReady is not ready!");
    }else if(authQueueReady && !encQueueReady){
      NS_LOG_FUNCTION(this << "encQueueReady is not ready!");
    }else{
      NS_LOG_FUNCTION(this << "authQueueReady and encQueueReady are not ready!");
    }
}


/**
 * ********************************************************************************************

 *        HTTP handling to KMS

 * ********************************************************************************************
 */
void
QKDApp004::PushHttpKmsRequest(std::string uri, KeyStreamSession::Type sessionType)
{
  NS_LOG_FUNCTION(this << uri << sessionType);
  m_httpRequestsKMS.insert(std::make_pair(uri, sessionType));
}

KeyStreamSession::Type
QKDApp004::PopHttpKmsRequest(std::string uri)
{
  NS_LOG_FUNCTION(this << uri);
  KeyStreamSession::Type sessionType = KeyStreamSession::EMPTY;
  auto it = m_httpRequestsKMS.find("http://" + uri);
  if(it != m_httpRequestsKMS.end()){
    sessionType = it->second;
    m_httpRequestsKMS.erase(it);
  }else
    NS_LOG_DEBUG(this << "could not map response " << uri);

  return sessionType;

}

/**
 * ********************************************************************************************

 *        APPLICATION functions

 * ********************************************************************************************
 */
void
QKDApp004::StartApplication()
{
  NS_LOG_FUNCTION(this << m_master << m_local << m_peer);

  m_packetsSent = 0;
  if(m_encryption < 0 || m_encryption > 2)
    NS_FATAL_ERROR(this << "invalid encryption type" << m_encryption
      << "allowed values are(0-unencrypted, 1-OTP, 2-AES)");
  if(m_authentication < 0 || m_authentication > 3)
    NS_FATAL_ERROR(this << "invalid authentication type" << m_authentication
      << "allowed values are(0-unauthenticated, 1-VMAC, 3-SHA2)");
  if(m_aesLifetime < 0){
    NS_FATAL_ERROR(this << "invalid AES lifetime " << m_aesLifetime
      << "the value must be positive");
  }else if(m_aesLifetime  && m_aesLifetime < m_packetSize)
    NS_FATAL_ERROR(this << "invalid AES lifetime " << m_aesLifetime
      << "the value must be larger than packet size " << m_packetSize);

  if(m_encryption == 1) //OTP encryption
    m_aesLifetime = m_packetSize;

  if(GetState() == INITIALIZED){
    SetCryptoSettings(
      m_encryption,
      m_authentication,
      m_authenticationTagLengthInBits
    );
    AppTransitionTree(); //Transition states
    PrepareSocketToApp(); //Create sink sockets for peer QKD applications

  }else
      NS_FATAL_ERROR(this << "invalid state " << GetAppStateString() << " for StartApplication()");

}

void
QKDApp004::StopApplication()
{
  NS_LOG_FUNCTION(this);

  if(m_sendEvent.IsPending()) Simulator::Cancel(m_sendEvent);

  if(m_master){ //Only Sender App004 calls CLOSE
    if(!m_encStream->GetId().empty())
      Close(m_encStream->GetId()); //CLOSE encryption key stream session
      //NS_LOG_FUNCTION(this << "close" << "enc");
    if(!m_authStream->GetId().empty())
      Close(m_authStream->GetId()); //CLOSE authentication key stream session
      //NS_LOG_FUNCTION(this << "close" << "auth");

  }else{ //Replica QKDApp closes sockets to the KMS
    if(m_socketToKMS)   m_socketToKMS->Close();
    else  NS_LOG_WARN("QKDApp004 found null m_socketToKMS to close in StopApplication");
  }

  //Closing app send and sink sockets
  if(m_dataSocketApp)       m_dataSocketApp->Close();
  else  NS_LOG_WARN("QKDApp004 found null m_dataSocketApp to close in StopApplication");

  if(m_signalingSocketApp)  m_signalingSocketApp->Close();
  else  NS_LOG_WARN("QKDApp004 found null m_signalingSocketApp to close in StopApplication");

  if(m_socketToKMS)          m_socketToKMS->Close();
  else  NS_LOG_WARN("QKDApp004 found null m_socketToKMS to close in StopApplication");

  //Clear key stream sessions
  m_encStream->ClearStream();
  m_authStream->ClearStream();

  SetState(STOPPED);

}

void
QKDApp004::SendPacket()
{
  NS_LOG_FUNCTION(this);

  if(!m_dataSocketApp  || !m_isDataConnectedToApp)
    PrepareSocketToApp();

  NS_ASSERT(m_master);
  if(GetState() == READY) {
    SetState(SEND_DATA); //Direct call from SceduleTx()
  }

  if(GetState() == SEND_DATA){ //Only in SEND_DATA can app send data

    Ptr<AppKey> encKey, authKey;
    uint32_t encKeyId {0};
    uint32_t authKeyId {0}; //Necessary for headers
    std::string confidentialMsg {GetPacketContent()}, encryptedMsg {confidentialMsg}, authTag {GetPacketContent(32)};
    if(GetEncryptionKeySize() ){ //Obtain encryption key!
      encKey = m_encStream->GetKey(m_packetSize);
      if(!encKey){
        NS_LOG_ERROR(this << "no encryption key available");
        SetState(READY);
        return;

      }else{
        encKey->UseLifetime(m_packetSize);
        if(encKey->GetLifetime() == 0)
          GetKeyFromKMS(m_encStream->GetId());
        encKeyId = encKey->GetIndex();
        if(m_useCrypto) encryptedMsg = m_encryptor->EncryptMsg(confidentialMsg, encKey->GetKeyString());
        NS_LOG_FUNCTION(this << "\nConfidential message:\t\t" << confidentialMsg.size() << confidentialMsg
                             << "\nEncryption key ID:\t\t" << encKey->GetIndex() << encKey->GetKeyString()
                             << "\nEncrypted message:\t\t" << m_encryptor->Base64Encode(encryptedMsg));
      }

    }
    if(GetAuthenticationKeySize() ){//Obtain authentication
      authKey = m_authStream->GetKey();
      if(!authKey){
        NS_LOG_ERROR(this << "no autentication key available");
        SetState(READY);
        return;

      }else{
        GetKeyFromKMS(m_authStream->GetId());
        authKeyId = authKey->GetIndex();
        if(m_useCrypto) authTag = m_encryptor->Authenticate(encryptedMsg, authKey->GetKeyString());
        NS_LOG_FUNCTION(this << "\nAuthentication key ID:\t\t" << authKey->GetIndex() << authKey->GetKeyString()
                             << "\nAuthentication tag:\t\t" << authTag);
      }

    }else if(m_authenticationType != QKDEncryptor::UNAUTHENTICATED){
      authTag = m_encryptor->Authenticate(encryptedMsg, "");
      NS_LOG_FUNCTION(this << "\nAuthentication tag:\t\t" << authTag);

    }
    //Create packet with protected/unprotected data
    std::string msg = encryptedMsg;
    Ptr<Packet> packet = Create<Packet>((uint8_t*) msg.c_str(), msg.length() );
    NS_ASSERT(packet );
    m_authenticationTrace(packet, authTag);

    //Add qkd header!
    QKDAppHeader qHeader;
    qHeader.SetEncrypted(m_encryptionType);
    qHeader.SetEncryptionKeyId(std::to_string(encKeyId));
    qHeader.SetAuthenticated(m_authenticationType);
    qHeader.SetAuthenticationKeyId(std::to_string(authKeyId));
    qHeader.SetAuthTag(authTag);
    qHeader.SetLength(packet->GetSize() + qHeader.GetSerializedSize());
    packet->AddHeader(qHeader);

    //Send packet!
    m_txTrace(GetId(), packet);
    m_dataSocketApp->Send(packet);
    m_packetsSent++;
    m_dataSent += packet->GetSize();

    NS_LOG_FUNCTION(this << "packet sent" << packet->GetUid() << packet->GetSize());
    SetState(READY);
    ScheduleTx();

  }else if(GetState() == WAIT){
    m_mxTrace(GetId(), nullptr);
    ScheduleTx();
    NS_LOG_FUNCTION(this << "unable to send data" << GetAppStateString(GetState()));

  }else
    NS_FATAL_ERROR(this << "invalid state" << GetAppStateString(GetState()));

}

void
QKDApp004::ProcessDataPacket(QKDAppHeader header, Ptr<Packet> packet, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this);
  NS_ASSERT(!m_master); //Only receiver App014

  SetState(DECRYPT_DATA);
  std::string payload = PacketToString(packet); //Read the packet data
  m_packetSize = payload.size();
  if(m_encryptionType != QKDEncryptor::QKDCRYPTO_AES)
    m_aesLifetime = m_packetSize;

  NS_LOG_FUNCTION(this << "\n\nreceived payload" << m_encryptor->Base64Encode(payload));

  SetCryptoSettings(header.GetEncrypted(), header.GetAuthenticated(), m_authenticationTagLengthInBits);
  std::string decryptedMsg;
  bool authSuccessful {true};
  if(GetAuthenticationKeySize() )
  { 
    //Authentication requires QKD key
    if(!m_authStream->SyncStream(std::stoi(header.GetAuthenticationKeyId()))) //Key has been changed
      GetKeyFromKMS(m_authStream->GetId());

    Ptr<AppKey> authKey {m_authStream->GetKey()}; //Obtain new authentication key(note that the stream is in sync before this)
    if(!authKey){ //Packet received out of sync(dealyed packet). Packet is dropped!
      NS_LOG_DEBUG(this << "key missing " << std::stoi(header.GetAuthenticationKeyId()) << " packet is DROPPED");
      SetState(READY);
      return;

    }else
      GetKeyFromKMS(m_authStream->GetId());

    NS_LOG_FUNCTION(this << "authentication key" << authKey->GetIndex() << authKey->GetKeyString());
    if(m_useCrypto) //Authentication
      if(!m_encryptor->CheckAuthentication(payload, header.GetAuthTag(), authKey->GetKeyString())) //Check AuthTag
        authSuccessful = false;

  }else if(header.GetAuthenticated() && m_useCrypto){ //Authentication does not require quantum key
    if(!m_encryptor->CheckAuthentication(payload, header.GetAuthTag(), ""))
      authSuccessful = false;

  }
  if(authSuccessful)
    NS_LOG_FUNCTION(this << "authentication successful");
  else{
    NS_LOG_DEBUG(this << "authentication failed -> packet is dropped");
    return;
  }

  //Perform decryption
  if(header.GetEncrypted())
  {
    if(!m_encStream->SyncStream(std::stoi(header.GetEncryptionKeyId()))) //Synchronization
      GetKeyFromKMS(m_encStream->GetId()); //Calling get_key request

    Ptr<AppKey> encKey {m_encStream->GetKey(m_packetSize)}; //Obtain new encryption key
    if(!encKey){ //Out of sync(delayed packet)! Packet is dropped!
      NS_LOG_DEBUG(this << "key missing " << std::stoi(header.GetEncryptionKeyId()) << " packet is DROPPED");
      GetKeyFromKMS(m_encStream->GetId());
      SetState(READY);
      return;

    }else if(encKey->GetLifetime() == 0)
      GetKeyFromKMS(m_encStream->GetId());

    NS_LOG_FUNCTION(this << "decryption key" << encKey->GetIndex() << encKey->GetKeyString());
    if(m_useCrypto && authSuccessful){//Packet is decrypted only when it is succesfully  authenticated
      decryptedMsg = m_encryptor->DecryptMsg(payload, encKey->GetKeyString());
      NS_LOG_FUNCTION(this << "decrypted message\n" << decryptedMsg);

    }else if(authSuccessful)//Fake decryption process
      NS_LOG_FUNCTION(this << "decrypted message" << payload);

    else //Receiving unprotected packet
       NS_LOG_FUNCTION(this << "received message" << payload);

    SetState(READY);

  }
}

void
QKDApp004::ProcessResponseFromKMS(HTTPMessage& header, Ptr<Packet> packet, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << packet->GetUid() << packet->GetSize());
  std::string methodName {ReadUri(header.GetRequestUri())[5]};
  if(methodName == "open_connect" && GetState() != STOPPED)
    ProcessOpenConnectResponse(header);

  else if(methodName == "get_key" && GetState() != STOPPED)
    ProcessGetKeyResponse(header);

  else if(methodName == "close" && GetState() != STOPPED)
    ProcessCloseResponse(header);

  else
    NS_LOG_DEBUG(this << "invalid method" << methodName);

}

/**
 * ********************************************************************************************

 *        KEY MANAGEMENT functions

 * ********************************************************************************************
 */

void
QKDApp004::OpenConnect(std::string ksid, KeyStreamSession::Type sessionType)
{
  NS_LOG_FUNCTION(this << ksid << sessionType);
  uint32_t keySize;
  if(sessionType == KeyStreamSession::ENCRYPTION)
    keySize = GetEncryptionKeySize();
  else
    keySize = GetAuthenticationKeySize();

  NS_LOG_FUNCTION(this << m_master << ksid << sessionType << keySize);
  if(m_master)                 NS_ASSERT(keySize );

  nlohmann::json msgBody {
    {"Source", GetId()},
    {"Destination", GetPeerId()}
    //{"Qos", {{"priority", 2}} }
  };
  if(!m_master)
    msgBody["Key_stream_ID"] = ksid;
  else
    msgBody["QoS"]["Key_chunk_size"] = keySize;

  //Create packet
  std::string reqUri {"http://"+IpToString(GetKmsIp())+"/api/v1/keys/"+GetPeerId()+"/open_connect"};
  HTTPMessage httpMessage;
  httpMessage.CreateRequest(reqUri, "POST", msgBody.dump());
  httpMessage.SetHeader("User-Agent", "QKDApp004_" + GetId());
  std::string hMessage = httpMessage.ToString();
  Ptr<Packet> packet = Create<Packet>(
   (uint8_t*)(hMessage).c_str(),
    hMessage.size()
  );
  NS_ASSERT(packet );

  Address temp; //check whether the socket to KMS is active and connected
  if(m_socketToKMS)
  {
    PushHttpKmsRequest(reqUri, sessionType);
    m_txKmsTrace(GetId(),packet);
    m_socketToKMS->Send(packet);
    NS_LOG_FUNCTION(this << "packet sent" << packet->GetUid() << packet->GetSize() << m_socketToKMS);
  }else{
    PrepareSocketToKMS();
    QKDApp004::KMSPacket kmsPacket {
      packet, //packet
      reqUri,
      sessionType
    };
    m_queue_kms.push_back(kmsPacket);
    NS_LOG_FUNCTION(this << "packet enqueued" << packet->GetUid() << packet->GetSize() << m_socketToKMS);
  }
}

void
QKDApp004::GetKeyFromKMS(std::string ksid)
{
  NS_LOG_FUNCTION(this << m_master << ksid);
  if(GetState() == QKDApp004::STOPPED)  return;

  std::string reqUri = "http://" + IpToString(GetKmsIp()) + "/api/v1/keys/" + ksid + "/get_key";
  nlohmann::json msgBody {{"Key_stream_ID", ksid}};

  //Create packet
  HTTPMessage httpMessage;
  httpMessage.CreateRequest(reqUri, "POST", msgBody.dump());
  httpMessage.SetHeader("User-Agent", "QKDApp004_" + GetId());
  std::string hMessage = httpMessage.ToString();
  Ptr<Packet> packet = Create<Packet>(
   (uint8_t*)(hMessage).c_str(),
    hMessage.size()
  );
  NS_ASSERT(packet );

  Address temp; //Check whether the socket to KMS is active and connected
  if(!m_socketToKMS || m_socketToKMS->GetPeerName(temp) != 0 )
  {
    PrepareSocketToKMS();
    QKDApp004::KMSPacket kmsPacket{
      packet,
      reqUri,
      KeyStreamSession::ENCRYPTION //not important
    };
    m_queue_kms.push_back(kmsPacket);
    NS_LOG_FUNCTION(this << "packet enqueud" << packet->GetUid() << packet->GetSize() << m_socketToKMS);

  }else{
    PushHttpKmsRequest(reqUri); //open_connect->0, get_key->1, close->2; encKey->0, authKey->1
    m_txKmsTrace(GetId(),packet);
    m_socketToKMS->Send(packet);
    NS_LOG_FUNCTION(this << "packet sent" << packet->GetUid() << packet->GetSize() << m_socketToKMS);

  }
}

void
QKDApp004::Close(std::string ksid)
{
  NS_LOG_FUNCTION(this << m_master << ksid);
  if(m_encStream->GetId() == ksid)
    m_encStream->ClearStream();
  else if(m_authStream->GetId() == ksid)
    m_authStream->ClearStream();
  else
    NS_LOG_ERROR(this << "unknown ksid" << ksid);

  std::string reqUri {"http://" + IpToString(GetKmsIp()) + "/api/v1/keys/" + ksid + "/close"};
  //Create packet
  HTTPMessage httpMessage;
  httpMessage.CreateRequest(reqUri, "GET");
  httpMessage.SetHeader("User-Agent", "QKDApp004_" + GetId());
  std::string hMessage = httpMessage.ToString();
  Ptr<Packet> packet = Create<Packet>(
   (uint8_t*)(hMessage).c_str(),
    hMessage.size()
  );
  NS_ASSERT(packet );

  Address temp; //check whether the socket to KMS is active and connected
  if(m_socketToKMS)
  {
    PushHttpKmsRequest(reqUri);
    m_txKmsTrace(GetId(),packet);
    m_socketToKMS->Send(packet);
    NS_LOG_FUNCTION(this << "packet sent" << packet->GetUid() << packet->GetSize() << m_socketToKMS);

  }else{
    PrepareSocketToKMS();
    QKDApp004::KMSPacket kmsPacket{
      packet,
      reqUri,
      KeyStreamSession::ENCRYPTION //not important
    };
    m_queue_kms.push_back(kmsPacket);
    NS_LOG_FUNCTION(this << "packet enqueued" << packet->GetUid() << packet->GetSize() << m_socketToKMS);
  }

}

void
QKDApp004::ProcessOpenConnectResponse(HTTPMessage& header)
{
  NS_LOG_FUNCTION(this << m_master);

  KeyStreamSession::Type sessionType {PopHttpKmsRequest(header.GetRequestUri())};
  std::string payload = header.GetMessageBodyString(); //Read HTTP body message
  nlohmann::json jOpenConnect; //Read JSON data structure from message
  if(!payload.empty()){
    try{
      jOpenConnect = nlohmann::json::parse(payload);
    }catch(...){
      NS_FATAL_ERROR(this << "json parse error");
    }

  }

  std::string ksid;
  if(m_master){
    if(header.GetStatus() == HTTPMessage::Ok){
      if(jOpenConnect.contains("Key_stream_ID")) ksid = jOpenConnect["Key_stream_ID"];
      NS_ASSERT(!ksid.empty());

      if(sessionType == KeyStreamSession::ENCRYPTION)
        m_encStream->SetId(ksid);
      else
        m_authStream->SetId(ksid);

      SendKsid(ksid, sessionType);

    }else
      NS_LOG_ERROR(this << "open_connect refused " << jOpenConnect["status"]);

  }else{//!m_master
    if(sessionType == KeyStreamSession::ENCRYPTION)
      ksid = m_encStream->GetId();
    else
      ksid = m_authStream->GetId();

    if(header.GetStatus() == HTTPMessage::Ok){
      if(sessionType == KeyStreamSession::ENCRYPTION)
        m_encStream->SetVerified(true);
      else
        m_authStream->SetVerified(true);

      SendKsid(ksid, sessionType, HTTPMessage::Ok);

    }else{
      NS_LOG_FUNCTION(this << "open_connect refused");
      if(sessionType == KeyStreamSession::ENCRYPTION)
        m_encStream->ClearStream();
      else
        m_authStream->ClearStream();

      SendKsid(ksid, sessionType, HTTPMessage::BadRequest);

    }
  }
}

void
QKDApp004::ProcessGetKeyResponse(HTTPMessage& header)
{
  NS_LOG_FUNCTION(this);
  std::string payload {header.GetMessageBodyString()};
  std::string ksid;
  KeyStreamSession::Type sessionType {PopHttpKmsRequest(header.GetRequestUri())};
  if(sessionType == KeyStreamSession::ENCRYPTION)
    ksid = m_encStream->GetId();
  else
    ksid = m_authStream->GetId();
  NS_ASSERT(!ksid.empty());

  nlohmann::json jGetKeyResponse;
  if(!payload.empty())
    try{
      jGetKeyResponse = nlohmann::json::parse(payload);
    }catch(...){
      NS_FATAL_ERROR( this << "JSON parse error!");
    }

  if(header.GetStatus() == HTTPMessage::Ok){
    uint32_t index = -1;
    std::string keyValue;
    if(jGetKeyResponse.contains("index"))       index = jGetKeyResponse["index"];
    if(jGetKeyResponse.contains("Key_buffer"))  keyValue = jGetKeyResponse["Key_buffer"];
    NS_ASSERT(index >= 0 || !keyValue.empty());

    AppKey::Type keyType = AppKey::ENCRYPTION;
    if(sessionType == KeyStreamSession::ENCRYPTION) 
      keyType = AppKey::ENCRYPTION;
    else if(sessionType == KeyStreamSession::AUTHENTICATION) 
      keyType = AppKey::AUTHENTICATION;
    
    Ptr<AppKey> key {CreateObject<AppKey>(index, keyValue, keyType, m_aesLifetime)};
    if(sessionType == KeyStreamSession::ENCRYPTION)
      m_encStream->AddKey(key);
    else
      m_authStream->AddKey(key);

    if(GetState() == ESTABLISHING_KEY_QUEUES)
      CheckQueues();
    else if(GetState() == WAIT){
      if( !(GetEncryptionKeySize()  && m_encStream->GetKeyCount() == 0) &&
          !(GetAuthenticationKeySize()  && m_authStream->GetKeyCount() == 0) )
        SetState(READY);
    }

  }else{ //Process status field of response(ETSI004 defined: 2, 3, 8) @toDo
    if(GetState() == ESTABLISHING_KEY_QUEUES){
      Time t {"300ms"};
      EventId event = Simulator::Schedule(t, &QKDApp004::GetKeyFromKMS, this, ksid);

    }else if(m_master){
      Time t {"500ms"};
      EventId event = Simulator::Schedule(t, &QKDApp004::GetKeyFromKMS, this, ksid);

    }else if(!m_master)
      NS_LOG_DEBUG(this << "unexpected get_key error on receiver App004");

  }
}

void
QKDApp004::ProcessCloseResponse(HTTPMessage& header)
{
  NS_LOG_FUNCTION(this << header.GetStatus());
  KeyStreamSession::Type sessionType {PopHttpKmsRequest(header.GetRequestUri())};
  if(m_httpRequestsKMS.empty()){ //Sockets are closed when both CLOSE responses are received!
    if(m_socketToKMS)   m_socketToKMS->Close();
  }

  if(header.GetStatus() != HTTPMessage::Ok)   NS_LOG_DEBUG(this);
  std::string ksid {};
  if(sessionType == KeyStreamSession::ENCRYPTION)
    m_encStream->ClearStream();
  else
    m_authStream->ClearStream();

}

void
QKDApp004::ProcessSignalingPacketFromApp(HTTPMessage& header, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << m_master);
  if(m_master){ //Sender App004 processes responses from peer Receiver App004
    std::string method { ReadUri( header.GetRequestUri() )[5] };
    if(method == "send_ksid"){ //Sender App004 processes send_ksid response
      if(ReadUri( header.GetRequestUri() )[6] != "?ksid=" || ReadUri( header.GetRequestUri() )[8] != "&scope=")   NS_LOG_DEBUG(this);

      std::string ksid { ReadUri( header.GetRequestUri() )[7] };
      std::string scope { ReadUri( header.GetRequestUri() )[9] };
      NS_LOG_FUNCTION(this << "emir" << ksid << scope);
      NS_ASSERT(!ksid.empty() || !scope.empty());
      if(header.GetStatus() == HTTPMessage::Ok){ //status code 200
        if(scope == "enc"){
          if(m_encStream->GetId() != ksid)   NS_LOG_DEBUG(this << "ksid not matching scope");
          m_encStream->SetVerified(true);

        }else if(scope == "auth"){
          if(m_authStream->GetId() != ksid)  NS_LOG_DEBUG(this << "ksid not matching scope");
          m_authStream->SetVerified(true);

        }else
          NS_LOG_DEBUG(this << "unknown scope" << scope);

        CheckStreamSessions();

      }else{ //status code not 200
        NS_LOG_DEBUG(this << "unexpected SEND_KSID error");
        Close(ksid);

      }
    }else if(method == "establish_queues"){
      m_replicaQueueEstablished = true;
      if(m_primaryQueueEstablished){
        SetState(KEY_QUEUES_ESTABLISHED);
        AppTransitionTree();

      }
    }else
      NS_LOG_DEBUG(this << "invalid method" << method);

  }else{ //Receiver App004 processes requests from peer Sender App004
    std::string method { ReadUri(header.GetUri())[4] };
    if(method == "send_ksid")
    { //Receiver App004 receives SEND_KSID request

      if(ReadUri(header.GetUri())[5] != "?ksid=" || ReadUri(header.GetUri())[7] != "&scope=") 
        NS_LOG_DEBUG(this);

      std::string ksid { ReadUri(header.GetUri())[6] };
      std::string scope { ReadUri(header.GetUri())[8] };
      NS_ASSERT(!ksid.empty() || !scope.empty());

      KeyStreamSession::Type type = KeyStreamSession::EMPTY;
      if(scope == "enc"){
        m_encStream->SetId(ksid); //Register KSID for encryption
        type = KeyStreamSession::ENCRYPTION;
      }
      else if(scope == "auth"){
        m_authStream->SetId(ksid); //Register KSID for autentication
        type = KeyStreamSession::AUTHENTICATION;
      }
      else
        NS_LOG_DEBUG(this << "unknown scope" << scope);

      SetState(ESTABLISHING_ASSOCIATIONS);
      OpenConnect(ksid, type); //Send OpenConnect to local KMS!

    }else if(method == "establish_queues"){ //ESTABLISH_QUEUES request
      SetState(ESTABLISHING_KEY_QUEUES);
      CheckQueues();

    }else
      NS_LOG_DEBUG(this << "invalid method" << method);

  }

}

/**
 * ********************************************************************************************

 *        Application SIGNALING

 * ********************************************************************************************
 */
void
QKDApp004::SendKsid(std::string ksid, KeyStreamSession::Type sessionType, HTTPMessage::HttpStatus statusCode)
{
  NS_LOG_FUNCTION(this << m_master << ksid << GetSessionScope(sessionType));

  if(!m_signalingSocketApp  || !m_isSignalingConnectedToApp)
    PrepareSocketToApp();

  HTTPMessage httpMessage;
  if(m_master){ //Sender App004 sends send_ksid request

    std::string uri = "http://" + IpToString( GetPeerIp() ) + "/api/v1/" + GetPeerId() + "/send_ksid/?" + "ksid=/" + ksid + "/&scope=/" + GetSessionScope(sessionType);
    httpMessage.CreateRequest(uri, "GET");
    NS_LOG_FUNCTION(this << uri << httpMessage.GetUri());
    httpMessage.SetHeader("User-Agent", "QKDApp004_" + GetId());

  }else{ //Receiver App004 sends send_ksid response
    httpMessage.CreateResponse(statusCode, "", {
      {"Content-Type", "application/json; charset=utf-8"},
      {"Request URI", "http://" + IpToString( GetIp() ) + "/api/v1/" + GetId() + "/send_ksid/?" + "ksid=/" + ksid + "/&scope=/" + GetSessionScope(sessionType)} //reconstruct req uri
    });

  }
  std::string hMessage = httpMessage.ToString();
  Ptr<Packet> packet = Create<Packet>(
   (uint8_t*)(hMessage).c_str(),
    hMessage.size()
  );
  NS_ASSERT(packet );

  m_txSigTrace(GetId(), packet);
  m_signalingSocketApp->Send(packet);

  if(m_master)
    NS_LOG_FUNCTION(this << "Request sent" << packet->GetUid() << packet->GetSize() << httpMessage.GetUri());
  else
    NS_LOG_FUNCTION(this << "Response sent" << packet->GetUid() << packet->GetSize() << httpMessage.GetStatus());

}

void
QKDApp004::EstablishQueues()
{
    NS_LOG_FUNCTION(this << m_master);

    HTTPMessage httpMessage;
    if(m_master){
      httpMessage.CreateRequest("http://" + IpToString( GetPeerIp() ) + "/api/v1/" + GetPeerId() + "/establish_queues", "GET");
      httpMessage.SetHeader("User-Agent", "QKDApp004_" + GetId());

    }else{
      httpMessage.CreateResponse(HTTPMessage::Ok, "", {
        {"Content-Type", "application/json; charset=utf-8"},
        {"Request URI", "http://" + IpToString( GetIp() ) + "/api/v1/" + GetId() + "/establish_queues"} //reconstruct req uri
      });

    }
    std::string hMessage = httpMessage.ToString();
    Ptr<Packet> packet = Create<Packet>(
     (uint8_t*)(hMessage).c_str(),
      hMessage.size()
    );
    NS_ASSERT(packet );

    m_txSigTrace(GetId(), packet);
    m_signalingSocketApp->Send(packet);

    if(m_master)
      NS_LOG_FUNCTION(this << "Request sent" << packet->GetUid() << packet->GetSize() << httpMessage.GetUri());
    else
      NS_LOG_FUNCTION(this << "Response sent" << packet->GetUid() << packet->GetSize() << httpMessage.GetStatus());

}

void
QKDApp004::CreateKeyStreamSessions()
{
    NS_LOG_FUNCTION(this << m_master);

    NS_ASSERT(m_master);
    if(GetEncryptionKeySize()  && m_encStream->GetId().empty())
        OpenConnect("", KeyStreamSession::ENCRYPTION); //Establish association for a set of future encryption keys

    if(GetAuthenticationKeySize()  && m_authStream->GetId().empty())
        OpenConnect("", KeyStreamSession::AUTHENTICATION); //Establish association for a set of future authentication keys

}

void
QKDApp004::RegisterAckTime(Time oldRtt, Time newRtt)
{
  NS_LOG_FUNCTION(this << oldRtt << newRtt);
}


/**
 * ********************************************************************************************

 *        STATE functions

 * ********************************************************************************************
 */

void
QKDApp004::AppTransitionTree()
{
    NS_LOG_FUNCTION(this);
    if(m_master){ //Transitions for Primary QKDApp
        if(GetState() == INITIALIZED){
            if(GetEncryptionKeySize() == 0 && GetAuthenticationKeySize() == 0){ //QKD key material not needed!
                SetState(READY);
                SendPacket(); //Immediately sends unprotected packets

            }else{ //Establish key stream sessions for a set of future QKD keys
                SetState(ESTABLISHING_ASSOCIATIONS);
                PrepareSocketToKMS();
                CreateKeyStreamSessions(); //Call OPEN_CONNECT

            }

        }else if(GetState() == ASSOCIATIONS_ESTABLISHED){
            SetState(ESTABLISHING_KEY_QUEUES);
            EstablishQueues();
            CheckQueues();

        }else if(GetState() == KEY_QUEUES_ESTABLISHED){
            SetState(READY);
            SendPacket(); //Start sending packets!

        }else
            NS_FATAL_ERROR(this << "invalid entry state" << GetState() <<
                                    "for AppTransitionTree()");

    }else if(!m_master){ //Data transmision state transition for Replica QKDApp
        if(GetState() == INITIALIZED){
            SetState(READY);
            PrepareSocketToKMS();

        }else if(GetState() == KEY_QUEUES_ESTABLISHED){
            SetState(READY);
            EstablishQueues();

        }else
            NS_FATAL_ERROR(this << "invalid entry state" << GetState() <<
                                    "for AppTransitionTree()");
    }

}


QKDApp004::State
QKDApp004::GetState() const
{
  return m_state;
}

std::string
QKDApp004::GetAppStateString(QKDApp004::State state)
{
  switch(state)
    {
    case NOT_STARTED:
      return "NOT_STARTED";
      break;
    case INITIALIZED:
      return "INITIALIZED";
      break;
    case ESTABLISHING_ASSOCIATIONS:
      return "ESTABLISHING_ASSOCIATIONS";
      break;
    case ASSOCIATIONS_ESTABLISHED:
      return "ASSOCIATIONS_ESTABLISHED";
      break;
    case ESTABLISHING_KEY_QUEUES:
      return "ESTABLISHING_KEY_QUEUES";
      break;
    case KEY_QUEUES_ESTABLISHED:
      return "KEY_QUEUES_ESTABLISHED";
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
QKDApp004::GetAppStateString() const
{
  return GetAppStateString(GetState());
}

void
QKDApp004::SetState(QKDApp004::State state)
{
  const std::string oldState = GetAppStateString();
  const std::string newState = GetAppStateString(state);

  //Check transition matrix! @toDo
  if(oldState == "SEND_DATA" && newState == "READY") {
    if ((!m_encStream->GetId().empty() && m_encStream->GetKeyCount() == 0) ||
         (!m_authStream->GetId().empty() && m_authStream->GetKeyCount() == 0)
        )
      state = QKDApp004::State::WAIT; //Queues are empty. Go to state WAIT!

  }
  m_state = state;
  NS_LOG_FUNCTION( this << "QKDApp" << oldState << "-->" << GetAppStateString(state) );
  //m_appStateTransitionTrace(oldState, newState);

}

/**
 * ********************************************************************************************

 *        ADDTIONAL functions

 * ********************************************************************************************
 */

void
QKDApp004::SetCryptoSettings(
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
QKDApp004::GetPacketContent(uint32_t msgLength)
{
  NS_LOG_FUNCTION(this);

  if(msgLength == 0)
    msgLength = m_packetSize;

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

uint32_t
QKDApp004::GetEncryptionKeySize()
{
    switch(m_encryptionType){
        case QKDEncryptor::UNENCRYPTED:
            return 0;
            break;
        case QKDEncryptor::QKDCRYPTO_OTP:
            return m_packetSize * 8;
            break;
        case QKDEncryptor::QKDCRYPTO_AES:
            return CryptoPP::AES::MAX_KEYLENGTH * 8; //In bits 256! Quantum resistant!
            break;
    }
    return 0;
}

uint32_t
QKDApp004::GetAuthenticationKeySize()
{
    switch(m_authenticationType){
        case QKDEncryptor::UNAUTHENTICATED:
            return 0;
            break;
        case QKDEncryptor::QKDCRYPTO_AUTH_VMAC:
            return CryptoPP::AES::DEFAULT_KEYLENGTH * 8; //Use with AES. In bits 128 bits!
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

Ipv4Address
QKDApp004::GetKmsIp()
{
  NS_LOG_FUNCTION(this);
  return InetSocketAddress::ConvertFrom(m_kms).GetIpv4();
}

Ipv4Address
QKDApp004::GetIp()
{
  NS_LOG_FUNCTION(this);
  return InetSocketAddress::ConvertFrom(m_peer).GetIpv4();
}

Ipv4Address
QKDApp004::GetPeerIp()
{
  NS_LOG_FUNCTION(this);
  return InetSocketAddress::ConvertFrom(m_peer).GetIpv4();
}

std::string
QKDApp004::IpToString(Ipv4Address address)
{
  NS_LOG_FUNCTION(this << address);
  std::ostringstream lkmsAddressTemp;
  address.Print(lkmsAddressTemp);
  return lkmsAddressTemp.str();
}

std::string
QKDApp004::PacketToString(Ptr<Packet> packet)
{
  NS_LOG_FUNCTION( this );

  uint8_t *buffer = new uint8_t[packet->GetSize()];
  packet->CopyData(buffer, packet->GetSize());
  std::string payload = std::string((char*)buffer, packet->GetSize());
  delete[] buffer;

  return payload;
}

std::vector<std::string>
QKDApp004::ReadUri(std::string s)
{
  NS_LOG_FUNCTION(this << s );

  std::string delimiter {"/"}, token;
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


} // Namespace ns3

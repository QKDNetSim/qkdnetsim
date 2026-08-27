/*
 * Copyright(c) 2024 DOTFEESA www.tk.etf.unsa.ba
 * 
 *
 * Author:  Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 *          Miralem Mehic <miralem.mehic@ieee.org>
 */

#include "ns3/log.h"
#include "ns3/qcen-control.h"
#include "ns3/address.h"
#include "ns3/node.h"
#include "ns3/nstime.h"
#include "ns3/socket.h"
#include "ns3/simulator.h"
#include "ns3/tcp-socket-factory.h"
#include "ns3/packet.h"
#include "ns3/uinteger.h"
#include "ns3/trace-source-accessor.h"
#include "http.h"
#include "json.h"
#include <iostream>
#include <fstream>
#include <string>

#include "qkd-key-manager-system-application.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("QKDKeyManagerSystemApplication");

NS_OBJECT_ENSURE_REGISTERED(QKDKeyManagerSystemApplication);

TypeId
QKDKeyManagerSystemApplication::GetTypeId()
{
  static TypeId tid = TypeId("ns3::QKDKeyManagerSystemApplication")
    .SetParent<Application>()
    .SetGroupName("Applications")
    .AddConstructor<QKDKeyManagerSystemApplication>()
    .AddAttribute("Protocol", "The type of protocol to use.",
                   TypeIdValue(TcpSocketFactory::GetTypeId()),
                   MakeTypeIdAccessor(&QKDKeyManagerSystemApplication::m_tid),
                   MakeTypeIdChecker())
    .AddAttribute("LocalAddress", "The ipv4 address of the application",
                   Ipv4AddressValue(),
                   MakeIpv4AddressAccessor(&QKDKeyManagerSystemApplication::m_local),
                   MakeIpv4AddressChecker())
    .AddAttribute("MaximalKeysPerRequest",
                   "The maximal number of keys per request(ESTI QKD 014)",
                   UintegerValue(20),
                   MakeUintegerAccessor(&QKDKeyManagerSystemApplication::m_maxKeyPerRequest),
                   MakeUintegerChecker<uint32_t>())
    .AddAttribute("MinimalKeySize",
                   "The minimal size of key QKDApp can request",
                   UintegerValue(32), //in bits
                   MakeUintegerAccessor(&QKDKeyManagerSystemApplication::m_minKeySize),
                   MakeUintegerChecker<uint32_t>())
    .AddAttribute("MaximalKeySize",
                   "The maximal size of key QKDApp can request",
                   UintegerValue(10240), //in bits
                   MakeUintegerAccessor(&QKDKeyManagerSystemApplication::m_maxKeySize),
                   MakeUintegerChecker<uint32_t>())  
    .AddAttribute("BufferList", "The list of Qbuffers needed for plotting QKDGraphs.",
                   ObjectVectorValue(),
                   MakeObjectVectorAccessor(&QKDKeyManagerSystemApplication::m_qbuffersVector),
                   MakeObjectVectorChecker<QKDGraph>()) 

    .AddAttribute("pqc_enabled",
                   "Is PQC Eenabled?",
                   UintegerValue(0),
                   MakeUintegerAccessor(&QKDKeyManagerSystemApplication::m_pqc_enabled),
                   MakeUintegerChecker<uint32_t>()) 
    .AddAttribute("pqc_default_number_of_keys",
                   "The default number of PQC keys to establish between KMSs",
                   UintegerValue(10),
                   MakeUintegerAccessor(&QKDKeyManagerSystemApplication::m_pqc_default_number_of_keys),
                   MakeUintegerChecker<uint32_t>()) 
    .AddAttribute("pqc_c", "pqc_c",
                    DoubleValue(10),
                    MakeDoubleAccessor(&QKDKeyManagerSystemApplication::m_pqc_c),
                    MakeDoubleChecker<double>(0.0)) 

    .AddTraceSource("Tx", "A new packet is created and is sent to the APP",
                   MakeTraceSourceAccessor(&QKDKeyManagerSystemApplication::m_txTrace),
                   "ns3::QKDKeyManagerSystemApplication::Tx")
    .AddTraceSource("Rx", "A packet from the APP has been received",
                   MakeTraceSourceAccessor(&QKDKeyManagerSystemApplication::m_rxTrace),
                   "ns3::QKDKeyManagerSystemApplication::Rx")
    .AddTraceSource("TxKMSs", "A new packet is created and is sent to the KMS",
                   MakeTraceSourceAccessor(&QKDKeyManagerSystemApplication::m_txTraceKMSs),
                   "ns3::QKDKeyManagerSystemApplication::TxKMSs")
    .AddTraceSource("RxKMSs", "A packet from the APP has been received",
                   MakeTraceSourceAccessor(&QKDKeyManagerSystemApplication::m_rxTraceKMSs),
                   "ns3::QKDKeyManagerSystemApplication::RxKMSs")
    .AddTraceSource("QKDKeyGenerated", "The trace to monitor key material received from QL",
                     MakeTraceSourceAccessor(&QKDKeyManagerSystemApplication::m_qkdKeyGeneratedTrace),
                     "ns3::QKDKeyManagerSystemApplication::QKDKeyGenerated")
    .AddTraceSource("KeyServed", "The trece to monitor E2E key usage",
                     MakeTraceSourceAccessor(&QKDKeyManagerSystemApplication::m_keyServedTrace),
                     "ns3::QKDKeyManagerSystemApplication::KeyServed")
    .AddTraceSource("KeyServedMixed", "The trece to monitor E2E key usage",
                     MakeTraceSourceAccessor(&QKDKeyManagerSystemApplication::m_keyServedTraceMixed),
                     "ns3::QKDKeyManagerSystemApplication::KeyServedMixed")
    .AddTraceSource("KeyConsumedLink", "The trece to monitor P2P key usage",
                     MakeTraceSourceAccessor(&QKDKeyManagerSystemApplication::m_keyConsumedLink),
                     "ns3::QKDKeyManagerSystemApplication::KeyConsumedLink")
    .AddTraceSource("RelayConsumption", "The trace to monitor key material consumed for key relay",
                     MakeTraceSourceAccessor(&QKDKeyManagerSystemApplication::m_keyConsumedRelay),
                     "ns3::QKDKeyManagerSystemApplication::RelayConsumption") 
    .AddTraceSource("WasteRelay", "The trace to monitor failed relays",
                     MakeTraceSourceAccessor(&QKDKeyManagerSystemApplication::m_keyWasteRelay),
                     "ns3::QKDKeyManagerSystemApplication::WasteRelay")
    .AddTraceSource("KSIDUpdated", "The trace generated ETSI 004 KSIDs",
                     MakeTraceSourceAccessor(&QKDKeyManagerSystemApplication::m_ksidGenerated),
                     "ns3::QKDKeyManagerSystemApplication::Etsi004KSIDGenerated")

  ;
  return tid;
}

QKDKeyManagerSystemApplication::QKDKeyManagerSystemApplication()
{
  NS_LOG_FUNCTION(this);
  m_totalRx = 0;
  m_kms_key_id = 0;
  m_encryptor = CreateObject<QKDEncryptor>(64); //64 bits long key IDs. Collisions->0
  //m_queueLogic = CreateObject<QKDKMSQueueLogic>();
}

QKDKeyManagerSystemApplication::~QKDKeyManagerSystemApplication()
{
  NS_LOG_FUNCTION(this);
}


uint32_t
QKDKeyManagerSystemApplication::GetTotalRx() const
{
  NS_LOG_FUNCTION(this);
  return m_totalRx;
}

std::string
QKDKeyManagerSystemApplication::GetAddressString(Ipv4Address address)
{
  NS_LOG_FUNCTION(this);
  std::ostringstream srcKmsAddressTemp;
  address.Print(srcKmsAddressTemp); //IPv4Address to string
  return srcKmsAddressTemp.str();
}

void
QKDKeyManagerSystemApplication::SetController(Ptr<QKDControl> controller)
{
  NS_LOG_FUNCTION(this);
  m_controller = controller;
  GetController()->AssignKeyManager( GetNode() );
}

void
QKDKeyManagerSystemApplication::SetCenController(Ptr<QCenController> controller)
{
  NS_LOG_FUNCTION(this);
  m_cen_controller = controller;
}

Ptr<QCenController>
QKDKeyManagerSystemApplication::GetCenController()
{
  NS_LOG_FUNCTION(this);
  return m_cen_controller;
}

void
QKDKeyManagerSystemApplication::UpdateLinkState(uint32_t dstKmNodeId) //Should always be for point-to-point links! Is it enough to check on fill?(do not cosider state of S-Buffer)
{
  NS_LOG_FUNCTION(this << GetNode()->GetId() << dstKmNodeId);
  if(!GetCenController())
  {
    NS_LOG_FUNCTION(this << "Do nothing since centralized controller is not set!");
    return; //Do nothing since centralized controller is not set!
  } 

  Ptr<QBuffer> qBuffer {GetQBuffer(dstKmNodeId)};
  NS_ASSERT(qBuffer);

  Ptr<SBuffer> sBuffer {GetSBuffer(dstKmNodeId, "enc")};
  NS_ASSERT(sBuffer);

  auto it = m_link_states.find(dstKmNodeId);
  if(it == m_link_states.end()) NS_FATAL_ERROR(this << "Link not found!");
  if(it->second != 3 && qBuffer->GetState() == 3){// && sBuffer->GetSBitCount() < sBuffer->GetMthr()){
    NS_LOG_FUNCTION(this << "Link going down.");
    //std::cout << "\nLink going DOWN: " << GetNode()->GetId() << "--" << dstKmNodeId << "at time -- " << Simulator::Now() << std::endl;
    GetCenController()->LinkDown(GetNode()->GetId(),dstKmNodeId);
    it->second = 3;
  }else if(it->second == 3 && qBuffer->GetBitCount() > qBuffer->GetMthr() && sBuffer->GetSBitCount() > sBuffer->GetMthr()){//qBuffer->GetState() != 3){// && sBuffer->GetSBitCount() > sBuffer->GetMthr()){
    NS_LOG_FUNCTION(this << "Link going up.");
    //std::cout << "\nLink going UP: " << GetNode()->GetId() << "--" << dstKmNodeId << "at time -- " << Simulator::Now() << std::endl;
    GetCenController()->LinkUp(GetNode()->GetId(),dstKmNodeId);
    it->second = 0;
  }

}

std::vector<Ipv4Address> 
QKDKeyManagerSystemApplication::GetAddresses()
{ 
  std::vector<Ipv4Address> addresses;
  Ptr<Node> node = GetNode ();  // from Application
  Ptr<Ipv4> ipv4 = node->GetObject<Ipv4> ();

  for (uint32_t i = 0; i < ipv4->GetNInterfaces (); ++i)
  {
      for (uint32_t j = 0; j < ipv4->GetNAddresses (i); ++j)
      {
          Ipv4InterfaceAddress ifAddr = ipv4->GetAddress (i, j);
          Ipv4Address addr = ifAddr.GetLocal ();

          // Optional: skip loopback
          if (addr != Ipv4Address::GetLoopback ())
          {
            NS_LOG_FUNCTION(this << node->GetId() << " - My address " << addr );
              addresses.push_back(addr);
          }
      }
  }
  return addresses;
}

Ptr<QKDControl>
QKDKeyManagerSystemApplication::GetController()
{
    NS_LOG_FUNCTION(this);
    return m_controller;
}

void
QKDKeyManagerSystemApplication::SetPeerKmAddress(uint32_t dstKmNodeId, Ipv4Address dstKmAddress)
{
  NS_LOG_FUNCTION(this << dstKmNodeId << dstKmAddress);
  m_peerAddressTable.insert(std::make_pair(dstKmNodeId, dstKmAddress));
}

Ipv4Address
QKDKeyManagerSystemApplication::GetPeerKmAddress(uint32_t dstKmNodeId)
{
  NS_LOG_FUNCTION(this << dstKmNodeId);
  /*
  Ipv4Address address;
  auto it = m_peerAddressTable.find(dstKmNodeId);
  if(it!=m_peerAddressTable.end())
    address = it->second;
  else
    NS_LOG_ERROR(this << "Entry not found");

  return address;
  */
 
  QKDLocationRegisterEntry conn = GetController()->GetRoute(dstKmNodeId);
  return conn.GetDestinationKmsAddress();
}


uint32_t
QKDKeyManagerSystemApplication::GetPeerKmNodeId(Ipv4Address dstKmAddress)
{
  NS_LOG_FUNCTION(this << dstKmAddress); 
  /*
  for(auto it = m_peerAddressTable.begin(); it != m_peerAddressTable.end(); ++it) 
  {
    if(it->second == dstKmAddress)
      return it->first;
  }
  NS_LOG_ERROR(this << "Entry not found");
  return 0;
  */
  QKDLocationRegisterEntry conn = GetController()->GetRouteByKMSAddress(dstKmAddress);
  return conn.GetDestinationKmNodeId();

}

void
QKDKeyManagerSystemApplication::CreateQBuffer(
  uint32_t dstId,
  Ptr<QBuffer> bufferConf
)
{
  NS_LOG_FUNCTION(this << dstId);
  //Create Q-Buffer
  Ptr<QBuffer> buffer = CreateObject<QBuffer>();
  buffer->Init(
    dstId,
    bufferConf->GetMmin(),
    bufferConf->GetMthr(),
    bufferConf->GetMmax(),
    bufferConf->GetBitCount(),
    bufferConf->GetKeySize()
  );

  buffer->SetIndex( m_qbuffersVector.size() );
  m_qbuffers.insert(std::make_pair(dstId, buffer) );
  m_qbuffersVector.push_back(buffer);

  NS_LOG_FUNCTION(this << "NEW QBUFFER created on KMS " << GetNode()->GetId() << "  with index " << buffer->GetIndex() << " - " << m_qbuffersVector.size() );;

  m_link_states.insert(std::make_pair(dstId, 3));
  //Create S-Buffers for this Q-Buffer

  Ptr<SBuffer> SBufferEnc = CreateObject<SBuffer>();
  SBufferEnc->SetRemoteNodeId(dstId);
  SBufferEnc->Initialize(); 
  SBufferEnc->SetDescription ("-Encryption");
  m_keys_enc.insert(std::make_pair(dstId, SBufferEnc));
  SBufferEnc->SetIndex( m_qbuffersVector.size() ); 
  m_qbuffersVector.push_back(SBufferEnc);
  m_qbuffers.insert(std::make_pair(dstId, buffer) );
  NS_LOG_FUNCTION(this << "NEW SBUFFER:ENC created on KMS " << GetNode()->GetId() << "  with index " << SBufferEnc->GetIndex() << " - " << m_qbuffersVector.size() );;

  Ptr<SBuffer> SBufferDec = CreateObject<SBuffer>(); 
  SBufferDec->SetRemoteNodeId(dstId);
  SBufferDec->Initialize();
  SBufferDec->SetDescription ("-Decryption");
  m_keys_dec.insert(std::make_pair(dstId, SBufferDec));
  SBufferDec->SetIndex( m_qbuffersVector.size() );
  m_qbuffersVector.push_back(SBufferDec);
  m_qbuffers.insert(std::make_pair(dstId, buffer) );
  NS_LOG_FUNCTION(this << "NEW SBUFFER:DNC created on KMS " << GetNode()->GetId() << "  with index " << SBufferDec->GetIndex() << " - " << m_qbuffersVector.size() );;
 
  StartSBufferClients(dstId);
}

void
QKDKeyManagerSystemApplication::StartSBufferClients(uint32_t dstKmNodeId)
{
  NS_LOG_FUNCTION(this << dstKmNodeId);

  //First initialize S-buffers(symmetric enc and dec capacities)
  auto it = m_keys_enc.find(dstKmNodeId);
  if(it!=m_keys_enc.end())
  {
    it->second->Initialize();
    it->second->SetRemoteNodeId(dstKmNodeId);
    it->second->SetKeySize(
        GetQBuffer(dstKmNodeId)->GetKeySize() //Not USED, nor important!
    );
    it->second->SetType(SBuffer::Type::LOCAL_SBUFFER);
  }else
    NS_LOG_FUNCTION(this << "Unexpected error: s-buffer(enc) not found!");

  auto it1 = m_keys_dec.find(dstKmNodeId);
  if(it1!=m_keys_dec.end())
  {
    it1->second->Initialize();
    it1->second->SetRemoteNodeId(dstKmNodeId);
    it1->second->SetKeySize(
        GetQBuffer(dstKmNodeId)->GetKeySize() //Not USED, nor important!
    );
    it1->second->SetType(SBuffer::Type::LOCAL_SBUFFER);
  }else
    NS_LOG_FUNCTION(this << "Unexpected error: s-buffer(dec) not found!");

  //Only primary KM node decides to FILL the S-Buffers if possible
  if(GetNode()->GetId() < dstKmNodeId)
    SBufferClientCheck(dstKmNodeId);
}

void
QKDKeyManagerSystemApplication::SBufferClientCheck(uint32_t dstKmNodeId)
{
  NS_LOG_FUNCTION(this << dstKmNodeId);

  //Differentiate LOCAL_SBUFFER and RELAY_SBUFFER
  auto ie = m_keys_enc.find(dstKmNodeId); //Fetch s-buffer
  NS_ASSERT(ie != m_keys_enc.end());

  //LOCAL_SBUFFER, Fill from Q-Buffer
  if(ie->second->GetType() == SBuffer::Type::LOCAL_SBUFFER)
  {
    NS_LOG_FUNCTION(this << "Checking SBuffer::Type::LOCAL_SBUFFER");

    //Check also the dec buffer for LOCAL_SBUFFER type
    auto id = m_keys_dec.find(dstKmNodeId);
    NS_ASSERT(id != m_keys_dec.end());

    //Check buffers states
    uint32_t encState = ie->second->GetState();
    NS_LOG_FUNCTION(this << "LOCAL_SBUFFER::State::Enc" << encState << ie->second->GetBitCount() ); //testing

    uint32_t decState = id->second->GetState();
    NS_LOG_FUNCTION(this << "LOCAL_SBUFFER::State::Dec" << decState << id->second->GetBitCount() ); //testing

    //If Q-Buffer is EMPTY then we cannot fill S-Buffers!
    if(GetQBuffer(dstKmNodeId)->GetState() == 3)
    {
      NS_LOG_FUNCTION(this << "QBuffer is EMPTY! Exiting!");
      UpdateLinkState(dstKmNodeId);
      return; //Force exit from function!
    }

    NS_LOG_FUNCTION(this 
      << "\n BitCount: " << ie->second->GetBitCount() 
      << "\n SBitCount: " << ie->second->GetSBitCount() 
      << "\n Max: " << ie->second->GetMmax() 
    );

    if(
      ie->second->GetBitCount() >= ie->second->GetMmax() &&
      id->second->GetBitCount() >= id->second->GetMmax()
    ){
      //This should never happen! But, still, we check once again!
      NS_LOG_FUNCTION(this << "SBuffers are full! No need for fill!");
      return;
    }

    //Amount of keys available at Q-buffer
    Ptr<QBuffer> qBuffer = GetQBuffer(dstKmNodeId);
    uint32_t qBufferBits = qBuffer->GetBitCount() - qBuffer->GetMmin();
    uint32_t encDemand = ie->second->GetMmax() - ie->second->GetBitCount();
    uint32_t decDemand = id->second->GetMmax() - id->second->GetBitCount();
    if(encState && decState)
    { 
      NS_LOG_FUNCTION(this << "Both enc and dec s-buffers require charging (states != READY)" << encState << decState << qBufferBits);
      double decreaseProcentage = 0.05;
      while(encDemand + decDemand > qBufferBits)
      {
        encDemand -= encDemand*decreaseProcentage;
        decDemand -= decDemand*decreaseProcentage;
      }
      Fill(dstKmNodeId, "enc", encDemand, qBuffer);
      Fill(dstKmNodeId, "dec", decDemand, qBuffer);

    }else if(encState){

      NS_LOG_FUNCTION(this << "Assign all available key material from q-buffer -> ENC!");
      if(encDemand > qBufferBits)
        encDemand = qBufferBits; 
      Fill(dstKmNodeId, "enc", encDemand, qBuffer);

    }else if(decState){

      NS_LOG_FUNCTION(this << "Assign all available key material from q-buffer -> DEC!");
      if(decDemand > qBufferBits)
        decDemand = qBufferBits;
      Fill(dstKmNodeId, "dec", decDemand, qBuffer);

    }else{
      NS_LOG_FUNCTION(this << "LOCAL_SBUFFER(s)" << dstKmNodeId << "are in READY state!");
    }

  //RELAY_SBUFFER
  }else if(ie->second->GetType() == SBuffer::Type::RELAY_SBUFFER){ 

    NS_LOG_FUNCTION(this << "Checking SBuffer::Type::RELAY_SBUFFER");

    uint32_t encState = ie->second->GetState(); //Check s-buffer state
    NS_LOG_FUNCTION(this << "RELAY_SBUFFER::State" << encState); //testing

    if(encState)
    { 
      //Triger relay to fill
      QKDLocationRegisterEntry conn = GetController()->GetRoute(dstKmNodeId); //Get route information
      uint32_t nextHop = conn.GetNextHop(); //Identify LOCAL_SBUFFER accessed for relay purposes
      uint32_t encDemand = ie->second->GetMmax() - ie->second->GetBitCount(); //This is desired amount to relay!

      NS_LOG_FUNCTION(this << "33333:" << nextHop << encDemand);

      Ptr<SBuffer> sBuffer = GetSBuffer(nextHop, "enc");  //@todo id1125
      NS_ASSERT(sBuffer);
      uint32_t nextHopKeyCount = sBuffer->GetSKeyCount();
      uint32_t nextHopMmax = sBuffer->GetMmax();
      uint32_t sBufferBits = sBuffer->GetDefaultKeyCount()*sBuffer->GetKeySize(); //Available amount of key material in LOCAL_SBUFFER
      NS_LOG_FUNCTION(this << sBuffer << " How many keys in nextHop S-Buffer" << nextHopKeyCount
                           << "\nHot many bits in nextHop S-Buffer" << sBufferBits
                           << "\nnextHop SBuffer Max:" << nextHopMmax
                     );

      Ptr<SBuffer> sBufferDst = GetSBuffer(dstKmNodeId, "enc");  //@todo id1125
      NS_ASSERT(sBufferDst);
      uint32_t dstKeyCount = sBufferDst->GetSKeyCount();
      uint32_t dstMmax = sBufferDst->GetMmax();
      uint32_t dstSBufferBits = sBufferDst->GetDefaultKeyCount()*sBufferDst->GetKeySize(); //Available amount of key material in LOCAL_SBUFFER
      NS_LOG_FUNCTION(this << sBufferDst << " How many keys in dst S-Buffer" << dstKeyCount
                           << "\nHot many bits in dst S-Buffer" << dstSBufferBits
                           << "\ndst SBuffer Max:" << dstMmax
                     );

      if(20*ie->second->GetKeySize() < encDemand)
          encDemand = 20*ie->second->GetKeySize(); //No more than 20 keys!!!(@toDo failed relay should decrease this value, and succesfull relay should increse it till 20)

      if(encDemand > sBufferBits)
          encDemand = sBufferBits; //Assign all available key material from q-buffer

      if(!encDemand)
      {
        NS_LOG_FUNCTION(this << "We do not have enoguh keys on P2P QKD link to the nextHop. We cannot proceed with relay nor fill!");
        return;
      }

      NS_LOG_FUNCTION(this << "encDemand:" << encDemand << "KeySize: " << ie->second->GetKeySize() << "sBufferBits:" << sBufferBits);

      Ptr<SBuffer> relayBuffer = GetSBuffer(dstKmNodeId, "enc");
      NS_ASSERT(relayBuffer);

      //this is master KMS 
      //if not master, the relay request will trigger check
      //if buffer is not READY, we start RELAY procedure
      if( 
        //GetNode()->GetId() > dstKmNodeId && 
        relayBuffer->GetState() > 0
      )
        Relay(dstKmNodeId, encDemand); 
 
    }else
      NS_LOG_FUNCTION(this << "RELAY_SBUFFER" << dstKmNodeId << "is in READY state!");

  }
}


Ptr<SBuffer>
QKDKeyManagerSystemApplication::GetSBuffer(uint32_t dstKmNodeId, std::string type)
{
  NS_LOG_FUNCTION(this << dstKmNodeId << type );
  if(type == "enc"){
    NS_LOG_FUNCTION(this << "m_keys_enc.size():" << m_keys_enc.size());
    auto it = m_keys_enc.find(dstKmNodeId);
    if(it != m_keys_enc.end())
      return it->second;
  }else if(type == "dec"){
    NS_LOG_FUNCTION(this << "m_keys_dec.size():" << m_keys_dec.size());
    auto it = m_keys_dec.find(dstKmNodeId);
    if(it != m_keys_dec.end())
      return it->second;
  }else if(type == "pqc"){
    NS_LOG_FUNCTION(this << "m_keys_pqc.size():" << m_keys_pqc.size());
    auto it = m_keys_pqc.find(dstKmNodeId);
    if(it != m_keys_pqc.end())
      return it->second;
  }else
    NS_LOG_FUNCTION(this << "unknown type" << type);

  NS_LOG_FUNCTION(this << "We are unable to find SBuffer for destination: " << dstKmNodeId << type );
  return NULL;
}

void
QKDKeyManagerSystemApplication::RegisterQKDModule(
  uint32_t dstId,
  std::string moduleId
)
{
  NS_LOG_FUNCTION(this << dstId << moduleId);
  m_qkdmodules.insert(std::make_pair(moduleId, dstId) );
}

Ptr<QBuffer>
QKDKeyManagerSystemApplication::GetQBuffer(uint32_t remoteKmNodeId, std::string type)
{
  NS_LOG_FUNCTION(this << remoteKmNodeId);
 
  for (auto it = m_qbuffers.begin(); it != m_qbuffers.end(); ++it) 
  {
    Ptr<QBuffer> qbuffer = it->second; 
    if(it->first == remoteKmNodeId && qbuffer->GetInstanceTypeId().GetName() == type)
    {
      return qbuffer;
    }
  }
  NS_FATAL_ERROR(this << " QBuffer not found!"); 

  return nullptr;
}

/**
 * ********************************************************************************************
 *        SOCKET functions
 * ********************************************************************************************
 */

Ptr<Socket>
QKDKeyManagerSystemApplication::GetSocket() const
{
  NS_LOG_FUNCTION(this);
  return m_sinkSocket;
}

void
QKDKeyManagerSystemApplication::SetSocket(std::string type, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << type << socket);
  m_sinkSocket = socket;
}

void
QKDKeyManagerSystemApplication::DoDispose()
{
  NS_LOG_FUNCTION(this);
  if(m_sinkSocket) {
    //m_sinkSocket->Close();
    m_sinkSocket = nullptr;
  }

  std::map<Ipv4Address, KMSNode>::iterator it;
  for( it = m_socketPairsKMS.begin(); !(it == m_socketPairsKMS.end());  it++ ){
    if(it->second.socket) {
      //it->second.first->Close();
      it->second.socket = nullptr;
    } 
  }
  Application::DoDispose();
}

void
QKDKeyManagerSystemApplication::HandleAccept(Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION(this << s << from << InetSocketAddress::ConvertFrom(from).GetIpv4());
  s->SetRecvCallback(MakeCallback(&QKDKeyManagerSystemApplication::HandleRead, this));
}

void
QKDKeyManagerSystemApplication::HandleAcceptKMSs(Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION(this
    << s
    << from
    << InetSocketAddress::ConvertFrom(from).GetIpv4()
    << InetSocketAddress::ConvertFrom(from).GetPort()
  );

  s->SetRecvCallback(MakeCallback(&QKDKeyManagerSystemApplication::HandleReadKMSs, this));

  //Check is it necessary to create response socket
  Ipv4Address destKMS = InetSocketAddress::ConvertFrom(from).GetIpv4();
  auto it = m_socketPairsKMS.find(destKMS);
  if( it != m_socketPairsKMS.end() )
  {
      it->second.socket = s; //Set receiving socket
      it->second.pqcStarted = 0; //Set receiving socket
  }else{ 
    KMSNode val;
    val.socket = s;
    val.address = destKMS;
    val.pqcStarted = 0;
    m_socketPairsKMS.insert(
      std::make_pair(
        destKMS,
        val
      )
    );
  }
  CheckSocketsKMS(destKMS);
}



void
QKDKeyManagerSystemApplication::ConnectionSucceeded(Ptr<Socket> socket)
{
    NS_LOG_FUNCTION(this << socket);
    NS_LOG_FUNCTION(this << "QKDKeyManagerSystemApplication Connection succeeded");

    std::map<Ptr<Socket>, Ptr<Packet> >::iterator j;
    for(j = m_packetQueues.begin(); !(j == m_packetQueues.end()); j++){
      if(j->first == socket){
        uint32_t response = j->first->Send(j->second);
        response = j->first->Send(j->second);
        m_txTrace(j->second);
        m_packetQueues.erase(j);
        NS_LOG_FUNCTION(this << j->first << "Sending packet from the queue!" << response );
      }
    }
}

void
QKDKeyManagerSystemApplication::ConnectionSucceededKMSs(Ptr<Socket> socket)
{
    NS_LOG_FUNCTION(this << socket);
    NS_LOG_FUNCTION(this << "QKDKeyManagerSystemApplication KMSs Connection succeeded");

    std::map<Ptr<Socket>, Ptr<Packet> >::iterator j;
    for(j = m_packetQueuesKMS.begin(); !(j == m_packetQueuesKMS.end()); j++){
      if(j->first == socket){
        uint32_t response = j->first->Send(j->second);
        response = j->first->Send(j->second); 
        m_txTraceKMSs(j->second, GetNode()->GetId());
        m_packetQueuesKMS.erase(j);
        NS_LOG_FUNCTION(this << j->first << "Sending packet from the queue!" << response );
      }
    }

    if(m_pqc_enabled)      
      SendPQCPublicKey(socket);
}

void
QKDKeyManagerSystemApplication::ConnectionFailed(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);
  NS_LOG_FUNCTION(this << "QKDKeyManagerSystemApplication, Connection Failed");
}

void
QKDKeyManagerSystemApplication::ConnectionFailedKMSs(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);
  NS_LOG_FUNCTION(this << "QKDKeyManagerSystemApplication, Connection Failed");
}

void
QKDKeyManagerSystemApplication::DataSend(Ptr<Socket> s, uint32_t par)
{
    NS_LOG_FUNCTION(this << s << par );
}

void
QKDKeyManagerSystemApplication::DataSendKMSs(Ptr<Socket> s , uint32_t par)
{
    NS_LOG_FUNCTION(this << s << par);
}

void
QKDKeyManagerSystemApplication::HandlePeerClose(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);
}

void
QKDKeyManagerSystemApplication::HandlePeerCloseKMSs(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);
}

void
QKDKeyManagerSystemApplication::HandlePeerError(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);
}

void
QKDKeyManagerSystemApplication::HandlePeerErrorKMSs(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);
}

void
QKDKeyManagerSystemApplication::SendToSocketPair(Ptr<Socket> socket, Ptr<Packet> packet)
{
  NS_LOG_FUNCTION( this << socket);

  //check if socket is connected
  //https://www.nsnam.org/doxygen/classns3_1_1_socket.html#a78a3c37a539d2e70869bb82cc60fbb09
  Address connectedAddress;

  //send the packet only if connected!
  if(socket->GetPeerName(connectedAddress) == 0){
    socket->Send(packet);
    m_txTrace(packet);
    NS_LOG_FUNCTION(this << "Packet " << packet->GetUid() << " sent via socket " << socket);
  //otherwise wait in the queue
  }else{
    m_packetQueues.insert( std::make_pair(  socket ,  packet) );
    NS_LOG_FUNCTION(this << "Packet " << packet->GetUid() << " enqued for socket " << socket);
  }
}

void
QKDKeyManagerSystemApplication::SendToSocketPairKMS(Ptr<Socket> socket, Ptr<Packet> packet)
{
    NS_LOG_FUNCTION( this << socket );
    //check if socket is connected
    //https://www.nsnam.org/doxygen/classns3_1_1_socket.html#a78a3c37a539d2e70869bb82cc60fbb09
    Address connectedAddress;

    //send the packet only if connected!
    if(socket->GetPeerName(connectedAddress) == 0){
      socket->Send(packet); 
      m_txTraceKMSs(packet, GetNode()->GetId());
      NS_LOG_FUNCTION(this << "Packet " << packet->GetUid() << " sent via socket " << socket);
    //otherwise wait in the queue
    }else{
      m_packetQueuesKMS.insert( std::make_pair(  socket ,  packet) );
      NS_LOG_FUNCTION(this << "Packet " << packet->GetUid() << " enqued for socket " << socket);
    }
}

void
QKDKeyManagerSystemApplication::CheckSocketsKMS(Ipv4Address kmsDstAddress)
{
  NS_LOG_FUNCTION( this << kmsDstAddress );
  //Local KMS should create socket to send data to peer KMS
  //Local KMS should check if the socket for this connection already exists?
  //Local KMS can have connections to multiple KMS systems - neighbor and distant KMSs
  auto i = m_socketPairsKMS.find( kmsDstAddress );
  if(i == m_socketPairsKMS.end() )
  { 
    NS_LOG_FUNCTION( this << "No connection between KMS defined!"); //@toDo: include HTTP response! 
    KMSNode val;
    val.socket = nullptr;
    val.address = kmsDstAddress;
    val.pqcStarted = 0;
    m_socketPairsKMS.insert(
      std::make_pair(
        kmsDstAddress,
        val
      )
    );
    CheckSocketsKMS(kmsDstAddress);
    return;

  }else if(!i->second.socket)
  {
    NS_LOG_FUNCTION(this << "Let's create a new TCP socket to reach KMS!" << kmsDstAddress);

    Ptr<Socket> socket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId() );
    //disable Nagle’s algorithm
    socket->SetAttribute("TcpNoDelay", BooleanValue(true));
    socket->SetConnectCallback(
      MakeCallback(&QKDKeyManagerSystemApplication::ConnectionSucceededKMSs, this),
      MakeCallback(&QKDKeyManagerSystemApplication::ConnectionFailedKMSs, this));
    socket->SetDataSentCallback( MakeCallback(&QKDKeyManagerSystemApplication::DataSendKMSs, this));
    socket->SetRecvCallback(MakeCallback(&QKDKeyManagerSystemApplication::HandleReadKMSs, this));
    socket->SetAcceptCallback(
      MakeNullCallback<bool, Ptr<Socket>, const Address &>(),
      MakeCallback(&QKDKeyManagerSystemApplication::HandleAcceptKMSs, this)
    );
    socket->SetCloseCallbacks(
      MakeCallback(&QKDKeyManagerSystemApplication::HandlePeerCloseKMSs, this),
      MakeCallback(&QKDKeyManagerSystemApplication::HandlePeerErrorKMSs, this)
    ); 
    InetSocketAddress peerAddress = InetSocketAddress(
      kmsDstAddress,
      8080
    );
    socket->Bind();
    socket->Connect( peerAddress );

    //update socket pair entry
    i->second.socket = socket; 

    NS_LOG_FUNCTION(this
      << "Create the send socket " << socket
      << " from KMS to KMS which is on " << kmsDstAddress
    );

  }else{
    NS_LOG_FUNCTION(this << "Socket to peer KMS exist. No action required"); 
  }
}

Ptr<Socket>
QKDKeyManagerSystemApplication::GetSocketKMS(Ipv4Address kmsDstAddress)
{
  NS_LOG_FUNCTION( this << kmsDstAddress );
  //Local KMS should create socket to send data to peer KMS
  //Local KMS should check if the socket for this connection already exists?
  //Local KMS can have connections to multiple KMS systems - neighbor and distant KMSs
  auto i = m_socketPairsKMS.find( kmsDstAddress );

  if(i == m_socketPairsKMS.end())
  {
    NS_FATAL_ERROR( this << "No connection between KMS defined!"); //@toDo: include HTTP response!
    return NULL;
  } else {
    KMSNode pair = i->second; 
    Ptr<Socket> socket = pair.socket;
    NS_ASSERT(socket);
    return socket;
  }
}


void
QKDKeyManagerSystemApplication::HandleRead(Ptr<Socket> socket)
{

  NS_LOG_FUNCTION(this << socket);

  Ptr<Packet> packet;
  Address from;
  while((packet = socket->RecvFrom(from)))
  {
      if(packet->GetSize() == 0)
      { //EOF
        break;
      }

      m_totalRx += packet->GetSize();
      NS_LOG_FUNCTION(this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() );

      if(InetSocketAddress::IsMatchingType(from))
      {
          NS_LOG_FUNCTION(this << "At time " << Simulator::Now().GetSeconds()
                   << "s KMS received packet ID: "
                   <<  packet->GetUid() << " of "
                   <<  packet->GetSize() << " bytes from "
                   << InetSocketAddress::ConvertFrom(from).GetIpv4()
                   << " port " << InetSocketAddress::ConvertFrom(from).GetPort()
                   << " total Rx " << m_totalRx << " bytes");
      }

      m_rxTrace(packet, from);
      PacketReceived(packet, from, socket);
  }
}

void
QKDKeyManagerSystemApplication::HandleReadKMSs(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << socket);

  Ptr<Packet> packet;
  Address from;
  while((packet = socket->RecvFrom(from)))
  {
      if(packet->GetSize() == 0)
      { //EOF
        break;
      }

      m_totalRxKMSs += packet->GetSize();
      NS_LOG_FUNCTION(this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() );

      if(InetSocketAddress::IsMatchingType(from))
      {
          NS_LOG_FUNCTION(this << "At time " << Simulator::Now().GetSeconds()
                   << "s KMS received packet ID: "
                   <<  packet->GetUid() << " of "
                   <<  packet->GetSize() << " bytes from KMS "
                   <<  InetSocketAddress::ConvertFrom(from).GetIpv4()
                   << " port " << InetSocketAddress::ConvertFrom(from).GetPort()
                   << " total Rx " << m_totalRx << " bytes");
      }

      m_rxTraceKMSs( packet, InetSocketAddress::ConvertFrom(from).GetIpv4(), GetNode()->GetId() );
      PacketReceivedKMSs(packet, from, socket);
  }
}

 
void
QKDKeyManagerSystemApplication::PacketReceived(const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << p->GetUid() << p->GetSize() << from);

  // Buffer management per sender
  Ptr<Packet> &buffer = m_buffer[from];
  if (!buffer) buffer = Create<Packet>(0);

  buffer->AddAtEnd(p);
  NS_LOG_DEBUG("[DEBUG] Buffer after appending packet UID " << p->GetUid() << ": " << buffer->GetSize() << " bytes");

  // Parse the HTTP message
  HTTPMessageParser parser;

  while (buffer->GetSize() > 0) {
    // Copy raw buffer data into a string
    std::string bufferStr(buffer->GetSize(), '\0');
    buffer->CopyData(reinterpret_cast<uint8_t*>(&bufferStr[0]), bufferStr.size());

    // Try to extract exactly one full HTTP message
    std::string singleMessage;
    size_t messageSize = 0;
    if (!parser.TryExtractHttpMessage(bufferStr, singleMessage, messageSize)) {
      NS_LOG_DEBUG("[DEBUG] HTTP message is incomplete or fragmented, waiting for more data...");
      break;
    }

    HTTPMessage request;
    parser.Parse(&request, singleMessage);

    NS_LOG_DEBUG("[DEBUG] Parsed HTTP message:\n" << request.ToString());
    NS_LOG_DEBUG("[DEBUG] Total HTTP message size: " << messageSize);

    // Slice the packet and remove from buffer
    Ptr<Packet> completePacket = buffer->CreateFragment(0, static_cast<uint32_t>(messageSize));
    buffer->RemoveAtStart(static_cast<uint32_t>(messageSize));

    ProcessRequest(request, completePacket, socket);

    NS_LOG_DEBUG("[DEBUG] Remaining buffer size: " << buffer->GetSize());
  }
}


void
QKDKeyManagerSystemApplication::PacketReceivedKMSs(const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << p->GetUid() << p->GetSize() << from);

  // Retrieve or create buffer
  Ptr<Packet> &buffer = m_bufferKMS[from];
  if (!buffer)
    buffer = Create<Packet>(0);

  buffer->AddAtEnd(p);
  NS_LOG_DEBUG("[DEBUG] Buffer after adding packet UID " << p->GetUid() << ": " << buffer->GetSize() << " bytes");

  HTTPMessageParser parser;
  while (buffer->GetSize() > 0) {
    // Copy current buffer to string
    std::string bufferStr(buffer->GetSize(), '\0');
    buffer->CopyData(reinterpret_cast<uint8_t*>(&bufferStr[0]), bufferStr.size());

    // Try to extract a single HTTP message from the buffer
    std::string singleMessage;
    size_t messageSize = 0;
    if (!parser.TryExtractHttpMessage(bufferStr, singleMessage, messageSize)) {
      NS_LOG_DEBUG("[DEBUG] HTTP message is incomplete or fragmented, waiting for more data...");
      break;
    }

    // Parse the extracted message
    HTTPMessage httpMessage;
    parser.Parse(&httpMessage, singleMessage);

    NS_LOG_DEBUG("[DEBUG] Parsed HTTP headers:\n" << httpMessage.ToString());
    NS_LOG_DEBUG("[DEBUG] Parsed Content-Length: " << httpMessage.GetContentLength());
    NS_LOG_DEBUG("[DEBUG] Total HTTP message size (headers + body): " << messageSize);

    // Create packet from parsed message
    Ptr<Packet> messagePacket = buffer->CreateFragment(0, messageSize);
    buffer->RemoveAtStart(messageSize);

    ProcessPacketKMSs(httpMessage, messagePacket, socket);
    NS_LOG_DEBUG("[DEBUG] Remaining buffer size: " << buffer->GetSize());
  }
}



/**
 * ********************************************************************************************

 *        APPLICATION functions

 * ********************************************************************************************
 */

void
QKDKeyManagerSystemApplication::StartApplication() // Called at time specified by Start
{
  NS_LOG_FUNCTION(this);
  PrepareSinkSocket();

  NS_LOG_FUNCTION(this << "m_pqc_enabled:" << m_pqc_enabled ); 
  NS_LOG_FUNCTION(this << "m_pqc_c:" << m_pqc_c );

  if(!m_pqc_c) m_pqc_enabled = 0;
  if(m_pqc_enabled && m_pqc_c)
  {

#ifdef QKDNETSIM_WITH_PQC
    //Create and store PQC public key
    m_PQCKem = "Kyber512";
    //m_PQCKem = "ML-KEM-768";
    //m_PQCKem = "ML-KEM-1024";
      
    m_PQCkeyEncapsulation = std::make_shared<oqs::KeyEncapsulation>(m_PQCKem);
    oqs::bytes pub = m_PQCkeyEncapsulation->generate_keypair();
    m_PQCPublicKey.assign(reinterpret_cast<const char*>(pub.data()), pub.size());
#endif
  
  }
}

void
QKDKeyManagerSystemApplication::PrepareSinkSocket() // Called at time specified by Start
{

  NS_LOG_FUNCTION(this);

  ////////////////////////////////////////
  // SINK SOCKET APP-KMS
  ////////////////////////////////////////

  // Create the sink socket if not already
  if(!m_sinkSocket){
    m_sinkSocket = Socket::CreateSocket(GetNode(), m_tid);
    NS_LOG_FUNCTION(this << "Create the sink KMS socket!" << m_sinkSocket);
  }

  NS_LOG_FUNCTION(this << "Sink APP-KMS socket listens on " << Ipv4Address::GetAny() << " and port " << m_port << " for APP requests" );
  //NS_LOG_FUNCTION(this << "Sink KMS socket listens on " << m_local << " and port " << m_port << " for APP requests" );

  //InetSocketAddress sinkAddress = InetSocketAddress(m_local, m_port);
  InetSocketAddress sinkAddress = InetSocketAddress(Ipv4Address::GetAny(), m_port);

  m_sinkSocket->Bind(sinkAddress);
  m_sinkSocket->Listen();
  //m_sinkSocket->ShutdownSend();
  m_sinkSocket->SetRecvCallback(MakeCallback(&QKDKeyManagerSystemApplication::HandleRead, this));
  m_sinkSocket->SetAcceptCallback(
    MakeNullCallback<bool, Ptr<Socket>, const Address &>(),
    MakeCallback(&QKDKeyManagerSystemApplication::HandleAccept, this)
  );
  m_sinkSocket->SetCloseCallbacks(
    MakeCallback(&QKDKeyManagerSystemApplication::HandlePeerClose, this),
    MakeCallback(&QKDKeyManagerSystemApplication::HandlePeerError, this)
  );

  ////////////////////////////////////////
  // SINK SOCKET KMS-KMS
  ////////////////////////////////////////

  // Create the sink socket if not already
  if(!m_sinkSocketKMS){
    m_sinkSocketKMS = Socket::CreateSocket(GetNode(), m_tid);
    NS_LOG_FUNCTION(this << "Create the sink KMS socket!" << m_sinkSocketKMS);
  }
  NS_LOG_FUNCTION(this << "Sink KMS-KMS socket listens on " << Ipv4Address::GetAny() << " and port " << 8080 << " for KMS requests" );

  InetSocketAddress sinkAddressKMS = InetSocketAddress(Ipv4Address::GetAny(), 8080); 
  m_sinkSocketKMS->Bind(sinkAddressKMS);
  m_sinkSocketKMS->Listen();
  //m_sinkSocketKMS->ShutdownSend();
  m_sinkSocketKMS->SetRecvCallback(MakeCallback(&QKDKeyManagerSystemApplication::HandleReadKMSs, this));
  m_sinkSocketKMS->SetAcceptCallback(
    MakeNullCallback<bool, Ptr<Socket>, const Address &>(),
    MakeCallback(&QKDKeyManagerSystemApplication::HandleAcceptKMSs, this)
  );
  m_sinkSocketKMS->SetCloseCallbacks(
    MakeCallback(&QKDKeyManagerSystemApplication::HandlePeerCloseKMSs, this),
    MakeCallback(&QKDKeyManagerSystemApplication::HandlePeerErrorKMSs, this)
  );
}

void
QKDKeyManagerSystemApplication::StopApplication() // Called at time specified by Stop
{
  NS_LOG_FUNCTION(this);
  if(m_sinkSocket)
  {
    m_sinkSocket->Close();
    m_sinkSocket->SetRecvCallback(MakeNullCallback<void, Ptr<Socket> >());
  }
  if(m_sinkSocketKMS)
  {
    m_sinkSocketKMS->Close();
    m_sinkSocketKMS->SetRecvCallback(MakeNullCallback<void, Ptr<Socket> >());
  }
}

void
QKDKeyManagerSystemApplication::ScheduleReleaseAssociation(Time t, std::string action, std::string ksid, std::string surplusKeyId, uint32_t syncIndex)
{
  NS_LOG_FUNCTION(this << "Postponing ReleaseAssociation for slave KMS!" << ksid << surplusKeyId << syncIndex << " ...");  
  if(action == "ReleaseAssociation")
  {
    auto it = m_scheduledChecks.find(ksid);
    if(it==m_scheduledChecks.end())
    {
      std::string temp = ksid + "-" + surplusKeyId + "-" + std::to_string(syncIndex);
      EventId event = Simulator::Schedule(t, &QKDKeyManagerSystemApplication::ReleaseAssociation, this, ksid, surplusKeyId, syncIndex);
      m_scheduledChecks.insert( std::make_pair( temp ,  event) );
      NS_LOG_FUNCTION(this << "NEW event successfully scheduled!" << action << ksid);        
    } else {
      NS_LOG_FUNCTION(this << "Event already scheduled!" << action << ksid);        
    }
  }else
    NS_FATAL_ERROR(this << "Invalid action as the function input recived " << action);
}

/**
 * ********************************************************************************************

 *        Southbound interface functions(ETSI 014 & ETSI 004)

 * ********************************************************************************************
 */

void
QKDKeyManagerSystemApplication::ProcessRequest(HTTPMessage headerIn, Ptr<Packet> packet, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << headerIn.GetUri() << headerIn.GetRequestUri() << packet->GetUid());
  NS_ASSERT(!headerIn.GetUri().empty() || !headerIn.GetRequestUri().empty());

  std::string uriIn = (!headerIn.GetUri().empty()) ? headerIn.GetUri() : headerIn.GetRequestUri();

  auto uriParams = ReadUri(uriIn);
  std::string ksid, remoteAppId; //Read ksid or remoteAppId
  QKDKeyManagerSystemApplication::RequestType requestType = EMPTY;

  if(
    uriParams.size() > 3 &&
    uriParams[1] == "api" &&
    uriParams[2] == "v1" &&
    uriParams[3] == "keys"
  ){
    std::string receivedAddressStr(uriParams[0]);
    Ipv4Address receivedAddress = Ipv4Address(receivedAddressStr.c_str());  //string to IPv4Address
    if(receivedAddress != GetAddress()){
      NS_LOG_LOGIC( this << "The request is not for me!\t" << receivedAddress << "\t" << GetAddress() << "\t" << headerIn.GetUri());
      return; //Do nothing
    }
    remoteAppId = uriParams[4];
    ksid = uriParams[4];
    requestType = FetchRequestType(uriParams[5]);
  }

  if(requestType == ETSI_QKD_014_GET_STATUS)
  { 
    ProcessEtsi014GetStatus(remoteAppId, headerIn, socket);
  } else if(requestType == ETSI_QKD_014_GET_KEY)
  {   
    ProcessEtsi014GetKey(remoteAppId, headerIn, socket);
  } else if(requestType == ETSI_QKD_014_GET_KEY_WITH_KEY_IDS)
  { 
    ProcessEtsi014GetKeyWithIds(remoteAppId, headerIn, socket);
  } else if(requestType == ETSI_QKD_004_OPEN_CONNECT) {

      //m_queueLogic->Enqueue(headerIn);
      //HTTPMessage h2 = m_queueLogic->Dequeue();
      ProcessEtsi004OpenConnect(headerIn, socket);

  } else if(requestType == ETSI_QKD_004_GET_KEY) {
      
      ProcessEtsi004GetKey(ksid, headerIn, socket); //@toDo "" should be ksid, read from uri param
  } else if(requestType == ETSI_QKD_004_CLOSE) {

      ProcessEtsi004Close(ksid, headerIn, socket);
  } else if(requestType == STORE_KEY) {

    ProcessStoreKey(headerIn, socket);
  }
}

////////////////////////
/// ETSI GS 014
////////////////////////
void QKDKeyManagerSystemApplication::ProcessEtsi014GetStatus(std::string remoteAppId, HTTPMessage headerIn, Ptr<Socket> socket)
{
    
  NS_LOG_FUNCTION(this << remoteAppId);
  std::string uriIn = (!headerIn.GetUri().empty()) ? headerIn.GetUri() : headerIn.GetRequestUri();
  auto uriParams = ReadUri(uriIn);
  //Process GET_STATUS request
  QKDLocationRegisterEntry conn = GetController()->GetRoute(remoteAppId); //Get Route Info
  /**@todo id1124
   * What if remote App ID is not known? Respond with an error.
   */
  Ptr<SBuffer> sBuffer = GetSBuffer(conn.GetDestinationKmNodeId(), "enc");
  if(!sBuffer)
  { 
    NS_LOG_FUNCTION(this << "The S-Buffer does not exists! This is new virtual connection!");
    uint32_t srcNodeId = GetNode()->GetId();
    uint32_t dstNodeId = conn.GetDestinationKmNodeId();
    sBuffer = CreateSBuffer(srcNodeId, dstNodeId, "(RELAY)", "relay");
    m_keys_enc.insert(std::make_pair(dstNodeId, sBuffer)); //Store a pointer to new sBuffer
    m_keys_dec.insert(std::make_pair(dstNodeId, sBuffer)); //Store a pointer to new sBuffer
    SBufferClientCheck(conn.GetDestinationKmNodeId()); //Start relaying keys 
  }
  NS_ASSERT(sBuffer);

  nlohmann::json j = { //Status data format
    {"soruce_KME_ID", GetAddressString(GetAddress())}, //Local KM Ipv4 address
    {"target_KME_ID", GetAddressString(conn.GetDestinationKmsAddress())}, //Destination KM Ipv4 address
    {"master_SAE_ID", GetController()->GetApplicationId(remoteAppId)}, //Local Application ID defined as UUID
    {"slave_SAE_ID", remoteAppId}, //Remote Application ID defined as UUID
    {"key_size", sBuffer->GetKeySize()}, //Default key size for this QKD buffer
    {"stored_key_count", sBuffer->GetSKeyCount()}, //Stored key(default size) count
    {"max_key_count", uint32_t(sBuffer->GetMmax() / sBuffer->GetKeySize())}, //Maximum key count
    {"max_key_per_request", GetMaxKeyPerRequest()}, //Defined by the KM!
    {"max_key_size", m_maxKeySize}, //Can be defined by KM! QKDBuffers should not have this limitation!
    {"min_key_size", m_minKeySize}, //Can be defined by KM! QKDBuffers should not have this limitation!
    {"max_SAE_ID_count", 0}
  };

  uint32_t sBitCountTemp = sBuffer->GetSBitCount();
  NS_LOG_FUNCTION( this << "sBuffer->GetSBitCount " << sBitCountTemp );

  HTTPMessage httpMessage; //Create response!
  httpMessage.CreateResponse(HTTPMessage::HttpStatus::Ok, j.dump(), {
    {"Content-Type", "application/json; charset=utf-8"},
    {"Request URI", uriIn }
  });
  std::string hMessage = httpMessage.ToString();
  Ptr<Packet> packet = Create<Packet>(
   (uint8_t*)(hMessage).c_str(),
    hMessage.size()
  );
  NS_ASSERT(packet);

  NS_LOG_FUNCTION(this << "Sending response:" << uriIn << "\tPacketID: " << packet->GetUid() << " of size: " << packet->GetSize() << hMessage  );
  SendToSocketPair(socket, packet);
}

void QKDKeyManagerSystemApplication::ProcessEtsi014GetKey(std::string remoteAppId, HTTPMessage headerIn, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << remoteAppId);

  std::string uriIn = (!headerIn.GetUri().empty()) ? headerIn.GetUri() : headerIn.GetRequestUri();
  auto uriParams = ReadUri(uriIn);
  QKDLocationRegisterEntry conn = GetController()->GetRoute(remoteAppId); //@todo id1124
  Ptr<SBuffer> sBuffer = GetSBuffer(conn.GetDestinationKmNodeId(), "enc");  //@todo id1125
  NS_ASSERT(sBuffer);

  Ptr<SBuffer> sBufferPQC = nullptr;
  if(m_pqc_enabled)
  {
    sBufferPQC = GetSBuffer(conn.GetDestinationKmNodeId(), "pqc");        
    if(!sBufferPQC)
    { 
      NS_LOG_FUNCTION(this << "The S-Buffer (PQC) does not exists! This is new virtual connection!");  
      sBufferPQC = CreateSBuffer(GetNode()->GetId(), conn.GetDestinationKmNodeId(), "(PQC)", "pqc"); 
      m_keys_pqc.insert(std::make_pair(conn.GetDestinationKmNodeId(), sBufferPQC)); 
    }
    NS_ASSERT(sBufferPQC);
  }

  uint32_t keyNumber {1}, keySize {sBuffer->GetKeySize()}; //Set default values
  nlohmann::json jrequest; //Read request parameters
  if(headerIn.GetMethod() == HTTPMessage::HttpMethod::GET){
      int k = 6;
      while(k < int(uriParams.size())){ //Read number and size from URI
          if(uriParams[k] == "number")
            keyNumber = std::stoi(uriParams[k+1]);
          else if(uriParams[k] == "size")
            keySize = std::stoi(uriParams[k+1]); //Key size in bits!
          k += 2;
      }
      NS_LOG_FUNCTION(this << keyNumber << keySize);
  }else if(headerIn.GetMethod() == HTTPMessage::HttpMethod::POST){ //Read number and size from payload
      std::string payload = headerIn.GetMessageBodyString(); //Read payload
      try{ //Try parse JSON
          jrequest = nlohmann::json::parse(payload);
          if(jrequest.contains("number"))
              keyNumber = jrequest["number"];
          if(jrequest.contains("size"))
              keySize = uint32_t(jrequest["size"]);
      }catch(...){
          NS_FATAL_ERROR( this << "JSON parse error of the received payload: " << payload << "\t" << payload.length() );
      }
  }else {
    NS_FATAL_ERROR(this << "Invalid HTTP request method" << headerIn.GetMethod());
    
    HTTPMessage httpMessage;
    httpMessage.CreateResponse(HTTPMessage::HttpStatus::BadRequest, "", {
      {"Request URI", headerIn.GetUri() }
    });
    std::string hMessage = httpMessage.ToString();
    Ptr<Packet> packet = Create<Packet>(
     (uint8_t*)(hMessage).c_str(),
      hMessage.size()
    );
    NS_ASSERT(packet);

    SendToSocketPair(socket, packet);
    return;
  }

  NS_LOG_FUNCTION(this << "Validate request and probe ability to serve!");
  uint32_t keySize_qkd = 0;
  nlohmann::json errorDataStructure = ValidateEtsi014GetKeyRequest(keyNumber, keySize, sBuffer, keySize_qkd);

  uint32_t requestedBits = keySize*keyNumber;
  uint32_t keySize_pqc = requestedBits - keySize_qkd;
  NS_LOG_FUNCTION(this << "requestedBits:" << requestedBits);
  NS_LOG_FUNCTION(this << "keySize_qkd:" << keySize_qkd);
  NS_LOG_FUNCTION(this << "keySize_pqc:" << keySize_pqc);
  NS_ASSERT( keySize_qkd + keySize_pqc == requestedBits );
  
  if(m_pqc_enabled && sBufferPQC->GetBitCount() < keySize_pqc){
    NS_LOG_FUNCTION(this << "We do not have enough PQC keys!"); 
    errorDataStructure = {{"message", "insufficient amount of key material"}};
  }

  HTTPMessage::HttpStatus statusCode {HTTPMessage::HttpStatus::Ok};
  std::string msg;
  if(!errorDataStructure.empty())
  { 
    NS_LOG_DEBUG(this << "We have an error. Request is not valid, or KM is unable to serve!");
    statusCode = HTTPMessage::HttpStatus::BadRequest;
    msg = errorDataStructure.dump();
  }else{ 
    NS_LOG_FUNCTION(this << "The request is valid. KM can serve key(s)");

    //QKD part
    std::vector<std::string> candidateSetIds {};
    std::string mergedKey, surplusKeyId;
    uint32_t targetSize = keySize_qkd;
    NS_LOG_FUNCTION(this << "targetSize:" << targetSize);
    while(true)
    { 
      NS_LOG_FUNCTION(this << "Form a transform set, and a large merged key!" << targetSize);
      uint32_t tempTarget {0};
      if(targetSize <= sBuffer->GetKeySize())
        tempTarget = targetSize;

      Ptr<QKDKey> candidateKey = sBuffer->GetTransformCandidate(tempTarget);
      NS_LOG_FUNCTION(this << "PPP1: " << candidateKey->GetId());
      NS_ASSERT(candidateKey);

      candidateSetIds.push_back(candidateKey->GetId());
      mergedKey += candidateKey->GetKeyString();

      if(candidateKey->GetState() == QKDKey::INIT)
        surplusKeyId = candidateKey->GetId();

      if(candidateKey->GetSizeInBits() >= targetSize)
        break;
      else
        targetSize -= candidateKey->GetSizeInBits();
    }

    NS_LOG_FUNCTION(this << "Now create supply keys!");
    std::vector<std::string> supplyKeyIds {};
    std::vector<Ptr<QKDKey>> supplyKeys {};
    uint32_t k{0};
    while(k++<keyNumber)
    {
      std::string keyString = mergedKey.substr(0, keySize_qkd/8);
      if(!keyString.empty())
      {
        std::string skeyId = GenerateUUID();
        mergedKey.erase(0, keySize_qkd/8);
        Ptr<QKDKey> tempKey = CreateObject<QKDKey>(skeyId, keyString);
        //NS_LOG_FUNCTION(this << "PPP2: " << tempKey->GetKeyString());
        supplyKeys.push_back(tempKey);
        supplyKeyIds.push_back(skeyId);
 
        //etsi014
        m_keyServedTraceMixed(
          remoteAppId,
          "",
          remoteAppId,
          GetNode()->GetId(),
          conn.GetDestinationKmNodeId(),
          tempKey->GetId(), 
          tempKey->GetSizeInBits(), 
          std::string("qkd")
        ); 

        if(sBuffer->GetType() == SBuffer::LOCAL_SBUFFER) //Then this is p2p connection!
          m_keyConsumedLink(
            GetNode()->GetId(), //Source
            conn.GetDestinationKmNodeId(), //Destination
            //tempKey->GetId(),
            tempKey->GetSizeInBits()
          ); 
      }
    }
    if(m_pqc_enabled )
      NS_ASSERT(mergedKey.empty());

    //Send skey_create message to peer KM node
    NS_LOG_FUNCTION( this << "keySize_qkd" << keySize_qkd ); //Testing @rm
    NS_LOG_FUNCTION( this << "keySize_pqc" << keySize_pqc ); //Testing @rm
    NS_LOG_FUNCTION( this << "key_number" << keyNumber);
    NS_LOG_FUNCTION( this << "supply_key_IDs" << supplyKeyIds );
    NS_LOG_FUNCTION( this << "candidate_set_IDs" << candidateSetIds );
    NS_LOG_FUNCTION( this << "surplus_key_ID" << surplusKeyId);

    //PQC part
    std::vector<std::string> candidateSetIdsPQC {};
    std::string mergedKeyPQC, surplusKeyIdPQC; 
    uint32_t targetSizePQC = keySize_pqc;
    if(m_pqc_enabled && keySize_pqc)
    {
      while(true)
      {
        NS_LOG_FUNCTION(this << "Form a transform PQC set, and a large merged key!" << targetSizePQC);
        uint32_t tempTarget {0};
        if(targetSizePQC <= sBuffer->GetKeySize())
          tempTarget = targetSizePQC;

        Ptr<QKDKey> candidateKey = sBufferPQC->GetTransformCandidate(tempTarget);
        if(!candidateKey)
        {
          NS_LOG_FUNCTION(this << "We do not have enough PQC keys!");
          Ipv4Address dstKms = conn.GetDestinationKmsAddress(); //Destination KMS adress
          CheckSocketsKMS(dstKms); //Check connection to peer KMS!
          CheckPQCBuffer(dstKms);
          return;
        }

        //NS_LOG_FUNCTION(this << "QQQ1: " << candidateKey->GetKeyString());
        NS_ASSERT(candidateKey);

        candidateSetIdsPQC.push_back(candidateKey->GetId());
        mergedKeyPQC += candidateKey->GetKeyString();

        if(candidateKey->GetState() == QKDKey::INIT)
          surplusKeyIdPQC = candidateKey->GetId();

        if(candidateKey->GetSizeInBits() >= targetSizePQC)
          break;
        else
          targetSizePQC -= candidateKey->GetSizeInBits();
      }
    }

    NS_LOG_FUNCTION(this << "Now create supply keys for PQC!");
    std::vector<std::string> supplyKeyIdsPQC {};
    std::vector<Ptr<QKDKey>> supplyKeysPQC {};

    std::vector<std::string> mixedKeyIds {};
    std::vector<Ptr<QKDKey>> mixedKeys {};
    uint32_t kPQC{0};
    if(m_pqc_enabled && keySize_pqc)
    {
      while(kPQC++<keyNumber)
      {
        std::string keyString = mergedKeyPQC.substr(0, keySize_pqc/8);
        if(!keyString.empty())
        {
          std::string skeyId = GenerateUUID();
          mergedKeyPQC.erase(0, keySize_pqc/8);

          Ptr<QKDKey> tempKey = CreateObject<QKDKey>(skeyId, keyString);
          //NS_LOG_FUNCTION(this << "QQQ2: " << tempKey->GetKeyString());
          supplyKeysPQC.push_back(tempKey);
          supplyKeyIdsPQC.push_back(skeyId);
 
          //etsi014          
          m_keyServedTraceMixed(
            remoteAppId,
            "",
            remoteAppId,
            GetNode()->GetId(),
            conn.GetDestinationKmNodeId(),
            tempKey->GetId(), 
            tempKey->GetSizeInBits(), 
            std::string("pqc")
          ); 

        }
      }
      NS_ASSERT(mergedKeyPQC.empty());
    }

    //Send skey_create message to peer KM node
    NS_LOG_FUNCTION( this << "keySize_pqc" << keySize_pqc ); //Testing @rm
    NS_LOG_FUNCTION( this << "key_number" << keyNumber);
    NS_LOG_FUNCTION( this << "supply_key_IDs_PQC" << supplyKeyIdsPQC );
    NS_LOG_FUNCTION( this << "candidate_set_IDs_PQC" << candidateSetIdsPQC );
    NS_LOG_FUNCTION( this << "surplus_key_ID_PQC" << surplusKeyIdPQC);

    NS_LOG_FUNCTION( "supplyKeys.size():" << supplyKeys.size() );
    NS_LOG_FUNCTION( "supplyKeysPQC.size():" << supplyKeysPQC.size() );
    NS_LOG_FUNCTION( "candidateSetIds.size():" << candidateSetIds.size() );
    NS_LOG_FUNCTION( "candidateSetIdsPQC.size():" << candidateSetIdsPQC.size() );

    //Create HTTP message transform
    nlohmann::json jtransform;
    jtransform["source_node_id"] = GetNode()->GetId(); //Currently to find S-Buffer on remote KM @todo use KM ID
    jtransform["target_SAE_ID"] = remoteAppId;
    jtransform["key_size_QKD"] = keySize_qkd;
    jtransform["key_size_PQC"] = keySize_pqc;
    jtransform["key_number"] = keyNumber;

    if(m_pqc_enabled && keySize_pqc)
      NS_ASSERT(supplyKeys.size() == supplyKeysPQC.size());

    //QKD
    for(size_t i = 0; i < supplyKeyIds.size(); i++)
      jtransform["supply_key_ID"].push_back({{"key_ID", supplyKeyIds[i]}});
    for(size_t i = 0; i < candidateSetIds.size(); i++)
      jtransform["candidate_set_ID"].push_back({{"key_ID", candidateSetIds[i]}});

    //PQC
    if(m_pqc_enabled && keySize_pqc) 
    {
      for(size_t i = 0; i < supplyKeyIdsPQC.size(); i++)
      {
        jtransform["supply_key_ID_PQC"].push_back({{"key_ID", supplyKeyIdsPQC[i]}});

        std::string mKeyId = GenerateUUID();
        std::string mixedKeyVal = (supplyKeys[i])->GetKeyString() + (supplyKeysPQC[i])->GetKeyString(); 
        Ptr<QKDKey> mKey = CreateObject<QKDKey>(mKeyId, mixedKeyVal);

        //NS_LOG_FUNCTION(this << "QQQ: " << supplyKeys[i]->GetKeyString());
        //NS_LOG_FUNCTION(this << "PPP: " << supplyKeysPQC[i]->GetKeyString());
        //NS_LOG_FUNCTION(this << "MMM: " << mKey->GetKeyString());

        mixedKeys.push_back(mKey); 
        NS_LOG_FUNCTION(this << "mKey.size():" << mKey->GetSizeInBits());

        SBuffer::MixedKey mKeyStruct;
        mKeyStruct.mixedKey = mKey;
        mKeyStruct.qkdKeyIds.push_back(supplyKeyIds[i]);
        mKeyStruct.qkdStartBits.push_back(0);
        mKeyStruct.qkdEndBits.push_back(
          supplyKeys[i]->GetSizeInBits() - 1
        );

        mKeyStruct.pqcKeyIds.push_back(supplyKeyIdsPQC[i]);
        mKeyStruct.pqcStartBits.push_back(0);
        mKeyStruct.pqcEndBits.push_back(
          supplyKeysPQC[i]->GetSizeInBits() - 1
        );

        sBufferPQC->StoreMixedKey(mKeyId, mKeyStruct); 
        
        nlohmann::json jMixed;
        jMixed["key_ID"] = mKeyId;
        jMixed["qkd"] = nlohmann::json::array();
        jMixed["qkd"].push_back({
          {"id", supplyKeyIds[i]},
          {"start_bit", 0},
          {
            "end_bit",
            supplyKeys[i]->GetSizeInBits() - 1
          }
        });

        jMixed["pqc"] =  nlohmann::json::array();
        jMixed["pqc"].push_back({
          {"id", supplyKeyIdsPQC[i]},
          {"start_bit", 0},
          {
            "end_bit",
            supplyKeysPQC[i]->GetSizeInBits() - 1
          }
        });
        jtransform["mixed_key_ids"].push_back(jMixed);
      }

      for(size_t i = 0; i < candidateSetIdsPQC.size(); i++)
      {
        jtransform["candidate_set_ID_PQC"].push_back({{"key_ID", candidateSetIdsPQC[i]}});
      }
    }

    std::string msg1 = jtransform.dump();
    NS_LOG_FUNCTION( this << "Transform payload" << msg1 ); //Testing @rm
    Ipv4Address dstKms = conn.GetDestinationKmsAddress(); //Destination KMS adress
    CheckSocketsKMS(dstKms); //Check connection to peer KMS!
    Ptr<Socket> socket = GetSocketKMS(dstKms); //Get send socket to peer KMS
    NS_ASSERT(socket); //Check

    //Create packet
    std::string headerUri = "http://" + GetAddressString(dstKms);
    headerUri += "/api/v1/sbuffers/skey_create";

    HTTPMessage httpMessage;
    httpMessage.CreateRequest(headerUri, "POST", msg1);
    std::string hMessage = httpMessage.ToString();
    Ptr<Packet> packet = Create<Packet>(
     (uint8_t*)(hMessage).c_str(),
      hMessage.size()
    );
    NS_ASSERT(packet);

    HttpQuery httpRequest;
    httpRequest.method_type = RequestType::TRANSFORM_KEYS;
    httpRequest.peerNodeId = conn.GetDestinationKmNodeId();
    httpRequest.surplus_key_ID = surplusKeyId;
    HttpKMSAddQuery(dstKms, httpRequest); //Remember request to properly map response! 
    SendToSocketPairKMS(socket, packet);
    
    NS_LOG_FUNCTION(this << "NextKMNodeId: " << conn.GetNextHopKMNodeId()  << "\t" << conn.GetNextHopAddress() );
    NS_LOG_FUNCTION(this << "DestKMNodeId: " << conn.GetDestinationKmNodeId()   << "\t" << conn.GetDestinationKmsAddress() );
    NS_LOG_FUNCTION(this << "SKEY_CREATE request sent to peer KM" << packet->GetUid() << packet->GetSize());

    //Create response on get_key
    //QKD + PQC
    if(m_pqc_enabled && mixedKeys.size())
    {
      nlohmann::json mixedKeysJson = CreateKeyContainer(mixedKeys);
      NS_LOG_FUNCTION(this << "mixedKeysJson:" << mixedKeysJson.dump()); 
      msg = mixedKeysJson.dump();    
    //Only QKD
    }else{
      nlohmann::json jkeys = CreateKeyContainer(supplyKeys);
      NS_LOG_FUNCTION(this << "jkeys:" << jkeys.dump()); 
      msg = jkeys.dump();  
    }
    CheckPQCBuffer(dstKms);
  }

  if(sBuffer->GetType() == SBuffer::RELAY_SBUFFER || GetNode()->GetId() < conn.GetDestinationKmNodeId()){
    SBufferClientCheck(conn.GetDestinationKmNodeId());
  }

  //create packet
  HTTPMessage httpMessage;
  httpMessage.CreateResponse(statusCode, msg, {
    {"Content-Type", "application/json; charset=utf-8"},
    {"Request URI", uriIn }
  });
  std::string hMessage = httpMessage.ToString();
  Ptr<Packet> packet = Create<Packet>(
   (uint8_t*)(hMessage).c_str(),
    hMessage.size()
  );
  NS_ASSERT(packet);


  NS_LOG_FUNCTION(this 
    << "Sending Response to ETSI_QKD_014_GET_KEY" 
    <<  "\n PacketID: " << packet->GetUid() 
    << " of size: " << packet->GetSize() 
    << hMessage  
  ); 

  //SendToSocketPair(socket, packet);
  Simulator::Schedule(Seconds(0.015), &QKDKeyManagerSystemApplication::SendToSocketPair, this, socket, packet);
}


nlohmann::json
QKDKeyManagerSystemApplication::ValidateEtsi014GetKeyRequest(
  uint32_t number,
  uint32_t size,
  Ptr<SBuffer> buffer,
  uint32_t& qkdBitsOutput
)
{
  NS_LOG_FUNCTION(this << number << size << GetMaxKeyPerRequest() << m_maxKeySize << m_minKeySize << size % 8);

  NS_LOG_FUNCTION(this <<(number > GetMaxKeyPerRequest()));
  NS_LOG_FUNCTION(this <<(number <= 0));
  NS_LOG_FUNCTION(this <<(size > m_maxKeySize));
  NS_LOG_FUNCTION(this <<(size < m_minKeySize));
  NS_LOG_FUNCTION(this <<(size % 8));

  nlohmann::json jError;
  if( //Validation check
    number > GetMaxKeyPerRequest() ||
    number <= 0 ||
    size > m_maxKeySize ||
    size < m_minKeySize ||
    size % 8
  ){
    jError["message"] = std::string {"requested parameters do not adhere to KM rules"};
    if(number > GetMaxKeyPerRequest()){
      std::string msgDetail = "requested number of keys(" + std::to_string(number) + ") is higher then a maximum number of keys(" + std::to_string(GetMaxKeyPerRequest()) + ") per request allowed by KMS";
      jError["details"].push_back({{"number_unsupported", msgDetail}});

    }else if(number <= 0){
      std::string msgDetail = "requested number of keys can not be lower or equal to zero";
      jError["details"].push_back({{"number_unsupported", msgDetail}});
    }

    if(size > m_maxKeySize){
      std::string msgDetail = "requested size of keys(" + std::to_string(size) + ") is higher then a maximum size of key(" + std::to_string(m_maxKeySize) + ") that KMS can deliver";
      jError["details"].push_back({{"size_unsupported", msgDetail}});

    }else if(size < m_minKeySize){
      std::string msgDetail = "requested size of keys(" + std::to_string(size) + ") is lower then a minimum size of key(" + std::to_string(m_minKeySize) + ") that KMS can deliver";
      jError["details"].push_back({{"size_unsupported", msgDetail}});

    }else if(size % 8){
      std::string msgDetail = "size shall be a multiple of 8";
      jError["details"].push_back({{"size_unsupported", msgDetail}});
    }


  }else{ //Others - ability to serve

    uint32_t requestedBits = size*number;
    uint32_t availableKeyBits = buffer->GetSBitCount();
    NS_LOG_FUNCTION(this << "\nTarget key size: " << size << "\nTarget number: " << number
                         << "\nRequired amount of key material: " << requestedBits
                         << "\nAmount of key material in s-buffer(READY): " << availableKeyBits);

    NS_LOG_FUNCTION(this 
      << "Buffer:" << buffer
      << "Descripion: " << buffer->GetDescription()
      << "\n BitCount: " << buffer->GetBitCount() 
      << "\n SBitCount: " << buffer->GetSBitCount() 
      << "\n Max: " << buffer->GetMmax() 
    );

    uint32_t keySize_qkd = 0;
    if(buffer->GetState() == 0)
    {
      keySize_qkd = requestedBits;
      NS_LOG_FUNCTION(this << "We are in READY state! let's TRY to serve keySize_qkd:" << keySize_qkd);
    }else{
      keySize_qkd = ComputePqcMixing(requestedBits, availableKeyBits);
      NS_LOG_FUNCTION(this << "CALCULATED keySize_qkd:" << keySize_qkd);
    }
  
    //Check if there is enough key material!
    if(requestedBits > availableKeyBits || !keySize_qkd)
    { 
 

      uint32_t demendForKeys = requestedBits * 1.2;
      NS_LOG_FUNCTION(this << buffer << " was in " << buffer->GetState() << " state!"  << buffer->GetBitCount()  << " -- " << buffer->GetMthr() ); //Check s-buffer state
      //Here, let's update SThreshold 
      buffer->SetMthr(demendForKeys);
      buffer->CheckState(); 
      NS_LOG_FUNCTION(this << buffer << " is NOW in " << buffer->GetState() << " state!"  << buffer->GetBitCount()  << " -- " << buffer->GetMthr() ); //Check s-buffer state


      NS_LOG_FUNCTION(this << "insufficient amount of key material");
      jError = {{"message", "insufficient amount of key material"}};
    }else{
      qkdBitsOutput = keySize_qkd;
    }

  }
  return jError;
}

void QKDKeyManagerSystemApplication::ProcessEtsi014GetKeyWithIds(std::string remoteAppId, HTTPMessage headerIn, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << remoteAppId);

  QKDLocationRegisterEntry conn = GetController()->GetRoute(remoteAppId); //@todo id1124
  Ptr<SBuffer> sBuffer = GetSBuffer(conn.GetDestinationKmNodeId(), "dec");
  NS_ASSERT(sBuffer);

  Ptr<SBuffer> sBufferPQC;
  if(m_pqc_enabled)
  {
    sBufferPQC = GetSBuffer(conn.GetDestinationKmNodeId(), "pqc");
    if(!sBufferPQC)
    { 
      NS_LOG_FUNCTION(this << "The S-Buffer (PQC) does not exists! This is new virtual connection!");  
      sBufferPQC = CreateSBuffer(GetNode()->GetId(), conn.GetDestinationKmNodeId(), "(PQC)", "pqc"); 
      m_keys_pqc.insert(std::make_pair(conn.GetDestinationKmNodeId(), sBufferPQC)); 
    }
    if(!sBufferPQC)
      NS_FATAL_ERROR( this << "No s-buffer found for this connection!" );
  }

  nlohmann::json jkeyIDs;
  try{
      jkeyIDs = nlohmann::json::parse(headerIn.GetMessageBodyString()); //Parse packet payload to JSON structure
  }catch(...){
      NS_FATAL_ERROR( this << "JSON parse error!" );
  }

  std::vector<std::string> keyIDs; //Vector containing keyIDs
  for(nlohmann::json::iterator it = jkeyIDs["key_IDs"].begin(); it != jkeyIDs["key_IDs"].end(); ++it)
      keyIDs.push_back((it.value())["key_ID"]); //keyIDs read from JSON

  //Fetch keys with defined keyIDs from buffer
  std::vector<Ptr<QKDKey>> keys {};
  bool error {false};
  for(const auto &el : keyIDs)
  {
    //first check for QKD+PQC key
    SBuffer::MixedKey mKeyStruct;
    std::string keyIdTemp =  el;
    if(m_pqc_enabled && sBufferPQC->GetMixedKey(keyIdTemp , mKeyStruct))
    { 
      NS_LOG_FUNCTION(this << "krec007 QKD+PQC " << el << "succeeded");

      NS_ASSERT(mKeyStruct.mixedKey);
      NS_LOG_FUNCTION(this << mKeyStruct.mixedKey);
      keys.push_back(mKeyStruct.mixedKey); 

      std::vector<std::string> qkdKeyIds = mKeyStruct.qkdKeyIds; 
      for(const auto &qkdKeyId : qkdKeyIds)
      {
        Ptr<QKDKey> qkdKey = sBuffer->GetSupplyKey(qkdKeyId);
        NS_ASSERT(qkdKey);  

        //Etsi014
        m_keyServedTraceMixed(
          remoteAppId,
          "",
          remoteAppId,
          GetNode()->GetId(),
          conn.GetDestinationKmNodeId(),
          qkdKey->GetId(), 
          qkdKey->GetSizeInBits(), 
          std::string("qkd")
        ); 
    }

      std::vector<std::string> pqcKeyIds = mKeyStruct.pqcKeyIds;
      for(const auto &pqcKeyId : pqcKeyIds)
      {
        Ptr<QKDKey> pqcKey = sBufferPQC->GetSupplyKey(pqcKeyId);
        NS_ASSERT(pqcKey);  

        //Etsi014
        m_keyServedTraceMixed(
          remoteAppId,
          "",
          remoteAppId,
          GetNode()->GetId(),
          conn.GetDestinationKmNodeId(),
          pqcKey->GetId(), 
          pqcKey->GetSizeInBits(), 
          std::string("pqc")
        ); 
    }

    }else{

      //then check only for QKD key
      Ptr<QKDKey> tempKey = sBuffer->GetSupplyKey(el);
      if(tempKey){
        NS_LOG_FUNCTION(this << "krec007 QKD " << el << "succeeded");
        keys.push_back(tempKey);
         
        //Etsi014
        m_keyServedTraceMixed(
          remoteAppId,
          "",
          remoteAppId,
          GetNode()->GetId(),
          conn.GetDestinationKmNodeId(),
          tempKey->GetId(), 
          tempKey->GetSizeInBits(), 
          std::string("qkd")
        );
         
        if(sBuffer->GetType() == SBuffer::LOCAL_SBUFFER) //Then this is p2p connection!
        {
          m_keyConsumedLink(
            GetNode()->GetId(), //Source
            conn.GetDestinationKmNodeId(), //Destination
            //tempKey->GetId(),
            tempKey->GetSizeInBits()
          );
        }
      }else{ //The key is not present in SBuffer
        error = true;
      }
    }
  }

  std::string msg;
  HTTPMessage::HttpStatus statusCode {HTTPMessage::HttpStatus::Ok};
  if(!error){
    nlohmann::json jkeys = CreateKeyContainer(keys);
    msg = jkeys.dump();

  }else{
    statusCode = HTTPMessage::HttpStatus::BadRequest;
    msg = nlohmann::json{ {"message", "key not found"} }.dump();
    NS_LOG_FUNCTION(this << msg);
  }

  //create packet
  HTTPMessage httpMessage;
  httpMessage.CreateResponse(statusCode, msg, {
    {"Content-Type", "application/json; charset=utf-8"},
    {"Request URI", headerIn.GetUri() }
  });

  std::string hMessage = httpMessage.ToString();
  Ptr<Packet> packet = Create<Packet>(
   (uint8_t*)(hMessage).c_str(),
    hMessage.size()
  );
  NS_ASSERT(packet);

  NS_LOG_FUNCTION(this 
    << "Sending Response to ETSI_QKD_014_GET_KEY_WITH_KEY_IDS" 
    <<  "\n PacketID: " << packet->GetUid() 
    << " of size: " << packet->GetSize() 
    << hMessage  
  );
  SendToSocketPair(socket, packet);
}

////////////////////////
/// ETSI GS 004
////////////////////////
void
QKDKeyManagerSystemApplication::ProcessEtsi004OpenConnect(HTTPMessage headerIn, Ptr<Socket> socket)
{
    NS_LOG_FUNCTION(this << headerIn.GetMessageBodyString());
    std::string payload = headerIn.GetMessageBodyString();
    nlohmann::json jOpenConnectRequest;
    try{
        jOpenConnectRequest = nlohmann::json::parse(payload);
    }catch(...) {
        NS_FATAL_ERROR( this << "JSON parse error!" );
    }

    std::string ksid;
    std::string srcSaeId;
    std::string dstSaeId;
    QKDKeyManagerSystemApplication::QoS inQos;
    if(jOpenConnectRequest.contains("Destination"))
        dstSaeId = jOpenConnectRequest["Destination"];
    if(jOpenConnectRequest.contains("Source"))
        srcSaeId = jOpenConnectRequest["Source"];
    if(jOpenConnectRequest.contains("Key_stream_ID"))
        ksid = jOpenConnectRequest["Key_stream_ID"];
    ReadJsonQos(inQos, jOpenConnectRequest);
    NS_ASSERT(!srcSaeId.empty() || !dstSaeId.empty());

    /**
     * @toDo
     * First some sort of CAC is neccessary. Do we have enough resources to allow this association?
     * Second, even if it seems that we do not have resources, if the request has high priority
     * can we gather enough key material that is reserved for different associations that have
     * lower priority. Or allow association, and from now on do not fill low priority association
     * and generated key use to fill this high priority association.
     *
     * For now, in the point-to-point link scenario, the open_connect request is always accepted!
     */

    QKDLocationRegisterEntry conn = GetController()->GetRoute(dstSaeId);
    bool callByMaster {ksid.empty()};
    if(callByMaster)
    {
        ksid = CreateEtsi004KeyStreamSession(srcSaeId, dstSaeId, inQos, ksid); //Create new key stream session!
        nlohmann::json jOpenConnectResponse {{"Key_stream_ID", ksid}}; //Key_stream_ID in response!
        HTTPMessage httpMessage;
        httpMessage.CreateResponse(HTTPMessage::HttpStatus::Ok, jOpenConnectResponse.dump(), {
          {"Content-Type", "application/json; charset=utf-8"},
          {"Request URI", headerIn.GetUri() }
        });
        std::string hMessage = httpMessage.ToString();
        Ptr<Packet> packet = Create<Packet>(
         (uint8_t*)(hMessage).c_str(),
          hMessage.size()
        );
        NS_ASSERT(packet); 
        //SendToSocketPair(socket, packet);
        Simulator::Schedule(Seconds(0.015), &QKDKeyManagerSystemApplication::SendToSocketPair, this, socket, packet);
        NewAppRequest(ksid); //Send NEW_APP notification 
    }else{ //Request made by slave SAE!
      auto it = m_associations004.find(ksid);
      if(it == m_associations004.end()){
          NS_LOG_ERROR(this << "Key stream association identified with " << ksid << "does not exists!");

          //TEMP TEMP TEMP
          ksid = CreateEtsi004KeyStreamSession(srcSaeId, dstSaeId, inQos, ksid); //Create new key stream session!
          ProcessEtsi004OpenConnect(headerIn, socket);

          //@toDo error response
          //return;

      }else if((it->second).srcSaeId != srcSaeId){
          NS_LOG_ERROR(this << "KSID is not registered for this application" <<(it->second).dstSaeId << srcSaeId);
          //@toDo error response
          return;

      }else{
         (it->second).peerRegistered = true; //Change the sate of key stream session to active!
          RegisterRequest(ksid); //Send REGISTER notification
          HTTPMessage httpMessage;
          httpMessage.CreateResponse(HTTPMessage::HttpStatus::Ok, "", {
            {"Content-Type", "application/json; charset=utf-8"},
            {"Request URI", headerIn.GetUri() }
          });
          std::string hMessage = httpMessage.ToString();
          Ptr<Packet> packet = Create<Packet>(
           (uint8_t*)(hMessage).c_str(),
            hMessage.size()
          );
          NS_ASSERT(packet);
          SendToSocketPair(socket, packet); //Respond to SAE!
      }
    }
}

void
QKDKeyManagerSystemApplication::ProcessEtsi004GetKey(std::string ksid, HTTPMessage headerIn, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION( this << "Processing get_key request(ETSI 004)" << ksid );
  auto it = m_associations004.find(ksid);
  if(it == m_associations004.end())
  {
      NS_LOG_DEBUG( this << "Key stream association identified with " << ksid << "does not exists!" );

      //create packet
      HTTPMessage httpMessage;
      httpMessage.CreateResponse(HTTPMessage::HttpStatus::BadRequest, "", {
        {"Request URI", headerIn.GetUri() }
      });
      std::string hMessage = httpMessage.ToString();
      Ptr<Packet> packet = Create<Packet>(
       (uint8_t*)(hMessage).c_str(),
        hMessage.size()
      );
      NS_ASSERT(packet);

      SendToSocketPair(socket, packet);
      return;
  }

  //PeerRegistered must be true @toDo - first check this(in case of QKDApp004 this will never happen)
  NS_LOG_FUNCTION(this << "EMIRS" << it->second.stre_buffer->GetStreamKeyCount() << it->second.peerRegistered);
  
  if( it->second.peerRegistered && it->second.stre_buffer->GetStreamKeyCount())
  {
    NS_LOG_FUNCTION(this << "We have enough keys in buffer " << it->second.stre_buffer << " to server ETSI 004 GET_KEY request!");
    //Check
    Ptr<QKDKey> keyChunk = it->second.stre_buffer->GetStreamKey();
    if(GetNode()->GetId() < it->second.dstNodeId)
      CheckEtsi004Association(ksid); //Check if new keys need to be negotiated

    nlohmann::json jresponse {
      {"index", std::stoi(keyChunk->GetId())},
      {"Key_buffer", keyChunk->GetKeyString()}
    };
    //No Metadata
    std::string msg = jresponse.dump();

    //create packet
    HTTPMessage httpMessage;
    httpMessage.CreateResponse(HTTPMessage::HttpStatus::Ok, msg, {
      {"Content-Type", "application/json; charset=utf-8"},
      {"Request URI", headerIn.GetUri() }
    });
    std::string hMessage = httpMessage.ToString();
    Ptr<Packet> packet = Create<Packet>(
     (uint8_t*)(hMessage).c_str(),
      hMessage.size()
    );
    NS_ASSERT(packet);
    SendToSocketPair(socket, packet);

    m_keyConsumedLink( //Is always p2p link now for 004
      it->second.srcNodeId, //Source
      it->second.dstNodeId, //Destination
      //{ksid + keyChunk->GetId()},  //Key ID should be combination of ksid+index!
      keyChunk->GetSizeInBits() //Size of key
    ); 
  }else{
    //Respond with an error. Currently this is the only error on GetKey004, therefore no message is included. @toDo
    NS_LOG_FUNCTION(this 
      << "We are looking for keys in buffer " << it->second.stre_buffer << it->second.stre_buffer->GetDescription() << it->second.stre_buffer->GetRemoteNodeId() 
    );
    NS_LOG_FUNCTION(this << "No keys available in the association buffer. " << it->second.stre_buffer << " Responding on the request ...");

    auto itSchedule = m_scheduledChecks.find(ksid);
    if(itSchedule != m_scheduledChecks.end())
    {
      NS_LOG_FUNCTION(this << "The CheckEtsi004Association for ksid ("<< ksid << ") is already scheduled!");
    }else{ 
      NS_LOG_FUNCTION(this << GetNode()->GetId() << it->second.srcNodeId << it->second.dstNodeId); 
      //Only Master KMS can start Fill procedure
      if(GetNode()->GetId() < it->second.dstNodeId) //this is master KMS
        CheckEtsi004Association(ksid);
    }

    //create packet
    HTTPMessage httpMessage;
    httpMessage.CreateResponse(HTTPMessage::HttpStatus::BadRequest, "", {
      {"Request URI", headerIn.GetUri() }
    });
    std::string hMessage = httpMessage.ToString();
    Ptr<Packet> packet = Create<Packet>(
     (uint8_t*)(hMessage).c_str(),
      hMessage.size()
    );
    NS_ASSERT(packet);

    SendToSocketPair(socket, packet);
  }
}

void
QKDKeyManagerSystemApplication::ProcessEtsi004Close(std::string ksid, HTTPMessage headerIn, Ptr<Socket> socketIn)
{
    NS_LOG_FUNCTION( this << "Processing CLOSE request ... " << ksid );
    auto it = m_associations004.find(ksid);
    if(it == m_associations004.end()){
      NS_LOG_DEBUG( this << "Key stream association identified with " << ksid << "does not exists!" );
      return;
    }

    HttpQuery query;
    query.method_type = ETSI_QKD_004_KMS_CLOSE; //Close made to peer KMS
    query.ksid = ksid; //Remember ksid
    if(it->second.stre_buffer->GetStreamKeyCount()){
        query.surplus_key_ID = GenerateUUID(); //Generate keyId to empty key stream association
        query.sync_index = it->second.stre_buffer->GetNextIndex(); //Take the first index in the buffer!
    }

    NS_LOG_FUNCTION( this << "Releasing key stream association buffer. Synchronizing with peer KMS ..." );
    CheckSocketsKMS((it->second).dstKmsAddr ); //Check connection to peer KMS!
    Ptr<Socket> socket = GetSocketKMS((it->second).dstKmsAddr );
    NS_ASSERT(socket);

    nlohmann::json msgBody;
    if(!query.surplus_key_ID.empty()){
        msgBody["surplus_key_ID"] = query.surplus_key_ID;
        msgBody["sync_index"] = query.sync_index;
    }
    std::string msg = msgBody.dump();

    std::string headerUri = "http://" + GetAddressString((it->second).dstKmsAddr); //Uri starts with destination KMS address
    headerUri += "/api/v1/associations/close_kms/" + ksid;

    //Create packet
    HTTPMessage httpMessage;
    httpMessage.CreateRequest(headerUri, "POST", msg);
    std::string hMessage = httpMessage.ToString();
    Ptr<Packet> packet = Create<Packet>(
     (uint8_t*)(hMessage).c_str(),
      hMessage.size()
    );
    NS_ASSERT(packet); 
    HttpKMSAddQuery((it->second).dstKmsAddr, query); //Save this query made to the peer KMS! 
    SendToSocketPairKMS(socket, packet); 
    NS_LOG_FUNCTION( this << "Synchronization information for releasing key stream association sent to peer KMS"
                          << packet->GetUid() << packet->GetSize() );

}

void
QKDKeyManagerSystemApplication::ScheduleCheckEtsi004Association(Time t, std::string action, std::string ksid)
{
    NS_LOG_FUNCTION(this << "Scheduling new event in an attempt to fill association buffer " << ksid << " ..."); 
    if(action == "CheckEtsi004Association")
    { 
      auto it = m_scheduledChecks.find(ksid);
      if(it==m_scheduledChecks.end())
      {
        EventId event = Simulator::Schedule(t, &QKDKeyManagerSystemApplication::CheckEtsi004Association, this, ksid); 
        m_scheduledChecks.insert( std::make_pair( ksid ,  event) );
        NS_LOG_FUNCTION(this << "NEW event successfully scheduled!" << action << ksid << t);        
      } else {
        NS_LOG_FUNCTION(this << "Event already scheduled!" << action << ksid);        
      }
    }else
        NS_FATAL_ERROR(this << "Invalid action as the function input recived " << action);
}

void
QKDKeyManagerSystemApplication::CheckEtsi004Association(std::string ksid)
{
  NS_LOG_FUNCTION(this << ksid);

  auto itSchedule = m_scheduledChecks.find(ksid);
  if(itSchedule!=m_scheduledChecks.end())
    m_scheduledChecks.erase(itSchedule);

  auto it = m_associations004.find(ksid);
  if(it == m_associations004.end()){
    NS_LOG_DEBUG(this << "unknown ksid" << ksid);
    return; 
  }
  uint32_t dstKmNodeId = it->second.dstNodeId;

  Ptr<SBuffer> sBufferPQC = nullptr;
  if(m_pqc_enabled)
  {
    sBufferPQC = GetSBuffer(dstKmNodeId, "pqc");
    if(!sBufferPQC)
    { 
      NS_LOG_FUNCTION(this << "The S-Buffer (PQC) does not exists! This is new virtual connection!");  
      sBufferPQC = CreateSBuffer(GetNode()->GetId(), dstKmNodeId, "(PQC)", "pqc"); 
      m_keys_pqc.insert(std::make_pair(dstKmNodeId, sBufferPQC)); 
    }
    NS_ASSERT(sBufferPQC);
  }

  if(
    (it->second.peerRegistered && (it->second).stre_buffer->GetStreamKeyCount() < 2) || //QKD
    (m_pqc_enabled && sBufferPQC && sBufferPQC->GetSKeyCount() < 2)                     //PQC
  )
  { 
    //Check
    /**
     * @toDo
     * The amount of key material to be assigned to the association must be determined by the QoS parameters.
     */
    QKDLocationRegisterEntry conn = GetController()->GetRoute(dstKmNodeId);
    uint32_t nextHopKMSId = conn.GetNextHop();
    NS_LOG_FUNCTION(this << "Fetched route to " << dstKmNodeId << " via " << nextHopKMSId );

    Ptr<QBuffer> qBuffer = GetQBuffer(nextHopKMSId);
    uint32_t availableKeys = qBuffer->GetBitCount();
    uint32_t availableKeyChunks = (availableKeys && it->second.qos.chunkSize) ? std::floor(availableKeys / it->second.qos.chunkSize) : 0;

    NS_LOG_FUNCTION(this << availableKeys << " via " << nextHopKMSId << it->second.qos.chunkSize << availableKeyChunks);

    if(availableKeyChunks >= 6){
      NS_LOG_FUNCTION(this << "Fill only 6 keys at time!");
      availableKeyChunks = 6; 
    } else if(availableKeyChunks >= 2){
      NS_LOG_FUNCTION(this << "Fill with available amount - 1!");
      availableKeyChunks--; 
    } else if(availableKeyChunks == 0){
      NS_LOG_FUNCTION(this << "Shedule new attempt!");
      ScheduleCheckEtsi004Association(Time("2s"), "CheckEtsi004Association", ksid); 
      return;
    }

    NS_LOG_FUNCTION(this << "Starts reservation of keys for the association!");
    uint32_t amountToFill = availableKeyChunks*it->second.qos.chunkSize;
  
    if(conn.GetHop() == 1)
    {
      NS_LOG_FUNCTION(this 
        << " We are on the point-to-point connection! Let's start FILL procedure!" 
        << dstKmNodeId
        << nextHopKMSId
      );

      Ptr<QBuffer> qBuffer = GetQBuffer(dstKmNodeId); 
      NS_ASSERT(qBuffer);

      Fill(
        dstKmNodeId, 
        ksid, 
        amountToFill,
        qBuffer
      );

    }else{

      NS_LOG_FUNCTION(this 
        << "We are on the virtual RELAY connection! Let's start check RELAY and FILL procedure!" 
        << dstKmNodeId
        << nextHopKMSId
      );

      Ptr<SBuffer> relayBuffer = GetSBuffer(dstKmNodeId, "enc");
      if(!relayBuffer)
      { 
        NS_LOG_FUNCTION(this << "The S-Buffer does not exists! This is new virtual connection!");
        uint32_t srcNodeId = GetNode()->GetId(); 
        relayBuffer = CreateSBuffer(srcNodeId, dstKmNodeId, "(RELAY)", "relay");
        m_keys_enc.insert(std::make_pair(dstKmNodeId, relayBuffer)); //Store a pointer to new sBuffer
        m_keys_dec.insert(std::make_pair(dstKmNodeId, relayBuffer)); //Store a pointer to new sBuffer 
      }
      NS_ASSERT(relayBuffer); 
      //Here, SBufferClientCheck check whether there are enough keys in relay buffer 
      SBufferClientCheck(dstKmNodeId);

      //Let's find etsi004 STREAM SBuffer based on KSID
      auto it = m_associations004.find(ksid);
      if(it == m_associations004.end())
          NS_LOG_ERROR(this << "Key stream association identified with " << ksid << "does not exists!"); 

      Ptr<SBuffer> streamBuffer = it->second.stre_buffer; 
      NS_ASSERT(streamBuffer);

      uint32_t demendForKeys = amountToFill * 1.2;

      if(relayBuffer->GetSBitCount() > demendForKeys) 
      {
        NS_LOG_FUNCTION(this << "Fill " << streamBuffer << " from relayBuffer " << relayBuffer << " with " << amountToFill << " bits!");
        NS_LOG_FUNCTION(this << "Avavilable keys: " << relayBuffer->GetSBitCount() << "\t" << relayBuffer->GetSKeyCount() );

        Fill(
          dstKmNodeId, 
          ksid, 
          amountToFill,
          relayBuffer
        ); 

      }else{        
        NS_LOG_FUNCTION(this 
          << "We cannot start FILL procedure from " 
          << relayBuffer << relayBuffer->GetDescription() << relayBuffer->GetRemoteNodeId() 
          << " and store keys to " 
          << streamBuffer << streamBuffer->GetDescription() << streamBuffer->GetRemoteNodeId()
          << " becase we have only " << relayBuffer->GetSBitCount() << "which is less then required " << demendForKeys
        );
        NS_LOG_FUNCTION(this << relayBuffer << " was in " << relayBuffer->GetState() << " state!"  << relayBuffer->GetBitCount()  << " -- " << relayBuffer->GetMthr() ); //Check s-buffer state
        //Here, let's update SThreshold 
        relayBuffer->SetMthr(demendForKeys);
        relayBuffer->CheckState(); 
        NS_LOG_FUNCTION(this << relayBuffer << " is NOW in " << relayBuffer->GetState() << " state!"  << relayBuffer->GetBitCount()  << " -- " << relayBuffer->GetMthr() ); //Check s-buffer state

        NS_LOG_FUNCTION(this << streamBuffer << " was in " << streamBuffer->GetState() << " state!"  << streamBuffer->GetBitCount()  << " -- " << streamBuffer->GetMthr() ); //Check s-buffer state
        streamBuffer->SetMthr(demendForKeys);
        streamBuffer->CheckState();
        NS_LOG_FUNCTION(this << streamBuffer << " is NOW in " << streamBuffer->GetState() << " state!"  << streamBuffer->GetBitCount()  << " -- " << streamBuffer->GetMthr() ); //Check s-buffer state

        SBufferClientCheck(dstKmNodeId);
      }
    }

  }else if(!it->second.peerRegistered)
    NS_LOG_ERROR(this << "peer not registered " << ksid);

}

////////////////////////
/// STORE KEY
////////////////////////

void QKDKeyManagerSystemApplication::ProcessStoreKey(HTTPMessage headerIn, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this);

  std::string payload = headerIn.GetMessageBodyString(); //Read payload
  nlohmann::json payloadContent;
  try{
    payloadContent = nlohmann::json::parse(payload); //Parse payload to JSON
  }catch(...){
    NS_LOG_FUNCTION( this << "JSON parse error!"); //Catch parse error
  }

  //Read JSON structure
  std::string keyValue, keyId, moduleId, matchingModuleId;
  if(payloadContent.contains("key_ID"))
    keyId = payloadContent["key_ID"]; //Read key ID(Mandatory)
  else{
    NS_LOG_ERROR(this << "QKD-key ID missing!");
    return;
  }
  if(payloadContent.contains("key")) 
  { 
    std::string keyValueBase64 = payloadContent["key"]; //Read key value(Mandatory)
    keyValue = m_encryptor->Base64Decode(keyValueBase64); //Read key value(Mandatory)
  }else{
    NS_LOG_ERROR(this << "QKD-key value missing!");
    return;
  }
  moduleId = payloadContent["qkd_module_ID"]; //Read local QKD module ID(Mandatory)
  matchingModuleId = payloadContent["matching_qkd_module_ID"]; //Read peer QKD module ID(Mandatory)

  NS_LOG_INFO(this << "\nRequest:\t" << "STORE_KEY"
                    << "\nKeyID:\t" << keyId
                    << "\nKeyValue:\t" << keyValue
                    << "\nKeySize(bits):\t" << keyValue.size()*8
                    << "\nQKD Module ID:\t" << moduleId
                    << "\nMatching QKD Module ID:\t" << matchingModuleId);

  /**
    * Currently we will go with the following idea:
    * - KM with a higher Node ID is selected as a master.
    * - Master and slave reformats keys to a default size for THIS connection!
    * - Master and slave KM store keys. Keys are marked as READY.
    *   Key IDs are:
    *     for master: HASH-SHA1(QKD-key ID | QKD module ID | matching QKD module ID | chunk number)
    *     for slave:  HASH-SHA1(QKD-key ID | matching QKD module ID | QKD module ID | chunk number)
    *
    * The verfication procedure is not implemented. It should be similar to a Q3P STORE subprotocol.
    */

  //Determine the destination KM node based on QKD module ID
  auto it = m_qkdmodules.find(moduleId);
  uint32_t dstNodeId;
  if(it!=m_qkdmodules.end())
    dstNodeId = it->second;
  else
    NS_FATAL_ERROR(this << "Unknown module ID");

  //Determine a KM role
  bool isMaster {false};
  if(GetNode()->GetId() < dstNodeId)
    isMaster = true; //This node, with higher node ID, takes role of a master!

  /**
    * In my opinion, KM should not transform the QKD-key in different block sizes,
    * but rather choose one, most appropriate. In fact, when provisioning keys,
    * KM would have to rendezvous with peer KM anyway, so the question is really
    * about key transformation operation and memory organization in key storage.
    *
    * @toDo How to choose this default key size?
    */
  Ptr<QBuffer> buffer = GetQBuffer(dstNodeId); //Select QKD buffer
  if(!buffer){
    NS_LOG_ERROR(this << "Buffer not found!");
    return;
  }
  Ptr<QKDEncryptor> encryptor = CreateObject<QKDEncryptor>(64); //64 bits long key IDs. Collisions->0
  uint32_t keySizeInBits = keyValue.size() ? keyValue.size()*8 : 0;
  if(isMaster)
    m_qkdKeyGeneratedTrace(moduleId, keyId, keySizeInBits);
  else
    m_qkdKeyGeneratedTrace(matchingModuleId, keyId, keySizeInBits);
  
  NS_LOG_FUNCTION(this << "keySizeInBytes:" << keyValue.size());

  NS_LOG_FUNCTION(this << "keySizeInBits:" << keySizeInBits);

  std::string hashInput;
  if(isMaster)
    hashInput = keyId + moduleId + matchingModuleId; //HASH input for master
  else
    hashInput = keyId + matchingModuleId + moduleId; //HASH input for slave
  NS_ASSERT(!hashInput.empty());

  uint16_t blockIndex {0};
  uint32_t blockSize {buffer->GetKeySize()/8}; //Current default key size for connection

  NS_LOG_FUNCTION(this << "blockSize:" << blockSize);

  while(!keyValue.empty())
  {
    std::string keyValueTemp {keyValue};
    if(keyValue.size() >= blockSize)
      keyValueTemp = keyValue.substr(0, blockSize); //Take portion of the QKD-key value for KMA-key
    std::string completeHashInput = hashInput + std::to_string(blockIndex); //Complete HASH input
    std::string blockKeyId {encryptor->SHA1(completeHashInput)}; //Generate KMA-key ID based on the HASH output
    Ptr<QKDKey> newKey = CreateObject<QKDKey>(blockKeyId, keyValueTemp); //Create a QKDKey object to represent KMA-key
    newKey->SetModuleId(moduleId);
    buffer->StoreKey(newKey); //Store KMA-key in QKD buffer
    keyValue.erase(0, blockSize); //Update QKD-key value
    blockIndex++;
  }

  UpdateLinkState(dstNodeId); //Update link state on generation for link UP.

  if(isMaster)
    SBufferClientCheck(dstNodeId); //We should check the state of the s-buffers now that there is fresh key material

}

void
QKDKeyManagerSystemApplication::ProcessPacketKMSs(HTTPMessage headerIn, Ptr<Packet> packet, Ptr<Socket> socket)
{
    NS_LOG_FUNCTION(this);
    if(headerIn.GetUri() != "") //Process request!
      ProcessRequestKMS(headerIn, socket);
    else //Process response!
      ProcessResponseKMS(headerIn, packet, socket);
}


void
QKDKeyManagerSystemApplication::ProcessRequestKMS(HTTPMessage headerIn, Ptr<Socket> socket)
{
    NS_LOG_FUNCTION(this);
    QKDKeyManagerSystemApplication::RequestType requestType;
    std::string s = headerIn.GetUri();
    std::string delimiter = "/";

    size_t pos = 0;
    std::string token;
    std::vector<std::string> uriParams;
    while((pos = s.find(delimiter)) != std::string::npos){
        token = s.substr(0, pos);
        if(!token.empty()){
            uriParams.push_back(token);
        }
        s.erase(0, pos + delimiter.length());
    }
    if(!s.empty()){
        uriParams.push_back(s);
    }
    requestType = FetchRequestType(uriParams[4]); // new_app, register, fill, transform_keys, close, relay_keys

    NS_LOG_FUNCTION(this << requestType);

    if(requestType == NEW_APP)
        ProcessNewAppRequest(headerIn, socket);
    else if(requestType == REGISTER){
        std::string ksid = uriParams[5];
        NS_ASSERT( !ksid.empty() );
        ProcessRegisterRequest(headerIn, ksid, socket);
    }else if(requestType == FILL){
        std::string resource = uriParams[3];
        ProcessFillRequest(headerIn, resource, socket);
    }else if(requestType == TRANSFORM_KEYS){
        ProcessSKeyCreateRequest(headerIn, socket);
    }else if(requestType == ETSI_QKD_004_KMS_CLOSE){
        std::string ksid = uriParams[5];
        NS_ASSERT( !ksid.empty() );
        ProcessKMSCloseRequest(headerIn, socket, ksid);
    }else if(requestType == RELAY_KEYS){
        ProcessRelayRequest(headerIn, socket);
    }else if(requestType == PQC_PUBLIC_KEY){
        ProcessPQCPublicKeyRequest(headerIn, socket);
    }else if(requestType == PQC_CIPHER){
        ProcessPQCCipherRequest(headerIn, socket);
    }else
        NS_FATAL_ERROR( this << "Invalid request made to this KMS!" );
}

void
QKDKeyManagerSystemApplication::ProcessResponseKMS(HTTPMessage headerIn, Ptr<Packet> packet, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION( this << "Processing peer KMS response" << headerIn.GetRequestUri());

  if(headerIn.GetRequestUri() != ""){
    std::vector<std::string> uriParams = ReadUri(headerIn.GetRequestUri());
    NS_LOG_FUNCTION(this << uriParams[4]);
    RequestType methodType = FetchRequestType(uriParams[4]);

    if(methodType == NEW_APP)
        ProcessNewAppResponse(headerIn, socket);
    else if(methodType == REGISTER)
        ProcessRegisterResponse(headerIn, socket);
    else if(methodType == FILL)
        ProcessFillResponse(headerIn, Ipv4Address(uriParams[0].c_str()));
    else if(methodType == TRANSFORM_KEYS)
        ProcessSKeyCreateResponse(headerIn, socket);
    else if(methodType == ETSI_QKD_004_KMS_CLOSE)
        ProcessKMSCloseResponse(headerIn, socket);
    else if(methodType == RELAY_KEYS)
        ProcessRelayResponse(headerIn);
    else if(methodType == PQC_PUBLIC_KEY)
        ProcessPQCPublicKeyResponse(headerIn, socket);
    else if(methodType == PQC_CIPHER)
        ProcessPQCCipherResponse(headerIn, socket); 
    else
      NS_FATAL_ERROR( this << "Invalid request method!" );
  }

}

 


Ptr<SBuffer>
QKDKeyManagerSystemApplication::CreateSBuffer(
  uint32_t srcNodeId, 
  uint32_t dstNodeId, 
  std::string description,
  std::string type
)
{
    NS_LOG_FUNCTION(this << srcNodeId << dstNodeId << description);
    Ptr<SBuffer> sBuffer = GetController()->CreateRSBuffer(dstNodeId); //QKDNController Create new S-Buffer
    if(type == "relay")
      sBuffer->SetType(SBuffer::Type::RELAY_SBUFFER); 
    else
      sBuffer->SetType(SBuffer::Type::PQC_SBUFFER);  

    sBuffer->Initialize();  
    sBuffer->SetDescription (description); 
    sBuffer->SetIndex( m_qbuffersVector.size() ); 
    
    m_qbuffersVector.push_back(sBuffer);
    m_qbuffers.insert(std::make_pair(dstNodeId, sBuffer) );

    Ptr<QKDKeyManagerSystemApplication> kms;
    uint32_t applicationIndex = 0;
    for(uint32_t i = 0; i < GetNode()->GetNApplications(); ++i)
    {
        kms = GetNode()->GetApplication(i)->GetObject <QKDKeyManagerSystemApplication>();
        applicationIndex = i;
        if(kms) break;
    }
    sBuffer->SetSrcKMSApplicationIndex(applicationIndex);

    //CREATE QKD GRAPH
    QKDGraphManager *QKDGraphManager = QKDGraphManager::getInstance();    
    std::string graphTitle;

    if(type == "relay")
      graphTitle = "SBUFFER (RELAY): " +  std::to_string(srcNodeId) + " - " + std::to_string(dstNodeId); 
    else
      graphTitle = "SBUFFER (PQC): " +  std::to_string(srcNodeId) + " - " + std::to_string(dstNodeId); 

    Ptr<Node> dstNode = NodeList::GetNode(dstNodeId); 
    QKDGraphManager->CreateGraphForBuffer(
      GetNode(), 
      dstNode,
      sBuffer->GetIndex(), 
      sBuffer->GetSrcKMSApplicationIndex(), 
      graphTitle, 
      "png",
      sBuffer
    );

    return sBuffer;
}

/**
 * ********************************************************************************************

 *        KMS-KMS functions

 * ********************************************************************************************
 */


////////////////////////
/// PQC
////////////////////////

// Encapsulate using peer's public key (raw bytes in pqcKeyDecoded).
// Returns ciphertext (binary string). Writes shared secret into outSharedSecret (binary).
std::vector<QKDKeyManagerSystemApplication::PqcPair>
QKDKeyManagerSystemApplication::PQCCipherOutput(const std::string& peerPubDecoded,
                                                uint32_t numberOfKeys)
{
  NS_LOG_FUNCTION(this << peerPubDecoded.size() << numberOfKeys);
  std::vector<QKDKeyManagerSystemApplication::PqcPair> out;
  out.reserve(numberOfKeys);

#ifdef QKDNETSIM_WITH_PQC
  oqs::KeyEncapsulation kem{m_PQCKem};
  oqs::bytes peerPub(peerPubDecoded.begin(), peerPubDecoded.end());

  for (uint32_t i = 0; i < numberOfKeys; ++i) {
    oqs::bytes ct, ss;
    std::tie(ct, ss) = kem.encap_secret(peerPub); 
    std::string secret(reinterpret_cast<const char*>(ss.data()), ss.size());
 
    std::string cipher(reinterpret_cast<const char*>(ct.data()), ct.size());
    std::string cipher_b64 = m_encryptor->Base64Encode(cipher);

    NS_LOG_DEBUG("Server shared secret (prefix): " << oqs::hex_chop(ss));

    std::string keyId = GenerateUUID();
    out.push_back(QKDKeyManagerSystemApplication::PqcPair{std::move(keyId), std::move(secret), std::move(cipher_b64)});
  }
#endif

  return out;
}

std::string 
QKDKeyManagerSystemApplication::PQCCipherInput(const std::string& input)
{       
  NS_LOG_FUNCTION(this);
  std::string output;

#ifdef QKDNETSIM_WITH_PQC
  oqs::bytes inputBytes(input.begin(), input.end()); 
  oqs::bytes sharedSecretClient = m_PQCkeyEncapsulation->decap_secret(inputBytes);
  NS_LOG_FUNCTION(this << "\n\nClient shared secret:\n" << oqs::hex_chop(sharedSecretClient) << "\n");
  return std::string(sharedSecretClient.begin(), sharedSecretClient.end());
#endif

  return output;
}


void 
QKDKeyManagerSystemApplication::GeneratePQCKeys(Ipv4Address peerKMSAddress, uint32_t dstNodeId, uint32_t numberOfKeyToGenerate)
{
  NS_LOG_FUNCTION (this << peerKMSAddress << numberOfKeyToGenerate);

  if(!m_pqc_enabled) return;

#ifdef QKDNETSIM_WITH_PQC

  uint32_t srcNodeId = GetNode()->GetId(); 
  NS_ASSERT(dstNodeId);

  std::ostringstream peerkmsAddressTemp;
  peerKMSAddress.Print(peerkmsAddressTemp); //IPv4Address to string
  std::string headerUri = "http://" + peerkmsAddressTemp.str(); //Uri starts with destination KMS address
  headerUri += "/api/v1/kms/kms_pqc_cipher";
 
  auto it = m_socketPairsKMS.find(peerKMSAddress);
  if( it == m_socketPairsKMS.end() )
    NS_LOG_ERROR("Unable to locate sockets for peer KMS address " << peerKMSAddress);

  if(it->second.PQCPublicKey.empty()) 
  {
    it->second.pqcStarted = 0;
    NS_LOG_FUNCTION(this << "We need to exchange PQC public keys with remote KMS!");

    if(!it->second.socket)
      CheckSocketsKMS(peerKMSAddress);

    SendPQCPublicKey(it->second.socket);
    return;
  }

  uint32_t keysToGenerate = std::min(numberOfKeyToGenerate, m_pqc_default_number_of_keys);
  auto pairs = PQCCipherOutput(it->second.PQCPublicKey, keysToGenerate);

  Ptr<SBuffer> sBuffer = GetSBuffer(dstNodeId, "pqc");
  if(!sBuffer)
  { 
    NS_LOG_FUNCTION(this << "The S-Buffer (PQC) does not exists! This is new virtual connection!");  
    sBuffer = CreateSBuffer(srcNodeId, dstNodeId, "(PQC)", "pqc"); 
    m_keys_pqc.insert(std::make_pair(dstNodeId, sBuffer)); 
  }
  NS_ASSERT(sBuffer);

  nlohmann::json keys = nlohmann::json::array();
  for (const auto& pr : pairs) 
  { 
    // Store SHARED SECRET locally, not the ciphertext
    Ptr<QKDKey> key = CreateObject<QKDKey>(pr.keyId, pr.secret);
    sBuffer->StoreKey(key, true);
    sBuffer->MarkKey(pr.keyId, QKDKey::INIT);
    NS_LOG_DEBUG("PQC key " << pr.keyId << " (" << key->GetSizeInBits() << " bits) stored");

    // Send ciphertext for peer decapsulation
    nlohmann::json item;
    item["key_id"]     = pr.keyId;
    item["pqc_cipher"] = pr.cipher_b64;   // base64
    keys.push_back(std::move(item));
  }

  nlohmann::json msgBody; 
  msgBody["src_kme_id"] = srcNodeId; 
  msgBody["dst_kme_id"] = dstNodeId; 
  msgBody["keys"]       = std::move(keys);
  std::string msg = msgBody.dump(); 

  HTTPMessage httpMessage;
  httpMessage.CreateRequest(headerUri, "POST", msg);
  std::string hMessage = httpMessage.ToString();
  Ptr<Packet> packet = Create<Packet>(
   (uint8_t*)(hMessage).c_str(),
    hMessage.size()
  );
  NS_ASSERT(packet);

  Ptr<Socket> socket = GetSocketKMS(peerKMSAddress); 
  SendToSocketPairKMS(socket, packet);
  NS_LOG_FUNCTION(this << "PQC_CIPHER sent to peer KM" << packet->GetUid() << packet->GetSize()); 

#endif

}


void
QKDKeyManagerSystemApplication::CheckPQCBuffer(Ipv4Address peerKMSAddress)
{
  NS_LOG_FUNCTION(this << peerKMSAddress);

  if(!m_pqc_enabled)
    return;

#ifdef QKDNETSIM_WITH_PQC

  std::string schheduledKey = "pqc_" + GetAddressString(peerKMSAddress);

  auto itSchedule = m_scheduledChecks.find(schheduledKey);
  if(itSchedule!=m_scheduledChecks.end())
    m_scheduledChecks.erase(itSchedule);

  auto it = m_socketPairsKMS.find(peerKMSAddress);
  if(it == m_socketPairsKMS.end()){
    CheckSocketsKMS(peerKMSAddress);
    NS_LOG_DEBUG(this << " unknown peerKMSAddress " << peerKMSAddress);
    return; 
  }
 
  uint32_t peerKMNodeId = GetPeerKmNodeId(peerKMSAddress); 
  NS_ASSERT(peerKMNodeId);

  Ptr<SBuffer> sBufferPQC = GetSBuffer(peerKMNodeId, "pqc"); 
  if(!sBufferPQC)
  { 
    NS_LOG_FUNCTION(this << "The S-Buffer (PQC) does not exists! This is new virtual connection!"); 
    sBufferPQC = CreateSBuffer(GetNode()->GetId(), peerKMNodeId, "(PQC)", "pqc");
    m_keys_pqc.insert(std::make_pair(GetNode()->GetId(), sBufferPQC)); //Store a pointer to new sBuffer
  } 
  NS_ASSERT(sBufferPQC);

  uint32_t availableKeys = sBufferPQC->GetSKeyCount(); 
  NS_LOG_FUNCTION(this << "availableKeys:" << availableKeys);

  uint32_t availableKeysBits = sBufferPQC->GetBitCount(); 
  NS_LOG_FUNCTION(this << "availableKeysBits:" << availableKeysBits);
  
  uint32_t keysToFill = 0;
  if(availableKeys <  m_pqc_default_number_of_keys)
  {
    keysToFill = m_pqc_default_number_of_keys-availableKeys;
    NS_LOG_FUNCTION(this << "Fill only " << keysToFill << " keys at time!");
  } else{
    NS_LOG_FUNCTION(this << "We have " << availableKeys << " which is more then " << m_pqc_default_number_of_keys);
    return;
  }
  NS_LOG_FUNCTION(this << "Starts new PQC key generation!");
  GeneratePQCKeys(peerKMSAddress, peerKMNodeId, keysToFill);

#endif

}

uint32_t
QKDKeyManagerSystemApplication::ComputePqcMixing(uint32_t requestedKeys, uint32_t qkdAvailableKeys)
{
    NS_LOG_FUNCTION(this << requestedKeys << qkdAvailableKeys << m_pqc_enabled << m_pqc_c);

#ifdef QKDNETSIM_WITH_PQC

    if (!m_pqc_enabled || !m_pqc_c) return requestedKeys; 

    NS_LOG_FUNCTION(this << "********* START PQC Optimal QKD Contribution ********* "); 
    NS_LOG_FUNCTION(this << "requestedKeys:" << requestedKeys);
    NS_LOG_FUNCTION(this << "qkdAvailableKeys:" << qkdAvailableKeys);
    NS_LOG_FUNCTION(this << "m_pqc_c:" << m_pqc_c);
 
    if (requestedKeys < 1) requestedKeys = 1;
    if (qkdAvailableKeys <= 0) {
      qkdAvailableKeys = 0;
      return 0;
    }

 
    //calculate single delta based on requestedKeys
    double delta = std::log2(m_pqc_c) / std::log2(std::log2(requestedKeys));
    NS_LOG_FUNCTION(this << "delta:" << delta);

    //Compute target size of n0 for this delta
    double n_target_size = std::pow(2.0, std::pow(m_pqc_c, 1.0 / delta));
    long long threshold_n0 = (n_target_size < (double)LLONG_MAX) ? (long long)std::ceil(n_target_size) : LLONG_MAX;
    NS_LOG_FUNCTION(this << "n_target_size:" << n_target_size << " threshold_n0:" << threshold_n0);

    //Compute percentage of requestedKeys (D16)
    double qkdKeys_d = std::pow(std::log2(n_target_size), delta + 1);
    NS_LOG_FUNCTION(this << "qkdKeys_d:" << qkdKeys_d);

    //Convert to uint32 and make divisible by 8
    uint32_t qkdKeysToUse = (uint32_t)std::llround(qkdKeys_d);
    qkdKeysToUse = (qkdKeysToUse / 8) * 8;
    qkdKeysToUse = std::min(qkdAvailableKeys, qkdKeysToUse);
    qkdKeysToUse = (qkdKeysToUse / 8) * 8;

    NS_LOG_FUNCTION(this << "qkdKeysToUse:" << qkdKeysToUse);
    return qkdKeysToUse;
#endif
    return 0;
}

void
QKDKeyManagerSystemApplication::SendPQCPublicKey(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << "*** 1 *** " << socket);
  NS_ASSERT(socket);

#ifdef QKDNETSIM_WITH_PQC
  std::map<Ipv4Address, KMSNode>::iterator it;
  for( it = m_socketPairsKMS.begin(); !(it == m_socketPairsKMS.end());  it++ )
  {

    NS_LOG_FUNCTION(this << "checking socket: " << it->second.socket << "\t" << it->second.pqcStarted);

    //we do not have info about KMS destination address ?
    if( it->second.socket == socket && !it->second.pqcStarted )
    {  
      it->second.pqcStarted = 1;
      std::ostringstream peerkmsAddressTemp;
      (it->second).address.Print(peerkmsAddressTemp); //IPv4Address to string
      std::string headerUri = "http://" + peerkmsAddressTemp.str(); //Uri starts with destination KMS address
      headerUri += "/api/v1/kms/kms_pqc_public_key";

      nlohmann::json msgBody; 
      msgBody["src_kme_id"] = GetNode()->GetId();
      msgBody["pqc_key"] = m_encryptor->Base64Encode (m_PQCPublicKey);  
      std::string msg = msgBody.dump();

      HTTPMessage httpMessage;
      httpMessage.CreateRequest(headerUri, "POST", msg);
      std::string hMessage = httpMessage.ToString();
      Ptr<Packet> packet = Create<Packet>(
       (uint8_t*)(hMessage).c_str(),
        hMessage.size()
      );
      NS_ASSERT(packet);
      SendToSocketPairKMS(socket, packet);
      NS_LOG_FUNCTION(this << "PQC_PUBLIC_KEY request sent to peer KM " << peerkmsAddressTemp.str() << "! PacketId: " << packet->GetUid() << packet->GetSize()); 

      return;
    }
  }
#endif

}

void QKDKeyManagerSystemApplication::ProcessPQCPublicKeyRequest(HTTPMessage headerIn, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << "*** 2 *** " << headerIn.GetUri());

#ifdef QKDNETSIM_WITH_PQC

  std::vector<std::string> uriParams {ReadUri(headerIn.GetUri())};
  
  std::string payload = headerIn.GetMessageBodyString();
  nlohmann::json payloadContent;
  try{
    payloadContent = nlohmann::json::parse(payload);
  }catch(...){
    NS_FATAL_ERROR( this << "JSON parse error!" );
  }

  uint32_t srcNodeId;
  uint32_t dstNodeId = GetNode()->GetId();
  if(payloadContent.contains("pqc_key") && payloadContent.contains("src_kme_id")) 
  { 
    srcNodeId = payloadContent["src_kme_id"]; 
    std::string keyValueBase64 = payloadContent["pqc_key"]; //Read key value(Mandatory)
    std::string keyVal = m_encryptor->Base64Decode(keyValueBase64); //Read key value(Mandatory)

    std::map<Ipv4Address, KMSNode>::iterator it;
    for( it = m_socketPairsKMS.begin(); !(it == m_socketPairsKMS.end());  it++ )
    {
      if(it->second.socket == socket) 
      {
        it->second.PQCPublicKey = keyVal;
        NS_LOG_FUNCTION(this << "PQC public key of " << it->second.address << " stored!");
 
        Ptr<SBuffer> sBuffer = GetSBuffer(srcNodeId, "pqc");
        if(!sBuffer)
        { 
          NS_LOG_FUNCTION(this << "The S-Buffer (PQC) does not exists! This is new virtual connection!"); 
          sBuffer = CreateSBuffer(dstNodeId, srcNodeId, "(PQC)", "pqc");
          m_keys_pqc.insert(std::make_pair(srcNodeId, sBuffer)); //Store a pointer to new sBuffer
        }
        NS_ASSERT(sBuffer); 
        NS_ASSERT(srcNodeId);

        nlohmann::json msgBody;  
        msgBody["src_kme_id"] = srcNodeId;  
        msgBody["dst_kme_id"] = dstNodeId;
        msgBody["pqc_key"] = m_encryptor->Base64Encode (m_PQCPublicKey);  
        std::string msg = msgBody.dump(); 

        //create packet
        HTTPMessage httpMessage;
        httpMessage.CreateResponse(HTTPMessage::HttpStatus::Ok, msg, {
          {"Content-Type", "application/json; charset=utf-8"},
          {"Request URI", headerIn.GetUri() }
        });
        std::string hMessage = httpMessage.ToString();
        Ptr<Packet> packet = Create<Packet>(
         (uint8_t*)(hMessage).c_str(),
          hMessage.size()
        );
        NS_ASSERT(packet);
        NS_LOG_FUNCTION(this << "Answering with my PQC Public key!");
        SendToSocketPairKMS(socket, packet);

        return; 
      } 
    }

  }else{
    NS_LOG_ERROR(this << "KMS NODE node detected!");
    return;
  }

#endif

}

void QKDKeyManagerSystemApplication::ProcessPQCPublicKeyResponse(HTTPMessage headerIn, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << "*** 3 *** " << headerIn.GetUri());

#ifdef QKDNETSIM_WITH_PQC

  std::vector<std::string> uriParams {ReadUri(headerIn.GetUri())};
  
  std::string payload = headerIn.GetMessageBodyString();
  nlohmann::json payloadContent;
  try{
    payloadContent = nlohmann::json::parse(payload);
  }catch(...){
    NS_FATAL_ERROR( this << "JSON parse error!" );
  } 
  
  uint32_t srcNodeId = GetNode()->GetId();
  uint32_t dstNodeId;

  if(payloadContent.contains("pqc_key") && 
    payloadContent.contains("src_kme_id") && 
    payloadContent.contains("dst_kme_id")
  )
  {
    dstNodeId = payloadContent["dst_kme_id"];
    NS_LOG_FUNCTION(this << srcNodeId);
    NS_LOG_FUNCTION(this << payloadContent["src_kme_id"]);
    NS_ASSERT(srcNodeId == payloadContent["src_kme_id"]);

    std::string keyValueBase64 = payloadContent["pqc_key"]; //Read key value(Mandatory)
    std::string publicKeyVal = m_encryptor->Base64Decode(keyValueBase64); //Read key value(Mandatory)
 
    std::map<Ipv4Address, KMSNode>::iterator it;
    for( it = m_socketPairsKMS.begin(); !(it == m_socketPairsKMS.end());  it++ )
    {
      if(it->second.socket == socket) 
      {
        it->second.PQCPublicKey = publicKeyVal;
        NS_LOG_FUNCTION(this << "PQC public key of " << it->second.address << " (Node " << dstNodeId << ") successfully generated!"); 

        GeneratePQCKeys(it->second.address, dstNodeId, m_pqc_default_number_of_keys); 
        return;
      } 
    }

  }else{
    NS_LOG_ERROR(this << "KMS connection not found!");
    return;
  }

#endif

}

void QKDKeyManagerSystemApplication::ProcessPQCCipherRequest(HTTPMessage headerIn, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << "*** 4 *** " << headerIn.GetUri());

#ifdef QKDNETSIM_WITH_PQC

  std::vector<std::string> uriParams {ReadUri(headerIn.GetUri())};
   
  const std::string payload = headerIn.GetMessageBodyString();
  nlohmann::json j;
  try {
    j = nlohmann::json::parse(payload);
  } catch (...) {
    NS_FATAL_ERROR(this << "JSON parse error!");
  }

  // Expected shape:
  // { "src_kme_id": <uint>, "dst_kme_id": <uint>, "keys": [ { "key_id": "...", "pqc_cipher": "BASE64..." }, ... ] }
  if (!j.contains("src_kme_id") || !j.contains("dst_kme_id") || !j.contains("keys") || !j["keys"].is_array()) {
    NS_LOG_ERROR(this << "Invalid PQC_CIPHER payload shape");
    return;
  }

  const uint32_t srcNodeId = j["src_kme_id"];
  const uint32_t dstNodeId = GetNode()->GetId();
  NS_ASSERT(dstNodeId == j["dst_kme_id"]);

  // Process each item
  nlohmann::json ack = nlohmann::json::array();
  size_t storedCount = 0;
  
  Ptr<SBuffer> sBuffer = GetSBuffer(srcNodeId, "pqc"); 
  NS_ASSERT(sBuffer);

  for (const auto& item : j["keys"]) 
  {
    if (!item.contains("key_id") || !item.contains("pqc_cipher"))
    {
      NS_LOG_ERROR(this << "Skipping malformed item (missing key_id/pqc_cipher)");
      continue;
    }

    const std::string keyId   = item["key_id"].get<std::string>();
    const std::string ct_b64  = item["pqc_cipher"].get<std::string>();

    // Decode and decapsulate
    std::string ct_bin;
    try {
      ct_bin = m_encryptor->Base64Decode(ct_b64);  // Handles stray newlines if your encoder inserts them
    } catch (...) {
      NS_LOG_ERROR(this << "Base64 decode failed for key_id=" << keyId << " (skipping)");
      continue;
    }
 

    // Store shared secret under provided key_id
    std::string secret_bin;
    Ptr<QKDKey> key = CreateObject<QKDKey>(keyId, secret_bin);
    key->SwitchToState(QKDKey::READY);
    bool isStored = sBuffer->StoreKey(key, true);

    if(isStored)
    {
      ++storedCount;
      NS_LOG_DEBUG(this << "Stored PQC key " << keyId << " (" << key->GetSizeInBits() << " bits), READY");

      // Build ACK entry
      nlohmann::json ackItem;
      ackItem["key_id"] = keyId;  
      ack.push_back(std::move(ackItem));
    }else{
      NS_LOG_DEBUG(this << "WARNING: UNABLE to STORE PQC key " << keyId << " (" << key->GetSizeInBits() << " bits)!");
    }
  }

  // Build response
  nlohmann::json resp;
  resp["src_kme_id"] = srcNodeId;   // echo back sender as src
  resp["dst_kme_id"] = dstNodeId;   // us
  resp["ack"]        = std::move(ack);
  resp["stored"]     = storedCount;

  std::string msg = resp.dump();

  HTTPMessage httpMessage;
  httpMessage.CreateResponse(HTTPMessage::HttpStatus::Ok, msg, {
    {"Content-Type", "application/json; charset=utf-8"},
    {"Request URI", headerIn.GetUri()}
  });

  const std::string hMessage = httpMessage.ToString();
  Ptr<Packet> packet = Create<Packet>(reinterpret_cast<const uint8_t*>(hMessage.data()), hMessage.size());
  NS_ASSERT(packet);

  NS_LOG_FUNCTION(this << "Answering PQC_CIPHER with ACKs; stored_keys=" << storedCount << ". PacketId: " << packet->GetUid() << " of size: " << packet->GetSize() << "\n");
  //std::cout << "Answering PQC_CIPHER with ACKs; stored_keys=" << storedCount << ". PacketId: " << packet->GetUid() << " of size: " << packet->GetSize() << "\n";
  SendToSocketPairKMS(socket, packet);

  // Clear pqcStarted flag for this peer entry
  for (auto& [ip, node] : m_socketPairsKMS) {
    if (node.socket == socket) {
      NS_LOG_FUNCTION(this << "Mark pqcStarted = 0");
      node.pqcStarted = 0;
      break;
    }
  }

#endif

}

void QKDKeyManagerSystemApplication::ProcessPQCCipherResponse (HTTPMessage headerIn, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << "*** 5 *** " << headerIn.GetUri());

#ifdef QKDNETSIM_WITH_PQC

  // Parse JSON
  const std::string payload = headerIn.GetMessageBodyString();
  nlohmann::json j;
  try {
    j = nlohmann::json::parse(payload);
  } catch (...) {
    NS_FATAL_ERROR(this << "JSON parse error!");
  }

  if (headerIn.GetStatus() != HTTPMessage::HttpStatus::Ok) {
    NS_LOG_ERROR(this << "Non-OK HTTP status in PQC_CIPHER response: " << int(headerIn.GetStatus()));
    return;
  }
  
  // Expected shape:
  // { "src_kme_id": <uint>, "dst_kme_id": <uint>, "ack": [ { "key_id": "...", "status": "ok"|"error" }, ... ], "stored": <uint> }
  if (!j.contains("src_kme_id") || !j.contains("dst_kme_id") || !j.contains("ack") || !j["ack"].is_array()) {
    NS_LOG_ERROR(this << "Invalid PQC_CIPHER response shape");
    return;
  }

  const uint32_t localId = GetNode()->GetId();
  const uint32_t srcId   = j["src_kme_id"];
  const uint32_t dstId   = j["dst_kme_id"];

  // We originated the request, so response src_kme_id must equal our nodeId
  NS_ASSERT(localId == srcId);

  Ptr<SBuffer> sBuffer = GetSBuffer(dstId, "pqc");
  if(!sBuffer) {
    NS_LOG_ERROR(this << "S-Buffer (PQC) not found for peer " << dstId << " in response; cannot mark keys");
    return;
  }

  size_t okCount = 0, skipCount = 0;
  for(const auto& item : j["ack"]) 
  {
    if(!item.contains("key_id"))
    {
      ++skipCount;
      continue;
    }
    const std::string keyId = item["key_id"].get<std::string>();
    sBuffer->MarkKey(keyId, QKDKey::READY);   
    okCount++;  
  }
  NS_LOG_FUNCTION(this << "PQC_CIPHER response processed: ok=" << okCount << " skip=" << skipCount);
  NS_LOG_FUNCTION(this << "Now we have in PQC buffer with " << dstId << " in total (keys): " << sBuffer->GetSKeyCount() << sBuffer->GetSBitCount() );

  // Clear pqcStarted flag for this peer entry
  for(auto& [ip, node] : m_socketPairsKMS) 
  {
    if (node.socket == socket) 
    {
      NS_LOG_FUNCTION(this << "Mark pqcStarted = 0");
      node.pqcStarted = 0;
      break;
    }
  }

#endif

}
 


////////////////////////
/// KMS-KMS RELAY
////////////////////////
void
QKDKeyManagerSystemApplication::Relay(uint32_t dstKmNodeId, uint32_t amount)
{
  NS_LOG_FUNCTION(this << "START RELAY TO " << dstKmNodeId << " to RELAY " << amount << " bits");

  if(amount == 0)
  {
    NS_LOG_FUNCTION(this << "Source cannot perform relay due to the lack of key material!");
    return;
  }

  QKDLocationRegisterEntry conn = GetController()->GetRoute(dstKmNodeId); //Get connection details
  NS_LOG_FUNCTION(this << "NEXT HOP:" << conn.GetNextHop());

  //QKDLocationRegisterEntry conn = GetController()->GetRoute(dstKmNodeId); //Get connection details 
  Ptr<SBuffer> relayBuffer = GetSBuffer(dstKmNodeId, "enc");
  NS_ASSERT(relayBuffer);
  if(relayBuffer->IsRelayActive())
  {
    NS_LOG_FUNCTION(this << "RELAY ACTIVE");
    return;
  } else {
    NS_LOG_FUNCTION(this << "RELAY was NOT ACTIVE");
    relayBuffer->SetRelayState(true);
  }

  Ptr<SBuffer> localBuffer = m_keys_enc.find(conn.GetNextHop())->second; //Get LOCAL_SBUFFER
  NS_ASSERT(localBuffer);

  //Obtain necessary amount of keys from LOCAL_SBUFFER, Mark them as INIT, stored them in RELAY_SBUFFER
  //NOTE: Keys must be in default size! We now assume all Q(and S) buffers have same default key size!
  //      We will extend this with relay and skey_create combined!
  //      Greater the amount, greater the possibility of relay to fail!
  //      Similar to SECOQC -- use of TCP congestion -- we should implement
  //      incremental key relay until it failes, and then decrease it if it does!
  nlohmann::json relayPayload; //RELAY method payload -- This is RELAY-BEGIN
  std::vector<std::string> keyIds {};
  relayPayload["source_node_id"] = GetNode()->GetId(); //This KM node ID
  relayPayload["destination_node_id"] = conn.GetDestinationKmNodeId(); //Destination KM node ID
  relayPayload["encryption_type"] = "OTP"; //Only OTP is supported now

  if(relayBuffer->GetBitCount() + amount > relayBuffer->GetMmax())
  { 
    NS_LOG_FUNCTION(this << "BUFFER IS FULL! We are unable to add more relayed keys!");
    return;
  }


  bool stored = false;
  while(true)
  {
    Ptr<QKDKey> key = localBuffer->GetKey(relayBuffer->GetKeySize()); //Get key from sBuffer(key MUST be in default size!)
    NS_ASSERT(key); 
    NS_LOG_FUNCTION(this 
        << "RELAY:  we fetched key " << key->GetId() << key->GetStateString() 
        << " from LOCAL sourceBuffer " << localBuffer << localBuffer->GetDescription() << localBuffer->GetRemoteNodeId() 
      );
    if(key->GetState() != QKDKey::READY)
    {
      NS_LOG_FUNCTION(this 
        << "BUT it was not READY! So, we returned it back."
      );
      localBuffer->StoreKey(key, true);;
      continue;
    } 
 
    relayPayload["keys"].push_back({ {"key_ID", key->GetId()} }); //Add keyId object to JSON
    keyIds.push_back(key->GetId());
    NS_LOG_FUNCTION(this << "key state" << key->GetState());
    //First store the key to relay SBuffer and trigger QKDPlot (new key added)
    stored = relayBuffer->StoreKey(key, true); //Store keys to RELAY_SBUFFER
    if(!stored)
    {
      NS_LOG_FUNCTION(this << relayBuffer->GetRemoteNodeId() << "\t" << relayBuffer->GetDescription() );
 
      uint32_t dstKeyCount = relayBuffer->GetSKeyCount();
      uint32_t dstMmax = relayBuffer->GetMmax();
      uint32_t dstSBufferBits = relayBuffer->GetDefaultKeyCount()*relayBuffer->GetKeySize(); //Available amount of key material in LOCAL_SBUFFER
      NS_LOG_FUNCTION(this << relayBuffer << " How many keys in dst S-Buffer" << dstKeyCount
                           << "\nHot many bits in dst S-Buffer" << dstSBufferBits
                           << "\ndst SBuffer Max:" << dstMmax
                     );

      localBuffer->StoreKey(key, true); //Store keys to RELAY_SBUFFER
      NS_FATAL_ERROR(this << "Unable to store key to buffer!!" << key->GetId() ); 
      break;
    }else{   
      NS_LOG_FUNCTION(this << "relay key added" << key->GetId());

      NS_LOG_FUNCTION(this 
        << "Take key " << key->GetId() << key->GetStateString() 
        << " from LOCAL sourceBuffer " << localBuffer << localBuffer->GetDescription() << localBuffer->GetRemoteNodeId()
        << " and store it in RELAY sBuffer " 
        << relayBuffer << relayBuffer->GetDescription() << relayBuffer->GetRemoteNodeId()
      );
      //Then mark the key as INIT and also trigger QKDPlot (key removed)
      relayBuffer->MarkKey(key->GetId(), QKDKey::INIT); //Keys are marked INIT until relay is completed! 
      m_keyConsumedRelay(
        GetNode()->GetId(),
        GetNode()->GetId(),
        conn.GetNextHop(),
        key->GetSizeInBits()
      );
    }

    //if(key->GetSizeInBits() + relayBuffer->GetBitCount() > amount) //To be sure that we not exceed capacity of S-Buffer
    if(key->GetSizeInBits() + relayBuffer->GetKeySize() > amount) //To be sure that we not exceed capacity of S-Buffer
      break;
    else
      amount -= key->GetSizeInBits();
  }

  if(GetNode()->GetId() < conn.GetNextHop()) //this is master KMS //if not master, the relay request will trigger check
    SBufferClientCheck(conn.GetNextHop()); //run sbuffer client check for LOCAL Sbuffer

  Ipv4Address nextHopAddress = GetPeerKmAddress(conn.GetNextHop());
  std::string headerUri = "http://" + GetAddressString(nextHopAddress);
  headerUri += "/api/v1/keys/relay";

  std::string reqId {GenerateUUID()}; //HTTP request ID! Help parameter for simulation of proxies!
  headerUri += "/?req_id=/" + reqId; //We include our Request ID in URI. It helps map responses in chain of proxies.

  std::string msg = relayPayload.dump();

  NS_LOG_FUNCTION(this << "relay_uri: " << headerUri);
  NS_LOG_FUNCTION(this << "relay msg: " << msg);

  //Create packet
  HTTPMessage httpMessage;
  httpMessage.CreateRequest(headerUri, "POST", msg);
  std::string hMessage = httpMessage.ToString();
  Ptr<Packet> packet = Create<Packet>(
   (uint8_t*)(hMessage).c_str(),
    hMessage.size()
  );
  NS_ASSERT(packet);

  CheckSocketsKMS( nextHopAddress ); //Check connection to peer KMS!
  Ptr<Socket> socket = GetSocketKMS( nextHopAddress );
  NS_ASSERT(socket);

  /**
   * Chain of responsibility pattern. HTTP chain of proxies!
   */
  HttpQuery query;
  query.req_id = reqId;
  query.method_type = RELAY_KEYS;
  query.peerNodeId = dstKmNodeId;
  query.prev_hop_id = GetNode()->GetId(); //Previous is ME, response reached ME!
  query.keyIds = keyIds;
  HttpProxyRequestAdd(query);
  SendToSocketPairKMS(socket, packet);
}

void
QKDKeyManagerSystemApplication::ProcessRelayRequest(HTTPMessage headerIn, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << headerIn.GetUri());
  std::vector<std::string> uriParams {ReadUri(headerIn.GetUri())};
  std::string reqId = uriParams[6];
  NS_LOG_FUNCTION(this << reqId);

  std::string payload = headerIn.GetMessageBodyString();
  nlohmann::json jRelayPayload;
  try{
    jRelayPayload = nlohmann::json::parse(payload);
  }catch(...){
    NS_FATAL_ERROR( this << "JSON parse error!" );
  }

  uint32_t srcNodeId {0}, dstNodeId {0};
  if(jRelayPayload.contains("source_node_id"))
    srcNodeId = jRelayPayload["source_node_id"];
  if(jRelayPayload.contains("destination_node_id"))
    dstNodeId = jRelayPayload["destination_node_id"];
  NS_ASSERT(srcNodeId && dstNodeId);
  NS_LOG_FUNCTION(this << srcNodeId << GetNode()->GetId() << dstNodeId);

  bool terminateRelay {false};
  std::vector<std::string> keyIds {}, keys {};
  if(!jRelayPayload.contains("repeater_node_id"))
  { 
    NS_LOG_FUNCTION(this << "Is this first node in path?");
    Ptr<SBuffer> sBuffer = GetSBuffer(srcNodeId, "dec"); //Get decryption buffer!
    NS_ASSERT(sBuffer);
    std::string keyId;
    for(nlohmann::json::iterator it = jRelayPayload["keys"].begin(); it != jRelayPayload["keys"].end(); ++it)
    {
      //Ptr<QKDKey> key = sBuffer->QBuffer::GetKey((it.value())["key_ID"] );
      keyId = (it.value())["key_ID"];
      Ptr<QKDKey> key = sBuffer->GetKey(keyId);
      //First error: no keys to relay on first hop(not normal case)
      if(!key){
        NS_LOG_FUNCTION(this << "Relay key with ID" <<(it.value())["key_ID"] << "not found! Relay is terminated!");
        terminateRelay = true;
        continue;
        //continue to spent same key material(easy version)
        //(harder: first hop can move keys back to S-Buffer, and same will be done at source!)
      }
      if(key->GetState() != QKDKey::READY)
      {
        NS_LOG_FUNCTION(this 
          << "BUT it was not READY! So, we returned it back."
        );
        sBuffer->StoreKey(key, true);;
        terminateRelay = true;
        continue;
      } 

      NS_LOG_FUNCTION(this << "\nFirstNode -> Relay key -> ID: " << key->GetId()
                           << "\nFirstNode -> Relay key -> key: " << key->GetKeyString());
      keyIds.push_back(key->GetId());
      keys.push_back(key->GetKeyString());
    }

    if(GetNode()->GetId() < srcNodeId)//this is master KMS
      SBufferClientCheck(srcNodeId); //run sbuffer client check for LOCAL Sbuffer

  }else{ //Read {KeyId, eKey, eKeyId}, decrypt eKey!

    NS_LOG_FUNCTION(this << "Read {KeyId, eKey, eKeyId}, decrypt eKey!");

    uint32_t previousNodeId = jRelayPayload["repeater_node_id"];
    std::vector<std::string> ekeys {}, ekeyIds {};
    Ptr<SBuffer> decBuffer = GetSBuffer(previousNodeId, "dec");
    NS_ASSERT(decBuffer); 
    std::string keyId;
    for(nlohmann::json::iterator it = jRelayPayload["keys"].begin(); it != jRelayPayload["keys"].end(); ++it)
    {
      ekeys.push_back((it.value())["ekey"] );
      ekeyIds.push_back((it.value())["ekey_ID"] );
      keyIds.push_back((it.value())["key_ID"] );
      //Get ekey_ID
      //Ptr<QKDKey> key = decBuffer->QBuffer::GetKey((it.value())["ekey_ID"] );
      keyId = (it.value())["ekey_ID"];
      Ptr<QKDKey> key = decBuffer->GetKey(keyId);
      if(!key){
        //Second error: no keys to decrypt relay keys(not normal case)
        NS_LOG_FUNCTION(this << "Decryption key with ID" <<(it.value())["ekey_ID"] << "is not found! Relay is terminated!");
        terminateRelay = true;
      }
      keys.push_back( m_encryptor->COTP(key->GetKeyString(),(it.value())["ekey"]) );
    }

    if(GetNode()->GetId() < previousNodeId) //this is master KMS
      SBufferClientCheck(previousNodeId); //run sbuffer client check for LOCAL Sbuffer
  }

  //If it is relay node encrypt keys to next Hop
  if(GetNode()->GetId() != dstNodeId && !terminateRelay)//0
  {
    NS_LOG_FUNCTION(this << "Forwarding relay");
    QKDLocationRegisterEntry conn = GetController()->GetRoute(dstNodeId);
    Ptr<SBuffer> encBuffer = GetSBuffer(conn.GetNextHop(), "enc");
    NS_ASSERT(encBuffer);

    uint32_t availableKeysCount = encBuffer->GetDefaultKeyCount(keyIds.size());
    //Third error: no keys to forward relay!(common case -> should be tested before obtaining actual keys!)
    //Check the availability of keys at forwarding QKD link!
    NS_LOG_FUNCTION(this << "zzz:" << availableKeysCount << keyIds.size() );
    if(encBuffer->GetDefaultKeyCount(keyIds.size()) != keyIds.size())
    {
      terminateRelay = true;
      uint32_t previousNodeId;
      if(jRelayPayload.contains("repeater_node_id")){ //Is this first node in path?
        previousNodeId = jRelayPayload["repeater_node_id"];
      }else{
        if(jRelayPayload.contains("source_node_id"))
          previousNodeId = jRelayPayload["source_node_id"];
      }
      NS_LOG_FUNCTION(this << previousNodeId);
      //Onda je dovoljno pratiti waste na source node kao vezu source-this node
      //m_keyWasteRelay( previousNodeId, GetNode()->GetId(), keyIds.size()*encBuffer->GetKeySize() );

      NS_LOG_FUNCTION(this << "Relay Failed!");
      //Respond with error! Include Node ID in response!
      nlohmann::json jrelayResponse{ {"node-id", GetNode()->GetId()} };
      std::string msg = jrelayResponse.dump();
      //create packet
      HTTPMessage httpMessage;
      httpMessage.CreateResponse(HTTPMessage::HttpStatus::BadRequest, msg, {
        {"Request URI", headerIn.GetUri() }
      });
      std::string hMessage = httpMessage.ToString();
      Ptr<Packet> packet = Create<Packet>(
       (uint8_t*)(hMessage).c_str(),
        hMessage.size()
      );
      NS_ASSERT(packet);

      NS_LOG_FUNCTION(this << "Sending response" << packet->GetUid() << packet->GetSize() );
      Ipv4Address peerAddress = GetPeerKmAddress(previousNodeId);
      //Ipv4Address peerAddress = GetController()->GetRoute(previousNodeId).GetNextHopAddress();
      Ptr<Socket> socket = GetSocketKMS(peerAddress);
      SendToSocketPairKMS(socket, packet);
      return;

    }
 
    nlohmann::json jRelay;
    uint32_t encDefaultKeySize = encBuffer->GetKeySize();
    for(uint32_t i = 0; i < keyIds.size(); i++)
    {
      NS_LOG_FUNCTION(this << i << keyIds.size() << encDefaultKeySize);
      Ptr<QKDKey> encKey = encBuffer->GetKey(encDefaultKeySize); //Get key with default key size!
      if(encKey){
        NS_LOG_FUNCTION(this << "\nMiddleNode -> Relay key -> eKeyId" << encKey->GetId()
                             << "\nMiddleNode -> Relay key -> keyId" << keyIds[i]);
        std::string encryptedKey = m_encryptor->COTP(encKey->GetKeyString(), keys[i]); //key, input
        NS_LOG_FUNCTION(this << "\nMiddleNode -> Relay key -> ekey" << encryptedKey);
        jRelay["keys"].push_back({ {"key_ID", keyIds[i]}, {"ekey_ID", encKey->GetId()}, {"ekey", encryptedKey} });
        m_keyConsumedRelay(
          GetNode()->GetId(),
          GetNode()->GetId(),
          conn.GetNextHop(),
          encKey->GetSizeInBits()
        );
      }
    }
    if(GetNode()->GetId() < conn.GetNextHop()) //this is master KMS
      SBufferClientCheck(conn.GetNextHop()); //run sbuffer client check for LOCAL Sbuffer

    jRelay["source_node_id"] = srcNodeId;
    jRelay["destination_node_id"] = dstNodeId;
    jRelay["repeater_node_id"] = GetNode()->GetId();

    //m_keyConsumedRelay( GetNode()->GetId(), GetNode()->GetId(), conn.GetNextHop(), keyIds.size()*encBuffer->GetKeySize() );

    Ipv4Address nextHopAddress = GetPeerKmAddress(conn.GetNextHop());
    std::string headerUri = "http://" + GetAddressString(nextHopAddress);
    headerUri += "/api/v1/keys/relay/?req_id=/" + reqId;
    std::string msg = jRelay.dump();

    //Create packet
    HTTPMessage httpMessage;
    httpMessage.CreateRequest(headerUri, "POST", msg);
    std::string hMessage = httpMessage.ToString();
    Ptr<Packet> packet = Create<Packet>(
     (uint8_t*)(hMessage).c_str(),
      hMessage.size()
    );
    NS_ASSERT(packet);

    CheckSocketsKMS( nextHopAddress ); //Check connection to peer KMS!
    Ptr<Socket> socket = GetSocketKMS( nextHopAddress );

    HttpQuery query;
    query.method_type = RELAY_KEYS; //Relay
    query.req_id = reqId;
    query.peerNodeId = conn.GetNextHop(); //Peer -- next hop
    if(jRelayPayload.contains("repeater_node_id"))
      query.prev_hop_id = jRelayPayload["repeater_node_id"];
    else
      query.prev_hop_id = srcNodeId;

    query.request_uri = headerIn.GetUri();
    HttpProxyRequestAdd(query);
    SendToSocketPairKMS(socket, packet);
    NS_LOG_FUNCTION(this << "Packet sent" << conn.GetNextHop()
                          << packet->GetUid() << packet->GetSize());

  }else if(!terminateRelay)
  {
    //Destination reached
    NS_LOG_FUNCTION(this << "Destination reached!");
    NS_LOG_FUNCTION(this << "srcNodeId:" << srcNodeId);
    Ptr<SBuffer> sBuffer = GetSBuffer(srcNodeId, "dec");
    if(!sBuffer)
    { 
      NS_LOG_FUNCTION(this << "The S-Buffer does not exists! This is new virtual connection!"); 
      uint32_t dstNodeId = GetNode()->GetId();
      sBuffer = CreateSBuffer(dstNodeId, srcNodeId, "(RELAY)", "relay");
      m_keys_enc.insert(std::make_pair(srcNodeId, sBuffer)); //Store a pointer to new sBuffer
      m_keys_dec.insert(std::make_pair(srcNodeId, sBuffer)); //Store a pointer to new sBuffer 
    }
    NS_ASSERT(sBuffer);
    NS_LOG_FUNCTION(this << keyIds.size() << keys.size());
    bool saved = false;
    for(uint32_t i = 0; i < keyIds.size(); i++){ //Add keys to RELAY_SBUFFER -- "dec"
      Ptr<QKDKey> key = CreateObject<QKDKey>(keyIds[i], keys[i]);
      saved = sBuffer->StoreKey(key, true);

      NS_LOG_FUNCTION(this << sBuffer->GetRemoteNodeId() << "\t" << sBuffer->GetDescription() );
      uint32_t dstKeyCount = sBuffer->GetSKeyCount();
      uint32_t dstMmax = sBuffer->GetMmax();
      uint32_t dstSBufferBits = sBuffer->GetDefaultKeyCount()*sBuffer->GetKeySize(); //Available amount of key material in LOCAL_SBUFFER
      NS_LOG_FUNCTION(this << sBuffer << " How many keys in dst S-Buffer" << dstKeyCount
                           << "\nHot many bits in dst S-Buffer" << dstSBufferBits
                           << "\ndst SBuffer Max:" << dstMmax
                     ); 
      if(!saved)
      { 
        NS_FATAL_ERROR(this << "Unable to store keys to buffer!!" << keyIds[i]);
        break;
      }else{        
        NS_LOG_FUNCTION(this << "Relayed key " << keyIds[i] << " successfully stored in buffer " << sBuffer << sBuffer->GetRemoteNodeId() << "\t" << sBuffer->GetDescription() );
      }
    }
    //@toDo Response to prev_hop

    //create packet
    HTTPMessage httpMessage;
    httpMessage.CreateResponse(HTTPMessage::HttpStatus::Ok, "", {
      {"Content-Type", "application/json; charset=utf-8"},
      {"Request URI", headerIn.GetUri() }
    });
    std::string hMessage = httpMessage.ToString();
    Ptr<Packet> packet = Create<Packet>(
     (uint8_t*)(hMessage).c_str(),
      hMessage.size()
    );
    NS_ASSERT(packet);

    uint32_t previousNodeId = jRelayPayload["repeater_node_id"]; //It has this field for sure!!!
    Ipv4Address peerAddress = GetPeerKmAddress(previousNodeId);

    NS_LOG_FUNCTION( this 
      << "Sending response" 
      << headerIn.GetUri()
      << packet->GetUid() 
      << packet->GetSize() 
      << "previousNodeId:" 
      << previousNodeId 
      << "peerAddress:" 
      << peerAddress 
      << hMessage
    );

    Ptr<Socket> socket = GetSocketKMS(peerAddress);
    NS_ASSERT(socket);
    SendToSocketPairKMS(socket, packet);
  }
}

void
QKDKeyManagerSystemApplication::ProcessRelayResponse(HTTPMessage headerIn)
{

  std::vector<std::string> uriParams = ReadUri(headerIn.GetRequestUri());
  std::string payload = headerIn.GetMessageBodyString();
  std::string reqId = uriParams[6];
  Ipv4Address from = uriParams[0].c_str();
  NS_LOG_FUNCTION(this << reqId << from);

  HttpQuery sQuery = GetProxyQuery(reqId); //Find query!
  uint32_t prevHop = sQuery.prev_hop_id; //Get previous node

  if(prevHop != GetNode()->GetId())
  {
    HTTPMessage httpMessage;
    httpMessage.CreateResponse(headerIn.GetStatus(), payload, {
      {"Content-Type", "application/json; charset=utf-8"},
      {"Request URI", sQuery.request_uri }
    });
    std::string hMessage = httpMessage.ToString();
    Ptr<Packet> packet = Create<Packet>(
     (uint8_t*)(hMessage).c_str(),
      hMessage.size()
    );
    NS_ASSERT(packet);
 
    //PrevHopAddress? for now we take it from routing table! if routing is changed it will not work!
    Ipv4Address peerAddress = GetPeerKmAddress(prevHop);
    //Ipv4Address peerAddress = GetController()->GetRoute(prevHop).GetNextHopAddress();
    CheckSocketsKMS(peerAddress);
    Ptr<Socket> socket = GetSocketKMS(peerAddress);
    NS_ASSERT(socket);
    NS_LOG_FUNCTION( this << "Forwarding response" << packet->GetUid() << packet->GetSize() );
    SendToSocketPairKMS(socket, packet);

  }else{

    //Response have reached the source
    NS_LOG_FUNCTION(this << "Response have reached the source!" << headerIn.GetStatus());
    
    Ptr<SBuffer> relayBuffer = GetSBuffer(sQuery.peerNodeId, "enc");

    NS_ASSERT(relayBuffer);
    std::vector<std::string> keyIds = sQuery.keyIds;
    bool fail {headerIn.GetStatus() != HTTPMessage::HttpStatus::Ok};

    NS_LOG_FUNCTION(this << "Store keys in Sbuffer " << relayBuffer << relayBuffer->GetDescription() << relayBuffer->GetRemoteNodeId());

    NS_LOG_FUNCTION(this << "\nAmount of key material in RELAY s-buffer (READY) BEFORE relay confirmation: " << relayBuffer->GetSBitCount() << " peer: " << sQuery.peerNodeId);  
    uint32_t dstKeyCount = relayBuffer->GetSKeyCount();
    uint32_t dstMmax = relayBuffer->GetMmax();
    uint32_t dstSBufferBits = relayBuffer->GetDefaultKeyCount()*relayBuffer->GetKeySize(); //Available amount of key material in LOCAL_SBUFFER
    NS_LOG_FUNCTION(this << "How many keys in dst S-Buffer" << dstKeyCount
                         << "\nHot many bits in dst S-Buffer" << dstSBufferBits
                         << "\ndst SBuffer Max:" << dstMmax << " \npeer: " << sQuery.peerNodeId   
                   );

    for(const auto& keyId : keyIds)
    {
      if(headerIn.GetStatus() == HTTPMessage::HttpStatus::Ok)
      {
        NS_LOG_FUNCTION(this << "since relay " << reqId << " SUCCEDED, we mark key " << keyId << " as READY in sBuffer " 
          << relayBuffer << relayBuffer->GetDescription() << relayBuffer->GetRemoteNodeId()
        ); 
        relayBuffer->MarkKey(keyId, QKDKey::READY);
      }else{
        /*nlohmann::json jrelayResponse;
        try{
          jrelayResponse = nlohmann::json::parse(payload);
        }catch(...){
          NS_FATAL_ERROR(this << "JSON parse error!");
        }
        uint32_t dstNodeFail;
        if(jrelayResponse.contains("node-id"))
          dstNodeFail = jrelayResponse["node-id"];
        else
          NS_LOG_ERROR(this << "Response is missing mandatory 'node-id' value!");
        m_keyWasteRelay(GetNode()->GetId(), dstNodeFail, relayBuffer->GetKeySize());*/
        NS_LOG_FUNCTION(this << "since relay " << reqId << " FAILED, we mark key " << keyId << " as OBSOLETE in sBuffer " 
          << relayBuffer << relayBuffer->GetDescription() << relayBuffer->GetRemoteNodeId()
        );
        relayBuffer->MarkKey(keyId, QKDKey::OBSOLETE);
      }
    }
    relayBuffer->SetRelayState(false);
    NS_LOG_FUNCTION(this << "\nAmount of key material in RELAY s-buffer (READY) AFTER relay confirmation: " << relayBuffer->GetSBitCount() << " peer: " << sQuery.peerNodeId);  
    dstKeyCount = relayBuffer->GetSKeyCount();
    dstMmax = relayBuffer->GetMmax();
    dstSBufferBits = relayBuffer->GetDefaultKeyCount()*relayBuffer->GetKeySize(); //Available amount of key material in LOCAL_SBUFFER
    NS_LOG_FUNCTION(this << "How many keys in dst S-Buffer" << dstKeyCount
                         << "\nHot many bits in dst S-Buffer" << dstSBufferBits
                         << "\ndst SBuffer Max:" << dstMmax << " \npeer: " << sQuery.peerNodeId   
                   );
    if(fail){
      //SBufferClientCheck(sQuery.peerNodeId);
      NS_LOG_FUNCTION(this << "relay fail");
    }
  }

  RemoveProxyQuery(reqId);
}




////////////////////////
/// KMS-KMS FILL
////////////////////////

void
QKDKeyManagerSystemApplication::Fill(
  uint32_t dstKmNodeId,
  std::string direction,//or ksid
  uint32_t amount,
  Ptr<QBuffer> sourceBuffer
) {
  NS_LOG_FUNCTION(this << dstKmNodeId << direction << amount);

  if(!amount)return;

  Ipv4Address peerAddress = GetPeerKmAddress(dstKmNodeId);

  Ptr<SBuffer> sBuffer; 
  if (direction == "enc" || direction == "dec")
  {
    sBuffer = GetSBuffer(dstKmNodeId, direction);
    NS_ASSERT(sBuffer);
  }
  else
  {
    auto it = m_associations004.find(direction);
    if (it == m_associations004.end())
      NS_FATAL_ERROR(this << "Unknown key stream session " << direction); 
    sBuffer = it->second.stre_buffer; 
  }

  NS_LOG_FUNCTION(this << "We have sBuffer " << direction << " to " << sBuffer->GetRemoteNodeId());
  
  // =========================
  // PAYLOAD INIT
  // =========================
  nlohmann::json fillPayload;
  std::vector<std::string> keyIds;

  fillPayload["source_node_id"] = GetNode()->GetId();

  if (direction == "enc")
    fillPayload["s_buffer_type"] = "dec";
  else if (direction == "dec")
    fillPayload["s_buffer_type"] = "enc";
  else
  {
    fillPayload["s_buffer_type"] = "stream";
    fillPayload["ksid"] = direction;
  }

  // =========================
  // PQC buffer init
  // =========================
  Ptr<SBuffer> sBufferPQC = nullptr;
  if (m_pqc_enabled)
  {
    sBufferPQC = GetSBuffer(dstKmNodeId, "pqc");
    if (!sBufferPQC)
    {
      sBufferPQC = CreateSBuffer(GetNode()->GetId(), dstKmNodeId, "(PQC)", "pqc");
      m_keys_pqc.insert({dstKmNodeId, sBufferPQC});
    }
    NS_ASSERT(sBufferPQC);
  }

  // =========================
  // STATE SNAPSHOT (IMPORTANT)
  // =========================
  uint32_t availableQKD = sourceBuffer->GetBitCount();
  uint32_t availablePQC = sBufferPQC ? sBufferPQC->GetSBitCount() : 0;
  uint32_t requestedAmount = amount;
  NS_LOG_FUNCTION(this << "requested=" << requestedAmount
                       << "available QKD=" << availableQKD
                       << "available PQC=" << availablePQC);

  // ==========================================================
  // 1. DETERMINE QKD / PQC SPLIT (DETERMINISTIC RULE)
  // ==========================================================

  uint32_t qkdAmount = 0;
  uint32_t pqcAmount = 0;

  if (sourceBuffer->GetState() == 0 && availableQKD >= requestedAmount)
  {
    qkdAmount = requestedAmount;
    pqcAmount = 0;
  }
  else if(requestedAmount <= availableQKD + availablePQC)
  {
    qkdAmount = ComputePqcMixing(requestedAmount, availableQKD);
    pqcAmount = requestedAmount - qkdAmount;

    NS_LOG_FUNCTION(this << "qkdKeysToUse: " << qkdAmount);
    NS_LOG_FUNCTION(this << "pqcKeysToUse: " << pqcAmount);

    if(availablePQC < pqcAmount)
    {
      NS_LOG_FUNCTION(this << "We do not have enough PQC keys!" << availablePQC << " < " << pqcAmount);
      CheckPQCBuffer(peerAddress);
      return;
    }
    if(availableQKD < qkdAmount)
    {
      NS_LOG_FUNCTION(this << "We do not have enough QKD keys!" << availableQKD << " < " << qkdAmount);
      ScheduleCheckEtsi004Association(Time("2s"), "CheckEtsi004Association", direction);
      return;
    }

  }else{

    NS_LOG_FUNCTION(this << "We do not enough QKD+PQC keys!");

    // ==========================================================
    // 2. VALIDATION
    // ==========================================================
    if (availableQKD < requestedAmount)
    {
      NS_LOG_FUNCTION(this << "We do not have enough QKD keys!" << availableQKD << " < " << requestedAmount);
      ScheduleCheckEtsi004Association(Time("2s"), "CheckEtsi004Association", direction);
    }

    if (m_pqc_enabled && (!pqcAmount || availablePQC < pqcAmount))
    {
      NS_LOG_FUNCTION(this << "We do not have enough PQC keys!" << availablePQC << " < " << pqcAmount);
      CheckPQCBuffer(peerAddress);
    }
    return;
  }

  if(pqcAmount)
    NS_LOG_FUNCTION(this << "We HAVE enough PQC keys!" << availablePQC << " > " << pqcAmount);

  if(qkdAmount)
    NS_LOG_FUNCTION(this << "We HAVE enough QKD keys!" << availableQKD << " > " << qkdAmount);
  
  fillPayload["amount_qkd"] = qkdAmount;
  fillPayload["amount_pqc"] = pqcAmount;

  // ==========================================================
  // 3. KEY SELECTION (DETERMINISTIC LIST)
  // ==========================================================
  std::vector<std::string> qkdKeys;
  std::vector<std::string> pqcKeys;

  bool keyStored = false;

  //QKD
  uint64_t qkdRemaining = qkdAmount;
  while (qkdRemaining > 0)
  {
    NS_LOG_FUNCTION(this << "We have in sourceBuffer " << sourceBuffer->GetBitCount() << " and we need " << qkdRemaining << sourceBuffer->GetInstanceTypeId().GetName() );
    Ptr<QKDKey> key;

    if(sourceBuffer->GetInstanceTypeId().GetName() == "ns3::QBuffer")
    {
      key = sourceBuffer->GetKey();
    }else{
      Ptr<SBuffer> sbTemp = DynamicCast<SBuffer>(sourceBuffer);
      key = sbTemp->GetTransformCandidate(0);
    }
    NS_ASSERT(key);
    if(key->GetState() != QKDKey::READY)
    {
      NS_LOG_FUNCTION(this 
        << "BUT it was not READY! So, we returned it back."
      );
      sourceBuffer->StoreKey(key, true);; 
      continue;
    } 

    NS_LOG_FUNCTION(this 
      << "Take key " << key->GetId() << key->GetStateString() 
      << " from sourceBuffer " << sourceBuffer << sourceBuffer->GetDescription() << sourceBuffer->GetRemoteNodeId()
      << " and store it in sBuffer " 
      << sBuffer << sBuffer->GetDescription() << sBuffer->GetRemoteNodeId()
    );
    NS_ASSERT(key->GetStateString() == "READY");
    uint32_t take = std::min(key->GetSizeInBits(), qkdRemaining);

    qkdKeys.push_back(key->GetId());
    keyIds.push_back(key->GetId());
    fillPayload["keys"].push_back({{"key_ID", key->GetId()}}); 

    keyStored = sBuffer->StoreKey(key, true);
    if(!keyStored)
    {
      qkdAmount = 0;
      NS_LOG_FUNCTION(this << "Unable to store key " << key->GetId() << " in sBuffer " << sBuffer);
      break;
    }    
    sBuffer->MarkKey(key->GetId(), QKDKey::INIT); 
    qkdRemaining -= take;    
  }

  ///PQC 
  uint64_t pqcRemaining = pqcAmount;
  while (pqcRemaining > 0 && sBufferPQC)
  {
    Ptr<QKDKey> key = sBufferPQC->GetTransformCandidate(0);
    NS_ASSERT(key);

    NS_LOG_FUNCTION(this << "We fetched PQC key " << key->GetId() <<  " of size " << key->GetSizeInBits());
    uint32_t take = std::min(key->GetSizeInBits(), pqcRemaining);

    pqcKeys.push_back(key->GetId());
    keyIds.push_back(key->GetId());

    fillPayload["keys_pqc"].push_back({{"key_ID", key->GetId()}});
    sBufferPQC->StoreKey(key, true);
    sBufferPQC->MarkKey(key->GetId(), QKDKey::INIT);

    pqcRemaining -= take;
  }

  // ==========================================================
  // 4. SAFETY CHECK
  // ==========================================================
  if (fillPayload["keys"].empty())
  {
    NS_LOG_FUNCTION(this << "We do have NO QKD keys? Let's try to refill");
    ScheduleCheckEtsi004Association(Time("5s"), "CheckEtsi004Association", direction);
    return;
  }

  // ==========================================================
  // 5. FINALIZE REQUEST
  // ==========================================================
  UpdateLinkState(dstKmNodeId); 

  std::string headerUri = "http://" + GetAddressString(peerAddress) +
                          "/api/v1/sbuffers/fill";

  std::string msg = fillPayload.dump();

  HTTPMessage httpMessage;
  httpMessage.CreateRequest(headerUri, "POST", msg);
  std::string hMessage = httpMessage.ToString();
  Ptr<Packet> packet = Create<Packet>(
    (uint8_t*)hMessage.c_str(),
    hMessage.size()); 

  CheckSocketsKMS(peerAddress);
  Ptr<Socket> socketKMS = GetSocketKMS(peerAddress);

  HttpQuery query;
  query.method_type = FILL;
  query.peerNodeId = dstKmNodeId;
  query.sBuffer = direction;
  query.keyIds = keyIds;

  HttpKMSAddQuery(peerAddress, query);
  SendToSocketPairKMS(socketKMS, packet);

  NS_LOG_FUNCTION(this << "FILL sent QKD="
                       << qkdAmount
                       << " PQC="
                       << pqcAmount);
  NS_LOG_FUNCTION(this << "FILL msg: " << hMessage);
}


void
QKDKeyManagerSystemApplication::ProcessFillRequest(
  HTTPMessage headerIn,
  std::string resource,
  Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this);

  std::string payload = headerIn.GetMessageBodyString();
  nlohmann::json jFillPayload;

  try {
    jFillPayload = nlohmann::json::parse(payload);
  } catch (...) {
    NS_FATAL_ERROR(this << "JSON parse error!");
  }

  // =====================================================
  // CONTEXT
  // =====================================================

  uint32_t peerNodeId = 100000;
  std::string sBufferType;
  std::string ksid;

  if (jFillPayload.contains("source_node_id"))
    peerNodeId = jFillPayload["source_node_id"];

  if (jFillPayload.contains("s_buffer_type"))
    sBufferType = jFillPayload["s_buffer_type"];

  if (sBufferType == "stream") {
    if (jFillPayload.contains("ksid"))
      ksid = jFillPayload["ksid"];
    else
      NS_FATAL_ERROR(this << "Missing ksid");
  }

  NS_ASSERT(peerNodeId != 100000);
  Ptr<QBuffer> sourceBuffer = nullptr;  
  if(GetController()->GetRoute(peerNodeId).GetHop() == 1)
  { 
    sourceBuffer = GetQBuffer(peerNodeId);
  }else{ 
    sourceBuffer = GetSBuffer(peerNodeId, "enc");
  }
  
  Ptr<SBuffer> sBuffer;
  if (sBufferType != "stream") {
    sBuffer = GetSBuffer(peerNodeId, sBufferType);

    if (!sBuffer) {
      sBuffer = CreateSBuffer(
        GetNode()->GetId(),
        peerNodeId,
        "(RELAY)",
        "relay");

      m_keys_enc[peerNodeId] = sBuffer;
      m_keys_dec[peerNodeId] = sBuffer;
    }
  } else {
    auto it = m_associations004.find(ksid);
    if (it == m_associations004.end())
      NS_FATAL_ERROR(this << "Unknown ksid " << ksid);
    sBuffer = it->second.stre_buffer;
    NS_LOG_FUNCTION(this << "Found STREAM buffer with ksid " << ksid);
  }

  // =====================================================
  // RESPONSE
  // =====================================================

  bool storeSuccess = true;

  nlohmann::json result;
  result["keys_accepted"] = nlohmann::json::array();
  result["keys_rejected"] = nlohmann::json::array();
  result["keys_mixed"]    = nlohmann::json::array();

  //We need to pass KSID so peer KMS can identify the STREAM buffer to store the key!
  if(!ksid.empty()) result["ksid"] = ksid;

  bool pqcMixing =
    m_pqc_enabled &&
    jFillPayload.contains("keys_pqc") &&
    jFillPayload.contains("amount_qkd") &&
    jFillPayload.contains("amount_pqc");

  NS_LOG_FUNCTION(this << "pqcMixing enabled:" << pqcMixing);

  // =====================================================
  // OFFSETS (CRITICAL FIX)
  // =====================================================

  std::unordered_map<std::string, uint32_t> qkdOffsetBits;
  std::unordered_map<std::string, uint32_t> pqcOffsetBits;

  // =====================================================
  // CASE 1: SIMPLE QKD
  // =====================================================

  if (!pqcMixing)
  {
    for (auto &it : jFillPayload["keys"])
    {
      std::string keyId = it["key_ID"];

      Ptr<QKDKey> key = nullptr;
      if(sourceBuffer->GetKeyStatus(keyId) == QKDKey::READY)
        key = sourceBuffer->GetKey(keyId);

      if (!key) 
      {
        result["keys_rejected"].push_back({{"key_ID", keyId}});
        NS_LOG_FUNCTION(this << "key rejected:" << keyId);
        continue;
      }

      bool ok = true;
      if (sBufferType != "stream") 
      {
        NS_LOG_FUNCTION(this << "Store key " << keyId << " in buffer " << sBuffer << sBuffer->GetDescription() << sBuffer->GetRemoteNodeId());
        ok = sBuffer->StoreKey(key, true);
        if (ok)
        {
          NS_LOG_FUNCTION(this << "Mark key " << keyId << " READY in buffer " << sBuffer << sBuffer->GetDescription() << sBuffer->GetRemoteNodeId());
          sBuffer->MarkKey(keyId, QKDKey::READY);
        }
      } else {
        NS_LOG_FUNCTION(this << "InsertKeyToStreamSession " << keyId << " in buffer " << sBuffer << sBuffer->GetDescription() << sBuffer->GetRemoteNodeId());
        sBuffer->InsertKeyToStreamSession(key);
      }

      uint32_t fullBits = key->GetSizeInBits();
      uint32_t startBit = qkdOffsetBits[keyId];
      uint32_t takeBits = fullBits - startBit;
      uint32_t endBit = startBit + takeBits - 1;
      if (ok)
      {
        result["keys_accepted"].push_back({
          {"key_ID", keyId},
          {"start_bit", startBit},
          {"end_bit", endBit}
        });
        qkdOffsetBits[keyId] += takeBits; 

        std::string srcSaeId = "";
        std::string dstSaeId = "";
        auto itx = m_associations004.find(ksid);
        if(itx != m_associations004.end()){
          srcSaeId = itx->second.srcSaeId;
          dstSaeId = itx->second.dstSaeId;
        } 

        //fill
        m_keyServedTraceMixed(
          ksid,
          srcSaeId,
          dstSaeId,
          GetNode()->GetId(),
          peerNodeId,
          keyId, 
          takeBits, 
          std::string("qkd")
        );
      } else {

        NS_LOG_FUNCTION(this << "Not able to save key " << keyId << " in buffer " << sBuffer << " " << sBuffer->GetBitCount() << " " << sBuffer->GetMmax() );
        
        if(sourceBuffer->StoreKey(key, true))
        {
          NS_LOG_FUNCTION(this << "We returned key " << keyId << " back in buffer " << sourceBuffer);
        }

        result["keys_rejected"].push_back({
          {"key_ID", keyId},
          {"start_bit", startBit},
          {"end_bit", endBit}
        });
        storeSuccess = false;
      }
    }
  }

  // =====================================================
  // CASE 2: PQC + QKD MIX
  // =====================================================

  else
  {
    Ptr<SBuffer> sBufferPQC = GetSBuffer(peerNodeId, "pqc");

    if (!sBufferPQC) {
      sBufferPQC = CreateSBuffer(
        GetNode()->GetId(),
        peerNodeId,
        "(PQC)",
        "pqc");
      m_keys_pqc[peerNodeId] = sBufferPQC;
    }

    uint32_t amountQkd = jFillPayload["amount_qkd"];
    uint32_t amountPqc = jFillPayload["amount_pqc"];

    NS_ASSERT_MSG((amountQkd + amountPqc) % 8 == 0,
                  "Byte alignment required");

    uint32_t qRemaining = amountQkd;
    uint32_t pRemaining = amountPqc;

    std::string mixedBytes;

    std::vector<std::tuple<std::string,uint32_t,uint32_t>> qkdTrace;
    std::vector<std::tuple<std::string,uint32_t,uint32_t>> pqcTrace;

    // =================================================
    // QKD STREAM
    // =================================================

    for (auto &it : jFillPayload["keys"])
    {
      std::string keyId = it["key_ID"];
 
      Ptr<QKDKey> key = nullptr;
      if(sourceBuffer->GetKeyStatus(keyId) == QKDKey::READY)
      {
        key = sourceBuffer->GetKey(keyId);
        NS_LOG_FUNCTION(this 
          << "ProcessFillRequest:  we fetched key " << key->GetId() << key->GetStateString() 
          << " from sourceBuffer " << sourceBuffer << sourceBuffer->GetDescription() << sourceBuffer->GetRemoteNodeId() 
        );
      }else{  
        NS_LOG_FUNCTION(this 
          << "BUT it was not READY! So, we we didn't pick it up!"
        );
        result["keys_rejected"].push_back({{"key_ID", keyId}});
        continue; 
      } 
      NS_ASSERT(key);
      
      uint32_t fullBits = key->GetSizeInBits();
      if (qkdOffsetBits.find(keyId) == qkdOffsetBits.end())
        qkdOffsetBits[keyId] = 0;
      uint32_t startBit = qkdOffsetBits[keyId];

      if (startBit >= fullBits)continue;
      uint32_t take = std::min(fullBits - startBit, qRemaining);

      if (take == 0) break;
      uint32_t endBit = startBit + take - 1;
      NS_ASSERT_MSG(take % 8 == 0, "QKD byte alignment");

      mixedBytes += key->GetKeyString().substr(startBit / 8, take / 8);
      qkdTrace.push_back({keyId, startBit, endBit});
      qkdOffsetBits[keyId] += take;
      qRemaining -= take;

      NS_LOG_FUNCTION(this << "We fetched proposed QKD key " << keyId);

      std::string srcSaeId = "";
      std::string dstSaeId = "";
      auto itx = m_associations004.find(ksid);
      if(itx != m_associations004.end()){
        srcSaeId = itx->second.srcSaeId;
        dstSaeId = itx->second.dstSaeId;
      }

      //fill
      m_keyServedTraceMixed(
        ksid,
        srcSaeId, 
        dstSaeId,
        GetNode()->GetId(),
        peerNodeId,
        keyId, 
        take, 
        std::string("qkd")
      );
    }

    // =================================================
    // PQC STREAM
    // =================================================
    if (m_pqc_enabled)
    {
      for (auto &it : jFillPayload["keys_pqc"])
      {
        std::string keyId = it["key_ID"];

        Ptr<QKDKey> key = sBufferPQC->GetKey(keyId);
        if (!key) continue;

        uint32_t fullBits = key->GetSizeInBits();

        if (pqcOffsetBits.find(keyId) == pqcOffsetBits.end())
          pqcOffsetBits[keyId] = 0;

        uint32_t startBit = pqcOffsetBits[keyId];

        if (startBit >= fullBits)
          continue;

        uint32_t take = std::min(fullBits - startBit, pRemaining);

        if (take == 0)
          break;

        NS_ASSERT_MSG(take % 8 == 0, "PQC byte alignment");

        uint32_t endBit = startBit + take - 1;

        mixedBytes += key->GetKeyString().substr(startBit / 8, take / 8);

        pqcTrace.push_back({keyId, startBit, endBit});

        pqcOffsetBits[keyId] += take;
        pRemaining -= take;

        NS_LOG_FUNCTION(this << "We fetched proposed PQC key " << keyId);
        
        std::string srcSaeId = "";
        std::string dstSaeId = "";
        auto itx = m_associations004.find(ksid);
        if(itx != m_associations004.end()){
          srcSaeId = itx->second.srcSaeId;
          dstSaeId = itx->second.dstSaeId;
        }

        //fill
        m_keyServedTraceMixed(
          ksid,
          srcSaeId,
          dstSaeId,
          GetNode()->GetId(),
          peerNodeId,
          keyId, 
          take, 
          std::string("pqc")
        );
      }
    }

    // =================================================
    // BUILD MIXED KEYS
    // =================================================

    if (m_pqc_enabled)
    {
      uint32_t chunkBytes = sBuffer->GetKeySize() / 8;
      uint32_t offset = 0;

      while (offset < mixedBytes.size())
      {
        uint32_t len = std::min(chunkBytes, (uint32_t)mixedBytes.size() - offset);
        std::string chunk = mixedBytes.substr(offset, len);
        std::string mixedId = GenerateUUID();

        Ptr<QKDKey> mixedKey = CreateObject<QKDKey>(mixedId, chunk);

        SBuffer::MixedKey mk;
        mk.mixedKey = mixedKey;

        uint32_t remainingBits = len * 8;
        size_t qi = 0;
        while (qi < qkdTrace.size() && remainingBits > 0)
        {
          auto &q = qkdTrace[qi];

          uint32_t available = std::get<2>(q) - std::get<1>(q) + 1;
          uint32_t take = std::min(available, remainingBits);

          uint32_t start = std::get<1>(q);
          uint32_t end   = start + take - 1;

          mk.qkdKeyIds.push_back(std::get<0>(q));
          mk.qkdStartBits.push_back(start);
          mk.qkdEndBits.push_back(end);

          remainingBits -= take;
     
          if (take == available)
          {
            qkdTrace.erase(qkdTrace.begin() + qi);
          }
          else
          {
            std::get<1>(q) += take;
            qi++;
          }
     
          if (remainingBits == 0)
            break;
        }

        size_t pi = 0; 
        while (pi < pqcTrace.size() && remainingBits > 0)
        {
          auto &p = pqcTrace[pi];

          uint32_t available = std::get<2>(p) - std::get<1>(p) + 1;
          uint32_t take = std::min(available, remainingBits);

          uint32_t start = std::get<1>(p);
          uint32_t end   = start + take - 1;

          mk.pqcKeyIds.push_back(std::get<0>(p));
          mk.pqcStartBits.push_back(start);
          mk.pqcEndBits.push_back(end);

          remainingBits -= take;

          if (take == available)
          {
            pqcTrace.erase(pqcTrace.begin() + pi);
          }
          else
          {
            std::get<1>(p) += take;
            pi++;
          }

          if (remainingBits == 0)
            break;
        }

        NS_LOG_FUNCTION(this << "Storing mixed key : " << mixedId);
        sBufferPQC->StoreMixedKey(mixedId, mk);

        nlohmann::json jMk;
        jMk["key_ID"] = mixedId;

        // ======================
        // QKD TRACE EXPORT
        // ======================
        jMk["qkd"] = nlohmann::json::array();

        for (size_t i = 0; i < mk.qkdKeyIds.size(); i++)
        {
          jMk["qkd"].push_back({
            {"id", mk.qkdKeyIds[i]},
            {"start_bit", mk.qkdStartBits[i]},
            {"end_bit", mk.qkdEndBits[i]}
          });
        }

        // ======================
        // PQC TRACE EXPORT
        // ======================
        jMk["pqc"] = nlohmann::json::array();

        for (size_t i = 0; i < mk.pqcKeyIds.size(); i++)
        {
          jMk["pqc"].push_back({
            {"id", mk.pqcKeyIds[i]},
            {"start_bit", mk.pqcStartBits[i]},
            {"end_bit", mk.pqcEndBits[i]}
          });
        }

        // ======================
        // PUSH RESULT
        // ======================
        result["keys_mixed"].push_back(jMk);

        offset += len;
      }
    }
  }

  // =====================================================
  // FINAL STATUS
  // =====================================================

  result["status"] = storeSuccess ? "success" : "error";

  HTTPMessage httpMessage;

  httpMessage.CreateResponse(
    storeSuccess ? HTTPMessage::HttpStatus::Ok
                 : HTTPMessage::HttpStatus::NotAcceptable,
    result.dump(),
    {
      {"Content-Type", "application/json; charset=utf-8"},
      {"Request URI", headerIn.GetUri()}
    }
  );
  std::string msg = httpMessage.ToString();
  NS_LOG_FUNCTION(this << "Output message:" << msg);

  Ptr<Packet> packet =
    Create<Packet>((uint8_t*)msg.c_str(), msg.size());

  Ipv4Address peer = GetPeerKmAddress(peerNodeId);
  CheckSocketsKMS(peer);
  Ptr<Socket> sock = GetSocketKMS(peer);
  sock->Send(packet);
  m_txTraceKMSs(packet, GetNode()->GetId());
}

void
QKDKeyManagerSystemApplication::ProcessFillResponse(
  HTTPMessage headerIn,
  Ipv4Address from)
{
  NS_LOG_FUNCTION(this << headerIn.GetRequestUri());

  Ipv4Address dstKms { ReadUri(headerIn.GetRequestUri())[0].c_str() };
  auto itQuery = m_httpRequestsQueryKMS.find(dstKms);

  if (itQuery == m_httpRequestsQueryKMS.end() || itQuery->second.empty())
    NS_FATAL_ERROR(this << "Response cannot be mapped! HttpQuery empty!");

  HttpQuery query = itQuery->second[0];
  if (query.method_type != FILL) {
    NS_LOG_ERROR(this << "Invalid mapping");
    HttpKMSCompleteQuery(dstKms);
    return;
  }

  std::string payload = headerIn.GetMessageBodyString();
  nlohmann::json j;
  try {
    j = nlohmann::json::parse(payload);
  } catch (...) {
    NS_FATAL_ERROR(this << "JSON parse error");
  }

  std::string ksid;
  if (j.contains("ksid")) ksid = j["ksid"];
  NS_LOG_FUNCTION(this << " We received KSID " << ksid);

  uint32_t peerNodeId = query.peerNodeId;

  Ptr<QBuffer> sourceBuffer = nullptr;  
  if(GetController()->GetRoute(peerNodeId).GetHop() == 1)
  { 
    sourceBuffer = GetQBuffer(peerNodeId);
    NS_LOG_FUNCTION(this << peerNodeId << "sourceBuffer is QBuffer! " << sourceBuffer  );

  }else{ 
    sourceBuffer = GetSBuffer(peerNodeId, "enc");
    NS_LOG_FUNCTION(this << peerNodeId << "sourceBuffer is encSbuffer! " << sourceBuffer );
  }
  NS_ASSERT(sourceBuffer);

  std::string sBufferType = query.sBuffer;
  Ptr<SBuffer> sBuffer = nullptr; 
  if(sBufferType == "enc" || sBufferType == "dec")
  {
    sBuffer = GetSBuffer(peerNodeId, sBufferType);
    NS_LOG_FUNCTION(this << "dstBuffer is SBuffer! " << sBuffer);
  }else
  { 
    if(!ksid.empty())
    {
      auto it = m_associations004.find(ksid);
      if(it == m_associations004.end()){
        NS_LOG_DEBUG( this << "Key stream association identified with " << ksid << "does not exists!" );
        return;
      }
      sBuffer = it->second.stre_buffer;
      NS_LOG_FUNCTION(this << "1 dstBuffer is STREAM buffer!" << sBuffer);
    }else{   
      auto itA = m_associations004.find(sBufferType);
      if (itA == m_associations004.end())
        NS_FATAL_ERROR(this << "unknown ksid " << sBufferType);
      sBuffer = itA->second.stre_buffer;
      NS_LOG_FUNCTION(this << "2 dstBuffer is STREAM buffer!" << sBuffer);
    } 
  } 
  NS_ASSERT(sBuffer);

  Ptr<SBuffer> sBufferPQC = nullptr;
  if(m_pqc_enabled)
  {
    sBufferPQC = GetSBuffer(peerNodeId, "pqc");
    if (!sBufferPQC) {
      sBufferPQC = CreateSBuffer(GetNode()->GetId(), peerNodeId, "(PQC)", "pqc");
      m_keys_pqc[peerNodeId] = sBufferPQC;
    }
  }

  std::vector<std::string> keyIds = query.keyIds;

  // =========================================================
  // 1. ACCEPTED KEYS (UNCHANGED)
  // =========================================================
  if (j.contains("keys_accepted"))
  {
    for (auto &it : j["keys_accepted"])
    {
      std::string keyId = it["key_ID"];

      auto a = std::find(keyIds.begin(), keyIds.end(), keyId);
      if (a != keyIds.end()) keyIds.erase(a);

      NS_LOG_FUNCTION(this << "since FILL SUCCEDED, we mark key " << keyId << " as READY in sBuffer " 
        << sBuffer << sBuffer->GetDescription() << sBuffer->GetRemoteNodeId()
      ); 

      if (sBufferType == "enc" || sBufferType == "dec")
      {
        sBuffer->MarkKey(keyId, QKDKey::READY);
      }
      else
      {
        if(sBuffer->GetKeyStatus(keyId) == QKDKey::INIT)
        {
          NS_LOG_FUNCTION(this << "keys_accepted: Let's change status to READY of the key " << keyId << " so we can fetch it!");
          sBuffer->MarkKey(keyId, QKDKey::READY);
        }else{
          NS_LOG_FUNCTION(this << "Key was not in INIT state!");
          continue;
        }

        Ptr<QKDKey> key = sBuffer->GetKey(keyId, true);
        NS_ASSERT(key);
        if (key)
        {
          key->SwitchToState(QKDKey::READY);
          sBuffer->InsertKeyToStreamSession(key);
         
          std::string srcSaeId = "";
          std::string dstSaeId = "";
          auto itx = m_associations004.find(ksid);
          if(itx != m_associations004.end()){
            srcSaeId = itx->second.srcSaeId;
            dstSaeId = itx->second.dstSaeId;
          }

          //fill
          m_keyServedTraceMixed(
            ksid,
            srcSaeId,
            dstSaeId,
            GetNode()->GetId(),
            peerNodeId,
            key->GetId(), 
            key->GetSizeInBits(), 
            std::string("qkd")
          );

        }
      }
    }
  }

  // =========================================================
  // 2. REJECTED KEYS (UNCHANGED)
  // =========================================================
  if (j.contains("keys_rejected"))
  {
    for (auto &it : j["keys_rejected"])
    {
      std::string keyId = it["key_ID"];

      auto a = std::find(keyIds.begin(), keyIds.end(), keyId);
      if (a != keyIds.end())
        keyIds.erase(a);

      if(sBuffer->GetKeyStatus(keyId) == QKDKey::INIT)
      {
        NS_LOG_FUNCTION(this << "keys_mixed: Let's change status to READY of the key " << keyId << " so we can fetch it!");
        sBuffer->MarkKey(keyId, QKDKey::READY);
      }else{
        NS_LOG_FUNCTION(this << "Key was not in INIT state!");
      }

      Ptr<QKDKey> key = sBuffer->GetKey(keyId, true);
      if (key)
      {
        key->SwitchToState(QKDKey::READY);
        if(sourceBuffer->StoreKey(key, true)){
          NS_LOG_FUNCTION(this << "Stored back rejected key " << keyId << " from " << sBuffer << " in " << sourceBuffer);
        }else{
          NS_LOG_FUNCTION(this << "UNABLE to store back rejected key " << keyId << " from " << sBuffer << " in " << sourceBuffer);
        }
      }
    }
  }

  // =========================================================
  // 3. MIXED KEYS (NEW start/end logic)
  // =========================================================
  if (m_pqc_enabled && j.contains("keys_mixed"))
  {
    for (auto &mkJson : j["keys_mixed"])
    {
      std::string mixedId = mkJson["key_ID"];

      std::string reconstructed;
      SBuffer::MixedKey mk;

      // -------------------------
      // QKD reconstruction
      // -------------------------
      for (auto &q : mkJson["qkd"])
      {
        std::string qid = q["id"];
        uint32_t startBit = q["start_bit"];
        uint32_t endBit   = q["end_bit"];

        Ptr<QKDKey> k = nullptr;
        NS_LOG_FUNCTION(this << "Trying to fetch key " << qid << " from buffer " << sBuffer);
        if(sBuffer->GetKeyStatus(qid) == QKDKey::INIT)
        {
          NS_LOG_FUNCTION(this << "FILL accepted! Let's change status to READY of the key " << qid << " so we can fetch it!");
          k = sBuffer->GetKey(qid);
        }else{
          NS_LOG_FUNCTION(this << "FILL accepted BUT Key was not in INIT state!" << sBuffer->GetKeyStatus(qid));
        }        
        if (!k) 
        {
          NS_LOG_FUNCTION(this << "Missing QKD key " << qid);
          continue;
        }

        std::string full = k->GetKeyString();

        uint32_t startByte = startBit / 8;
        uint32_t endByte   = endBit / 8;

        NS_ASSERT_MSG(endByte <= full.size(), "QKD range overflow");

        reconstructed += full.substr(startByte, endByte - startByte);

        mk.qkdKeyIds.push_back(qid);
        mk.qkdStartBits.push_back(startBit);
        mk.qkdEndBits.push_back(endBit);

        //return key to buffer since we didn't use it in whole
        if(endBit+1 < k->GetSizeInBits())
          sBuffer->StoreKey(k, true);

        std::string srcSaeId = "";
        std::string dstSaeId = "";
        auto itx = m_associations004.find(ksid);
        if(itx != m_associations004.end()){
          srcSaeId = itx->second.srcSaeId;
          dstSaeId = itx->second.dstSaeId;
        }

        m_keyServedTraceMixed(
          ksid,
          srcSaeId,
          dstSaeId,
          GetNode()->GetId(),
          peerNodeId,
          qid, 
          k->GetSizeInBits(), 
          std::string("qkd")
        );
      }

      // -------------------------
      // PQC reconstruction
      // -------------------------
      for (auto &p : mkJson["pqc"])
      {
        std::string pid = p["id"];
        uint32_t startBit = p["start_bit"];
        uint32_t endBit   = p["end_bit"];

        Ptr<QKDKey> k = sBufferPQC->GetKey(pid, false);
        if (!k)
          NS_FATAL_ERROR(this << "Missing PQC key " << pid);

        std::string full = k->GetKeyString();

        uint32_t startByte = startBit / 8;
        uint32_t endByte   = endBit / 8;

        NS_LOG_FUNCTION(this << "We fetched proposed PQC key " << pid);

        NS_ASSERT_MSG(endByte <= full.size(), "PQC range overflow");

        reconstructed += full.substr(startByte, endByte - startByte);

        mk.pqcKeyIds.push_back(pid);
        mk.pqcStartBits.push_back(startBit);
        mk.pqcEndBits.push_back(endBit);

        //return key to buffer since we didn't use it in whole
        if(endBit+1 < k->GetSizeInBits())
          sBufferPQC->StoreKey(k, true);

        std::string srcSaeId = "";
        std::string dstSaeId = "";
        auto itx = m_associations004.find(ksid);
        if(itx != m_associations004.end()){
          srcSaeId = itx->second.srcSaeId;
          dstSaeId = itx->second.dstSaeId;
        }

        m_keyServedTraceMixed(
          ksid,
          srcSaeId,
          dstSaeId,
          GetNode()->GetId(),
          peerNodeId,
          pid, 
          k->GetSizeInBits(), 
          std::string("pqc")
        );
      }

      Ptr<QKDKey> mixedKey =
        CreateObject<QKDKey>(mixedId, reconstructed);

      mixedKey->SwitchToState(QKDKey::READY);

      mk.mixedKey = mixedKey;

      sBufferPQC->StoreMixedKey(mixedId, mk);
    }
  }

  // =========================================================
  // 4. QKD ONLY
  // =========================================================
  if (j.contains("keys_qkd_only"))
  {
    for (auto &kjson : j["keys_qkd_only"])
    {
      std::string id = kjson["key_ID"];

      Ptr<QKDKey> key = sourceBuffer->GetKey(id);
      if (!key)
        continue;

      key->SwitchToState(QKDKey::READY);

      if (sBufferType == "enc" || sBufferType == "dec")
        sBuffer->MarkKey(id, QKDKey::READY);
      else
        sBuffer->InsertKeyToStreamSession(key);

      std::string srcSaeId = "";
      std::string dstSaeId = "";
      auto itx = m_associations004.find(ksid);
      if(itx != m_associations004.end()){
        srcSaeId = itx->second.srcSaeId;
        dstSaeId = itx->second.dstSaeId;
      }

      m_keyServedTraceMixed(
        ksid,
        srcSaeId,
        dstSaeId,
        GetNode()->GetId(),
        peerNodeId,
        id, 
        key->GetSizeInBits(), 
        std::string("qkd")
      );
    }
  }

  // =========================================================
  // FINALIZE
  // =========================================================
  UpdateLinkState(peerNodeId);
  HttpKMSCompleteQuery(dstKms);
}







void
QKDKeyManagerSystemApplication::NewAppRequest(std::string ksid)
{
    NS_LOG_FUNCTION(this << ksid);
    auto it = m_associations004.find(ksid);
    if(it == m_associations004.end()){
      NS_LOG_DEBUG( this << "Key stream association identified with " << ksid << "does not exists!" );
      return;
    }

    CheckSocketsKMS((it->second).dstKmsAddr ); //Check connection to peer KMS!
    Ptr<Socket> socket = GetSocketKMS((it->second).dstKmsAddr );
    NS_ASSERT(socket);

    nlohmann::json msgBody = {
      {"Source",(it->second).srcSaeId},
      {"Destination",(it->second).dstSaeId},
      {"QoS", {
        {"Key_chunk_size",(it->second).qos.chunkSize}
      }},
      {"Key_stream_ID", ksid}
    };
    std::string msg = msgBody.dump();

    std::ostringstream peerkmsAddressTemp;
   (it->second).dstKmsAddr.Print(peerkmsAddressTemp); //IPv4Address to string
    std::string headerUri = "http://" + peerkmsAddressTemp.str(); //Uri starts with destination KMS address
    headerUri += "/api/v1/associations/new_app";

    //Create packet
    HTTPMessage httpMessage;
    httpMessage.CreateRequest(headerUri, "POST", msg);
    std::string hMessage = httpMessage.ToString();
    Ptr<Packet> packet = Create<Packet>(
     (uint8_t*)(hMessage).c_str(),
      hMessage.size()
    );
    NS_ASSERT(packet);

    HttpQuery query;
    query.method_type = RequestType::NEW_APP;
    query.source_sae =(it->second).srcSaeId;
    query.destination_sae =(it->second).dstSaeId;
    query.ksid = ksid;
    HttpKMSAddQuery((it->second).dstKmsAddr, query);
    SendToSocketPairKMS(socket, packet);
    NS_LOG_FUNCTION( this << "NEW_APP: KMS informs peer KMS on new association established!" );
}

void
QKDKeyManagerSystemApplication::ProcessNewAppRequest(HTTPMessage headerIn, Ptr<Socket> socket)
{
    NS_LOG_FUNCTION(this << "Processing NEW_APP request!");
    std::string payload = headerIn.GetMessageBodyString();
    nlohmann::json jNewAppRequest;
    try{
        jNewAppRequest = nlohmann::json::parse(payload);
    }catch(...){
        NS_FATAL_ERROR( this << "JSON parse error!" );
    }

    //uint32_t srcSaeId = -1, dstSaeId = -1;
    std::string srcSaeId, dstSaeId;
    QKDKeyManagerSystemApplication::QoS inQoS;
    std::string ksid;
    if(jNewAppRequest.contains("Destination"))
        dstSaeId = jNewAppRequest["Destination"];
    if(jNewAppRequest.contains("Source"))
        srcSaeId = jNewAppRequest["Source"];
    if(jNewAppRequest.contains("Key_stream_ID"))
        ksid = jNewAppRequest["Key_stream_ID"];
    ReadJsonQos(inQoS, jNewAppRequest);
    NS_ASSERT(!srcSaeId.empty() || !dstSaeId.empty() || !ksid.empty());

    bool qosAgreed {true}; //Check if the QoS can be met! @toDo
    if(qosAgreed){
        CreateEtsi004KeyStreamSession(dstSaeId, srcSaeId, inQoS, ksid);
        /* Send positive response on the NEW_APP request! In case where
        it is not point-to-point conncetion between the source and the destination
        msg will carry destination_kms address. @toDoR */

        //create packet
        HTTPMessage httpMessage;
        httpMessage.CreateResponse(HTTPMessage::HttpStatus::Ok, "", {
          {"Content-Type", "application/json; charset=utf-8"},
          {"Request URI", headerIn.GetUri() }
        });
        std::string hMessage = httpMessage.ToString();
        Ptr<Packet> packet = Create<Packet>(
         (uint8_t*)(hMessage).c_str(),
          hMessage.size()
        );
        NS_ASSERT(packet);

        NS_LOG_FUNCTION( this << "NEW_APP request accepted. Association created." );

        auto it = m_associations004.find(ksid);
        if(it == m_associations004.end())
          NS_FATAL_ERROR(this);

        Ipv4Address dstKms =(it->second).dstKmsAddr; //Read destination KMS address from the association entry
        CheckSocketsKMS( dstKms ); //Check connection to dstKms
        Ptr<Socket> socket = GetSocketKMS( dstKms ); //Obtain send socket object to reach dstKms
        NS_ASSERT(socket);
        SendToSocketPairKMS(socket, packet); 

    }else{
        NS_LOG_ERROR(this << "QoS requirements can not be satisfied");
        return;
    }

}

void
QKDKeyManagerSystemApplication::ProcessNewAppResponse(HTTPMessage headerIn, Ptr<Socket> socket)
{
    NS_LOG_FUNCTION( this << "Processing NEW_APP response" );
    std::vector<std::string> uriParams = ReadUri(headerIn.GetRequestUri());
    Ipv4Address dstKms = uriParams[0].c_str();
    NS_LOG_FUNCTION(this << dstKms);
    auto it = m_httpRequestsQueryKMS.find(dstKms);
    if(it == m_httpRequestsQueryKMS.end() ||(it->second).empty())
        NS_FATAL_ERROR( this << "Response cannot be mapped! HttpQuery empty!" );

    std::string dstSaeId = it->second[0].destination_sae;

    if(headerIn.GetStatus() == 200)
    { 
      NS_LOG_FUNCTION(this << "Hops: " << GetController()->GetRoute(dstSaeId).GetHop());
      if(GetController()->GetRoute(dstSaeId).GetHop() == 1) //dstKms for point-to-point scenario!
          HttpKMSCompleteQuery(dstKms); //Point-to-point scenario. Response just as acknowledgement!
      else{//@toDo Trusted relay scenario. QKDApp is waiting for OPEN_CONNECT response!
          bool QoS {true}; //Read QoS from response, calculate its own, and make response!
          if(QoS)
          {
            nlohmann::json jOpenConnectResponse;
            jOpenConnectResponse["Key_stream_ID"] = it->second[0].ksid;
            std::string msg = jOpenConnectResponse.dump();

            //create packet
            HTTPMessage httpMessage;
            httpMessage.CreateResponse(HTTPMessage::HttpStatus::Ok, msg, {
              {"Content-Type", "application/json; charset=utf-8"},
              {"Request URI", headerIn.GetUri() }
            });
            std::string hMessage = httpMessage.ToString();
            Ptr<Packet> packet = Create<Packet>(
             (uint8_t*)(hMessage).c_str(),
              hMessage.size()
            );
            NS_ASSERT(packet);

            HttpKMSCompleteQuery(dstKms);
            CheckSocketsKMS( dstKms ); //Check connection to dstKms
            Ptr<Socket> socket = GetSocketKMS( dstKms ); //Obtain send socket object to reach dstKms
            NS_ASSERT(socket);            
            SendToSocketPairKMS(socket, packet);
          }else{
              //Respond to the QKDApp with QoS that can be offered! @toDo Trusted relay scenario
          }
      }

    }else{ //Status indicating error!
        std::string ksid = it->second[0].ksid;
        if(GetController()->GetRoute(dstSaeId).GetHop() == 1) //dstKms for point-to-point scenario!
            HttpKMSCompleteQuery(dstKms); //Point-to-point scenario. Response just as acknowledgement!
        else{
            //Check the error! @toDo Respond to peer QKDApp in case of Trusted relay scenario!
            HttpKMSCompleteQuery(dstKms);
        }
        auto it = m_associations004.find(ksid);
        if(it != m_associations004.end()){
            m_associations004.erase(it); //Myb not erase, but for a few seconds mark as closed, and then erase! @toDo
        }else{
          NS_FATAL_ERROR(this << "Closing non existing association!");
        }
    }

}

void
QKDKeyManagerSystemApplication::RegisterRequest(std::string ksid)
{
    NS_LOG_FUNCTION( this << ksid);
    auto it = m_associations004.find(ksid); //Find association entry identified with ksid
    if(it == m_associations004.end()){
      NS_LOG_DEBUG( this << "Key stream association identified with " << ksid << "does not exists!" );
      return;
    }

    Ipv4Address dstKms =(it->second).dstKmsAddr; //Read destination KMS address from the association entry
    CheckSocketsKMS( dstKms ); //Check connection to dstKms
    Ptr<Socket> socket = GetSocketKMS( dstKms ); //Obtain send socket object to reach dstKms
    NS_ASSERT(socket);

    std::string headerUri = "http://" + GetAddressString(dstKms);
    headerUri += "/api/v1/associations/register/" + ksid; //Create an URI for the register request

    //Create packet
    HTTPMessage httpMessage;
    httpMessage.CreateRequest(headerUri, "GET");
    std::string hMessage = httpMessage.ToString();
    Ptr<Packet> packet = Create<Packet>(
     (uint8_t*)(hMessage).c_str(),
      hMessage.size()
    );
    NS_ASSERT(packet);

    HttpQuery query;
    query.method_type = REGISTER;
    query.ksid = ksid;
    HttpKMSAddQuery(dstKms, query); //Remember HTTP query to be able to map response later
    SendToSocketPairKMS(socket, packet);
}

void
QKDKeyManagerSystemApplication::ProcessRegisterRequest( HTTPMessage headerIn , std::string ksid, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this << "Processing register request " << ksid);

  auto it = m_associations004.find(ksid); //Find association entry identified with ksid
  if(it != m_associations004.end() && ! ((it->second).peerRegistered))
      NS_LOG_FUNCTION(this << "Key stream session has been registered!");
  else if(it != m_associations004.end() && (it->second).peerRegistered )
      NS_LOG_FUNCTION(this << "Key stream session has already been registered!");
  else{
      NS_LOG_FUNCTION(this << "Key stream association identified with " << ksid << "does not exists!");
      return; //@toDo004
  }

 (it->second).peerRegistered = true; //The peer application is registered if not already

  //create packet
  HTTPMessage httpMessage;
  httpMessage.CreateResponse(HTTPMessage::HttpStatus::Ok, "", {
    {"Content-Type", "application/json; charset=utf-8"},
    {"Request URI", headerIn.GetUri() }
  });
  std::string hMessage = httpMessage.ToString();
  Ptr<Packet> packet = Create<Packet>(
   (uint8_t*)(hMessage).c_str(),
    hMessage.size()
  );
  NS_ASSERT(packet);

  CheckSocketsKMS( it->second.dstKmsAddr ); //Check connection to peer KMS!
  Ptr<Socket> socketKMS = GetSocketKMS( it->second.dstKmsAddr );
  NS_ASSERT(socketKMS);
  SendToSocketPairKMS(socketKMS, packet);

  //If master KMS monitor association. If slave do nothing!
  if(it->second.srcNodeId > it->second.dstNodeId){
    NS_LOG_FUNCTION(this << "MASTER KMS 004!");
    CheckEtsi004Association(ksid); //KMS starts monitoring the active association
  }
}

void
QKDKeyManagerSystemApplication::ProcessRegisterResponse(HTTPMessage headerIn, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION( this << "Processing /register response!");
  std::vector<std::string> uriParams = ReadUri(headerIn.GetRequestUri());
  std::string ksid;
  NS_LOG_FUNCTION(this << uriParams[4] << uriParams[5]);
  if(uriParams[4] != "register"){
    NS_LOG_ERROR(this << "Not a register response! Invalid HTTP mapping!");
    return;
  }else if(!uriParams[5].empty())
    ksid = uriParams[5];

  auto it1 = m_associations004.find(ksid);
  if(it1 == m_associations004.end()){
    NS_LOG_ERROR(this << "Association with given KSID" << ksid << "cannot be found!");
    return;
  }

  Ipv4Address dstKms =(it1->second.dstKmsAddr);
  auto it = m_httpRequestsQueryKMS.find(dstKms);
  if(it == m_httpRequestsQueryKMS.end() ||(it->second).empty())
      NS_FATAL_ERROR( this << "Response cannot be mapped! HttpQuery empty!" );

  if(headerIn.GetStatus() == HTTPMessage::HttpStatus::Ok){
      NS_LOG_FUNCTION( this << "Successful notification REGISTER" );
      if(it1->second.srcNodeId > it1->second.dstNodeId){
        NS_LOG_FUNCTION(this << "MASTER KMS 004");
        CheckEtsi004Association(ksid);
      }
  }else{
      NS_LOG_FUNCTION( this << "/register error! Releasing established association" << ksid );
      if(it1 != m_associations004.end()){
          m_associations004.erase(it1); //Myb not erase, but for a few seconds mark as closed, and then erase! @toDo
      }else{
        NS_FATAL_ERROR(this << "Closing non existing association!");
      }
  }
  HttpKMSCompleteQuery(dstKms);
}

void
QKDKeyManagerSystemApplication::ProcessSKeyCreateRequest(
    HTTPMessage headerIn,
    Ptr<Socket> socket)
{
    NS_LOG_FUNCTION(this << socket);

    std::string payload = headerIn.GetMessageBodyString();
    nlohmann::json jPayload;

    try
    {
        jPayload = nlohmann::json::parse(payload);
    }
    catch (...)
    {
        NS_FATAL_ERROR(this << "JSON parse error!");
    }

    // =====================================================
    // READ JSON PARAMETERS
    // =====================================================

    uint32_t keySizeQKD {0};
    uint32_t keySizePQC {0};
    uint32_t keyNumber  {0};

    uint32_t peerNodeId {0};
    std::string targetSaeId;

    std::vector<std::string> candidateSetIds;
    std::vector<std::string> supplyKeyIds;

    std::vector<std::string> candidateSetIdsPQC;
    std::vector<std::string> supplyKeyIdsPQC;

    std::vector<std::string> mixedKeyIds;
    std::vector<Ptr<QKDKey>> supplyKeys;

    if (jPayload.contains("source_node_id"))
        peerNodeId = jPayload["source_node_id"];

    if (jPayload.contains("target_SAE_ID"))
        targetSaeId = jPayload["target_SAE_ID"];

    if (jPayload.contains("key_size_QKD"))
        keySizeQKD = jPayload["key_size_QKD"];

    if (jPayload.contains("key_size_PQC"))
        keySizePQC = jPayload["key_size_PQC"];

    if (jPayload.contains("key_number"))
        keyNumber = jPayload["key_number"];

    if (jPayload.contains("supply_key_ID"))
    {
        for (auto& it : jPayload["supply_key_ID"])
            supplyKeyIds.push_back(it["key_ID"]);
    }

    if (jPayload.contains("candidate_set_ID"))
    {
        for (auto& it : jPayload["candidate_set_ID"])
            candidateSetIds.push_back(it["key_ID"]);
    }

    if (jPayload.contains("supply_key_ID_PQC"))
    {
        for (auto& it : jPayload["supply_key_ID_PQC"])
            supplyKeyIdsPQC.push_back(it["key_ID"]);
    }

    if (jPayload.contains("candidate_set_ID_PQC"))
    {
        for (auto& it : jPayload["candidate_set_ID_PQC"])
            candidateSetIdsPQC.push_back(it["key_ID"]);
    }

    if (jPayload.contains("mixed_key_ids"))
    {
        for (auto& it : jPayload["mixed_key_ids"])
        {
            mixedKeyIds.push_back(it["key_ID"]);
            NS_LOG_FUNCTION(this << "mixed key id: " << it["key_ID"]);
        }
    }

    NS_ASSERT(peerNodeId != 0);
    NS_ASSERT(keySizeQKD || keyNumber);

    // =====================================================
    // LOG INPUT
    // =====================================================

    NS_LOG_FUNCTION(this
        << "\nSource KM node ID:\t" << peerNodeId
        << "\nTarget SAE ID:\t" << targetSaeId
        << "\nKey size QKD:\t" << keySizeQKD
        << "\nKey size PQC:\t" << keySizePQC
        << "\nKey number:\t" << keyNumber
        << "\nSupply key IDs:\t" << supplyKeyIds
        << "\nCandidateSetIDs:\t" << candidateSetIds
        << "\nSupply key IDs PQC:\t" << supplyKeyIdsPQC
        << "\nCandidateSetIDs PQC:\t" << candidateSetIdsPQC
        << "\nMixed key IDs:\t" << mixedKeyIds
    );

    // =====================================================
    // QKD PART
    // =====================================================

    Ptr<SBuffer> sBuffer = GetSBuffer(peerNodeId, "dec");
    NS_ASSERT(sBuffer);

    if (!sBuffer)
        NS_FATAL_ERROR(this << "No DEC s-buffer found!");

    /*
     * IMPORTANT:
     * candidate_set_ID is authoritative.
     *
     * KMS-A already selected exact candidate keys from its buffer.
     * KMS-B must use EXACTLY those same key IDs to reconstruct
     * the same mergedKey.
     */

    std::string mergedKey;
    uint32_t targetSize = keySizeQKD;

    for (size_t i = 0; i < candidateSetIds.size(); ++i)
    {
        Ptr<QKDKey> candidateKey;

        if (i != candidateSetIds.size() - 1)
        {
            candidateKey = sBuffer->GetKey(candidateSetIds[i], true);
            NS_ASSERT(candidateKey);

            mergedKey += candidateKey->GetKeyString();

            NS_LOG_FUNCTION(this
                << "QKD full key used: "
                << candidateKey->GetId());
        }
        else
        {
            /*
             * Last key may be partial
             */

            uint32_t alreadyBits = mergedKey.size() * 8;
            uint32_t neededBits  = targetSize - alreadyBits;

            candidateKey = sBuffer->GetHalfKey(
                candidateSetIds[i],
                neededBits);

            NS_ASSERT(candidateKey);

            mergedKey += candidateKey->GetKeyString();

            NS_LOG_FUNCTION(this
                << "QKD partial key used: "
                << candidateSetIds[i]
                << " bits=" << neededBits);
        }
    }

    /*
     * Create supply keys using UUIDs received from KMS-A
     */

    for (size_t i = 0; i < supplyKeyIds.size(); ++i)
    {
        std::string keyString =
            mergedKey.substr(0, keySizeQKD / 8);

        mergedKey.erase(0, keySizeQKD / 8);

        Ptr<QKDKey> skey =
            CreateObject<QKDKey>(
                supplyKeyIds[i],
                keyString);

        sBuffer->StoreSupplyKey(skey);
        supplyKeys.push_back(skey);

        NS_LOG_FUNCTION(this
            << "Created QKD supply key: "
            << skey->GetId());
    }

    // =====================================================
    // PQC PART
    // =====================================================

    if (!candidateSetIdsPQC.empty() &&
        !supplyKeyIdsPQC.empty())
    {
        Ptr<SBuffer> sBufferPQC =
            GetSBuffer(peerNodeId, "pqc");

        NS_ASSERT(sBufferPQC);

        if (!sBufferPQC)
            NS_FATAL_ERROR(this << "No PQC s-buffer found!");

        std::string mergedKeyPQC;
        uint32_t targetSizePQC = keySizePQC;

        /*
         * Same logic:
         * candidate_set_ID_PQC is authoritative
         */

        for (size_t i = 0; i < candidateSetIdsPQC.size(); ++i)
        {
            Ptr<QKDKey> candidateKeyPQC;

            if (i != candidateSetIdsPQC.size() - 1)
            {
                candidateKeyPQC =
                    sBufferPQC->GetKey(
                        candidateSetIdsPQC[i],
                        true);

                NS_ASSERT(candidateKeyPQC);

                mergedKeyPQC +=
                    candidateKeyPQC->GetKeyString();

                NS_LOG_FUNCTION(this
                    << "PQC full key used: "
                    << candidateKeyPQC->GetId());
            }
            else
            {
                uint32_t alreadyBits =
                    mergedKeyPQC.size() * 8;

                uint32_t neededBits =
                    targetSizePQC - alreadyBits;

                candidateKeyPQC =
                    sBufferPQC->GetHalfKey(
                        candidateSetIdsPQC[i],
                        neededBits);

                NS_ASSERT(candidateKeyPQC);

                mergedKeyPQC +=
                    candidateKeyPQC->GetKeyString();

                NS_LOG_FUNCTION(this
                    << "PQC partial key used: "
                    << candidateSetIdsPQC[i]
                    << " bits=" << neededBits);
            }
        }

        /*
         * Create PQC supply keys
         * and final mixed keys
         */

        for (size_t i = 0; i < supplyKeyIdsPQC.size(); ++i)
        {
            std::string keyString =
                mergedKeyPQC.substr(0, keySizePQC / 8);

            mergedKeyPQC.erase(0, keySizePQC / 8);

            Ptr<QKDKey> skeyPQC =
                CreateObject<QKDKey>(
                    supplyKeyIdsPQC[i],
                    keyString);

            sBufferPQC->StoreSupplyKey(skeyPQC);

            /*
             * Rebuild final mixed key
             */

            std::string mixedId = mixedKeyIds[i];

            std::string mixedValue =
                supplyKeys[i]->GetKeyString() +
                skeyPQC->GetKeyString();

            Ptr<QKDKey> mixedKey =
                CreateObject<QKDKey>(
                    mixedId,
                    mixedValue);

            SBuffer::MixedKey mk;
            mk.mixedKey = mixedKey;

            /*
             * New structure uses vectors
             */

            mk.qkdKeyIds.push_back(supplyKeyIds[i]);
            mk.qkdStartBits.push_back(0);
            mk.qkdEndBits.push_back(
                supplyKeys[i]->GetSizeInBits() - 1);

            mk.pqcKeyIds.push_back(supplyKeyIdsPQC[i]);
            mk.pqcStartBits.push_back(0);
            mk.pqcEndBits.push_back(
                skeyPQC->GetSizeInBits() - 1);

            sBufferPQC->StoreMixedKey(
                mixedId,
                mk);

            NS_LOG_FUNCTION(this
                << "Stored mixed key: "
                << mixedId
                << " size="
                << mixedKey->GetSizeInBits());
        }
    }

    // =====================================================
    // RESPONSE
    // =====================================================

    HTTPMessage httpMessage;

    httpMessage.CreateResponse(
        HTTPMessage::HttpStatus::Ok,
        "",
        {
            {"Content-Type", "application/json; charset=utf-8"},
            {"Request URI", headerIn.GetUri()}
        });

    std::string response = httpMessage.ToString();

    Ptr<Packet> packet =
        Create<Packet>(
            (uint8_t*)response.c_str(),
            response.size());
    NS_ASSERT(packet);

    QKDLocationRegisterEntry conn = GetController()->GetRoute(peerNodeId);
    Ipv4Address dstKms = conn.GetDestinationKmsAddress();
    CheckSocketsKMS(dstKms);
    Ptr<Socket> socketKMS = GetSocketKMS(dstKms);

    NS_ASSERT(socketKMS);
    SendToSocketPairKMS(socketKMS, packet);

    NS_LOG_FUNCTION(this
        << "SKEY_CREATE response sent: packet="
        << packet->GetUid()
        << " size="
        << packet->GetSize());
}

void
QKDKeyManagerSystemApplication::ProcessSKeyCreateResponse(HTTPMessage headerIn, Ptr<Socket> socket)
{
    NS_LOG_FUNCTION(this);
    std::string payload = headerIn.GetMessageBodyString(); //Read payload

    std::vector<std::string> uriParams {ReadUri(headerIn.GetRequestUri())};

    Ipv4Address peerAddress = uriParams[0].c_str();
    auto it = m_httpRequestsQueryKMS.find(peerAddress);
    if(it == m_httpRequestsQueryKMS.end()){
      NS_LOG_ERROR(this);
      return;
    }

    if(headerIn.GetStatus() == HTTPMessage::HttpStatus::Ok)
    { //ACK message

      NS_LOG_FUNCTION(this << "We received HTTP OK(ack)!");

      if(it->second[0].surplus_key_ID.empty())
      { //There is nothing to perform on this ACK response
        NS_LOG_FUNCTION(this << "2895");
        HttpKMSCompleteQuery(peerAddress);
        return;
      }

      Ptr<SBuffer> sBuffer = GetSBuffer(it->second[0].peerNodeId, "enc");
      NS_ASSERT(sBuffer);
      std::string surplusKeyId {(it->second[0]).surplus_key_ID};
      sBuffer->MarkKey(surplusKeyId, QKDKey::READY);

    }else{
        NS_LOG_ERROR(this << "Unexpected error");
    }

    NS_LOG_FUNCTION(this << "2908");
    HttpKMSCompleteQuery(peerAddress);
}

void
QKDKeyManagerSystemApplication::ProcessKMSCloseRequest(HTTPMessage headerIn, Ptr<Socket> socket, std::string ksid)
{
    NS_LOG_FUNCTION(this << ksid);
    std::string payload = headerIn.GetMessageBodyString(); //Read the packet payload
    nlohmann::json jcloseRequest;
    try {
        jcloseRequest = nlohmann::json::parse(payload);
    } catch(...) {
        NS_FATAL_ERROR(this << "json parse error");
    }

    std::string surplusKeyId {};
    uint32_t syncIndex {0};
    if(jcloseRequest.contains("surplus_key_ID"))
        surplusKeyId = jcloseRequest["surplus_key_ID"];
    if(jcloseRequest.contains("sync_index"))
        syncIndex = jcloseRequest["sync_index"];

    auto it = m_associations004.find(ksid);
    if(it == m_associations004.end()){ //Key stream association does not exists(peer error, or association already released)
        NS_LOG_DEBUG(this << "unknown ksid " << ksid);

        //create packet
        HTTPMessage httpMessage;
        httpMessage.CreateResponse(HTTPMessage::HttpStatus::NotAcceptable, "", {
          {"Content-Type", "application/json; charset=utf-8"},
          {"Request URI", headerIn.GetUri() }
        });
        std::string hMessage = httpMessage.ToString();
        Ptr<Packet> packet = Create<Packet>(
         (uint8_t*)(hMessage).c_str(),
          hMessage.size()
        );
        NS_ASSERT(packet);

        NS_LOG_FUNCTION(this << "packet sent " << packet->GetUid() << packet->GetSize());
        CheckSocketsKMS( it->second.dstKmsAddr ); //Check connection to peer KMS!
        Ptr<Socket> socket = GetSocketKMS( it->second.dstKmsAddr );
        NS_ASSERT(socket);
        SendToSocketPairKMS(socket, packet);

    }else{
        it->second.peerRegistered = false; //QKDApp is no longer registered for particular association!
        bool empty {false};
        uint32_t localSyncIndex {0};
        if(it->second.stre_buffer->GetStreamKeyCount()) //Replica association buffer is not empty!
            localSyncIndex = it->second.stre_buffer->GetNextIndex(); //The oldest index in dedicated association buffer!
        else
            empty = true;

        if(!surplusKeyId.empty() && syncIndex < localSyncIndex) //Only if peer KMS dedicated association buffer is not empty(known by the surplusKeyId presence)
            syncIndex = localSyncIndex; //KMSs synchronize on largest index that exists at both peers!

        bool flag {false};
        if(empty && !surplusKeyId.empty())
            flag = true; //If replica empty, primary not. Replica sends flag insted of index!

        if(GetNode()->GetId() < it->second.dstNodeId) //Is master? If master schedule!
          ReleaseAssociation(ksid, surplusKeyId, syncIndex);
        else
          ScheduleReleaseAssociation(Time("20ms"), "ReleaseAssociation", ksid, surplusKeyId, syncIndex);

        nlohmann::json jresponse;
        if(!flag){
            if(!surplusKeyId.empty())
                jresponse["sync_index"] = syncIndex;
        }else
            jresponse["flag_empty"] = true;

        //create packet
        HTTPMessage httpMessage;
        httpMessage.CreateResponse(HTTPMessage::HttpStatus::Ok, jresponse.dump(), {
          {"Content-Type", "application/json; charset=utf-8"},
          {"Request URI", headerIn.GetUri()}
        });
        std::string hMessage = httpMessage.ToString();
        Ptr<Packet> packet = Create<Packet>(
         (uint8_t*)(hMessage).c_str(),
          hMessage.size()
        );
        NS_ASSERT(packet);

        NS_LOG_FUNCTION(this << "packet sent" << packet->GetUid() << packet->GetSize());
        CheckSocketsKMS( it->second.dstKmsAddr ); //Check connection to peer KMS!
        Ptr<Socket> socket = GetSocketKMS( it->second.dstKmsAddr );
        NS_ASSERT(socket);
        SendToSocketPairKMS(socket, packet);
    }
}

void
QKDKeyManagerSystemApplication::ReleaseAssociation(std::string ksid, std::string surplusKeyId, uint32_t syncIndex)
{
  NS_LOG_FUNCTION(this << ksid << surplusKeyId << syncIndex);

  std::string temp = ksid + "-" + surplusKeyId + "-" + std::to_string(syncIndex);
  auto itSchedule = m_scheduledChecks.find(temp);
  if(itSchedule!=m_scheduledChecks.end())
    m_scheduledChecks.erase(itSchedule);

  auto it = m_associations004.find(ksid);
  if(it == m_associations004.end()){ //Key stream association does not exists
    NS_LOG_DEBUG(this << "unkwnon ksid " << ksid);
    return;
  }

  if(surplusKeyId.empty())
  { //Remove key stream
    m_associations004.erase(it);
  }else{
    std::string preservedKeyString;
    uint32_t presentKeyMaterial {0};
    
    //Remove keys to sync index. Trace consumed keys
    while(it->second.stre_buffer->GetNextIndex() && it->second.stre_buffer->GetNextIndex() < syncIndex)
    { //@toDo GetNextIndex could be 0, but for now, we assume association is closed(released) sometimes after
		NS_LOG_FUNCTION(this << "emir1" << it->second.stre_buffer->GetNextIndex());
		Ptr<QKDKey> key = it->second.stre_buffer->GetStreamKey();
		presentKeyMaterial += key->GetSizeInBits();
     
    //etsi004
		m_keyServedTraceMixed(
			it->second.srcSaeId,
      it->second.srcSaeId,
      it->second.dstSaeId,
			it->second.srcNodeId,
			it->second.dstNodeId,
			key->GetId(), 
			key->GetSizeInBits(), 
			std::string("qkd")
		); 

		m_keyConsumedLink( //Is always p2p link now for 004
			it->second.srcNodeId, //Source
			it->second.dstNodeId, //Destination
			//{ksid + key->GetId()},  //Key ID should be combination of ksid+index!
			key->GetSizeInBits() //Size of key
		); 
    }
    
    //Get remaining keys, and group them in one string
    while(true)
    {
      Ptr<QKDKey> key = it->second.stre_buffer->GetStreamKey();
      if(key)
        preservedKeyString += key->GetKeyString();
      else
        break;
    }

    if(!preservedKeyString.empty())
    {
      
      Ptr<QBuffer> qBuffer = GetQBuffer(GetController()->GetRoute(it->second.dstSaeId).GetDestinationKmNodeId());
      if(qBuffer)
      {
        NS_LOG_FUNCTION(this << "preserved key material" << preservedKeyString.size());
        Ptr<QKDEncryptor> encryptor = CreateObject<QKDEncryptor>(64); //64 bits long key IDs. Collisions->0
        std::string hashInput {surplusKeyId + ksid}; //HASH input for key id
        NS_ASSERT(!hashInput.empty());

        uint32_t blockSize {qBuffer->GetKeySize()/8}, blockNum {0}; //Current default key size for connection
        while(!preservedKeyString.empty())
        {
          std::string keyValueTemp {preservedKeyString};
          if(preservedKeyString.size() >= blockSize)
            keyValueTemp = preservedKeyString.substr(0, blockSize); //Take portion of the QKD-key value for KMA-key
          std::string completeHashInput = hashInput + std::to_string(blockNum++); //Complete HASH input
          std::string blockKeyId {encryptor->SHA1(completeHashInput)}; //Generate KMA-key ID based on the HASH output
          NS_LOG_FUNCTION(this << "store key " << blockKeyId << keyValueTemp);
          Ptr<QKDKey> tempKey = CreateObject<QKDKey>(blockKeyId, keyValueTemp);
          qBuffer->StoreKey(tempKey); //Store KMA-key in QKD buffer
          preservedKeyString.erase(0, blockSize); //Update QKD-key value
        }

      }else
        NS_FATAL_ERROR(this << "unknown q-buffer");

    }
    m_associations004.erase(it);

  }

}

void
QKDKeyManagerSystemApplication::ProcessKMSCloseResponse(HTTPMessage headerIn, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this);
  std::string payload = headerIn.GetMessageBodyString();
  nlohmann::json jcloseResponse;
  try{
    jcloseResponse = nlohmann::json::parse(payload);
  }catch(...){
    NS_FATAL_ERROR(this << "json parse error");
  }

  Ipv4Address dstKms { ReadUri(headerIn.GetRequestUri())[0].c_str() };
  auto it = m_httpRequestsQueryKMS.find(dstKms);
  if(it == m_httpRequestsQueryKMS.end()){
    NS_LOG_ERROR(this << "unable to map response; query empty");
    return;

  }
  std::string ksid { ReadUri(headerIn.GetRequestUri())[5].c_str() };
  auto a = m_associations004.find(ksid);
  if(a == m_associations004.end()){
    NS_LOG_DEBUG(this << "unknown ksid " << ksid);
    return;

  }
  if(headerIn.GetStatus() == HTTPMessage::NotAcceptable){ //Remove key stream. Trace discarded key material
    //must record key consumed
    uint32_t presentKeyMaterial {0};
    while(true){
      Ptr<QKDKey> key {a->second.stre_buffer->GetStreamKey()};
      if(key){
        presentKeyMaterial += key->GetSizeInBits(); 

        //etsi004
        m_keyServedTraceMixed(
    			a->second.srcSaeId,
          a->second.srcSaeId,
          a->second.dstSaeId,
    			a->second.srcNodeId,
    			a->second.dstNodeId,
    			key->GetId(), 
    			key->GetSizeInBits(), 
    			std::string("qkd")
    		);  
        m_keyConsumedLink(a->second.srcNodeId, a->second.dstNodeId, key->GetSizeInBits());
      }else
        break;

    }
    m_associations004.erase(a); //Remove key stream.

  }else if(headerIn.GetStatus() == HTTPMessage::Ok){ //Perserve key material if any. Remove key stream. Trace discarded key material
    uint32_t peerSyncIndex {0}, localSyncIndex {it->second[0].sync_index};
    if(jcloseResponse.contains("sync_index")){
      peerSyncIndex = jcloseResponse["sync_index"];
      if(peerSyncIndex > localSyncIndex)
        localSyncIndex = peerSyncIndex;

      ReleaseAssociation(it->second[0].ksid, it->second[0].surplus_key_ID, localSyncIndex);

    }else{
      //must record key consumed 
      uint32_t presentKeyMaterial {0};
      while(true){
        Ptr<QKDKey> key {a->second.stre_buffer->GetStreamKey()};
        if(key)
        {
			NS_LOG_FUNCTION(this << key->GetId());
			presentKeyMaterial += key->GetSizeInBits(); 

      //etsi004
			m_keyServedTraceMixed(
				a->second.srcSaeId,
        a->second.srcSaeId,
        a->second.dstSaeId,
				a->second.srcNodeId,
				a->second.dstNodeId,
				key->GetId(), 
				key->GetSizeInBits(), 
				std::string("qkd")
			); 
          m_keyConsumedLink(a->second.srcNodeId, a->second.dstNodeId, key->GetSizeInBits());
        }else
          break;

      }
      m_associations004.erase(a);

    }

  }else
    NS_FATAL_ERROR(this << "unknown status code" << headerIn.GetStatus());

  HttpKMSCompleteQuery(dstKms);

}

/**
 * ********************************************************************************************

 *        HTTP handling

 * ********************************************************************************************
 */

void
QKDKeyManagerSystemApplication::HttpKMSAddQuery(Ipv4Address dstKms, HttpQuery request)
{
    NS_LOG_FUNCTION( this << dstKms);
    auto it = m_httpRequestsQueryKMS.find(dstKms);
    if(it != m_httpRequestsQueryKMS.end())
        it->second.push_back(request);
    else
        m_httpRequestsQueryKMS.insert(std::make_pair(dstKms, std::vector<HttpQuery> {request}));
}

void
QKDKeyManagerSystemApplication::HttpKMSCompleteQuery(Ipv4Address dstKms)
{
    NS_LOG_FUNCTION( this );
    auto it = m_httpRequestsQueryKMS.find(dstKms);
    if(it != m_httpRequestsQueryKMS.end())
    {
        if(!it->second.empty())
        {
            it->second.erase(it->second.begin());
        }else{
            NS_FATAL_ERROR( this << "HTTP query for this KMS is empty!");
        }
    }else{
        NS_FATAL_ERROR( this << "HTTP query to destination KMS does not exist!" );
    }
}
 


void
QKDKeyManagerSystemApplication::HttpProxyRequestAdd(HttpQuery query)
{
  NS_LOG_FUNCTION(this << query.req_id);
  m_httpProxyRequests.insert( std::make_pair(query.req_id, query) );
}

QKDKeyManagerSystemApplication::HttpQuery
QKDKeyManagerSystemApplication::GetProxyQuery(std::string reqId)
{
  NS_LOG_FUNCTION(this << reqId);
  HttpQuery query;
  auto it = m_httpProxyRequests.find(reqId);
  if(it == m_httpProxyRequests.end()){
    NS_FATAL_ERROR(this << "Unknown proxy request ID:" << reqId << "\tMapping of response failed!");
    //NS_LOG_DEBUG(this << "Unknown proxy request ID:" << reqId << "\tMapping of response failed!");
  } else
      query = it->second;

  return query;
}

void
QKDKeyManagerSystemApplication::RemoveProxyQuery(std::string reqId)
{
  NS_LOG_FUNCTION(this << reqId);
  auto it = m_httpProxyRequests.find(reqId);
  if(it == m_httpProxyRequests.end()){
    NS_FATAL_ERROR(this << "Unknown proxy request ID:" << reqId << "\tRemove failed!");
    //NS_LOG_DEBUG(this << "Unknown proxy request ID:" << reqId << "\tRemove failed!");

  } else
    m_httpProxyRequests.erase(it);

}

uint32_t
QKDKeyManagerSystemApplication::GetMaxKeyPerRequest(){
  return m_maxKeyPerRequest;
}

QKDKeyManagerSystemApplication::RequestType
QKDKeyManagerSystemApplication::FetchRequestType(std::string s)
{

  NS_LOG_FUNCTION(this << s );

  RequestType output;

  if(s == "status"){

      return ETSI_QKD_014_GET_STATUS;

  } else if(s == "enc_keys") {

      return ETSI_QKD_014_GET_KEY;

  } else if(s == "dec_keys"){

      return ETSI_QKD_014_GET_KEY_WITH_KEY_IDS;

  } else if(s == "open_connect"){

      return ETSI_QKD_004_OPEN_CONNECT;

  } else if(s == "get_key") {

      return ETSI_QKD_004_GET_KEY;

  } else if(s == "close") {

      return ETSI_QKD_004_CLOSE;

  } else if(s == "new_app") {

      return NEW_APP;

  } else if(s == "register") {

      return REGISTER;

  } else if(s == "fill") {

      return FILL;

  } else if(s == "store_key") {

      return STORE_KEY;

  } else if(s == "skey_create") {

    return TRANSFORM_KEYS;

  } else if(s == "close_kms") {

    return ETSI_QKD_004_KMS_CLOSE;

  } else if(s == "relay") {

    return RELAY_KEYS;

  } else if(s == "kms_pqc_cipher") {

    return PQC_CIPHER;

  } else if(s == "kms_pqc_public_key") {

    return PQC_PUBLIC_KEY;

  } else {

      NS_FATAL_ERROR(this << "Unknown Type: " << s);
  }

  return output;
}

 

nlohmann::json
QKDKeyManagerSystemApplication::CreateKeyContainer(std::vector<Ptr<QKDKey>> keys)
{
  NS_LOG_FUNCTION(this);
  nlohmann::json jkeys;
  for(uint32_t i = 0; i < keys.size(); i++){
    if(keys[i])
    {
      // Convert to bytes
      std::string byteKey = keys[i]->ConsumeKeyString();
      // Convert to Base64 for JSON storage
      std::string encodedKey = m_encryptor->Base64Encode(byteKey); 
      NS_LOG_FUNCTION(this << "KEY" << i+1 << keys[i]->GetId() << encodedKey << "\n");
      jkeys["keys"].push_back({ {"key_ID", keys[i]->GetId()}, {"key", encodedKey} });
    }

  }
  return jkeys;

}

/**
 * ********************************************************************************************

 *        KMS 004 Association operations, monitoring

 * ********************************************************************************************
 */

  std::string
  QKDKeyManagerSystemApplication::GenerateUUID()
  {
    NS_LOG_FUNCTION(this);
    std::string output;
    UUID ksidRaw = UUID::Sequential();
    output = ksidRaw.string();
    NS_LOG_FUNCTION(this << output);
    return output;
  }


void
QKDKeyManagerSystemApplication::ReadJsonQos(
  QKDKeyManagerSystemApplication::QoS &inQos,
  nlohmann::json jOpenConnectRequest)
{

  if(jOpenConnectRequest.contains("QoS")) { //Only Key_chunk_size from the QoS perspective supported!

    if(jOpenConnectRequest["QoS"].contains("Key_chunk_size"))
      inQos.chunkSize = jOpenConnectRequest["QoS"]["Key_chunk_size"];

  }
  NS_ASSERT(inQos.chunkSize >= 0);
}

std::vector<std::string>
QKDKeyManagerSystemApplication::ReadUri(std::string s)
{
  NS_LOG_FUNCTION(this);

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


std::string
QKDKeyManagerSystemApplication::CreateEtsi004KeyStreamSession(
  std::string srcSaeId, 
  std::string dstSaeId,
  QKDKeyManagerSystemApplication::QoS inQos,
  std::string ksid
){
    NS_LOG_FUNCTION(this << srcSaeId << dstSaeId << ksid << inQos.chunkSize);

    Ptr<SBuffer> SBufferStream = CreateObject<SBuffer>(SBuffer::STREAM_SBUFFER, inQos.chunkSize); 
    SBufferStream->Initialize();  
    SBufferStream->SetKeySize(inQos.chunkSize);
    SBufferStream->SetDescription ("(STREAM)"); 
    SBufferStream->SetKsid (ksid);
    SBufferStream->SetIndex( m_qbuffersVector.size() );  
    uint32_t dstNodeId = GetController()->GetRoute(dstSaeId).GetDestinationKmNodeId();
    m_qbuffersVector.push_back(SBufferStream);
    m_qbuffers.insert(std::make_pair(dstNodeId, SBufferStream) );
 
    QKDLocationRegisterEntry conn = GetController()->GetRoute(dstSaeId);
    uint32_t dstKmNodeId = conn.GetDestinationKmNodeId();
    SBufferStream->SetRemoteNodeId(dstKmNodeId);

    Ptr<QKDKeyManagerSystemApplication> kms;
    uint32_t applicationIndex = 0;
    for(uint32_t i = 0; i < GetNode()->GetNApplications(); ++i)
    {
        kms = GetNode()->GetApplication(i)->GetObject <QKDKeyManagerSystemApplication>();
        applicationIndex = i;
        if(kms) break;
    }
    SBufferStream->SetSrcKMSApplicationIndex(applicationIndex);

    //CREATE QKD GRAPH
    QKDGraphManager *QKDGraphManager = QKDGraphManager::getInstance();    
    uint32_t srcNodeId = GetNode()->GetId();
    std::string graphTitle = "SBUFFER (STREAM): " + std::to_string(srcNodeId) + "-SAE(" + srcSaeId + ") - " + std::to_string(dstNodeId) + "-SAE(" + dstSaeId + ")" ;

    Ptr<Node> dstNode = NodeList::GetNode(dstNodeId);

    QKDGraphManager->CreateGraphForBuffer(
      GetNode(), 
      dstNode,
      SBufferStream->GetIndex(), 
      SBufferStream->GetSrcKMSApplicationIndex(), 
      graphTitle, 
      "png",
      SBufferStream
    );     

    QKDKeyManagerSystemApplication::Association004 newKeyStreamSession{
      srcSaeId,
      dstSaeId,
      GetNode()->GetId(),
      dstNodeId,
      conn.GetDestinationKmsAddress(),
      inQos,
      true, //registered
      SBufferStream
    };
    if(ksid.empty())
    {
        ksid = GenerateUUID(); 
        NS_LOG_FUNCTION(this << "New ksid defined: " << ksid << srcSaeId << dstSaeId << inQos.chunkSize);
        m_ksidGenerated(
          ksid,
          srcSaeId,
          dstSaeId,
          inQos.chunkSize
        ); 
        newKeyStreamSession.peerRegistered = false;
    }
    m_associations004.insert(std::make_pair(ksid, newKeyStreamSession));

    return ksid;
}

std::string
QKDKeyManagerSystemApplication::GenerateRandomString(const int len, const uint32_t seed){
    std::string tmp_s;
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    //if(seed == 0)
    //    srand( m_kms_key_id );
    //else
    //    srand( seed );
    for(int i = 0; i < len; ++i){
        tmp_s += alphanum[rand() %(sizeof(alphanum) - 1)];
    }
    return tmp_s;
}

} // Namespace ns3

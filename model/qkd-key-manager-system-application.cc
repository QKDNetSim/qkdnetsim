/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina, www.tk.etf.unsa.ba
 *
 * Author:  Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 *          Miralem Mehic <miralem.mehic@etf.unsa.ba>
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

    .AddTraceSource("Tx", "A new packet is created and is sent to the APP",
                   MakeTraceSourceAccessor(&QKDKeyManagerSystemApplication::m_txTrace),
                   "ns3::QKDKeyManagerSystemApplication::Tx")
    .AddTraceSource("Rx", "A packet from the APP has been received",
                   MakeTraceSourceAccessor(&QKDKeyManagerSystemApplication::m_rxTrace),
                   "ns3::QKDKeyManagerSystemApplication::Rx")
    .AddTraceSource("TxKMSs", "A new packet is created and is sent to the APP",
                   MakeTraceSourceAccessor(&QKDKeyManagerSystemApplication::m_txTraceKMSs),
                   "ns3::QKDKeyManagerSystemApplication::TxKMSs")
    .AddTraceSource("RxKMSs", "A packet from the APP has been received",
                   MakeTraceSourceAccessor(&QKDKeyManagerSystemApplication::m_rxTraceKMSs),
                   "ns3::QKDKeyManagerSystemApplication::RxKMSs")
    .AddTraceSource("QKDKeyGenerated", "The trace to monitor key material received from QL",
                     MakeTraceSourceAccessor(&QKDKeyManagerSystemApplication::m_qkdKeyGeneratedTrace),
                     "ns3::QKDKeyManagerSystemApplication::QKDKeyGenerated")
    .AddTraceSource("KeyServed", "The trece to monitor key usage",
                     MakeTraceSourceAccessor(&QKDKeyManagerSystemApplication::m_keyServedTrace),
                     "ns3::QKDKeyManagerSystemApplication::KeyServed")
    .AddTraceSource("KeyConsumedLink", "The trece to monitor p2p key usage",
                     MakeTraceSourceAccessor(&QKDKeyManagerSystemApplication::m_keyConsumedLink),
                     "ns3::QKDKeyManagerSystemApplication::KeyConsumedLink")
    .AddTraceSource("RelayConsumption", "The trace to monitor key material consumed for key relay",
                     MakeTraceSourceAccessor(&QKDKeyManagerSystemApplication::m_keyConsumedRelay),
                     "ns3::QKDKeyManagerSystemApplication::RelayConsumption")
    .AddTraceSource("WasteRelay", "The trace to monitor failed relays",
                     MakeTraceSourceAccessor(&QKDKeyManagerSystemApplication::m_keyWasteRelay),
                     "ns3::QKDKeyManagerSystemApplication::WasteRelay")

  ;
  return tid;
}

QKDKeyManagerSystemApplication::QKDKeyManagerSystemApplication()
{
  NS_LOG_FUNCTION(this);
  m_totalRx = 0;
  m_kms_key_id = 0;
  m_encryptor = CreateObject<QKDEncryptor>(64); //64 bits long key IDs. Collisions->0
  m_queueLogic = CreateObject<QKDKMSQueueLogic>();

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
    std::cout << "\nLink going DOWN: " << GetNode()->GetId() << "--" << dstKmNodeId << "at time -- " << Simulator::Now() << std::endl;
    GetCenController()->LinkDown(GetNode()->GetId(),dstKmNodeId);
    it->second = 3;
  }else if(it->second == 3 && qBuffer->GetBitCount() > qBuffer->GetMthr() && sBuffer->GetSBitCount() > sBuffer->GetMthr()){//qBuffer->GetState() != 3){// && sBuffer->GetSBitCount() > sBuffer->GetMthr()){
    NS_LOG_FUNCTION(this << "Link going up.");
    std::cout << "\nLink going UP: " << GetNode()->GetId() << "--" << dstKmNodeId << "at time -- " << Simulator::Now() << std::endl;
    GetCenController()->LinkUp(GetNode()->GetId(),dstKmNodeId);
    it->second = 0;
  }

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
  Ipv4Address address;
  auto it = m_peerAddressTable.find(dstKmNodeId);
  if(it!=m_peerAddressTable.end())
    address = it->second;
  else
    NS_LOG_ERROR(this << "Entry not found");

  return address;
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
  if(GetNode()->GetId() > dstKmNodeId)
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
      << "BitCount: " << ie->second->GetSBitCount() 
      << "\n SBitCount: " << ie->second->GetBitCount() 
      << "\n Max: " << ie->second->GetMmax() 
    );

    if(
      ie->second->GetBitCount() >= ie->second->GetMmax() &&
      id->second->GetBitCount() >= id->second->GetMmax()
    ){
      NS_LOG_FUNCTION(this << "SBuffers are full! No need for fill!");
      return;
    }

    //Amount of keys available at Q-buffer
    uint32_t qBufferBits = GetQBuffer(dstKmNodeId)->GetBitCount() - GetQBuffer(dstKmNodeId)->GetMmin();
    uint32_t encDemand = ie->second->GetMmax() - ie->second->GetBitCount();
    uint32_t decDemand = id->second->GetMmax() - id->second->GetBitCount();
    if(encState && decState)
    { //Both enc and dec s-buffers require charging(states != READY)
        double decreaseProcentage = 0.05;
        while(encDemand + decDemand > qBufferBits){
          encDemand -= encDemand*decreaseProcentage;
          decDemand -= decDemand*decreaseProcentage;
        }
        Fill(dstKmNodeId, "enc", encDemand);
        Fill(dstKmNodeId, "dec", decDemand);
    }else if(encState){
        if(encDemand > qBufferBits)
          encDemand = qBufferBits; //Assign all available key material from q-buffer
        Fill(dstKmNodeId, "enc", encDemand);
    }else if(decState){
        if(decDemand > qBufferBits)
          decDemand = qBufferBits; //Assign all available key material from q-buffer
        Fill(dstKmNodeId, "dec", decDemand);
    }else
        NS_LOG_FUNCTION(this << "LOCAL_SBUFFER(s)" << dstKmNodeId << "are in READY state!");

  }else if(ie->second->GetType() == SBuffer::Type::RELAY_SBUFFER){ //RELAY_SBUFFER

    NS_LOG_FUNCTION(this << "Checking SBuffer::Type::RELAY_SBUFFER");

    uint32_t encState = ie->second->GetState(); //Check s-buffer state
    NS_LOG_FUNCTION(this << "RELAY_SBUFFER::State" << encState); //testing
    if(encState)
    { //Triger relay to fill
      QKDLocationRegisterEntry conn = GetController()->GetRoute(dstKmNodeId); //Get route information
      uint32_t nextHop = conn.GetNextHop(); //Identify LOCAL_SBUFFER accessed for relay purposes
      uint32_t encDemand = ie->second->GetMmax() - ie->second->GetBitCount(); //This is desired amount to relay!

      NS_LOG_FUNCTION(this << "33333:" << nextHop << encDemand);

      Ptr<SBuffer> sBuffer = GetSBuffer(nextHop, "enc");  //@todo id1125
      NS_ASSERT(sBuffer);

      uint32_t sBufferBits = sBuffer->GetDefaultKeyCount()*sBuffer->GetKeySize(); //Available amount of key material in LOCAL_SBUFFER

      NS_LOG_FUNCTION(this << "How many keys in S-Buffer" << sBuffer->GetSKeyCount()
                           << "Hot many bits in S-Buffer" << sBufferBits);

      if(20*ie->second->GetKeySize() < encDemand)
          encDemand = 20*ie->second->GetKeySize(); 

      if(encDemand > sBufferBits)
          encDemand = sBufferBits; //Assign all available key material from q-buffer

      NS_LOG_FUNCTION(this << "encDemand:" << encDemand << "KeySize: " << ie->second->GetKeySize() << "sBufferBits:" << sBufferBits);

      Relay(dstKmNodeId, encDemand);

    }else
      NS_LOG_FUNCTION(this << "RELAY_SBUFFER" << dstKmNodeId << "is in READY state!");

  }
}

void
QKDKeyManagerSystemApplication::Relay(uint32_t dstKmNodeId, uint32_t amount)
{
  NS_LOG_FUNCTION(this << dstKmNodeId << amount);
  QKDLocationRegisterEntry conn = GetController()->GetRoute(dstKmNodeId); //Get connection details
  NS_LOG_FUNCTION(this << "NEXT HOP:" << conn.GetNextHop());

  if(amount == 0){
    NS_LOG_FUNCTION(this << "Source cannot perform relay due to the lack of key material!");
    return;
  }

  //QKDLocationRegisterEntry conn = GetController()->GetRoute(dstKmNodeId); //Get connection details
  Ptr<SBuffer> relayBuffer = m_keys_enc.find(dstKmNodeId)->second; //Get RELAY_SBUFFER
  NS_ASSERT(relayBuffer);
  if(relayBuffer->IsRelayActive())
  {
    NS_LOG_FUNCTION(this << "RELAY ACTIVE");
    return;
  } else {
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
  while(true){
    Ptr<QKDKey> key = localBuffer->GetKey(relayBuffer->GetKeySize()); //Get key from sBuffer(key MUST be in default size!)
    NS_ASSERT(key);
    relayPayload["keys"].push_back({ {"key_ID", key->GetId()} }); //Add keyId object to JSON
    keyIds.push_back(key->GetId());
    NS_LOG_FUNCTION(this << "key state" << key->GetState());
    //First store the key to relay SBuffer and trigger QKDPlot (new key added)
    relayBuffer->StoreKey(key, true); //Store keys to RELAY_SBUFFER
    //Then mark the key as INIT and also trigger QKDPlot (key removed)
    relayBuffer->MarkKey(key->GetId(), QKDKey::INIT); //Keys are marked INIT until relay is completed!
    m_keyConsumedRelay(
      GetNode()->GetId(),
      GetNode()->GetId(),
      conn.GetNextHop(),
      key->GetSizeInBits()
    );
    if(key->GetSizeInBits() + relayBuffer->GetKeySize() > amount) //To be sure that we not exceed capacity of S-Buffer
      break;
    else
      amount -= key->GetSizeInBits();
  }

  if(GetNode()->GetId() > conn.GetNextHop()) //this is master KMS //if not master, the relay request will trigger check
    SBufferClientCheck(conn.GetNextHop()); //run sbuffer client check for LOCAL Sbuffer

  Ipv4Address nextHopAddress = GetPeerKmAddress(conn.GetNextHop());
  std::string headerUri = "http://" + GetAddressString(nextHopAddress);
  headerUri += "/api/v1/keys/relay";

  std::string reqId {GenerateUUID()}; //HTTP request ID! Help parameter for simulation of proxies!
  headerUri += "/?req_id=/" + reqId; //We include our Request ID in URI. It helps map responses in chain of proxies.

  std::string msg = relayPayload.dump();

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
  Ptr<Socket> sendSocket = GetSendSocketKMS( nextHopAddress );
  NS_ASSERT(sendSocket);

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

  sendSocket->Send(packet);
  NS_LOG_FUNCTION(this << "Packet sent" << conn.GetNextHop()
                        << packet->GetUid() << packet->GetSize());

}

void
QKDKeyManagerSystemApplication::Fill(
  uint32_t dstKmNodeId,
  std::string direction,
  uint32_t amount
)
{
  NS_LOG_FUNCTION(this << dstKmNodeId << direction << amount);

  Ptr<SBuffer> sBuffer;
  if(direction == "enc" || direction == "dec"){
    sBuffer = GetSBuffer(dstKmNodeId, direction);
    NS_ASSERT(sBuffer);
  }else{
    auto it = m_associations004.find(direction);
    if(it == m_associations004.end())
      NS_FATAL_ERROR(this << "Unknown key stream session" << direction);

    sBuffer = it->second.stre_buffer;
  }

  Ptr<QBuffer> qBuffer = GetQBuffer(dstKmNodeId);
  NS_ASSERT(qBuffer);

  nlohmann::json fillPayload; //FILL method payload
  std::vector<std::string> keyIds;
  fillPayload["source_node_id"] = GetNode()->GetId(); //This KM node ID
  if(direction == "enc") //For the peer KM node, the s-buffer type is oposite!!!
    fillPayload["s_buffer_type"] = "dec"; //s-buffer type
  else if(direction == "dec")
    fillPayload["s_buffer_type"] = "enc";
  else{
    fillPayload["s_buffer_type"] = "stream";
    fillPayload["ksid"] = direction;
  }


  while(true)
  {
    if(
      sBuffer->GetBitCount() + sBuffer->GetKeySize() > sBuffer->GetMmax() && 
      fillPayload["s_buffer_type"] != "stream"
    ){ 
      //To be sure that we not exceed capacity of S-Buffer
      NS_LOG_FUNCTION(this << "To be sure that we not exceed capacity of S-Buffer!");
      break;
    }

    if(amount < sBuffer->GetKeySize())
    {
      NS_LOG_FUNCTION(this << "amount < sBuffer->GetKeySize()" << amount << sBuffer->GetKeySize());
      break;
    } 

    Ptr<QKDKey> key = qBuffer->GetKey(); //Get random key from qBuffer
    NS_ASSERT(key);
    NS_LOG_FUNCTION(this << "We obtained random key from qBUFFER: " << key->GetId());

    fillPayload["keys"].push_back({ {"key_ID", key->GetId()} }); //Add keyId object to JSON
    keyIds.push_back(key->GetId()); 
    sBuffer->StoreKey(key, true);
    sBuffer->MarkKey(key->GetId(), QKDKey::INIT);

    if(key->GetSizeInBits() > amount)
    {
      NS_LOG_DEBUG(this << "Trying to FILL beyond buffer capacity! " << key->GetSizeInBits() << " / " << sBuffer->GetKeySize());
      //NS_FATAL_ERROR(this << "Trying to FILL beyond buffer capacity! " << key->GetSizeInBits() << " / " << sBuffer->GetKeySize());
      break;
    }
    else
      amount -= key->GetSizeInBits();
  }

  if(fillPayload["keys"].empty()) 
  {
    NS_LOG_FUNCTION(this << "fillPayload is EMPTY!");
    return;
  }

  UpdateLinkState(dstKmNodeId); //Only on fill update state down.

  Ipv4Address peerAddress = GetPeerKmAddress(dstKmNodeId);
  std::string headerUri = "http://" + GetAddressString(peerAddress);
  headerUri += "/api/v1/sbuffers/fill";

  std::string msg = fillPayload.dump();
  NS_LOG_FUNCTION(this << headerUri << msg);
  //Create packet
  HTTPMessage httpMessage;
  httpMessage.CreateRequest(headerUri, "POST", msg);
  std::string hMessage = httpMessage.ToString();
  Ptr<Packet> packet = Create<Packet>(
   (uint8_t*)(hMessage).c_str(),
    hMessage.size()
  );
  NS_ASSERT(packet);

  CheckSocketsKMS( peerAddress ); //Check connection to peer KMS!
  Ptr<Socket> sendSocket = GetSendSocketKMS( peerAddress );
  NS_ASSERT(sendSocket);

  HttpQuery query;
  query.method_type = FILL;
  query.peerNodeId = dstKmNodeId;
  query.sBuffer = direction;
  query.keyIds = keyIds;
  HttpKMSAddQuery(peerAddress, query);

  sendSocket->Send(packet);
  NS_LOG_FUNCTION(this << "Packet sent" << dstKmNodeId
                        << packet->GetUid() << packet->GetSize());

}

Ptr<SBuffer>
QKDKeyManagerSystemApplication::GetSBuffer(uint32_t dstKmNodeId, std::string type)
{
  NS_LOG_FUNCTION(this << dstKmNodeId << type);
  if(type == "enc"){
    auto it = m_keys_enc.find(dstKmNodeId);
    if(it != m_keys_enc.end())
      return it->second;
  }else if(type == "dec"){
    auto it = m_keys_dec.find(dstKmNodeId);
    if(it != m_keys_dec.end())
      return it->second;
  }else
    NS_LOG_FUNCTION(this << "unknown type" << type);

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
  NS_FATAL_ERROR(this << "Buffer not found!"); 

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

  std::map<Ipv4Address, std::pair<Ptr<Socket>, Ptr<Socket> > >::iterator it;
  for( it = m_socketPairsKMS.begin(); !(it == m_socketPairsKMS.end());  it++ ){
    if(it->second.first) {
      //it->second.first->Close();
      it->second.first = nullptr;
    }
    if(it->second.second) {
      //it->second.second->Close();
      it->second.second = nullptr;
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
      it->second.first = s; //Set receiving socket
  else{
    Ptr<Socket> sendSocket = 0;
    m_socketPairsKMS.insert(
      std::make_pair(
        destKMS,
        std::make_pair(s, sendSocket)
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
    NS_LOG_FUNCTION(this << packet->GetUid() << "sent via socket " << socket);
  //otherwise wait in the queue
  }else{
    m_packetQueues.insert( std::make_pair(  socket ,  packet) );
    NS_LOG_FUNCTION(this << packet->GetUid() << "enqued for socket " << socket);
  }
}

void
QKDKeyManagerSystemApplication::SendToSocketPairKMS(Ptr<Socket> socket, Ptr<Packet> packet)
{
    NS_LOG_FUNCTION( this << socket );

    std::map<Ipv4Address, std::pair<Ptr<Socket>, Ptr<Socket> > >::iterator it;
    for( it = m_socketPairsKMS.begin(); !(it == m_socketPairsKMS.end());  it++ )
      //we do not have info about KMS destination address ?
      if( it->second.first == socket )
      {
        Ptr<Socket> sendingSocket = it->second.second;
        sendingSocket->Send(packet);
        NS_LOG_FUNCTION( this << "Packet ID" << packet->GetUid() << "Sending socket" << sendingSocket );
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

  if(i == m_socketPairsKMS.end()){
    NS_LOG_FUNCTION( this << "No connection between KMS defined!"); //@toDo: include HTTP response!
    EstablishKMLinkSockets(kmsDstAddress);
    CheckSocketsKMS(kmsDstAddress);
  }else{

    std::pair<Ptr<Socket>, Ptr<Socket> > pair = i->second;
    if(!pair.second){

      NS_LOG_FUNCTION(this << "Let's create a new send socket to reach KMS!");

      Ptr<Socket> sendSocket;
      Ptr<Socket> sinkSocket = pair.first;

      if(sinkSocket->GetSocketType() != Socket::NS3_SOCK_STREAM &&
          sinkSocket->GetSocketType() != Socket::NS3_SOCK_SEQPACKET)
      {
        NS_LOG_FUNCTION("Create UDP socket!");
        sendSocket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId() );
      }else{
        NS_LOG_FUNCTION("Create TCP socket!");
        sendSocket = Socket::CreateSocket(GetNode(), TcpSocketFactory::GetTypeId() );
        //disable Nagle’s algorithm
        sendSocket->SetAttribute("TcpNoDelay", BooleanValue(true));  
      }
      //sendSocket->ShutdownRecv();
      sendSocket->SetConnectCallback(
        MakeCallback(&QKDKeyManagerSystemApplication::ConnectionSucceededKMSs, this),
        MakeCallback(&QKDKeyManagerSystemApplication::ConnectionFailedKMSs, this));
      sendSocket->SetDataSentCallback( MakeCallback(&QKDKeyManagerSystemApplication::DataSendKMSs, this));

      InetSocketAddress peerAddress = InetSocketAddress(
        kmsDstAddress,
        8080
      );
      sendSocket->Bind();
      sendSocket->Connect( peerAddress );

      //update socket pair entry
      i->second.second = sendSocket;

      NS_LOG_FUNCTION(this
        << "Create the send socket " << sendSocket
        << " from KMS to KMS which is on " << kmsDstAddress
      );

    }else{
      NS_LOG_FUNCTION(this << "Socket to peer KMS exist. No action required");
    }

  }
}

Ptr<Socket>
QKDKeyManagerSystemApplication::GetSendSocketKMS(Ipv4Address kmsDstAddress)
{
  NS_LOG_FUNCTION( this << kmsDstAddress );
  //Local KMS should create socket to send data to peer KMS
  //Local KMS should check if the socket for this connection already exists?
  //Local KMS can have connections to multiple KMS systems - neighbor and distant KMSs
  auto i = m_socketPairsKMS.find( kmsDstAddress );

  if(i == m_socketPairsKMS.end()){

    NS_FATAL_ERROR( this << "No connection between KMS defined!"); //@toDo: include HTTP response!
    return NULL;

  } else {

    std::pair<Ptr<Socket>, Ptr<Socket> > pair = i->second;
    NS_ASSERT(pair.first);
    NS_ASSERT(pair.second);
    Ptr<Socket> sendSocket = pair.second;

    return sendSocket;
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
                   << InetSocketAddress::ConvertFrom(from).GetIpv4()
                   << " port " << InetSocketAddress::ConvertFrom(from).GetPort()
                   << " total Rx " << m_totalRx << " bytes");
      }

      m_rxTraceKMSs(packet, from);
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
}

void
QKDKeyManagerSystemApplication::PrepareSinkSocket() // Called at time specified by Start
{

  NS_LOG_FUNCTION(this);

  // Create the sink socket if not already
  if(!m_sinkSocket){
    m_sinkSocket = Socket::CreateSocket(GetNode(), m_tid);
    NS_LOG_FUNCTION(this << "Create the sink KMS socket!" << m_sinkSocket);
  }

  NS_LOG_FUNCTION(this << "Sink KMS socket listens on " << Ipv4Address::GetAny() << " and port " << m_port << " for APP requests" );
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
  NS_LOG_FUNCTION(this << headerIn.GetUri() << packet->GetUid());
  NS_ASSERT(!headerIn.GetUri().empty());

  auto uriParams = ReadUri(headerIn.GetUri());
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
      //return; //We should return, but we allow it for now to enable emulation mode!
    }
    remoteAppId = uriParams[4];
    ksid = uriParams[4];
    requestType = FetchRequestType(uriParams[5]);
  }

  if(requestType == ETSI_QKD_014_GET_STATUS)
  { 
      //Process GET_STATUS request
      QKDLocationRegisterEntry conn = GetController()->GetRoute(remoteAppId); //Get Route Info
      //@todo id1124
      NS_LOG_FUNCTION(this << "emira" << conn.GetDestinationKmNodeId());
      Ptr<SBuffer> sBuffer = GetSBuffer(conn.GetDestinationKmNodeId(), "enc");
      if(!sBuffer)
      { 
        NS_LOG_FUNCTION(this << "The S-Buffer does not exists! This is new virtual connection!");

        uint32_t srcNodeId = GetNode()->GetId();
        uint32_t dstNodeId = conn.GetDestinationKmNodeId();
        sBuffer = CreateRelaySBuffer(srcNodeId, dstNodeId, "(RELAY)");
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
        {"Request URI", headerIn.GetUri() }
      });
      std::string hMessage = httpMessage.ToString();
      Ptr<Packet> packet = Create<Packet>(
       (uint8_t*)(hMessage).c_str(),
        hMessage.size()
      );
      NS_ASSERT(packet);

      NS_LOG_FUNCTION(this << "Sending response:" << uriParams[5] << "\tPacketID: " << packet->GetUid() << " of size: " << packet->GetSize() << hMessage  );
      SendToSocketPair(socket, packet);

  }else if(requestType == ETSI_QKD_014_GET_KEY){ //Process GET_KEY

      QKDLocationRegisterEntry conn = GetController()->GetRoute(remoteAppId); //@todo id1124
      Ptr<SBuffer> sBuffer = GetSBuffer(conn.GetDestinationKmNodeId(), "enc");  //@todo id1125
      NS_ASSERT(sBuffer);

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
      }else{
        NS_FATAL_ERROR(this << "Invalid HTTP request method" << headerIn.GetMethod()); //@toDo: include HTTP response
      }

      NS_LOG_FUNCTION(this << "Validate request and probe ability to serve!");
      nlohmann::json errorDataStructure = Check014GetKeyRequest(keyNumber, keySize, sBuffer);
      HTTPMessage::HttpStatus statusCode {HTTPMessage::HttpStatus::Ok};
      std::string msg;
      if(!errorDataStructure.empty())
      { 
        NS_LOG_DEBUG(this << "We have an error. Request is not valid, or KM is unable to serve!");
        statusCode = HTTPMessage::HttpStatus::BadRequest;
        msg = errorDataStructure.dump();
      }else{ 
        NS_LOG_FUNCTION(this << "The request is valid. KM can serve key(s)");

        std::vector<std::string> candidateSetIds {};
        std::string mergedKey, surplusKeyId;
        uint32_t targetSize = keySize*keyNumber;
        while(true)
        { 
          NS_LOG_FUNCTION(this << "Form a transform set, and a large merged key!");
          uint32_t tempTarget {0};
          if(targetSize <= sBuffer->GetKeySize())
            tempTarget = targetSize;

          Ptr<QKDKey> candidateKey = sBuffer->GetTransformCandidate(tempTarget);
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
          std::string skeyId = GenerateUUID();
          std::string keyString = mergedKey.substr(0, keySize/8);
          mergedKey.erase(0, keySize/8);

          Ptr<QKDKey> tempKey = CreateObject<QKDKey>(skeyId, keyString);
          supplyKeys.push_back(tempKey);
          supplyKeyIds.push_back(skeyId);

          //Record amount of served key to the end-user application
          m_keyServedTrace(
            remoteAppId,
            tempKey->GetId(),
            tempKey->GetSizeInBits()
          );

          if(sBuffer->GetType() == SBuffer::LOCAL_SBUFFER) //Then this is p2p connection!
            m_keyConsumedLink(
              GetNode()->GetId(), //Source
              conn.GetDestinationKmNodeId(), //Destination
              //tempKey->GetId(),
              tempKey->GetSizeInBits()
            );

        }
        NS_ASSERT(mergedKey.empty());

        //Create response on get_key
        nlohmann::json jkeys = CreateKeyContainer(supplyKeys);
        msg = jkeys.dump();


        //Send skey_create message to peer KM node
        NS_LOG_FUNCTION( this << "key_size" << keySize ); //Testing @rm
        NS_LOG_FUNCTION( this << "key_number" << keyNumber);
        NS_LOG_FUNCTION( this << "supply_key_IDs" << supplyKeyIds );
        NS_LOG_FUNCTION( this << "candidate_set_IDs" << candidateSetIds );
        NS_LOG_FUNCTION( this << "surplus_key_ID" << surplusKeyId);

        //Create HTTP message transform
        nlohmann::json jtransform;
        jtransform["source_node_id"] = GetNode()->GetId();
        jtransform["target_SAE_ID"] = remoteAppId;
        jtransform["key_size"] = keySize;
        jtransform["key_number"] = keyNumber;
        for(size_t i = 0; i < supplyKeyIds.size(); i++)
          jtransform["supply_key_ID"].push_back({{"key_ID", supplyKeyIds[i]}});
        for(size_t i = 0; i < candidateSetIds.size(); i++)
          jtransform["candidate_set_ID"].push_back({{"key_ID", candidateSetIds[i]}});

        std::string msg1 = jtransform.dump();
        NS_LOG_FUNCTION( this << "Transform payload" << msg1 ); //Testing @rm
        Ipv4Address dstKms = conn.GetDestinationKmsAddress(); //Destination KMS adress
        CheckSocketsKMS(dstKms); //Check connection to peer KMS!
        Ptr<Socket> sendSocket = GetSendSocketKMS(dstKms); //Get send socket to peer KMS
        NS_ASSERT(sendSocket); //Check

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

        sendSocket->Send(packet);
        NS_LOG_FUNCTION(this << "SKEY_CREATE request sent to peer KM" << packet->GetUid() << packet->GetSize());
      }

      if(sBuffer->GetType() == SBuffer::RELAY_SBUFFER || GetNode()->GetId() > conn.GetDestinationKmNodeId()){
        SBufferClientCheck(conn.GetDestinationKmNodeId());
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

      NS_LOG_FUNCTION(this << "\nSending PacketID: " << packet->GetUid() << " of size: " << packet->GetSize() << hMessage);

      //SendToSocketPair(socket, packet);
      Simulator::Schedule(Seconds(0.015), &QKDKeyManagerSystemApplication::SendToSocketPair, this, socket, packet);

  }else if(requestType == ETSI_QKD_014_GET_KEY_WITH_KEY_IDS){ //Process GET_KEY_WITH_KEY_IDS
      QKDLocationRegisterEntry conn = GetController()->GetRoute(remoteAppId); //@todo id1124
      Ptr<SBuffer> sBuffer = GetSBuffer(conn.GetDestinationKmNodeId(), "dec");
      NS_ASSERT(sBuffer);

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
      for(const auto &el : keyIDs){
        Ptr<QKDKey> tempKey = sBuffer->GetSupplyKey(el);
        if(tempKey){
          NS_LOG_FUNCTION(this << "krec007" << el << "succeeded");
          keys.push_back(tempKey);
          m_keyServedTrace(
            remoteAppId,
            tempKey->GetId(),
            tempKey->GetSizeInBits()
          );

          if(sBuffer->GetType() == SBuffer::LOCAL_SBUFFER) //Then this is p2p connection!
            m_keyConsumedLink(
              GetNode()->GetId(), //Source
              conn.GetDestinationKmNodeId(), //Destination
              //tempKey->GetId(),
              tempKey->GetSizeInBits()
            );

        }else //The key is not present in SBuffer
          error = true;

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

      NS_LOG_FUNCTION(this << "Sending Response to ETSI_QKD_014_GET_KEY\n PacketID: " << packet->GetUid() << " of size: " << packet->GetSize() << hMessage  );
      SendToSocketPair(socket, packet);

  } else if(requestType == ETSI_QKD_004_OPEN_CONNECT) {

      //m_queueLogic->Enqueue(headerIn);
      //HTTPMessage h2 = m_queueLogic->Dequeue();

      ProcessOpenConnectRequest(headerIn, socket);


  } else if(requestType == ETSI_QKD_004_GET_KEY) {
      ProcessGetKey004Request(ksid, headerIn, socket); 
  } else if(requestType == ETSI_QKD_004_CLOSE) {
      ProcessCloseRequest(ksid, headerIn, socket);

  } else if(requestType == STORE_KEY) {

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
    if(GetNode()->GetId() > dstNodeId)
      isMaster = true; //This node, with higher node ID, takes role of a master!

   
    Ptr<QBuffer> buffer = GetQBuffer(dstNodeId); //Select QKD buffer
    if(!buffer){
      NS_LOG_ERROR(this << "Buffer not found!");
      return;
    } 

    if(!m_encryptor)
      m_encryptor = CreateObject<QKDEncryptor>(64); //64 bits long key IDs. Collisions->0

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
      std::string blockKeyId {m_encryptor->SHA1(completeHashInput)}; //Generate KMA-key ID based on the HASH output
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
    else
      NS_FATAL_ERROR( this << "Invalid request method!" );
  }

}


/**
 * ********************************************************************************************

 *        ETSI004 APP-KMS functions

 * ********************************************************************************************
 */

void
QKDKeyManagerSystemApplication::ProcessOpenConnectRequest(HTTPMessage headerIn, Ptr<Socket> socket)
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
 

    QKDLocationRegisterEntry conn = GetController()->GetRoute(dstSaeId);
    bool callByMaster {ksid.empty()};
    if(callByMaster){ //Request made by master SAE!
        ksid = CreateKeyStreamSession(srcSaeId, dstSaeId, inQos, ksid); //Create new key stream session!
        if(conn.GetHop() == 1){ //Point-to-point connection
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
            SendToSocketPair(socket, packet); //Respond to SAE!

        }else{ //Not-Supported
            NS_FATAL_ERROR(this << "ETSI QKD 004 is supported only for point-to-point connections");
            return;
        }

        NewAppRequest(ksid); //Send NEW_APP notification

    }else{ //Request made by slave SAE!
      auto it = m_associations004.find(ksid);
      if(it == m_associations004.end()){
          NS_LOG_ERROR(this << "Key stream association identified with " << ksid << "does not exists!");
          //@toDo error response
          return;

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
QKDKeyManagerSystemApplication::ProcessGetKey004Request(std::string ksid, HTTPMessage headerIn, Ptr<Socket> socket)
{
    NS_LOG_FUNCTION( this << "Processing get_key request(ETSI 004)" << ksid );
    auto it = m_associations004.find(ksid);
    if(it == m_associations004.end()){
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
 
    NS_LOG_FUNCTION(this << "EMIRS" << it->second.stre_buffer->GetStreamKeyCount() << it->second.peerRegistered);
    
    if( it->second.peerRegistered && it->second.stre_buffer->GetStreamKeyCount())
    { //Check
        Ptr<QKDKey> keyChunk = it->second.stre_buffer->GetStreamKey();
        if(GetNode()->GetId() > it->second.dstNodeId)
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

        m_keyServedTrace(it->second.srcSaeId, keyChunk->GetId(), keyChunk->GetSizeInBits()); //trace served key material etsi 004
        m_keyConsumedLink( //Is always p2p link now for 004
          it->second.srcNodeId, //Source
          it->second.dstNodeId, //Destination
          //{ksid + keyChunk->GetId()},  //Key ID should be combination of ksid+index!
          keyChunk->GetSizeInBits() //Size of key
        );

    }else{
        //Respond with an error. Currently this is the only error on GetKey004, therefore no message is included. @toDo
        NS_LOG_FUNCTION(this << "No keys available in the association buffer. Responding on the request ...");

        auto itSchedule = m_scheduledChecks.find(ksid);
        if(itSchedule!=m_scheduledChecks.end())
        {
          NS_LOG_FUNCTION(this << "The CheckEtsi004Association for ksid ("<< ksid << ") is already scheduled!");
        }else{
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
QKDKeyManagerSystemApplication::ProcessCloseRequest(std::string ksid, HTTPMessage headerIn, Ptr<Socket> socket)
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
    Ptr<Socket> sendSocket = GetSendSocketKMS((it->second).dstKmsAddr );
    NS_ASSERT(sendSocket);

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

    sendSocket->Send(packet);
    NS_LOG_FUNCTION( this << "Synchronization information for releasing key stream association sent to peer KMS"
                          << packet->GetUid() << packet->GetSize() );

}


Ptr<SBuffer>
QKDKeyManagerSystemApplication::CreateRelaySBuffer(uint32_t srcNodeId, uint32_t dstNodeId, std::string description)
{
    NS_LOG_FUNCTION(this << srcNodeId << dstNodeId << description);

    Ptr<SBuffer> sBuffer = GetController()->CreateRSBuffer(dstNodeId); //QKDNController Create new S-Buffer
    sBuffer->SetType(SBuffer::Type::RELAY_SBUFFER); 
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
    std::string graphTitle = "SBUFFER (RELAY): " +  std::to_string(srcNodeId) + " - " + std::to_string(dstNodeId); 
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
      NS_LOG_FUNCTION(this << "\nFirstNode -> Relay key -> ID: " << key->GetId()
                           << "\nFirstNode -> Relay key -> key: " << key->GetKeyString());
      keyIds.push_back(key->GetId());
      keys.push_back(key->GetKeyString());
    }

    if(GetNode()->GetId() > srcNodeId)//this is master KMS
      SBufferClientCheck(srcNodeId); //run sbuffer client check for LOCAL Sbuffer

  }else{ //Read {KeyId, eKey, eKeyId}, decrypt eKey!

    NS_LOG_FUNCTION(this << "Read {KeyId, eKey, eKeyId}, decrypt eKey!");

    uint32_t previousNodeId = jRelayPayload["repeater_node_id"];
    std::vector<std::string> ekeys {}, ekeyIds {};
    Ptr<SBuffer> decBuffer = GetSBuffer(previousNodeId, "dec");
    NS_ASSERT(decBuffer);
    Ptr<QKDEncryptor> decryptor = CreateObject<QKDEncryptor>();
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
      keys.push_back( decryptor->COTP(key->GetKeyString(),(it.value())["ekey"]) );
    }

    if(GetNode()->GetId() > previousNodeId) //this is master KMS
      SBufferClientCheck(previousNodeId); //run sbuffer client check for LOCAL Sbuffer
  }

  //If it is relay node encrypt keys to next Hop
  if(GetNode()->GetId() != dstNodeId && !terminateRelay)//
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
      Ptr<Socket> sendSocket = GetSendSocketKMS(peerAddress);
      sendSocket->Send(packet);

      return;

    }

    Ptr<QKDEncryptor> encryptor = CreateObject<QKDEncryptor>(); //Get Encryptor to relay keys to destination
    NS_ASSERT(encryptor);

    nlohmann::json jRelay;

    uint32_t encDefaultKeySize = encBuffer->GetKeySize();
    for(uint32_t i = 0; i < keyIds.size(); i++)
    {
      NS_LOG_FUNCTION(this << i << keyIds.size() << encDefaultKeySize);
      Ptr<QKDKey> encKey = encBuffer->GetKey(encDefaultKeySize); //Get key with default key size!
      if(encKey){
        NS_LOG_FUNCTION(this << "\nMiddleNode -> Relay key -> eKeyId" << encKey->GetId()
                             << "\nMiddleNode -> Relay key -> keyId" << keyIds[i]);
        std::string encryptedKey = encryptor->COTP(encKey->GetKeyString(), keys[i]); //key, input
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
    if(GetNode()->GetId() > conn.GetNextHop()) //this is master KMS
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
    Ptr<Socket> sendSocket = GetSendSocketKMS( nextHopAddress );

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

    sendSocket->Send(packet);
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
      sBuffer = CreateRelaySBuffer(dstNodeId, srcNodeId, "(RELAY)");
      m_keys_enc.insert(std::make_pair(srcNodeId, sBuffer)); //Store a pointer to new sBuffer
      m_keys_dec.insert(std::make_pair(srcNodeId, sBuffer)); //Store a pointer to new sBuffer 
    }
    NS_ASSERT(sBuffer);
    NS_LOG_FUNCTION(this << keyIds.size() << keys.size());
    for(uint32_t i = 0; i < keyIds.size(); i++){ //Add keys to RELAY_SBUFFER -- "dec"
      Ptr<QKDKey> key = CreateObject<QKDKey>(keyIds[i], keys[i]);
      NS_LOG_FUNCTION(this << "relay key added" << keyIds[i]);
      sBuffer->StoreKey(key, true);
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

    //Ipv4Address peerAddress = GetController()->GetRoute(previousNodeId).GetNextHopAddress();
    Ptr<Socket> sendSocket = GetSendSocketKMS(peerAddress);
    NS_ASSERT(sendSocket);
    uint32_t outcome = sendSocket->Send(packet);
    NS_LOG_INFO(this << "outcome of sending packet:" << outcome);

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

  if(prevHop != GetNode()->GetId()){
    //create packet
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
    Ptr<Socket> sendSocket = GetSendSocketKMS(peerAddress);
    NS_ASSERT(sendSocket);

    NS_LOG_FUNCTION( this << "Forwarding response" << packet->GetUid() << packet->GetSize() );
    sendSocket->Send(packet);

  }else{

    //Response have reached the source
    NS_LOG_FUNCTION(this << "Response have reached the source!" << headerIn.GetStatus());
    Ptr<SBuffer> relayBuffer = GetSBuffer(sQuery.peerNodeId, "enc");
    NS_ASSERT(relayBuffer);
    std::vector<std::string> keyIds = sQuery.keyIds;
    bool fail {headerIn.GetStatus() != HTTPMessage::HttpStatus::Ok};
    for(const auto& keyId : keyIds){
      if(headerIn.GetStatus() == HTTPMessage::HttpStatus::Ok)
        relayBuffer->MarkKey(keyId, QKDKey::READY);
      else{
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
        relayBuffer->MarkKey(keyId, QKDKey::OBSOLETE);
      }
    }
    relayBuffer->SetRelayState(false);
    NS_LOG_FUNCTION(this << "\nAmount of key material in RELAY s-buffer (READY): " << relayBuffer->GetSBitCount());
    if(fail){
      //SBufferClientCheck(sQuery.peerNodeId);
      NS_LOG_FUNCTION(this << "relay fail");
    }

  }

  RemoveProxyQuery(reqId);
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
    Ptr<Socket> sendSocket = GetSendSocketKMS((it->second).dstKmsAddr );
    NS_ASSERT(sendSocket);

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

    sendSocket->Send(packet);
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
        CreateKeyStreamSession(dstSaeId, srcSaeId, inQoS, ksid);
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
        Ptr<Socket> sendSocket = GetSendSocketKMS( dstKms ); //Obtain send socket object to reach dstKms
        NS_ASSERT(sendSocket);
        sendSocket->Send(packet);

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
    if(headerIn.GetStatus() == 200){ //Status OK
        if(GetController()->GetRoute(dstSaeId).GetHop() == 1) //dstKms for point-to-point scenario!
            HttpKMSCompleteQuery(dstKms); //Point-to-point scenario. Response just as acknowledgement!
        else{//@toDo Trusted relay scenario. QKDApp is waiting for OPEN_CONNECT response!
            bool QoS {true}; //Read QoS from response, calculate its own, and make response!
            if(QoS){
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

                Ptr<Socket> responseSocket = GetSocketFromHttp004AppQuery(it->second[0].source_sae);
                Http004AppQueryComplete(it->second[0].source_sae);
                HttpKMSCompleteQuery(dstKms);
                CheckSocketsKMS( dstKms ); //Check connection to dstKms
                Ptr<Socket> sendSocket = GetSendSocketKMS( dstKms ); //Obtain send socket object to reach dstKms
                NS_ASSERT(sendSocket);
                sendSocket->Send(packet);
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
    Ptr<Socket> sendSocket = GetSendSocketKMS( dstKms ); //Obtain send socket object to reach dstKms
    NS_ASSERT(sendSocket);

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

    sendSocket->Send(packet); //Send the packet to dstKms
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
    Ptr<Socket> sendSocket = GetSendSocketKMS( it->second.dstKmsAddr );
    NS_ASSERT(sendSocket);
    sendSocket->Send(packet);

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
QKDKeyManagerSystemApplication::ProcessFillRequest(HTTPMessage headerIn, std::string resource, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this);

  std::string payload = headerIn.GetMessageBodyString();
  nlohmann::json jFillPayload;
  try{
    jFillPayload = nlohmann::json::parse(payload);
  }catch(...){
     NS_FATAL_ERROR( this << "JSON parse error!" );
  }

  //Read peer KM node ID
  uint32_t peerNodeId = 100000;
  std::string sBufferType, ksid;
  if(jFillPayload.contains("source_node_id"))
    peerNodeId = jFillPayload["source_node_id"];
  if(jFillPayload.contains("s_buffer_type"))
    sBufferType = jFillPayload["s_buffer_type"];

  if(sBufferType == "stream"){
    if(jFillPayload.contains("ksid"))
      ksid = jFillPayload["ksid"];
    else
      NS_FATAL_ERROR(this << "Mandatory parametar -- ksid -- not received");
  }
  NS_ASSERT(peerNodeId != 100000);

  NS_LOG_FUNCTION(this << "sBufferType:" << sBufferType);

  Ptr<QBuffer> qBuffer = GetQBuffer(peerNodeId);
  Ptr<SBuffer> sBuffer;
  if(sBufferType != "stream")
  {
    sBuffer = GetSBuffer(peerNodeId, sBufferType);
    if(!sBuffer)
    { 
      NS_LOG_FUNCTION(this << "Establishment of relay s-Buffer!"); 
      uint32_t srcNodeId = GetNode()->GetId();
      uint32_t dstNodeId = peerNodeId;
      sBuffer = CreateRelaySBuffer(srcNodeId, dstNodeId, "(RELAY)");  
      m_keys_enc.insert(std::make_pair(peerNodeId, sBuffer)); //Store a pointer to new sBuffer
      m_keys_dec.insert(std::make_pair(peerNodeId, sBuffer)); //Store a pointer to new sBuffer
    }
  }else if(sBufferType == "stream"){
    auto it = m_associations004.find(ksid);
    if(it == m_associations004.end()){
      NS_FATAL_ERROR(this << "Unknown ksid" << ksid);
      return;
    }
    sBuffer = it->second.stre_buffer;
  }
  NS_ASSERT(sBuffer || qBuffer);

  //Obtain keys!
  bool storeSuccesfull = true;
  nlohmann::json resultKeyIds; 
  for(nlohmann::json::iterator it = jFillPayload["keys"].begin(); it != jFillPayload["keys"].end(); ++it){
    Ptr<QKDKey> key = qBuffer->GetKey((it.value())["key_ID"] );
    if(key)
    {
      NS_LOG_FUNCTION(this << key->GetId() << key->GetKeyString());
      NS_LOG_FUNCTION(this << "Let's try to save key " << key->GetId() << " in sBuffer: " << sBuffer->GetDescription() );
      storeSuccesfull = true;
      if(sBufferType != "stream")
      { 
        storeSuccesfull = sBuffer->StoreKey(key, true);
        if(!storeSuccesfull)
        {
          NS_LOG_FUNCTION(this << "Unable to store key " << key->GetId() << " in SBUFFER! Return it back to QBuffer!");
          qBuffer->StoreKey(key, true);
        }else{
          sBuffer->MarkKey( key->GetId(), QKDKey::READY );
        }
      } else {
        sBuffer->InsertKeyToStreamSession(key); //Insert key to stream directly
      }
      if(storeSuccesfull)
        resultKeyIds["keys_accepted"].push_back( { {"key_ID", key->GetId()} } );
      else
        resultKeyIds["keys_rejected"].push_back( { {"key_ID", key->GetId()} } );
    } 
  }

  NS_LOG_FUNCTION(this << "FILL complete, check the state of S-Buffer" << sBuffer->GetSKeyCount());
  NS_LOG_FUNCTION(this << "FILL complete, but how many in default size: " << sBuffer->GetDefaultKeyCount() << sBuffer->GetKeySize()); 

  UpdateLinkState(peerNodeId);
 
  HTTPMessage httpMessage; 
  if(storeSuccesfull)
  { 
    NS_LOG_FUNCTION(this << resultKeyIds.dump());
    httpMessage.CreateResponse(HTTPMessage::HttpStatus::Ok, resultKeyIds.dump(), {
      {"Content-Type", "application/json; charset=utf-8"},
      {"Request URI", headerIn.GetUri() }
    });
  }else{
    httpMessage.CreateResponse(HTTPMessage::HttpStatus::NotAcceptable, resultKeyIds.dump(), {
      {"Content-Type", "application/json; charset=utf-8"},
      {"Request URI", headerIn.GetUri() }
    });
  } 
  std::string hMessage = httpMessage.ToString();
  Ptr<Packet> packet = Create<Packet>(
   (uint8_t*)(hMessage).c_str(),
    hMessage.size()
  );
  NS_ASSERT(packet);

  NS_LOG_FUNCTION( this << "Sending response" << packet->GetUid() << packet->GetSize() << hMessage );
  //Ipv4Address peerKMAddress = GetController()->GetRoute(peerNodeId).GetNextHopAddress();
  Ipv4Address peerKMAddress = GetPeerKmAddress(peerNodeId);
  CheckSocketsKMS(peerKMAddress);
  Ptr<Socket> sendSocket = GetSendSocketKMS(peerKMAddress);
  NS_ASSERT(sendSocket);
  sendSocket->Send(packet);
}

void
QKDKeyManagerSystemApplication::ProcessFillResponse(HTTPMessage headerIn, Ipv4Address from)
{
  NS_LOG_FUNCTION(this << headerIn.GetRequestUri());

  //Ipv4Address peerAddress = GetDestinationKmsAddress(socket);
  Ipv4Address dstKms { ReadUri(headerIn.GetRequestUri())[0].c_str() };
  auto it = m_httpRequestsQueryKMS.find(dstKms);
  for(;;){
    if(it == m_httpRequestsQueryKMS.end() ||(it->second).empty())
      NS_FATAL_ERROR( this << "Response cannot be mapped! HttpQuery empty!" );
    if(it->second[0].method_type != FILL){
      NS_LOG_ERROR(this << "invalid mapping");
      HttpKMSCompleteQuery(dstKms);
    }else
      break;
    NS_LOG_FUNCTION(this << it->second[0].method_type << it->second[0].sBuffer);
  }
 
  if(headerIn.GetStatus() == HTTPMessage::HttpStatus::Ok)
  { //ACK message
    NS_LOG_FUNCTION(this << "We received HTTP OK(ack)!");  
  }else{
    NS_LOG_ERROR(this << " *** Unexpected error received! *** ");
  }

  std::string payload { headerIn.GetMessageBodyString() };
  nlohmann::json resultKeyIds;
  try{
    resultKeyIds = nlohmann::json::parse(payload);
  }catch(...){
    NS_FATAL_ERROR(this << "json parse error");
  }

  uint32_t peerNodeId =(it->second)[0].peerNodeId; 
  Ptr<QBuffer> qBuffer = GetQBuffer(peerNodeId);
  std::string sBufferType =(it->second)[0].sBuffer;
  Ptr<SBuffer> sBuffer;
  if(sBufferType == "enc" || sBufferType == "dec"){
    sBuffer = GetSBuffer(peerNodeId, sBufferType);
    NS_ASSERT(sBuffer);
  }else{ //Find stream buffer
    auto it {m_associations004.find(sBufferType)};
    if(it == m_associations004.end())
      NS_FATAL_ERROR(this << "unknwon ksid" << sBufferType);
    else
      sBuffer = it->second.stre_buffer;
  }
  std::vector<std::string> keyIds =(it->second)[0].keyIds;

  NS_LOG_FUNCTION(this << "First take all ACCEPTED keys from response. Mark them ready. Remove them from local keyIds!");
  for(nlohmann::json::iterator it = resultKeyIds["keys_accepted"].begin(); it != resultKeyIds["keys_accepted"].end(); ++it)
  {
    std::string keyId {(it.value())["key_ID"]};
    auto a { std::find( keyIds.begin(), keyIds.end(), keyId ) };
    if(a != keyIds.end())
      keyIds.erase(a);
    else
      NS_FATAL_ERROR(this << "unknown key " <<(it.value())["key_ID"]);

    if(sBufferType == "enc" || sBufferType == "dec"){
      sBuffer->MarkKey( keyId, QKDKey::READY );
    } else {
      //association move keys from its store to stream
      //Ptr<QKDKey> key { sBuffer->QBuffer::GetKey(keyId) }; //This will remove key from store!
      Ptr<QKDKey> key { sBuffer->GetKey(keyId, false) }; //This will remove key from store!
      if(key)
      {
        key->SwitchToState( QKDKey::READY );
        sBuffer->InsertKeyToStreamSession(key);
      } else{
        NS_FATAL_ERROR(this << "unknown key " << keyId);
      }
    }
  }

  //CHECK rejected keyIds 
  NS_LOG_FUNCTION(this << "Now check REJECTED keys from response. Return them to QBuffer!");
  for(nlohmann::json::iterator it = resultKeyIds["keys_rejected"].begin(); it != resultKeyIds["keys_rejected"].end(); ++it)
  {
    std::string keyId {(it.value())["key_ID"]};
    auto a { std::find( keyIds.begin(), keyIds.end(), keyId ) };
    if(a != keyIds.end())
      keyIds.erase(a);
    else
      NS_FATAL_ERROR(this << "unknown key " <<(it.value())["key_ID"]);

    NS_LOG_FUNCTION(this << "Return key " << keyId << " to QBuffer!");
    Ptr<QKDKey> key = sBuffer->GetKey( keyId, false);
    key->SwitchToState( QKDKey::READY );
    qBuffer->StoreKey(key, false);
  }

  NS_LOG_FUNCTION(this << "FILL complete, check the state of S-Buffer: " << sBuffer->GetSKeyCount());

  UpdateLinkState(peerNodeId);
  //Then remaining keys in keyIds should be marked obsolute! This will remove them from store!
  NS_LOG_FUNCTION(this << "rejected keys " << keyIds.size() << keyIds);
  for(const auto& el: keyIds)
    sBuffer->MarkKey(el, QKDKey::OBSOLETE); //This will remove key from store!

  

  HttpKMSCompleteQuery(dstKms);
}

void
QKDKeyManagerSystemApplication::ProcessSKeyCreateRequest(HTTPMessage headerIn, Ptr<Socket> socket)
{
    NS_LOG_FUNCTION( this << socket );
    std::string payload = headerIn.GetMessageBodyString();
    nlohmann::json jPayload;
    try {
        jPayload = nlohmann::json::parse(payload);
    } catch(...) {
        NS_FATAL_ERROR( this << "JSON parse error!" );
    }
    //Read JSON parameters
    uint32_t keySize {0}, keyNumber {0};
    std::vector<std::string> candidateSetIds {}, supplyKeyIds {};
    std::string surplusKeyId, targetSaeId;

    uint32_t peerNodeId;
    if(jPayload.contains("source_node_id"))
      peerNodeId = jPayload["source_node_id"];
    if(jPayload.contains("target_SAE_ID"))
      targetSaeId = jPayload["target_SAE_ID"];
    if(jPayload.contains("key_size"))
        keySize = jPayload["key_size"];
    if(jPayload.contains("key_number"))
        keyNumber = jPayload["key_number"]; 
    if(jPayload.contains("supply_key_ID")){
        for(
          nlohmann::json::iterator it = jPayload["supply_key_ID"].begin();
          it != jPayload["supply_key_ID"].end();
          ++it
        ){
            supplyKeyIds.push_back((it.value())["key_ID"]);
          }
    }
    if(jPayload.contains("candidate_set_ID")){
        for(
          nlohmann::json::iterator it = jPayload["candidate_set_ID"].begin();
          it != jPayload["candidate_set_ID"].end();
          ++it
        )
          candidateSetIds.push_back((it.value())["key_ID"]);
    }
    NS_ASSERT(keySize || keyNumber);
    NS_ASSERT(!supplyKeyIds.empty() || !candidateSetIds.empty() || !targetSaeId.empty());

    //We read the request values, now we should create supply keys
    NS_LOG_FUNCTION(this << "\nSource KM node ID:\t" << peerNodeId
        << "\nTarget SAE ID:" << targetSaeId << "\nKey size:\t" << keySize
        << "\nKey number:\t" << keyNumber << "\nSupply key IDs:\t"<< supplyKeyIds
        << "\nCandidateSetIDs:" << candidateSetIds);

    Ptr<SBuffer> sBuffer = GetSBuffer(peerNodeId, "dec");
    NS_ASSERT(sBuffer);
    if(sBuffer)
    {
      //We assume that all keys exists and we can create supply keys!
      uint32_t targetSize = keySize*keyNumber;
      std::string mergedKey {};
      Ptr<QKDKey> tempKey;
      for(size_t i = 0; i < candidateSetIds.size(); i++)
      {
        if(i != candidateSetIds.size()-1)
        {
          tempKey = sBuffer->GetKey(candidateSetIds[i], true);
          mergedKey += tempKey->GetKeyString(); //GetKey will also remove key from SBuffer
          NS_LOG_FUNCTION(this << "em94" << targetSize << mergedKey);
        }else{
          uint32_t size = targetSize - mergedKey.size()*8;
          NS_LOG_FUNCTION(this << "em95" << targetSize << mergedKey.size()*8 << size << "\n" << mergedKey);
          mergedKey +=(sBuffer->GetHalfKey(candidateSetIds[i], size))->GetKeyString(); //This function should modify key
        }
      }

      for(size_t i = 0; i < supplyKeyIds.size(); i++)
      { //Should use keyNumber but the previus read is invalid! @toDo
        std::string keyString = mergedKey.substr(0, keySize/8);
        mergedKey.erase(0, keySize/8);
        Ptr<QKDKey> skey = CreateObject<QKDKey>(supplyKeyIds[i], keyString);
        sBuffer->StoreSupplyKey(skey);
      }

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

      QKDLocationRegisterEntry conn = GetController()->GetRoute(peerNodeId); //Get route information
      Ipv4Address dstKms = conn.GetDestinationKmsAddress();
      CheckSocketsKMS( dstKms ); //Check connection to peer KMS!
      Ptr<Socket> sendSocket = GetSendSocketKMS( dstKms );
      NS_ASSERT(sendSocket);
      sendSocket->Send(packet);

      NS_LOG_FUNCTION( this << "Sending packed id " << packet->GetUid() << " of size " << packet->GetSize());

      //SendToSocketPairKMS(socket, packet);

    }else
        NS_FATAL_ERROR( this << "No s-buffer found for this connection!" );

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
        Ptr<Socket> sendSocket = GetSendSocketKMS( it->second.dstKmsAddr );
        NS_ASSERT(sendSocket);
        sendSocket->Send(packet);

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
        Ptr<Socket> sendSocket = GetSendSocketKMS( it->second.dstKmsAddr );
        NS_ASSERT(sendSocket);
        sendSocket->Send(packet);

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
    { 
      NS_LOG_FUNCTION(this << "emir1" << it->second.stre_buffer->GetNextIndex());
      Ptr<QKDKey> key = it->second.stre_buffer->GetStreamKey();
      presentKeyMaterial += key->GetSizeInBits();
      m_keyServedTrace(it->second.srcSaeId, key->GetId(), key->GetSizeInBits());
      m_keyConsumedLink( //Is always p2p link now for 004
        it->second.srcNodeId, //Source
        it->second.dstNodeId, //Destination
        //{ksid + key->GetId()},  //Key ID should be combination of ksid+index!
        key->GetSizeInBits() //Size of key
      );

    }
    //Get remaining keys, and group them in one string
    while(true){
      Ptr<QKDKey> key = it->second.stre_buffer->GetStreamKey();
      if(key)
        preservedKeyString += key->GetKeyString();
      else
        break;

    }
    if(!preservedKeyString.empty()){
      Ptr<QBuffer> qBuffer = GetQBuffer(GetController()->GetRoute(it->second.dstSaeId).GetDestinationKmNodeId());
      if(qBuffer){
        NS_LOG_FUNCTION(this << "preserved key material" << preservedKeyString.size());

        if(!m_encryptor)
          m_encryptor = CreateObject<QKDEncryptor>(64); //64 bits long key IDs. Collisions->0

        std::string hashInput {surplusKeyId + ksid}; //HASH input for key id
        NS_ASSERT(!hashInput.empty());

        uint32_t blockSize {qBuffer->GetKeySize()/8}, blockNum {0}; //Current default key size for connection
        while(!preservedKeyString.empty()){
          std::string keyValueTemp {preservedKeyString};
          if(preservedKeyString.size() >= blockSize)
            keyValueTemp = preservedKeyString.substr(0, blockSize); //Take portion of the QKD-key value for KMA-key
          std::string completeHashInput = hashInput + std::to_string(blockNum++); //Complete HASH input
          std::string blockKeyId {m_encryptor->SHA1(completeHashInput)}; //Generate KMA-key ID based on the HASH output
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
        m_keyServedTrace(a->second.srcSaeId, key->GetId(), key->GetSizeInBits());
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
      //must record key consumed
      uint32_t presentKeyMaterial {0};
      while(true){
        Ptr<QKDKey> key {a->second.stre_buffer->GetStreamKey()};
        if(key){
          NS_LOG_FUNCTION(this << key->GetId());
          presentKeyMaterial += key->GetSizeInBits();
          m_keyServedTrace(a->second.srcSaeId, key->GetId(), key->GetSizeInBits());
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

QKDKeyManagerSystemApplication::RequestType
QKDKeyManagerSystemApplication::HttpQueryMethod(Ipv4Address dstKms)
{
    NS_LOG_FUNCTION( this );
    QKDKeyManagerSystemApplication::RequestType methodType;
    auto it = m_httpRequestsQueryKMS.find(dstKms);
    if(it!=m_httpRequestsQueryKMS.end())
        methodType = it->second.begin()->method_type;
    else
        NS_FATAL_ERROR( this << "HTTP response cannot be mapped: HTTP query is empty!" );
    return methodType;
}

void
QKDKeyManagerSystemApplication::Http004AppQuery( std::string saeId, Ptr<Socket> socket )
{
  NS_LOG_FUNCTION( this << saeId << socket );
  m_http004App.insert(std::make_pair(saeId, socket));
}

void
QKDKeyManagerSystemApplication::Http004AppQueryComplete(std::string saeId)
{
  NS_LOG_FUNCTION( this << saeId );
  //Must use equal_range
  std::pair<std::multimap<std::string, Ptr<Socket> >::iterator, std::multimap<std::string, Ptr<Socket> >::iterator > ret;
  ret = m_http004App.equal_range(saeId);

  if(ret.first == ret.second)
    NS_FATAL_ERROR( this << "Query is empty" );

  std::multimap<std::string, Ptr<Socket> >::iterator it = ret.first;
  m_http004App.erase(it);

}

Ptr<Socket>
QKDKeyManagerSystemApplication::GetSocketFromHttp004AppQuery(std::string saeId)
{
  NS_LOG_FUNCTION( this << saeId );

  std::pair<std::multimap<std::string, Ptr<Socket> >::iterator, std::multimap<std::string, Ptr<Socket> >::iterator > ret;
  ret = m_http004App.equal_range(saeId);
  if(ret.first == ret.second)
    NS_FATAL_ERROR( this << "sae query is not registered" );
  auto it = ret.first;

  NS_LOG_FUNCTION( this << saeId << it->second);
  return it->second;

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


Ipv4Address
QKDKeyManagerSystemApplication::GetDestinationKmsAddress(Ptr<Socket> socket)
{
  NS_LOG_FUNCTION( this );
  Ipv4Address dstKMSAddress;

  std::map<Ipv4Address, std::pair<Ptr<Socket>, Ptr<Socket> > >::iterator it;
  for(it = m_socketPairsKMS.begin(); it != m_socketPairsKMS.end(); ++it)
  {
    if((it->second).first == socket) {
      dstKMSAddress = it->first;
      break;
    }
  }

  return dstKMSAddress;
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

  } else {

      NS_FATAL_ERROR(this << "Unknown Type: " << s);
  }

  return output;
}


void
QKDKeyManagerSystemApplication::EstablishKMLinkSockets(Ipv4Address remoteKmAddress)
{
  NS_LOG_FUNCTION(this << "Create sink socket to listen requests exchanged between KMSs!");

  InetSocketAddress sinkAddress = InetSocketAddress(m_local, 8080);
  Ptr<Socket> sinkSocket = Socket::CreateSocket(GetNode(), m_tid);
  sinkSocket->Bind(sinkAddress);
  sinkSocket->Listen();
  //sinkSocket->ShutdownSend();
  sinkSocket->SetRecvCallback(MakeCallback(&QKDKeyManagerSystemApplication::HandleReadKMSs, this));
  sinkSocket->SetAcceptCallback(
    MakeNullCallback<bool, Ptr<Socket>, const Address &>(),
    MakeCallback(&QKDKeyManagerSystemApplication::HandleAcceptKMSs, this)
  );
  sinkSocket->SetCloseCallbacks(
    MakeCallback(&QKDKeyManagerSystemApplication::HandlePeerCloseKMSs, this),
    MakeCallback(&QKDKeyManagerSystemApplication::HandlePeerErrorKMSs, this)
  );

  //Store this socket for further use. Later we will create the send socket as well
  Ptr<Socket> sendSocket = 0;
  m_socketPairsKMS.insert(
    std::make_pair(
      remoteKmAddress,
      std::make_pair(sinkSocket, sendSocket)
    )
  );

}


nlohmann::json
QKDKeyManagerSystemApplication::Check014GetKeyRequest(
  uint32_t number,
  uint32_t size,
  Ptr<SBuffer> buffer
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
    uint32_t availableKeyBits = buffer->GetSBitCount();
    NS_LOG_FUNCTION(this << "\nTarget key size: " << size << "\nTarget number: " << number
                         << "\nRequired amount of key material: " << size*number
                         << "\nAmount of key material in s-buffer(READY): " << availableKeyBits);
    if(size*number > availableKeyBits) //Check if there is enough key material!
      jError = {{"message", "insufficient amount of key material"}};
  }

  return jError;
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

  if(it->second.peerRegistered &&(it->second).stre_buffer->GetStreamKeyCount() < 2)
  { 
    //Check
    Ptr<QBuffer> qBuffer = GetQBuffer(it->second.dstNodeId);
    uint32_t availableKeys = qBuffer->GetBitCount();
    uint32_t availableKeyChunks = std::floor(availableKeys / it->second.qos.chunkSize);

    NS_LOG_FUNCTION(this << availableKeys << it->second.qos.chunkSize << availableKeyChunks);

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
    Fill(it->second.dstNodeId, ksid, availableKeyChunks*it->second.qos.chunkSize); //Starts reservation of keys for the association

  }else if(!it->second.peerRegistered)
    NS_LOG_ERROR(this << "peer not registered " << ksid);

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
QKDKeyManagerSystemApplication::CreateKeyStreamSession(
  std::string srcSaeId, 
  std::string dstSaeId,
  QKDKeyManagerSystemApplication::QoS inQos,
  std::string ksid
){
    NS_LOG_FUNCTION(this << srcSaeId << dstSaeId << ksid);

    Ptr<SBuffer> SBufferStream = CreateObject<SBuffer>(SBuffer::STREAM_SBUFFER, inQos.chunkSize); 
    SBufferStream->Initialize();  
    SBufferStream->SetDescription ("(STREAM)"); 
    SBufferStream->SetIndex( m_qbuffersVector.size() ); 
    uint32_t dstNodeId = GetController()->GetRoute(dstSaeId).GetDestinationKmNodeId();
    m_qbuffersVector.push_back(SBufferStream);
    m_qbuffers.insert(std::make_pair(dstNodeId, SBufferStream) );

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
      GetController()->GetRoute(dstSaeId).GetDestinationKmsAddress(),
      inQos,
      true, //registered
      SBufferStream
    };
    if(ksid.empty()){
        ksid = GenerateUUID();
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

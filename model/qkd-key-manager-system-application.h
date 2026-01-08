/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 * Author:  Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 *          Miralem Mehic <miralem.mehic@etf.unsa.ba>
 */
#ifndef QKD_KEY_MANAGER_SYSTEM_APPLICATION_H
#define QKD_KEY_MANAGER_SYSTEM_APPLICATION_H

#include "ns3/address.h"
#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/data-rate.h"
#include "ns3/traced-callback.h"
#include "ns3/random-variable-stream.h"
#include "ns3/inet-socket-address.h"
#include "ns3/qkd-graph.h"
#include "ns3/q-buffer.h"
#include "ns3/s-buffer.h"
#include "ns3/qkd-control.h"
#include "ns3/qkd-encryptor.h"
//#include "ns3/qcen-control.h"
#include "ns3/qkd-location-register.h"
#include "ns3/qkd-location-register-entry.h"
#include "ns3/qkd-graph-manager.h"
#include "qkd-kms-queue-logic.h"
#include "http.h"
#include "json.h"
#include <unordered_map>
#include "ns3/uuid.h"

#include <iostream>
#include <sstream>
#include <unistd.h>
#include <sstream>
#include <string>
#include <regex>


namespace ns3 {

class Address;
class Socket;
class QKDLocationRegisterEntry;
class QKDControl;
class QCenController;

/**
 * @ingroup applications 
 * @defgroup qkd QKDKeyManagerSystemApplication
 * 
 * QKDKeyManagerSystemApplication is a class used to
 * serve requests for cryptographic keys from user's applications.
 */

/**
 * @ingroup qkd
 *
 * @brief QKDNetSim implements Key Management System(KMS) as an
 * application that listens on TCP port 80. 
 * 
 * The KMS can be installed
 * on any node but the QKD post-processing application expects the
 * existence of a local KMS application on the same nodes where the
 * post-processing application is implemented. The local KMS is
 * contacted to add the keys to the QKD buffer and is contacted
 * during the operation of the QKD application to retrieve the keys
 * from the QKD buffer as described in the following section.
 * Communication between KMS systems installed on different nodes
 * is under construction and will be based on the ETSI QKD 004 standard.
 * The KMS application tracks REST-full design serving status and
 * key retrieval requests from QKD applications.
 * The KMS follows HTTP 1.1 specification including Request-URI
 * for mapping of request-response values. More details available at
 * https://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html
 */
class QKDKeyManagerSystemApplication : public Application
{
public:

  /**
   * @brief Request types
   */
  enum RequestType
  {
    EMPTY = -1,
    ETSI_QKD_014_GET_STATUS = 0,              ///< Integer equivalent = 0.
    ETSI_QKD_014_GET_KEY = 1,                 ///< Integer equivalent = 1.
    ETSI_QKD_014_GET_KEY_WITH_KEY_IDS = 2,    ///< Integer equivalent = 2.
    ETSI_QKD_004_OPEN_CONNECT = 3,
    ETSI_QKD_004_GET_KEY = 4,
    ETSI_QKD_004_CLOSE = 5,
    NEW_APP = 6,
    REGISTER = 7,
    FILL = 8,
    STORE_KEY = 9, //Store postprocessing keys
    TRANSFORM_KEYS = 10, //Transform(merge, split) QKD keys
    ETSI_QKD_004_KMS_CLOSE = 11,
    RELAY_KEYS = 12
  };

  /**
   * @brief Get the type ID
   * @return the object TypeId
   */
  static TypeId GetTypeId();

  /**
   * @brief QKDKeyManagerSystemApplication constructor
   */
  QKDKeyManagerSystemApplication();

  /**
   * @brief QKDKeyManagerSystemApplication destructor
   */
  ~QKDKeyManagerSystemApplication() override;

  /**
   * @brief Get sink socket
   * @return pointer to the sink socket
   */
  Ptr<Socket> GetSocket() const;

  //void PrepareOutput(std::string key, uint32_t value); @toDo ? not used

  /**
   * @brief Set sink socket
   * @param type socket type
   * @param socket pointer to socket to be set
   */
  void SetSocket(std::string type, Ptr<Socket> socket);

  /**
   * @brief Get the total amount of bytes received
   * @return the total bytes received in this sink app
   */
  uint32_t GetTotalRx() const;


  /**
  *   @brief Get maximum number of keys per request(ETSI QKD 014)
  *   @return uint32_t maximum number of keys per request
  */
  uint32_t GetMaxKeyPerRequest();

  /**
   * @brief Set node
   * @param n node to be set
   */
  void SetNode(Ptr<Node> n){
    m_node = n;
  }

  /**
   * @brief Get node
   * @return pointer to node
   */
  Ptr<Node> GetNode(){
    return m_node;
  }

  /**
   * @brief Set key manager ID
   * @param id UUID ID
   */
  void  SetId(UUID id){
    m_km_id = id.string();
  }

  /**
   * @brief Set key manager ID
   * @param id string ID
   */
  void  SetId(std::string id){
    m_km_id = id;
  }

  /**
   * @brief Get key menager ID
   * @return string key manager ID
   */
  std::string GetId(){
    return m_km_id;
  }

  /**
   * @brief Set local address
   * @param Ipv4Address address
   */
  void SetAddress(Ipv4Address address) {
    m_local = address;
  }

  /**
   * @brief Get local address
   * @return return local address
   */
  Ipv4Address GetAddress() {
    return m_local;
  }

  /**
   * @brief Get address as string
   * @param address address
   * @return string address
   */
  std::string GetAddressString(Ipv4Address address);

  /**
   * @brief Set local port
   * @param uint32_t port
   */
  void SetPort(uint32_t port) {
    m_port = port;
  }

  /**
   * @brief Get local port
   * @return return local port
   */
  uint32_t GetPort() const 
  {
    return m_port;
  }

  /**
   * @brief Assign QKDN controller
   * @param controller pointer on QKDN controller
   */
  void  SetController(Ptr<QKDControl> controller);

  void  SetCenController(Ptr<QCenController> controller);

  /**
   * @brief Get QKDN controller object
   * @return QKDN controller
   */
  Ptr<QKDControl> GetController();

  Ptr<QCenController> GetCenController();

  /**
   * @brief Check the QKD link state to given destination.
   * @param dstKmNodeId The destination KM node identifier.
   *
   * @note Is used for centralized routing, to enable re-routing.
   */
  void UpdateLinkState(uint32_t dstKmNodeId);

  /**
   * @brief Create Q buffer shared with remote key manager node
   * @param dstId remote key manager node ID
   * @param bufferConf QKD buffer configuration
   */
  void CreateQBuffer(
    uint32_t dstId,
    Ptr<QBuffer> bufferConf
  );

  /**
   * @brief Set peer KM node address
   * @param dstKmNodeId peer KM node ID
   * @param dstKmAddress peer KM address
   *
   * It is called from qkd-control to register peer KM address.
   */
  void SetPeerKmAddress(uint32_t dstKmNodeId, Ipv4Address dstKmAddress);

  /**
   * @brief Get q-buffer established with remote key manager
   * @param remoteKmNodeId remote key manager node ID
   * @return Ptr on q-buffer
   */
  Ptr<QBuffer> GetQBuffer(uint32_t remoteKmNodeId, std::string type = "ns3::QBuffer");

  /**
   * @brief Registers a QKD module in key manager
   * @param dstId remote key manager node ID
   * @param moduleId local QKD module ID
   */
  void RegisterQKDModule(uint32_t dstId, std::string moduleId);

  /**
   * @brief Create sink socket to listen requests exchanged between KMSs
   * @param remoteKmAddress Ipv4 address of remote key manager
   */
  void EstablishKMLinkSockets(Ipv4Address remoteKmAddress);

  /**
   * @brief Get all QBuffers created on the KMS. Function used for plotting QKD Graphs
   */
  std::vector<Ptr<QBuffer> >  GetQBuffersVector(){
    return m_qbuffersVector;
  }
  
  /**
   * @brief Prepare send socket to communicate with peer KMS Application
   * @param uint32_t destination SAE ID
   */
  void CheckSocketsKMS(Ipv4Address dstSaeId);

protected:

  void DoDispose() override;

private:

  static uint32_t     nKMS;       //!< number of created KMSs - static value

  /**
   * @brief Get request type
   * @param s string from HTTP URI
   * @return request type
   */
  QKDKeyManagerSystemApplication::RequestType FetchRequestType(std::string s );

  /**
   * @brief Hashing for the Address class
   */
  struct AddressHash
  {
    /**
     * @brief operator()
     * @param x the address of which calculate the hash
     * @return the hash of x
     *
     * Should this method go in address.h?
     *
     * It calculates the hash taking the uint32_t hash value of the ipv4 address.
     * It works only for InetSocketAddresses(Ipv4 version)
     */
    size_t operator()(const Address &x) const
    {
      NS_ABORT_IF(!InetSocketAddress::IsMatchingType(x));
      InetSocketAddress a = InetSocketAddress::ConvertFrom(x);
      return std::hash<uint32_t>()(a.GetIpv4().Get());
    }
  };

  // inherited from Application base class.
  /**
   * @brief Start KMS Application
   */
  void StartApplication() override;    // Called at time specified by Start

  /**
   * @brief Stop KMS Application
   */
  void StopApplication() override;     // Called at time specified by Stop

  /**
   * @brief Send packet to the pair socket
   * @param socket receiving socket
   * @param packet packet to send
   */
  void SendToSocketPair(Ptr<Socket> socket, Ptr<Packet> packet);

  /**
   * @brief Send packet to the pair socket
   * @param socket receiving socket
   * @param packet packet to send
   */
  void SendToSocketPairKMS(Ptr<Socket> socket, Ptr<Packet> packet);

  /**
   * @brief Handle a packet received by the KMS application
   * @param socket the receiving socket
   */
  void HandleRead(Ptr<Socket> socket);

  /**
   * @brief Handle a packet received by the KMS from KMS
   * @param socket the receiving socket
   */
  void HandleReadKMSs(Ptr<Socket> socket);

  /**
   * @brief Handle an incoming connection
   * @param s the incoming connection socket
   * @param from the address the connection is from
   */
  void HandleAccept(Ptr<Socket> s, const Address& from);

  /**
   * @brief Handle an connection close
   * @param socket the connected socket
   */
  void HandlePeerClose(Ptr<Socket> socket);

  /**
   * @brief Handle an connection error
   * @param socket the connected socket
   */
  void HandlePeerError(Ptr<Socket> socket);

  /**
   * @brief Handle an incoming connection
   * @param s the incoming connection socket
   * @param from the address the connection is from
   */
  void HandleAcceptKMSs(Ptr<Socket> s, const Address& from);

  /**
   * @brief Handle an connection close
   * @param socket the connected socket
   */
  void HandlePeerCloseKMSs(Ptr<Socket> socket);

  /**
   * @brief Handle an connection error
   * @param socket the connected socket
   */
  void HandlePeerErrorKMSs(Ptr<Socket> socket);
  /**
   * @brief Assemble byte stream to extract HTTPMessage
   * @param p received packet
   * @param from from address
   *
   * The method assembles a received byte stream and extracts HTTPMessage
   * instances from the stream to export in a trace source.
   */
  void PacketReceived(const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket);

  /**
   * @brief Assemble byte stream to extract HTTPMessage
   * @param p received packet
   * @param from from address
   *
   * The method assembles a received byte stream and extracts HTTPMessage
   * instances from the stream to export in a trace source.
   */
  void PacketReceivedKMSs(const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket);

  /**
   * @brief QKD key manager system application process the request
   * from QKDApp, and complete certain actions
   * to respond on received request.
   * @param header received HTTP header
   * @param packet received packet
   * @param socket the receiving socket
   *
   * Data structure of key managment respond
   * is described in ETSI014 document.
   */
  void ProcessRequest(HTTPMessage header, Ptr<Packet> packet, Ptr<Socket> socket);

  /**
   * @brief QKD key manager system application process the request
   * peer KMS, and complete certain actions
   * to respond on received request.
   * @param header received HTTP header
   * @param packet received packet
   * @param socket the receiving socket
   *
   * Data structure of key managment respond
   * is described in ETSI004 document.
   */
  void ProcessPacketKMSs(HTTPMessage header, Ptr<Packet> packet, Ptr<Socket> socket);

  void ProcessRequestKMS(HTTPMessage header, Ptr<Socket> socket);

  void ProcessResponseKMS(HTTPMessage header, Ptr<Packet> packet, Ptr<Socket> socket);

  void ProcessPPRequest(HTTPMessage header, Ptr<Packet> packet, Ptr<Socket> socket);

  /**
   * @brief Start key relay function
   * @param dstKmNodeId destination KM node
   * @param amount amount of key material
   */
  void Relay(uint32_t dstKmNodeId, uint32_t amount);

  /**
   * @brief Process key relay request
   * @param header http request
   * @param socket receiving socket
   */
  void ProcessRelayRequest(HTTPMessage headerIn, Ptr<Socket> socket);

  /**
   * @brief Process key relay response
   * @param headerIn http response
   */
  void ProcessRelayResponse(HTTPMessage headerIn);

  /*
   * @brief Process OPEN_CONNECT request - ETSI QKD GS 004
   * @param header received request
   * @param socket receiving socket
   */
  void ProcessOpenConnectRequest(HTTPMessage header, Ptr<Socket> socket);

  /*
   * @brief Process GET_KEY request - ETSI QKD GS 004
   * @param ksid Unique identifier of the association
   * @param header received request
   * @param socket receiving socket
   */
  void ProcessGetKey004Request(std::string ksid, HTTPMessage header, Ptr<Socket> socket);

  /*
   * @brief Process CLOSE request - ETSI QKD GS 004
   * @param ksid Unique identifier of the association
   * @param header received request
   * @param socket receiving socket
   */
  void ProcessCloseRequest(std::string ksid, HTTPMessage header, Ptr<Socket> socket);

  /*
   * @brief Process NEW_APP request
   * @param header received request
   * @param socket receiving socket
   */
  void ProcessNewAppRequest(HTTPMessage header, Ptr<Socket> socket);

  void ProcessNewAppResponse(HTTPMessage header, Ptr<Socket> socket);

  void RegisterRequest(std::string ksid);

  void ProcessRegisterRequest(HTTPMessage header, std::string ksid, Ptr<Socket> socket);

  void ProcessRegisterResponse(HTTPMessage header, Ptr<Socket> socket);

  void PrepareSinkSocket();

  void ProcessFillRequest(HTTPMessage headerIn, std::string resource, Ptr<Socket> socket);

  void ProcessFillResponse(HTTPMessage headerIn, Ipv4Address from);

  /**
   * @brief process transform request
   * @param header receiving http header
   * @param socket receiving socket
   */
  void ProcessSKeyCreateRequest(HTTPMessage header, Ptr<Socket> socket);

  /**
   * @brief process transform response
   * @param header receiving http header
   * @param socket receiving socket
   */
  void ProcessSKeyCreateResponse(HTTPMessage header, Ptr<Socket> socket);

  /**
   * @brief process close request from peer KMS
   * @param header receiving http header
   * @param socket receiving socket
   * @param ksid unique key stream identifier
   *
   * When QKDApp initiate etsi004 close request, its local KMS should release quantum keys
   * currently assign to the key stream association. To do so, KMS should sync with peer KMS.
   * This function perform necessery processing on the peer KMS to do sync.
   */
  void ProcessKMSCloseRequest(HTTPMessage header, Ptr<Socket> socket, std::string ksid);

  /**
   * @brief process close response from peer KMS
   * @param header receiving http header
   * @param socket receiving socket
   */
  void ProcessKMSCloseResponse(HTTPMessage header, Ptr<Socket> socket);

  /**
   * @brief release key stream association
   * @param ksid unique key stream identifier
   * @param surplusKeyId unique key identifier for surplus key material in dedicated association buffer
   * @param syncIndex unique key index in dedicated association buffer for synchronisation
   */
  void ReleaseAssociation(std::string ksid, std::string surplusKeyId, uint32_t syncIndex);

  /**
   * @brief Validate request and probe ability to fullfil valid request
   * @param number number of requested keys
   * @param size requested keys size
   * @param buffer associated buffer
   * @return json error structure
   *
   * Funtion returns an empty json if the request is valid and can be fullfiled.
   */
  nlohmann::json Check014GetKeyRequest(uint32_t number, uint32_t size, Ptr<SBuffer> buffer);

  /**
   * @brief Create key container data structure described in ETSI014 document.
   * @param keys vector of pointers on the QKD key
   * @return json data structure for key container
   */
  nlohmann::json CreateKeyContainer(std::vector<Ptr<QKDKey>> keys);

private:

  struct QoS
  {
    uint32_t chunkSize; //Key_chunk_size
    uint32_t maxRate; //Max_bps
    uint32_t minRate; //Min_bps
    uint32_t jitter; //Jitter
    uint32_t priority; //Priority
    uint32_t timeout; //Timeout
    uint32_t TTL; //Time to Live
    //metadata mimetype is left out
  };

  struct ChunkKey
  {
    uint32_t index;
    uint32_t chunkSize;
    bool ready;
    std::string key; //key of key_chunk_size
    //std::vector<std::pair<std::string, std::pair<uint32_t, uint32_t> > > keyIds; //"QKDKey"s that form ChunkKey
                        //keyId                  start      end
  };

  struct HttpQuery
  {
    RequestType method_type; //For every query!

    //RELAY_KEYS
    std::string req_id;
    uint32_t prev_hop_id;
    Ipv4Address prev_hop_address;
    std::string request_uri;
    uint32_t next_hop_id;

    //Specific to new FILL method
    uint32_t peerNodeId;
    std::vector<std::string> keyIds;
    std::string sBuffer;

    //Specific to TRANSFORM / SKEY_CREATE(new)
    //uint32_t transform_key_size;
    //uint32_t transform_key_number;
    //std::vector<std::string> transform_key_IDs;
    //std::vector<std::string> to_transform_key_IDs;
    std::string surplus_key_ID;
    std::string sae_id; //Needed to specify buffer to fetch the key from

    //Specific to ETSI 004(NEW_APP)
    std::string source_sae;
    std::string destination_sae;
    std::string ksid;

    //Specific to ETSI 004(KMS CLOSE)
    uint32_t sync_index;

  };

  struct Association004 //Holds information of the association and dedicated key store
  {
    std::string srcSaeId; //Source application that requested the KSID
    std::string dstSaeId; //Destination application
    uint32_t srcNodeId; //Source KM node ID
    uint32_t dstNodeId; //Destination KM node ID
    Ipv4Address dstKmsAddr; //Address of the destination KMS. Important!
    QoS qos; //Quality of service
    bool peerRegistered; //KMS must know the state of connection for association on peer KMS!
    Ptr<SBuffer> stre_buffer; //A pointer on a SBUFFER
  };
  
  /**
   * @brief Help function to create relay SBuffers
   * @param srcNodeId source KM node ID
   * @param dstNodeId peer  KM node ID
   * @param descrition buffer description used for QKDGraph
   *
   * It is called to create new SBuffers for relay on demand.
   */
  Ptr<SBuffer> CreateRelaySBuffer(uint32_t srcNodeId, uint32_t dstNodeId, std::string description);

  std::map<std::string, Association004> m_associations004; //Associations map

  Ptr<Socket> m_sinkSocket;       // Associated socket

  Ipv4Address m_local;        //!< Local address to bind to

  uint32_t m_port;        //!< Local port to bind to

  uint32_t m_totalRx;      //!< Total bytes received

  uint32_t m_totalRxKMSs;      //!< Total bytes received between KMSs

  TypeId m_tid;

  std::string m_km_id; //Unique identifier assigned to Key Manager

  Ptr<QCenController> m_cen_controller; //!< Asigned Q centralized controler for routing!

  Ptr<QKDControl> m_controller; //!< Asigned QKDN controller

  std::map<uint32_t, uint32_t> m_link_states; //!<Notified link states!

  std::map<uint32_t, Ptr<QBuffer> > m_qbuffers; //!< Q-buffers for every QKD connection

  std::map<uint32_t, Ptr<SBuffer> > m_keys_enc; //!< LOCAL S-buffers for the outbound point-to-point usage

  std::map<uint32_t, Ptr<SBuffer> > m_keys_dec; //!< LOCAL S-buffers for the inbound point-to-poit usage

  std::map<std::string, uint32_t> m_qkdmodules;    //!< QKD modules and KM node ID they connect to

  uint32_t m_kms_id;

  uint32_t m_kms_key_id; //key counter to generate unique keyIDs on KMS

  EventId m_closeSocketEvent;

  std::map<std::string, EventId > m_scheduledChecks;

  /// Traced Callback: received packets, source address.
  TracedCallback<Ptr<const Packet>, const Address &> m_rxTrace;
  TracedCallback<Ptr<const Packet> > m_txTrace;
  TracedCallback<Ptr<const Packet>, const Address &> m_rxTraceKMSs;
  TracedCallback<Ptr<const Packet> > m_txTraceKMSs;

  TracedCallback<const std::string&, const std::string&, const uint32_t&> m_qkdKeyGeneratedTrace;   //Generated key material!
  TracedCallback<const std::string&, const std::string&, const uint32_t&> m_keyServedTrace; //Total amount of key material served by KMS
  TracedCallback<const uint32_t&, const uint32_t&, const uint32_t&> m_keyConsumedLink; //Total amount of key material consumed for direct p2p usage!
  TracedCallback<const uint32_t&, const uint32_t&, const uint32_t&, const uint32_t&> m_keyConsumedRelay;       //Amount of relayed key material
  TracedCallback<const uint32_t&, const uint32_t&, const uint32_t&> m_keyWasteRelay;          //Amount of wasted key material(traced on source node, and failed relay node only)

  uint32_t m_maxKeyPerRequest; //Maximal number of keys per request QKDApp can ask for
  uint32_t m_minKeySize; //Minimal size of key QKDApp can request from KMS
  uint32_t m_maxKeySize; //Maximal size of key QKDApp can request from KMS 


  uint32_t m_maxSBufferSizeInBits; //Maximal size of LOCAL SBuffer in bits
  uint32_t m_minSBufferSizeInBits; //Minimal size of LOCAL SBuffer in bits
  uint32_t m_thrSBufferSizeInBits; //Threshold value of LOCAL SBuffer in bits

  std::unordered_map<Address, Ptr<Packet>, AddressHash> m_buffer; //!< Buffer for received packets(TCP segmentation)
  std::unordered_map<Address, Ptr<Packet>, AddressHash> m_bufferKMS; //!< Buffer for received packets(TCP segmentation)

  std::map<Ipv4Address, std::pair<Ptr<Socket>, Ptr<Socket> > > m_socketPairsKMS;  //!< we do not know which KMS is going to initialize new TCP connection to peer KMS. Therefore, we have two sockets(sink and send) per node.

  Ptr<Node> m_node; //<! node on which KMS is installed
  std::map<Ptr<Socket>, Ptr<Packet> > m_packetQueues; //!< Buffering unsend messages due to connection problems

  Ptr<QKDKMSQueueLogic> m_queueLogic; //!< KMS Queue Logic for ETSI 004 QoS handling

  std::vector<Ptr<QBuffer> > m_qbuffersVector; //!< The list of QBuffers is necessary for plotting

  /**
    @toDo:following functions
    */
  void ConnectionSucceeded(Ptr<Socket> socket);
  void ConnectionFailed(Ptr<Socket> socket);
  void DataSend(Ptr<Socket>, uint32_t); // for socket's SetSendCallback

  void ConnectionSucceededKMSs(Ptr<Socket> socket);
  void ConnectionFailedKMSs(Ptr<Socket> socket);
  void DataSendKMSs(Ptr<Socket>, uint32_t); // for socket's SetSendCallback


  /**
   *     HTTP handling
   *
   * Each application can open only one connection with its local KMS(current socket).
   * Each KMS can have only one connection with arbitrary KMS(current socket).
   */

  std::map<Ipv4Address, std::vector<HttpQuery> > m_httpRequestsQueryKMS;
  //std::map<Ipv4Address, std::unordered_map<std::string, HttpQuery> > m_httpProxyRequests;
  std::unordered_map<std::string, HttpQuery> m_httpProxyRequests;
  std::multimap<std::string, Ptr<Socket> > m_http004App; //SAE_ID, receiving socket

  /**
   * @brief remember HTTP request made to peer KMS
   * @param dstKms destination kms IP address
   * @param request request parameters
   */
  void HttpKMSAddQuery(Ipv4Address dstKms, HttpQuery request);

  /**
   * @brief remove mapped HTTP response from query
   * @param dstKms destination kms IP address
   */
  void HttpKMSCompleteQuery(Ipv4Address dstKms);

  /**
   * @brief obtain method_type to map the HTTP response
   * @param dstKms destination KMS IP address
   * @return RequestType method function
   */
  RequestType HttpQueryMethod(Ipv4Address dstKms);

  void Http004AppQuery(std::string saeId, Ptr<Socket> socket);

  void Http004AppQueryComplete(std::string saeId);

  Ptr<Socket> GetSocketFromHttp004AppQuery(std::string saeId);


  /**
   * @brief Save query
   * @param query http query
   */
  void HttpProxyRequestAdd(HttpQuery query);

  /**
   * @brief Get saved query
   * @param reqId request identifier
   * @return HttpQuery query
   */
  HttpQuery GetProxyQuery(std::string reqId);

  /**
   * @brief Remove proxy query when processed
   * @param reqId request identifier
   */
  void RemoveProxyQuery(std::string reqId);


  Ipv4Address GetDestinationKmsAddress(Ptr<Socket> socket);

  /**
   * @brief Obtain send socket
   * @param kmsDstAddress Address of the destination KMS
   * @return Socket send socket
   */
  Ptr<Socket> GetSendSocketKMS(Ipv4Address kmsDstAddress);

  /**
   * @brief Convert packet to string
   * @param packet the packet
   * @return string packet
   */
  std::string PacketToString(Ptr<Packet> packet);

  /**
   * @brief Read the parameters from the JSON OPEN_CONNECT structure!
   * @param &dstSaeId destination secure application entity
   * @param &srcSaeId source secure application entity
   * @param &inQos requested QoS
   * @param &ksid Unique identifier of the association
   * @param jOpenConncetRequest JSON structure of the OPEN_CONNECT call
   */
  void ReadJsonQos(
      QKDKeyManagerSystemApplication::QoS &inQos,
      nlohmann::json jOpenConnectRequest );

  /**
   * @brief Read parameters from URI
   * @param s string URI
   * @return vector of uri parameters
   */
  std::vector<std::string> ReadUri(std::string s);

  /**
   * @brief Create a new assocation
   * @param srcSaeId source secure application entity
   * @param dstSaeId destination secure application entity
   * @param inQos Quality of Service
   * @param ksid Unique identifier of the association
   * @return string Unique identifier of the association
   *
   * Input ksid can be empty if it is not predefined. In that case
   * new ksid is generated for this new association and return from
   * the function.
   */
  std::string CreateKeyStreamSession(
      std::string srcSaeId, std::string dstSaeId,
      QKDKeyManagerSystemApplication::QoS inQos,
      std::string ksid );

  /**
   * @brief Make NEW_APP request to peer KMS
   * @param ksid Unique identifier of the association
   */
  void NewAppRequest(std::string ksid);

  /**
   * @brief Check the state of a single assocation
   * @param ksid Unique identifier of the association
   */
  void CheckEtsi004Association(std::string ksid);

  /**
   * @brief schedule next event in an attempt to fill association buffer
   * @param t time shift
   * @param action name of the action
   * @param ksid unique identifier of the association
   * @return uint32_t schedule event ID
   */
  void ScheduleCheckEtsi004Association(Time t, std::string action, std::string ksid);

  void ScheduleReleaseAssociation(Time t, std::string action, std::string ksid, std::string surplusKeyId, uint32_t syncIndex);

  /**
   * @brief Add key to dedicated key store corresponding to association identified with KSID
   * @param ksid Unique identifier of the association
   * @param key The QKD key being added to the store
   */
  void AddKeyToAssociationDedicatedStore(std::string ksid, Ptr<QKDKey> key);

  /**
   * @brief Generate UUID
   * @return string UUID
   */
  std::string GenerateUUID();

  /**
   * @brief Generate random string with given length
   * @param len string length
   * @return string random string
   */
  std::string GenerateRandomString(const int len, const uint32_t seed = 0);

  /**
   * @brief Start s-buffers control -- monitoring
   * @param dstKmNodeId remote KM node ID
   */
  void StartSBufferClients(uint32_t dstKmNodeId);

  /**
   * @brief Fill s-buffer
   * @param dstKmNodeId remote KM node ID
   * @param direction s-buffer type
   * @param amount key amount
   */
  void Fill(uint32_t dstKmNodeId, std::string direction,  uint32_t amount);

  /**
   * @brief check s-buffer levels
   * @param dstKmNodeId remote KM node ID
   */
  void SBufferClientCheck(uint32_t dstKmNodeId);

  Ptr<SBuffer> GetSBuffer(uint32_t dstKmNodeId, std::string type);

  Ipv4Address GetPeerKmAddress(uint32_t dstKmNodeId);

  std::map<uint32_t, Ipv4Address> m_peerAddressTable; //!<IP address of peer KM nodes

  Ptr<QKDEncryptor> m_encryptor;

};

} // namespace ns3

#endif /* QKD_APPLICATION_H */


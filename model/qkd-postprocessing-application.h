/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 * Author: Miralem Mehic <miralem.mehic@etf.unsa.ba>
 */

#ifndef QKD_POSTPROCESSING_APPLICATION_H
#define QKD_POSTPROCESSING_APPLICATION_H

#include "ns3/application.h"
#include "ns3/address.h"
#include "ns3/event-id.h"
#include "ns3/nstime.h"
#include "ns3/ptr.h"
#include "ns3/log.h"
#include "ns3/data-rate.h"
#include "ns3/traced-callback.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/ipv4-address.h"
#include "ns3/random-variable-stream.h"
#include "qkd-key-manager-system-application.h"
#include "ns3/qkd-encryptor.h"
#include "ns3/socket-factory.h"
#include "ns3/tcp-socket-factory.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/ipv4-l3-protocol.h"
#include "ns3/uuid.h"
#include "http.h"

namespace ns3 {

class Address;
class Socket;
class Packet;

/**
 * @ingroup applications
 * @defgroup qkd QKDPostprocessingApplication
 * 
 * QKDPostprocessingApplication is a class used to
 * generate QKD key in key establishment process.
 *
*/

/**
 * @ingroup qkd
 *
 * @brief QKDPostprocessingApplication is a class used to
 * generate QKD key in key establishment process. * 
 * 
 * QKD protocols are used to securely generate new key material.
 * Although there are different types of QKD protocols, each of them
 * requires raw material processing through post-processing applications
 * implementing the following steps: the extraction of the raw key(sifting),
 * error rate estimation, key reconciliation, privacy amplification and
 * authentication. However, since the QKDNetSim focus is primarily QKD
 * network organization, management and network traffic, one uses QKD
 * post-processing application to imitate the network activity of a QKD
 * protocol. The goal was to build an application that credibly imitates
 * the traffic from the existing post-processing applications to reduce
 * the simulation time and computational resources.
 * Such implementation of QKD post-processing allows analyzing the influence
 * of various parameters on the state of the network, such as: the impact of
 * key generation rate, the impact of traffic volume of the reconciled
 * protocol on network capacity and others.
 */
class QKDPostprocessingApplication : public Application
{
public:
  /**
  * @brief Get the type ID.
  * @return the object TypeId
  */
  static TypeId GetTypeId();

  QKDPostprocessingApplication();

  ~QKDPostprocessingApplication() override;

  /**
   * @return pointer to associated socket
   */
  Ptr<Socket> GetSendSocket() const;

  /**
   * @brief set the sink socket
   */
  Ptr<Socket> GetSinkSocket() const;

  /**
   * @param socket pointer to socket to be set
   */
  void SetSocket(std::string type, Ptr<Socket> socket, bool isMaster);

  /**
   * @param socket pointer to socket to be set
   */
  void SetSiftingSocket(std::string type, Ptr<Socket> socket);

  /**
   * @return the total bytes received in this sink app
   */
  uint32_t GetTotalRx() const;

  /**
   * @return pointer to listening socket
   */
  Ptr<Socket> GetListeningSocket() const;

  /**
   * @return list of pointers to accepted sockets
   */
  std::list<Ptr<Socket> > GetAcceptedSockets() const;

  Time GetLastAckTime();

  /**
   * @brief pointer to associated source node
   * @return Ptr<Node> pointer to associated source node
   */
  Ptr<Node> GetSrc();

  /**
   * @return Set the source node
   * @param <Ptr> sourceNode
   */
  void SetSrc(Ptr<Node>);

  /**
   * @brief pointer to associated destination node
   * @return Ptr<Node> pointer to associated destination node
   */
  Ptr<Node> GetDst();

  /**
   * @return Set the destination node
   * @param <Ptr> destinationNode
   */
  void SetDst(Ptr<Node>);

  /**
   * @brief Set QKD module ID
   * @param id UUID ID
   */
  void SetId(UUID id){
    m_module_id = id.string();
  }

  /**
   * @brief Set QKD module ID
   * @param id string ID
   */
  void SetId(std::string id){
    m_module_id = id;
  }

  /**
   * @brief Get QKD module ID
   * @return string QKD module ID
   */
  std::string GetId(){
    return m_module_id;
  }

  /**
   * @brief Set matching QKD module ID
   * @param id UUID ID
   */
  void SetPeerId(UUID id){
    m_matching_module_id = id.string();
  }

  /**
   * @brief Set matching QKD module ID
   * @param id string ID
   */
  void SetPeerId(std::string id){
    m_matching_module_id = id;
  }

  /**
   * @brief Get matching QKD module ID
   * @return string QKD module ID
   */
  std::string GetPeerId(){
    return m_matching_module_id;
  }

protected:

  void DoDispose() override;

private:


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

  /**
   * @brief Process data received
   * @param Packet to be processed
   */
  void ProcessIncomingPacket(Ptr<Packet> packet);

  // inherited from Application base class.
  void StartApplication() override;    //!< Called at time specified by Start

  void StopApplication() override;     //!< Called at time specified by Stop

  /**
   * @brief Send packet to the socket
   * @param Packet to be sent
   */
  void SendPacket(Ptr<Packet> packet);

  /**
   * @brief Help function to prepare output values
   * @param string value
   * @param string action
   */
  void PrepareOutput(std::string value, std::string action);

  /**
   * @brief Store generated key at KMS
   * @param keyId unique key identifier
   * @param keyValue generated key in byte format
   */
  void StoreKey(std::string keyId, std::string keyValue);

  /**
   * @brief Send SIFTING packet to the socket
   * @param Packet to be sent
   */
  void SendSiftingPacket();

  /**
   * @brief Handle a packet received by the application
   * @param socket the receiving socket
   */
  void HandleRead(Ptr<Socket> socket);

  /**
   * @brief Handle a packet received by the application
   * @param socket the receiving socket
   */
  void HandleReadQiskit(Ptr<Socket> socket);

  /**
   * @brief Handle a packet received by the application from KMS
   * @param socket the receiving socket
   */
  void HandleReadKMS(Ptr<Socket> socket);

  /**
   * @brief Handle a packet received by the application
   * @param socket the receiving socket
   */
  void HandleReadSifting(Ptr<Socket> socket);

  /**
   * @brief Handle an incoming connection
   * @param socket the incoming connection socket
   * @param from the address the connection is from
   */
  void HandleAccept(Ptr<Socket> socket, const Address& from);

  /**
   * @brief Handle an incoming connection
   * @param socket the incoming connection socket
   * @param from the address the connection is from
   */
  void HandleAcceptQiskit(Ptr<Socket> socket, const Address& from);

  /**
   * @brief Handle an incoming connection from KMS
   * @param socket the incoming connection socket
   * @param from the address the connection is from
   */
  void HandleAcceptKMS(Ptr<Socket> socket, const Address& from);

  /**
   * @brief Handle an incoming connection
   * @param socket the incoming connection socket
   * @param from the address the connection is from
   */
  void HandleAcceptSifting(Ptr<Socket> socket, const Address& from);

  /**
   * @brief Handle an connection close
   * @param socket the connected socket
   */
  void HandlePeerClose(Ptr<Socket> socket);

  /**
   * @brief Handle an connection close
   * @param socket the connected socket
   */
  void HandlePeerCloseQiskit(Ptr<Socket> socket);

  /**
   * @brief Handle an connection close
   * @param socket the connected socket
   */
  void HandlePeerCloseKMS(Ptr<Socket> socket);

  /**
   * @brief Handle an connection error KMS
   * @param socket the connected socket
   */
  void HandlePeerError(Ptr<Socket> socket);

  /**
   * @brief Handle an connection error KMS
   * @param socket the connected socket
   */
  void HandlePeerErrorQiskit(Ptr<Socket> socket);

  /**
   * @brief Handle an connection error KMS
   * @param socket the connected socket
   */
  void HandlePeerErrorKMS(Ptr<Socket> socket);

  void ConnectionSucceeded(Ptr<Socket> socket);
  void ConnectionFailed(Ptr<Socket> socket);

  void ConnectionSucceededKMS(Ptr<Socket> socket);
  void ConnectionFailedKMS(Ptr<Socket> socket);

  void ConnectionSucceededSifting(Ptr<Socket> socket);
  void ConnectionFailedSifting(Ptr<Socket> socket);

  /**
   * @brief Schedule data to be sent
   */
  void SendData();

  /**
   * @brief After completing post-processing round, reset counters
   */
  void ResetCounter();

  /**
   * @brief Schedule reset of post-processing round
   */
  void ScheduleNextReset();

  /**
   * @brief Generate Random Seed Used to Generate Key Values
   */
  void GenerateRandomKeyId();

  /**
   * @brief Obtain IPv4 address in string type
   * @param m_address input Address type
   * @return string IPv4 address as string
   */
  std::string GetStringAddress(Address m_address);

  static uint32_t m_applicationCounts;

  uint32_t m_ppId;

  Ptr<Node>       m_src;
  Ptr<Node>       m_dst;

  /**
  * IMITATE post-processing traffic(CASCADE, PRIVACY AMPLIFICATION and etc. )
  */
  Ptr<Socket>     m_sendSocket;       //!< Associated socket
  Ptr<Socket>     m_sinkSocket;       //!< Associated socket
  /**
  * Sockets used for SIFTING
  */
  Ptr<Socket>     m_sendSocket_sifting;       //!< Associated socket for sifting
  Ptr<Socket>     m_sinkSocket_sifting;       //!< Associated socket for sifting
  /**
  * Sockets to talk with LKMS
  */
  Ptr<Socket>     m_sendSocketKMS;       //!< Associated socket
  Ptr<Socket>     m_sinkSocketKMS;       //!< Associated socket

  Ptr<Socket>     m_sinkSocketQiskit;       //!< Associated socket

  Address         m_peer;         //!< Peer address
  Address         m_local;        //!< Local address to bind to

  Address         m_peer_sifting;         //!< Peer address for sifting
  Address         m_local_sifting;        //!< Local address for sifting to bind to
  Address         m_kms;

  uint32_t        m_keySize;     //!< KeyRate of the QKDlink
  bool            m_connected;    //!< Connection Status
  bool            m_master;       //!< Alice(1) or Bob(0)
  uint32_t        m_packetNumber;     // Total number of packets received so far
  uint32_t        m_totalRx;      //!< Total bytes received
  Time            m_lastAck;     // Time of last ACK received

  std::list<Ptr<Socket> > m_sinkSocketList; //!< the accepted sockets
  EventId         m_sendEvent;    //!< Event id of pending "send packet" event

  DataRate        m_dataRate;      //!< Rate that data is generatedm_pktSize
  DataRate        m_keyRate;      //!< QKD Key rate
  uint32_t        m_pktSize;      //!< Size of packets
  TypeId          m_tid;
  TypeId          m_tidSifting;

  std::string     m_module_id;            //!< Unique UUID of QKD module
  std::string     m_matching_module_id;   //!< Unique UUID of matching QKD module

  std::string     m_lastUUID;     //!< The latest UUID of the key
  std::unordered_map<Address, Ptr<Packet>, AddressHash> m_buffer; //!< Buffer for received packets(TCP segmentation)

  /// Traced Callback: received packets, source address.
  TracedCallback<Ptr<const Packet>, const Address &> m_rxTrace;
  TracedCallback<Ptr<const Packet> > m_txTrace;

  TracedCallback<Ptr<const Packet>, const Address &> m_rxTraceKMS;
  TracedCallback<Ptr<const Packet> > m_txTraceKMS;

  uint32_t        m_packetNumber_sifting; //!< How many sifting packets have been sent
  uint32_t        m_maxPackets_sifting;   //!< Limitation for the number of sifting packets
  uint64_t        m_randomSeed;                //!< Random seed used when generating key values

private:

  void ProcessQiskitRequest(HTTPMessage headerIn, Ptr<Packet> packet, Ptr<Socket> socket);
  void PacketReceived(const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket);

  void DataSend(Ptr<Socket> s, uint32_t); // for socket's SetSendCallback
  void DataSendKMS(Ptr<Socket> s, uint32_t); // for socket's SetSendCallback
  void RegisterAckTime(Time oldRtt, Time newRtt);  //!< Callback for ack messages
  std::string GenerateRandomString(const int len);  //!< Internal help function

  Ptr<UniformRandomVariable> m_random;

  Ptr<QKDEncryptor> m_encryptor;
};

} // namespace ns3

#endif /* QKD_POSTPROCESSING_APPLICATION_H */


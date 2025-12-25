/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 * Author:  Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 *          Miralem Mehic <miralem.mehic@etf.unsa.ba>
 */
#ifndef QKD_SEND_H004
#define QKD_SEND_H004

#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/traced-callback.h"
#include "ns3/address.h"
#include "ns3/core-module.h"
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "http.h"
#include "qkd-app-header.h"
#include "ns3/qkd-encryptor.h"
#include "ns3/app-key-stream.h"
#include <unordered_map>
#include <string>

#include <iostream>
#include <sstream>
#include <unistd.h>
#include "http.h"
#include "json.h"

namespace ns3 {

class Address;
class Socket;
class Packet;

/**
 * @ingroup applications
 * @defgroup qkd QKDApp004
 *
 * The QKDApp004 application implements communication
 * to Local Key Management System and it establish secure
 * communciation with counter-part QKDApp.
 */

/**
 * @ingroup qkd
 *
 * @brief Establish secure communication on application lavel to use the key and test LKSM
 *
 * This application was written to complement simple application to consume keys
 * so a generic QKDApp name was selected. The application(Alice) implements sockets for
 * connection with counter-party application(Bob) and implements sockets for
 * communication with local key management system.
 *
 */
class QKDApp004 : public Application
{
public:
    /**
    * @brief Get the type ID.
    * @return the object TypeId
    */
    static TypeId GetTypeId();
    QKDApp004();
    ~QKDApp004() override;

    /**
     * @brief QKD App states(App)
     * States that refer to QKDApp data transmision!
     */
    enum State {
        NOT_STARTED,
        INITIALIZED,
        ESTABLISHING_ASSOCIATIONS,
        ASSOCIATIONS_ESTABLISHED,
        ESTABLISHING_KEY_QUEUES,
        KEY_QUEUES_ESTABLISHED,
        READY,
        WAIT,
        SEND_DATA,
        DECRYPT_DATA,
        STOPPED
    };

    enum Method {
        OPEN_CONNECT,
        GET_KEY,
        CLOSE,
        SEND_KSID,
        ESTABLISH_QUEUES
    };

    void Setup(
      std::string socketType,
      std::string appId,
      std::string remoteAppId,
      const Address&  appAddress,
      const Address&  remoteAppAddress,
      const Address&  kmAddress,
      std::string type
    );

    void Setup(
      std::string socketType,
      std::string appId,
      std::string remoteAppId,
      const Address&  appAddress,
      const Address&  remoteAppAddress,
      const Address&  kmAddress,
      uint32_t packetSize,
      DataRate dataRate,
      std::string type
    );

    /**
     * @brief Set encryption and authentication type
     * @param ecryptionType encryption type
     * @param authenticationType authentication type
     */
    void SetCryptoSettings(
      uint32_t encryptionType,
      uint32_t authenticationType,
      uint32_t authenticationTagLengthInBits
    );

    /**
     * @brief Get key size for defined encryption algorithm
     * @return uint32_t key size
     */
    uint32_t GetEncryptionKeySize();

    /**
     * @brief Get key size for defined authentication algorithm
     * @return uint32_t key size
     */
    uint32_t GetAuthenticationKeySize();

    /**
     * @brief Set state
     * @param state new application state.
     */
    void SetState(State state);

    /**
     * @brief Returns the current state of the application.
     * @return string current state of the application.
     */
    State GetState() const;

    /**
     * @brief Returns the current state of the application in string format.
     * @return string current state of the application.
     */
    std::string GetAppStateString() const;

    /**
     * @brief Returns the given application state in string format.
     * @param state An arbitrary state of an application.
     * @return string given state equivalently expressed in string format.
     */
    static std::string GetAppStateString(State state);

    /**
     * @brief Get application identifier
     * @return string application id
     */
    std::string GetId(){
        return m_appId;
    }

    /**
     * @brief Get peer application identifier
     * @return string application id
     */
    std::string GetPeerId(){
        return m_dstAppId;
    }

    /**
     * @brief Get KMS Ipv4 address
     * @return Ipv4Address address
     */
    Ipv4Address GetKmsIp();

    /**
     * @brief Get application Ipv4 address
     * @return Ipv4Address address
     */
    Ipv4Address GetIp();

    /**
     * @brief Get peer application Ipv4 address
     * @return Ipv4Address address
     */
    Ipv4Address GetPeerIp();

    /// Traced Callback: transmitted data packets.
    TracedCallback<const std::string&, Ptr<const Packet> > m_txTrace;
    /// Traced Callback: transmitted signaling packets.
    TracedCallback<const std::string&, Ptr<const Packet> > m_txSigTrace;
    /// Traced Callback: transmitted packets to KMS.
    TracedCallback<const std::string&, Ptr<const Packet> > m_txKmsTrace;
    /// Traced Callback: received data packets.
    TracedCallback<const std::string&, Ptr<const Packet> > m_rxTrace;
    ///Traced Callback: missed send packet call.
    TracedCallback<const std::string&, Ptr<const Packet> > m_mxTrace;
    /// Traced Callback: received signaling packets.
    TracedCallback<const std::string&, Ptr<const Packet> > m_rxSigTrace;
    /// Traced Callback: received packets from KMS.
    TracedCallback<const std::string&, Ptr<const Packet> > m_rxKmsTrace;
    /// The `StateTransition` trace source.
    ns3::TracedCallback<const std::string &, const std::string &> m_stateTransitionTrace;

protected:
    void DoDispose() override;

private:

    /***
     *          STRUCTURES
     */
    struct      KMSPacket
    {
        Ptr<Packet> packet;
        std::string uri;
        KeyStreamSession::Type scope;
    };

    /***
     *          SOCKETS AND HandleRead
     */

    /**
     * @brief Callback function after the connection to the KMS has failed
     * @param socket the connected socket
     */
    void ConnectionToKMSFailed(Ptr<Socket> socket);

    /**
     * @brief Callback function after the connection to the KMS is complete
     * @param socket the connected socket
     */
    void ConnectionToKMSSucceeded(Ptr<Socket> socket);

    /**
     * @brief Callback function after the connection to the APP has failed
     * @param socket the connected socket
     */
    void ConnectionToAppFailed(Ptr<Socket> socket);

    /**
     * @brief Callback function after the connection to the APP is complete
     * @param socket the connected socket
     */
    void ConnectionToAppSucceeded(Ptr<Socket> socket);

    /**
     * @brief Callback function after the signaling connection to the APP has
     * @param socket the connected socket
     */
    void ConnectionSignalingToAppFailed(Ptr<Socket> socket);

    /**
     * @brief Callback function after the signaling connection to the APP is complete
     * @param socket the connected socket
     */
    void ConnectionSignalingToAppSucceeded(Ptr<Socket> socket);

    /**
     * @brief Callback function to notify that data to KMS has been sent
     * @param socket the connected socket
     * @param uint32_t amount of data sent
     */
    void DataToKMSSend(Ptr<Socket>, uint32_t);

    /**
     * @brief Handle a connection close from KMS
     * @param socket the connected socket
     */
    void HandlePeerCloseFromKMS(Ptr<Socket> socket);

    /**
     * @brief Handle a connection close to KMS
     * @param socket the connected socket
     */
    void HandlePeerCloseToKMS(Ptr<Socket> socket);

    /**
     * @brief Handle a connection error from KMS
     * @param socket the connected socket
     */
    void HandlePeerErrorFromKMS(Ptr<Socket> socket);

    /**
     * @brief Handle a connection error to KMS
     * @param socket the connected socket
     */
    void HandlePeerErrorToKMS(Ptr<Socket> socket);

    /**
     * @brief Handle an incoming connection from KMS
     * @param s the incoming connection socket
     * @param from the address the connection is from
     */
    void HandleAcceptFromKMS(Ptr<Socket> s, const Address& from);

        /**
     * @brief Handle a connection close from peer QKD application
     * @param socket the connected socket
     */
    void HandlePeerCloseFromApp(Ptr<Socket> socket);

    /**
     * @brief Handle a connection error from peer QKD application
     * @param socket the connected socket
     */
    void HandlePeerErrorFromApp(Ptr<Socket> socket);

    /**
     * @brief Handle an incoming connection from peer QKD application
     * @param s the incoming connection socket
     * @param from the address the connection is from
     */
    void HandleAcceptFromApp(Ptr<Socket> s, const Address& from);

    /**
     * @brief Handle a signaling connection close from peer QKD application
     * @param socket the connected socket
     */
    void HandlePeerCloseSignalingFromApp(Ptr<Socket> socket);

    /**
     * @brief Handle a signaling connection error from peer QKD application
     * @param socket the connected socket
     */
    void HandlePeerErrorSignalingFromApp(Ptr<Socket> socket);

    /**
     * @brief Handle a signaling incoming connection from peer QKD application
     * @param s the incoming connection socket
     * @param from the address the connection is from
     */
    void HandleAcceptSignalingFromApp(Ptr<Socket> s, const Address& from);

    /**
     * @brief Handle a packet received by the QKD application from KMS application
     * @param socket the receiving socket
     */
    void HandleReadFromKMS(Ptr<Socket> socket);

    /**
     * @brief Handle a packet received by the QKD application from peer QKD application
     * @param socket the receiving socket
     */
    void HandleReadFromApp(Ptr<Socket> socket);

    /**
     * @brief Handle a signaling packet received by the QKD application from peer QKD application
     * @param socket the receiving socket
     */
    void HandleReadSignalingFromApp(Ptr<Socket> socket);

    void RegisterAckTime(Time oldRtt, Time newRtt);

    /**
     * @brief Callback function after the connection for response from KMS has been received
     * @param socket the connected socket
     * @param address address of the KMS
     */
    bool ConnectionRequestedFromKMS(Ptr<Socket> socket, const Address &address);

    /**
     * @brief Callback function after the connection for response from KMS has been received
     * @param socket the connected socket
     * @param address address of the KMS
     */
    bool ConnectionRequestedFromApp(Ptr<Socket> socket, const Address &address);

    /**
     * @brief Callback function after the connection for response from KMS has been received
     * @param socket the connected socket
     * @param address address of the KMS
     */
    bool ConnectionRequestedSignalingFromApp(Ptr<Socket> socket, const Address &address);


    /**
     * @brief Prepare send socket to communicate with KMS Application
     */
    void PrepareSocketToKMS();

    /**
     * @brief Prepare send socket to communicate with QKD Application
     */
    void PrepareSocketToApp();

    /**
     * @brief Check for tcp segmentation of packets received from KMS
     * @param packet
     * @param address address of the KMS
     * @param socket the connected socket
     */
    void PacketReceivedFromKMS(const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket);

    /**
     * @brief Check for tcp segmentation of signaling packets received from APP
     * @param packet
     * @param address address of the KMS
     * @param socket the connected socket
     */
    void SignalingPacketReceivedFromApp(const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket);

    /**
     * @brief Check for tcp segmentation of signaling packets received from KMS
     * @param packet
     * @param address address of the KMS
     * @param socket the connected socket
     */
    void DataPacketReceived(const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket);

    /**
     * @brief Process response from KMS application
     * @param header received HTTP header
     * @param packet received packet
     * @param socket the receiving socket
     */
    void ProcessResponseFromKMS(HTTPMessage& header, Ptr<Packet> packet, Ptr<Socket> socket);

    /**
     * @brief Process signaling packets from peer QKD application
     * @param header HTTP packet header
     * @param packet received packet
     * @param socket the receiving socket
     */
    void ProcessSignalingPacketFromApp(HTTPMessage& header, Ptr<Socket> socket);

     /**
     * @brief Process data packets from peer QKD application
     * @param header QKDApp packet header
     * @param packet received packet
     * @param socket the receiving socket
     */
    void ProcessDataPacket(QKDAppHeader header, Ptr<Packet> packet, Ptr<Socket> socket);

    /**
     * @brief QKDApp reserves an association(Key_stream_ID)
     * @param ksid unique identifier for the group of syncronized bits
     * @param sessionType the purpose of given session
     *
     * Replica QKDApp always states KSID in OPEN_CONNECT call.
     * Primary QKDApp does not state KSID(design decision).
     * Each QKDApp is limited(by design decisions) to establish up to 2
     * associations(one for encryption and one for authentification).
     */
    void OpenConnect(std::string ksid, KeyStreamSession::Type sessionType);

    /**
     * @brief Obtain the required amount of key material.
     * @param ksid Unique identifier for the group of syncronized bits
     *
     * QKDApp request key via ETSI GS 004 interface. In current version
     * QKDApps request keys in synchronous order and index is not specified!
     */
    void GetKeyFromKMS(std::string ksid);

    /**
     * @brief Terminate the association
     * @param ksid Unique identifier of association
     */
    void Close(std::string ksid);

    /**
     * @brief Process response from KMS on OPEN_CONNECT call
     * @param header received HTTP header
     */
    void ProcessOpenConnectResponse(HTTPMessage& header);

    /**
     * @brief Process Get Key response from KMS
     * @param header received HTTP header
     */
    void ProcessGetKeyResponse(HTTPMessage& header);

    /**
     * @brief Process response from KMS on CLOSE call
     * @param header received HTTP header
     */
    void ProcessCloseResponse(HTTPMessage& header);

    /**
     * @brief Sends SEND_KSID request(for sender App004) or response(for receiver App004)
     * @param ksid unique key stream identifier
     * @param sessionType scope of the session
     * @param statusCode HTTP status code in case is response
     *
     */
    void SendKsid(std::string ksid, KeyStreamSession::Type sessionType, HTTPMessage::HttpStatus statusCode = HTTPMessage::Ok);

    /**
     * @brief Sends ESTABLISH_QUEUES request(for sende App004) or response(for receiver App004)
     *
     */
    void  EstablishQueues();

    std::string GetSessionScope(KeyStreamSession::Type type){
        if(type == KeyStreamSession::ENCRYPTION)
            return "enc";
        else
            return "auth";
    }

    /*
     * @brief Creates required key stream sessions
     *
     */
    void    CreateKeyStreamSessions();

    bool m_primaryQueueEstablished;
    bool m_replicaQueueEstablished;

    /**
     * @brief Check if the associations are successfuly established
     *
     * If the associations are established, establishing queues is started!
     */
    void  CheckStreamSessions();

    /**
     * @brief Application establishing key queues before establishing data traffic.
     *
     * Application can establish key queues of desired size prior to secure communication
     * to support fast rekeying scenarios.
     */
    void  CheckQueues();

    /**
     * @brief Add HTTP request to queue to map response later
     * @param uri request URI
     * @param sessionType session scope
     *
     */
    void      PushHttpKmsRequest(std::string uri, KeyStreamSession::Type sessionType = KeyStreamSession::ENCRYPTION);

    /**
     * @brief Pop HTTP request from the queue(mapping response)
     * @param uri request URI
     * @return KeyStreamSession::Type session scope
     *
     * Deletes request from the queue.
     */
    KeyStreamSession::Type  PopHttpKmsRequest(std::string uri);

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

    void StartApplication() override;
    void StopApplication() override;

    void ScheduleTx();

    /**
     * @brief Transition tree of the application. Change states and take actions!
     */
    void AppTransitionTree();

    /**
    * @brief Get the packet payload content
    * @param msgLength length of random string to generate
    * @return string random string
    */
    std::string GetPacketContent(uint32_t msgLength = 0);

    /**
     * @brief Convert packet to string
     * @param packet packet
     * @return string packet as a string
     */
    std::string PacketToString(Ptr<Packet> packet);

    std::vector<std::string>    ReadUri(std::string s);

    std::string IpToString(Ipv4Address address);


    /**
     * @brief QKDApp encrypts the data with obtained keys
     * and sends this encrypted data to the peer QKDApp.
     */
    void SendPacket();

    void ProcessPacketsToKMSFromQueue();

    Ptr<Socket>     m_signalingSocketApp;
    Ptr<Socket>     m_dataSocketApp;

    Ptr<Socket>     m_socketToKMS;
    bool            m_isSignalingConnectedToApp;
    bool            m_isDataConnectedToApp;

    Address         m_peer;
    Address         m_local;
    Address         m_kms;
    uint16_t        m_portSignaling;

    std::string     m_socketType;

    uint32_t        m_packetSize;
    DataRate        m_dataRate;
    EventId         m_sendEvent;
    EventId         m_closeSocketEvent;
    Time            m_holdTime;

    uint32_t        m_packetsSent;
    uint32_t        m_dataSent;
    TypeId          m_tid;
    uint32_t        m_master;

    std::string     m_dstAppId;
    std::string     m_appId;

    //HTTP mapping responses to requests!
    std::multimap<std::string, KeyStreamSession::Type> m_httpRequestsKMS;

    Ptr<KeyStreamSession> m_encStream;
    Ptr<KeyStreamSession> m_authStream;

    static uint32_t m_applicationCounts;

    //Crypto params
    uint32_t    m_useCrypto;
    uint32_t    m_encryption;
    uint32_t    m_authentication;
    uint32_t    m_authenticationTagLengthInBits; //!< length of the authentication tag in bits(32 by default)
    uint32_t    m_aesLifetime; //in packets!
    TracedCallback<Ptr<Packet> > m_encryptionTrace; //!< trace callback for encryption
    TracedCallback<Ptr<Packet> > m_decryptionTrace; //!< trace callback for decryption
    TracedCallback<Ptr<Packet>, std::string > m_authenticationTrace; //!< trace callback for authentication
    TracedCallback<Ptr<Packet>, std::string > m_deauthenticationTrace; //!< trace callback for authentication check
    QKDEncryptor::EncryptionType m_encryptionType;
    QKDEncryptor::AuthenticationType m_authenticationType;
    Ptr<QKDEncryptor> m_encryptor;
    uint32_t    m_keyBufferLengthEncryption;
    uint32_t    m_keyBufferLengthAuthentication;

    State m_state; //Application state!

    std::vector<KMSPacket > m_queue_kms;

    std::unordered_map<Address, Ptr<Packet>, AddressHash> m_buffer_kms; //!< Buffer for received packets(fragmentation)
    std::unordered_map<Address, Ptr<Packet>, AddressHash> m_buffer_sig; //!< Buffer for received packets(fragmentation)
    std::unordered_map<Address, Ptr<Packet>, AddressHash> m_buffer_qkdapp; //!< Buffer for received packets(fragmentation)

    std::multimap<std::string, std::string> m_transitionMatrix; //!< transition map of protocol states

};


} // namespace ns3

#endif /* QKD_SINK_H004 */

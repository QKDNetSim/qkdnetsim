/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 * Author:  Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 *          Miralem Mehic <miralem.mehic@etf.unsa.ba>
 */
#ifndef QKD014_SEND_H
#define QKD014_SEND_H

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
#include "ns3/app-key.h"
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
 * @defgroup qkd QKDApp014
 *
 * The QKDApp014 application implements communication
 * to Local Key Management System and it establish secure
 * communciation with counter-part QKDApp014.
 */

/**
 * @ingroup qkd
 *
 * @brief Establish secure communication on application lavel to use the key and test LKSM
 *
 * This application was written to complement simple application to consume keys
 * so a generic QKDApp014 name was selected. The application(Alice) implements sockets for
 * connection with counter-party application(Bob) and implements sockets for
 * communication with local key management system. At the moment, application follows
 * ETSI QKD 014 standardization exchanging HTTP requests/responses to obtain details about
 * the key from its local key management system. Obtained keys from Get key response are stored
 * in temporary memory on master QKDApp014(Alice) in JSON data structure, from where they are moved
 * to an application key buffer when confirmation of keys from peer application(Bob) is recieved.
 * Keys obtained from Get key with key IDs are directly stored to the application key buffer and
 * confirmation message for keys is sent to its peer application(Alice). Application(Alice) use
 * keys from the application key buffer to apply security services on its data. QKD application
 * header is then added to the protected data and sent to peer application. Slave QKD
 * application(Bob) will process recieved protected packet based on information in QKD header
 * and keys from the application key buffer. Communication between peers needed to negotiate keys
 * was not included in ETSI014, and this application use HTTP messages for this purpose.
 *
 */
class QKDApp014 : public Application
{
public:
    /**
    * @brief Get the type ID.
    * @return the object TypeId
    */
    static TypeId GetTypeId();
    QKDApp014();
    ~QKDApp014() override;

    /**
     * @brief QKD App states(App)
     * States that refer to QKDApp014 data transmision!
     */
    enum        State {
        NOT_STARTED,
        INITIALIZED,
        READY,
        WAIT,
        SEND_DATA,
        DECRYPT_DATA,
        STOPPED
    };

    void Setup(
        std::string socketType,
        std::string appId,
        std::string remoteAppId,
        const Address& appAddress,
        const Address& remoteAppAddress,
        const Address& kmAddress,
        uint32_t packetSize,
        DataRate dataRate,
        std::string type
    );

    void Setup(
        std::string socketType,
        std::string appId,
        std::string remoteAppId,
        const Address& appAddress,
        const Address& remoteAppAddress,
        const Address& kmAddress,
        std::string type
    );


    /**
     * @brief Initialize key stores at application layer
     */
    void InitKeyStores();

    /**
     * @brief Get key from key store
     * @param keyType key type(encryption or authentication)
     * @param keyId key identifier(optional)
     */
    Ptr<AppKey> GetLocalKey(std::string keyType, std::string keyId = "");

    /**
     * @brief Print status information on key stores
     */
    void PrintStoreStats();

    /**
     * @brief Checks the state of the key stores
     *
     * Function checks ste state of the application key stores
     * and submits get_key request if neccessary.
     */
    void ManageStores();

    /**
     * @brief Checks the conditions to change the application state
     *
     * Based on the states of the key stores, the application
     * will change its states between READY and WAIT.
     */
    void CheckAppState();

    /**
    * @brief returns application state
    * @return State application state
    */
    State       GetState() const {
        return m_state;
    }

    /**
    * @brief set application state
    * @param state application state
    */
    void SetState(State state){
        m_state = state;
    }

    /**
     * @brief Get status from local KMS
     *
     * Method defined by the ETSI QKD 014 document
     */
    void GetStatusFromKMS();

    /**
     * @brief Get keys from local KMS
     * @param keyType key type(encryption or authentication)
     *
     * Method defined by the ETSI QKD 014 document
     */
    void GetKeysFromKMS(std::string keyType);

    /**
     * @brief Get keys identified with given IDs from local KMS
     * @param keyIds key identifiers in JSON key_Ids string format
     *
     * Method defined by the ETSI QKD 014 document
     */
    void GetKeyWithKeyIDs(std::string keyIds);

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
     * @brief Handle a packet received by the QKD application from KMS application
     * @param socket the receiving socket
     */
    void HandleReadFromKMS(Ptr<Socket> socket);

    /**
     * @brief Handle a connection close from KMS
     * @param socket the connected socket
     */
    void HandlePeerCloseFromKMS(Ptr<Socket> socket);

    /**
     * @brief Handle a connection error from KMS
     * @param socket the connected socket
     */
    void HandlePeerErrorFromKMS(Ptr<Socket> socket);

    /**
     * @brief Handle an incoming connection from KMS
     * @param s the incoming connection socket
     * @param from the address the connection is from
     */
    void HandleAcceptFromKMS(Ptr<Socket> s, const Address& from);

    /**
     * @brief Handle a packet received by the QKD application from peer QKD application
     * @param socket the receiving socket
     */
    void HandleReadFromApp(Ptr<Socket> socket);

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
     * @brief Handle a signaling packet received by the QKD application from peer QKD application
     * @param socket the receiving socket
     */
    void HandleReadSignalingFromApp(Ptr<Socket> socket);

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
     * @brief Callback function after the connection for response from KMS has been received
     * @param socket the connected socket
     * @param address address of the KMS
     */
    bool        ConnectionRequestedFromKMS(Ptr<Socket> socket, const Address &address);

    /**
     * @brief Callback function after the connection for response from KMS has been received
     * @param socket the connected socket
     * @param address address of the KMS
     */
    bool        ConnectionRequestedFromApp(Ptr<Socket> socket, const Address &address);

    /**
     * @brief Callback function after the connection for response from KMS has been received
     * @param socket the connected socket
     * @param address address of the KMS
     */
    bool        ConnectionRequestedSignalingFromApp(Ptr<Socket> socket, const Address &address);

    /**
     * @brief Check for tcp segmentation of packets received
     * @param packet
     * @param address address of the KMS
     * @param socket the connected socket
     */
    void HttpPacketReceived(const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket);

    /**
     * @brief Check for tcp segmentation of signaling packets received from KMS
     * @param packet
     * @param address address of the KMS
     * @param socket the connected socket
     */
    void QAppPacketReceived(const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket);

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
    void ProcessSignalingPacketFromApp(HTTPMessage& header, Ptr<Packet> packet, Ptr<Socket> socket);

     /**
     * @brief Process data packets from peer QKD application
     * @param header QKDApp014 packet header
     * @param packet received packet
     * @param socket the receiving socket
     */
    void ProcessDataPacket(QKDAppHeader header, Ptr<Packet> packet, Ptr<Socket> socket);

    /**
     * @brief Prepare send socket to communicate with KMS Application
     */
    void PrepareSocketToKMS();

    /**
     * @brief Prepare send socket to communicate with QKD Application
     */
    void PrepareSocketToApp();

    /**
     * @brief Schedule action to performe
     * @param time eventTime
     * @param string eventAction 
     */
    void ScheduleAction(Time t, std::string action);

 

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
     * @brief Get the application ID
     * @return uint32_t application ID
     */
    std::string GetId(){
        return m_id;
    }

    /**
     * @brief Get ipv4 address of source
     * @return ipv4 address
     */
    Ipv4Address GetIp();

    /**
     * @brief Get ipv4 address of destination
     * @return ipv4 address
     */
    Ipv4Address GetPeerIp();

    /**
     * @brief Get ipv4 address of local KMS
     * @return ipv4 address
     */
    Ipv4Address GetKmsIp();

protected:
    void DoDispose() override;

private:

    /**
     * @brief Read http uri in vector
     * @param s uri string
     * @return vector of uri parameters
     */
    std::vector<std::string> ReadUri(std::string s);

    /**
     * @brief Convert ipv4 address in string
     * @param address ipv4 address
     * @return string ipv4 address
     */
    std::string IpToString(Ipv4Address address);

    /**
     * @brief Adds HTTP request to kms queue to properly map response later
     * @param input key type
     */
    void PushHttpKmsRequest(std::string input);

    /**
     * @brief Adds HTTP request to app queue to properly map response later
     * @param keyIds vector of key ids
     */
    void PushHttpAppRequest(std::vector<std::string> keyIds);

    /**
     * @brief Pop HTTP request from kms queue
     * @return string key type
     *
     * It deletes request from queue!
     */
    std::string PopHttpKmsRequest();

    /**
     * @brief Pop HTTP request from app queue
     * @return vector of strings key ids
     *
     * It deletes request from queue!
     */
    std::vector<std::string> PopHttpAppRequest();

    /**
     * @brief Create encryption key id field for the QKDApp header
     * @param keyId key ID used to create encryption key id field
     * @return string key ID prepared to be added to the field
     */
    std::string CreateKeyIdField(std::string keyId);

    /**
     * @brief Read key ID from the encryption key ID field of the QKDApp header
     * @param keyId key ID from the encryption key ID field
     * @return string read key ID
     */
    std::string ReadKeyIdField(std::string keyId);


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
     * @brief Start application
     */
    void StartApplication() override; 

    /**
     * @brief Stop application
     */
    void StopApplication() override;

    /**
     * @brief Schedule event to send data
     */
    void ScheduleTx();

    /**
     * @brief Send protected data
     *
     * App014 encrypts the data with obtained keys
     * and sends this encrypted data to the peer.
     */
    void SendDataPacket();


    /**
     * @brief Transition tree of the application. Change states and take actions!
     */
    void AppTransitionTree();

    /**
     * @brief Change the state of the application. Fires the `AppStateTransition` trace source.
     * @param state The new application state.
     */
    void SwitchAppState(State state);

    /**
    * @brief Get the packet payload content
    * @param msgLength length of random string to generate
    * @return string random string
    */
    std::string GetPacketContent(uint32_t msgLength = 0);

    /**
     * @brief Implementation of send KEY_IDS notification
     * @param keyIds key identifiers
     * @param statusCode http status code of response(default status is Ok)
     *
     * Master App014(Alice) sends key IDs of obtained keys from KMS
     * that will be used for encryption of outgoing messages. Slave App014
     *(Bob) agree or disagree on proposed key IDs.
     */
    void SendKeyIds(std::vector<std::string> keyIds, HTTPMessage::HttpStatus statusCode = HTTPMessage::Ok);


    //Sockets
    std::string     m_socketType;
    bool            m_isSignalingConnectedToApp;
    bool            m_isDataConnectedToApp;
    Ptr<Socket>     m_signalingSocketApp;
    Ptr<Socket>     m_dataSocketApp;
    Ptr<Socket>     m_socketToKMS;

    //Addresses
    Address         m_peer;                 //!< peer address
    Address         m_local;                //!< local address
    Address         m_kms;                  //!< local kms address
    uint16_t        m_portSignaling;

    //HTTP mappings
    std::vector<std::string>                        m_kmsHttpReqQueue;
    std::vector<std::vector<std::string> >          m_appHttpReqQueue;

    //App params
    static uint32_t m_applicationCounts;    //!< application count
    TypeId          m_tid;                  //!< tid
    State           m_state;                //!< application state
    uint32_t        m_master;               //!< is master App014
    std::string     m_dstId;                //!< destination application id
    std::string     m_id;                   //!< source application id
    uint32_t        m_size;                 //!< data packet size
    DataRate        m_rate;                 //!< data rate

    //Stores
    std::map<std::string, Ptr<AppKey>> m_commonStore;   //<! temporary/inbound key store
    std::map<std::string, Ptr<AppKey>> m_encStore;      //<! encryption key store
    std::map<std::string, Ptr<AppKey>> m_authStore;     //<! authentication key store

    Time        m_waitInsufficient;                 //!< time wait before submitting new get_key after error

    //Crypto params
    uint32_t    m_numberOfKeysKMS;                  //!< number of keys to fetch per request
    uint32_t    m_useCrypto;                        //!< execute crypo algorithms
    uint32_t    m_encryption;                       //!< encryption type
    uint32_t    m_authentication;                   //!< authentication type
    uint32_t    m_authTagSize;                      //!< length of the authentication tag in bits
    uint32_t    m_aesLifetime;                      //!< key lifetime in bytes

    QKDEncryptor::EncryptionType        m_encryptionType;       //!< encryption type
    QKDEncryptor::AuthenticationType    m_authenticationType;   //!< authentication type
    Ptr<QKDEncryptor> m_encryptor;                              //!< encryptor

    //Traces
    TracedCallback<Ptr<Packet> > m_encryptionTrace; //!< trace callback for encryption
    TracedCallback<Ptr<Packet> > m_decryptionTrace; //!< trace callback for decryption
    TracedCallback<Ptr<Packet>, std::string > m_authenticationTrace;    //!< trace callback for authentication
    TracedCallback<Ptr<Packet>, std::string > m_deauthenticationTrace;  //!< trace callback for authentication check

    /// Traced Callback: transmitted data packets.
    TracedCallback<const std::string&, Ptr<const Packet> > m_txTrace;
    /// Traced Callback: transmitted signaling packets.
    TracedCallback<const std::string&, Ptr<const Packet> > m_txSigTrace;
    /// Traced Callback: transmitted packets to KMS.
    TracedCallback<const std::string&, Ptr<const Packet> > m_txKmsTrace;
    /// Traced Callback: received data packets.
    TracedCallback<const std::string&, Ptr<const Packet> > m_rxTrace;
    /// Traced Callback: received signaling packets.
    TracedCallback<const std::string&, Ptr<const Packet> > m_rxSigTrace;
    /// Traced Callback: received packets from KMS.
    TracedCallback<const std::string&, Ptr<const Packet> > m_rxKmsTrace;
    ///Traced Callback: missed send packet call.
    TracedCallback<const std::string&, Ptr<const Packet> > m_mxTrace;
    /// The `StateTransition` trace source.
    ns3::TracedCallback<const std::string&, const std::string&> m_stateTransitionTrace;

    std::unordered_map<Address, Ptr<Packet>, AddressHash> m_buffer_kms;         //!< Buffer for received packets(fragmentation)
    std::unordered_map<Address, Ptr<Packet>, AddressHash> m_buffer_QKDApp014;   //!< Buffer for received packets(fragmentation)

    bool            m_internalAppWait; //Indicate if the longer wait is required(used after GetKey error!)
    EventId         m_sendEvent;
    EventId         m_scheduleManageStores;
 
    std::multimap<std::string, std::string> m_transitionMatrix; //!< transition map of protocol states

};


} // namespace ns3

#endif /* QKD_SINK_H */

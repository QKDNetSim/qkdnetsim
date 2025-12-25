/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 *
 *
 * Author: Miralem Mehic <miralem.mehic@etf.unsa.ba>
 */

#ifndef QKDEncryptor_H
#define QKDEncryptor_H

#include <algorithm>
#include <stdint.h>

#include "ns3/header.h"
#include "ns3/tcp-header.h"
#include "ns3/udp-header.h"
#include "ns3/icmpv4.h"

#include "ns3/dsdv-packet.h"
#include "ns3/aodv-packet.h"
#include "ns3/olsr-header.h"

#include "ns3/packet.h"
#include "ns3/tag.h"
#include "ns3/object.h"
#include "ns3/callback.h"
#include "ns3/assert.h"
#include "ns3/ptr.h"
#include "ns3/deprecated.h"
#include "ns3/traced-value.h"
#include "ns3/packet-metadata.h"
#include "ns3/trace-source-accessor.h"
#include "qkd-key.h"
#include "ns3/net-device.h"
#include "ns3/node.h"

#include <crypto++/aes.h>
#include <crypto++/modes.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>
#include <crypto++/osrng.h>
#include <crypto++/ccm.h>
#include <crypto++/vmac.h>
#include <crypto++/iterhash.h>
#include <crypto++/secblock.h>
#include <crypto++/sha.h>
#include <cryptopp/base64.h>
#include <vector>

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <crypto++/md5.h>

namespace ns3 {

/**
 * @ingroup qkd
 * @class QKD Encryptor
 * @brief QKD Encryptor is a class used to perform encryption, decryption, authentication,
 *  atuhentication-check operations and reassembly of previously fragmented packets.
 *
 *  @note QKD Encryptor uses cryptographic algorithms and schemes from
 *  Crypto++ free and open source C++ class cryptographic library. Currently,
 *  QKD Encryptor supports following crypto-graphic algorithms and schemes:
 *      - One-Time Pad(OTP) cipher,
 *      - Advanced Encryption Standard(AES) block cipher,
 *      - VMAC message authentication code(MAC) algorithm,
 *      - MD5 MAC algorithm,
 *      - SHA1 MAC algorithm.
 *
 *  As these algorithms can put a significant computational load on machines performing
 *  the simulation, the users can turn off actual execution of such algorithms and allow
 *  efficient simulation with more significant QKD topologies.
 */
class QKDEncryptor : public Object
{
public:

    /**
     * @brief Encryption type
     */
    enum EncryptionType {
        UNENCRYPTED,
        QKDCRYPTO_OTP,
        QKDCRYPTO_AES
    };

    /**
     * @brief Authentication type
     */
    enum AuthenticationType {
        UNAUTHENTICATED,
        QKDCRYPTO_AUTH_VMAC,
        QKDCRYPTO_AUTH_MD5,
        QKDCRYPTO_AUTH_SHA1
    };


    QKDEncryptor();

    /**
     * @brief Constructor
     */
    QKDEncryptor(uint32_t authTagLength);

    /**
    * @brief Constructor
    */
    QKDEncryptor(EncryptionType type1, AuthenticationType type2);
    /**
    * @brief Constructor
    */
    QKDEncryptor(EncryptionType type1, AuthenticationType type2, uint32_t authTagLength);
    /**
    * @brief Constructor
    */
    void ChangeSettings(EncryptionType type1, AuthenticationType type2, uint32_t authTagLength);
    /**
    * @brief Destructor
    */
    ~QKDEncryptor() override;

    /**
    * @brief Get the TypeId
    * @return The TypeId for this class
    */
    static TypeId GetTypeId();

    /**
    *  @brief Set node on which qkd encryptor is installed
     * @param Ptr<Node> node
    */
    void SetNode(Ptr<Node> node);

    /**
    *  @brief Get details about the node on which qkd encryptor is installed
     * @return Ptr<Node> node
    */
    Ptr<Node> GetNode() const;

    /**
    *  @brief Set internal index identifier in qkd encryptor container. @featureTask
     * @param uint32_t index
    */
    void SetIndex(uint32_t index);

    /**
    *  @brief Get internal index identifier in qkd encryptor container. @featureTask
     * @return uint32_t index
    */
    uint32_t GetIndex() const;

    /**
    *  @brief One-time cipher
     * @param key key for encryption
     * @param data message to encrypt/decrypt
     * @return string encypted/decrypted message
    */
    std::string OTP(const std::string& key, const std::string& data);

    /**
     * @brief One-Time Pad cipher where output is alfabet/number symbols
     * @param key symmetric key
     * @param input input message
     * @return string encrypted/decrypted message
     *
     * Solution adapted from: https://stackoverflow.com/questions/12671510/xor-on-two-hexadeicmal-values-stored-as-string-in-c
     */
    std::string COTP(const std::string& key, const std::string& input);

    /**
    *   AES encryption
    *   @param  std::string data
    *   @param  Ptr<QKDKey> key
    *   @return std::string
    */
    std::string AESEncrypt(const std::string& key, const std::string& data);

    /**
    *   AES decryption
    *   @param  std::string data
    *   @param  Ptr<QKDKey> key
    *   @return std::string
    */
    std::string AESDecrypt(const std::string& key, const std::string& data);

    /**
     * @brief Perform encryption of plaintext
     * @param input plaintext
     * @param key encryption key
     * @return string ciphertext
     */
    std::string EncryptMsg(std::string input, std::string key);

    /**
     * @brief Perform decryption of ciphertext
     * @param input ciphertext
     * @param key encryption key
     * @return string plaintext
     */
    std::string DecryptMsg(std::string input, std::string key);

    /**
    *   Help parent function used for calling child authentication functions
    *   @param  std::string data
    *   @param  Ptr<QKDKey> key
    *   @param  uint8_t authentic
    *   @return std::string
    */
    std::string Authenticate(std::string&, std::string key = "0");

    /**
    *   @brief Check Authentication on packet payload for authenticated packet
    *   @param  payload payload data
    *   @param  key key for authentication
    *   @return bool authentication check result
    */
    bool CheckAuthentication(std::string payload, std::string authTag, std::string key = "0");

    /**
    *   Help function used to encode string to HEX string
    *   @param  std::string data
    *   @return std::string
    */
    std::string HexEncode(const std::string& data);

    /**
    *   Help function used to decode string to HEX string
    *   @param  std::string data
    *   @return std::string
    */
    std::string HexDecode(const std::string& data);

    /**
     * @brief Base64 encoder
     * @param input input data
     * @return string base64 encoded input
     */
    std::string Base64Encode(std::string input);

    /**
     * @brief Base64 decoder
     * @param input input data
     * @return string decoded input
     */
    std::string Base64Decode(std::string input);

    /**
    *   Authentication function in Wegman-Carter fashion
    *   @param  std::string data
    *   @param  std::string data
    *   @param  uint32_t length of auth tag
    *   @return std::string
    */
    std::string VMAC(std::string& key, std::string& inputString);

    /**
    *   MD5 Authentication function
    *   @param  std::string data
    *   @return std::string
    */
    std::string MD5(std::string& inputString);

    /**
    *   SHA1 Authentication function
    *   @param  std::string data
    *   @return std::string
    */
    std::string SHA1(std::string& inputString);

private:

    unsigned char m_iv [ CryptoPP::AES::BLOCKSIZE ];

    Ptr<Node>   m_node; //!< pointer to node on which encryptor is installed
    uint32_t    m_index; //!< index in the qkd encryptor container

    bool        m_encryptionEnabled;  //!< real encryption used?
    bool        m_compressionEnabled; //!< should compression algorithms be used?
    uint32_t    m_authenticationTagLengthInBits; //!< length of the authentication tag in bits(32 by default)

    EncryptionType m_encryptionType;
    AuthenticationType m_authenticationType;

    TracedCallback<Ptr<Packet> > m_encryptionTrace; //!< trace callback for encryption
    TracedCallback<Ptr<Packet> > m_decryptionTrace; //!< trace callback for decryption

    TracedCallback<Ptr<Packet>, std::string > m_authenticationTrace; //!< trace callback for authentication
    TracedCallback<Ptr<Packet>, std::string > m_deauthenticationTrace; //!< trace callback for authentication check


};
} // namespace ns3

#endif /* QKDEncryptor_QKD_H */

/*
 * Copyright(c) 2005,2006 INRIA
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 *
 *
 * Author: Miralem Mehic <miralem.mehic@etf.unsa.ba>
 */

#define NS_LOG_APPEND_CONTEXT                                   \
  if(GetObject<Node>()) { std::clog << "[node " << GetObject<Node>()->GetId() << "] "; }

#include <string>
#include <cstdarg>
#include <iostream>
#include <sstream>
#include "ns3/packet.h"
#include "ns3/assert.h"
#include "ns3/log.h"
#include "ns3/node.h"
#include "qkd-encryptor.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("QKDEncryptor");

NS_OBJECT_ENSURE_REGISTERED(QKDEncryptor);

static const std::string base64_chars =
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

static inline bool is_base64(unsigned char c) {
  return(isalnum(c) ||(c == '+') ||(c == '/'));
}

TypeId
QKDEncryptor::GetTypeId()
{
  static TypeId tid = TypeId("ns3::QKDEncryptor")
    .SetParent<Object>()
    .AddAttribute("CompressionEnabled", "Indicates whether a compression of packets is enabled.",
                    BooleanValue(false),
                    MakeBooleanAccessor(&QKDEncryptor::m_compressionEnabled),
                    MakeBooleanChecker())
    .AddAttribute("EncryptionEnabled", "Indicates whether a real encryption of packets is enabled.",
                    BooleanValue(false),
                    MakeBooleanAccessor(&QKDEncryptor::m_encryptionEnabled),
                    MakeBooleanChecker())

    .AddTraceSource("PacketEncrypted",
                    "The change trance for currenly ecrypted packet",
                     MakeTraceSourceAccessor(&QKDEncryptor::m_encryptionTrace),
                     "ns3::QKDEncryptor::PacketEncrypted")
    .AddTraceSource("PacketDecrypted",
                    "The change trance for currenly decrypted packet",
                     MakeTraceSourceAccessor(&QKDEncryptor::m_decryptionTrace),
                     "ns3::QKDEncryptor::PacketDecrypted")

    .AddTraceSource("PacketAuthenticated",
                    "The change trance for currenly authenticated packet",
                     MakeTraceSourceAccessor(&QKDEncryptor::m_authenticationTrace),
                     "ns3::QKDEncryptor::PacketAuthenticated")
    .AddTraceSource("PacketDeAuthenticated",
                    "The change trance for currenly deauthenticated packet",
                     MakeTraceSourceAccessor(&QKDEncryptor::m_deauthenticationTrace),
                     "ns3::QKDEncryptor::PacketDeAuthenticated")
    ;
  return tid;
}

QKDEncryptor::QKDEncryptor()
{
    NS_LOG_FUNCTION(this);
}

QKDEncryptor::QKDEncryptor(uint32_t authTagLength)
{
    NS_LOG_FUNCTION(this << authTagLength);
    m_authenticationTagLengthInBits = 64;
}

QKDEncryptor::QKDEncryptor(
  EncryptionType encryptionType,
  AuthenticationType authenticationType
){
    NS_LOG_FUNCTION(this << encryptionType << authenticationType);
    ChangeSettings(encryptionType, authenticationType, 256);
    memset( m_iv,  0x00, CryptoPP::AES::BLOCKSIZE );
}

QKDEncryptor::QKDEncryptor(
  EncryptionType encryptionType,
  AuthenticationType authenticationType,
  uint32_t authTagLength
){
    NS_LOG_FUNCTION(this << encryptionType << authenticationType);
    ChangeSettings(encryptionType, authenticationType, authTagLength);
}

void
QKDEncryptor::ChangeSettings(
  EncryptionType encryptionType,
  AuthenticationType authenticationType,
  uint32_t authTagLength
){
    if(authTagLength != 128 && authTagLength != 256  ){
     NS_FATAL_ERROR( this << "Crypto++ supports VMAC with 16 or 32 bytes authentication tag length!");
    }

    m_encryptionType = encryptionType;
    m_authenticationType = authenticationType;
    m_authenticationTagLengthInBits = authTagLength;
}


QKDEncryptor::~QKDEncryptor()
{
  //NS_LOG_FUNCTION (this);
}

void
QKDEncryptor::SetNode(Ptr<Node> node){
    m_node = node;
}
Ptr<Node>
QKDEncryptor::GetNode() const
{
    return m_node;
}

void
QKDEncryptor::SetIndex(uint32_t index){
	m_index = index;
}
uint32_t
QKDEncryptor::GetIndex() const
{
	return m_index;
}

std::string
QKDEncryptor::EncryptMsg(std::string input, std::string key)
{
    NS_LOG_FUNCTION(this << m_encryptionType << input.length() << key.length() );
 
    std::string output;
    switch(m_encryptionType)
    {
        case UNENCRYPTED:
            return input; 
        case QKDCRYPTO_OTP: 
            if(key.length() > input.length())
            {
                std::string otpKey = key.substr(0, input.length());
                return OTP(key.substr(0, input.length()), input);   
            }
            return output = OTP(key, input); 
        case QKDCRYPTO_AES:
            return AESEncrypt(key, input); 
    }
    return output;
}

std::string
QKDEncryptor::DecryptMsg(std::string input, std::string key)
{
    NS_LOG_FUNCTION(this << m_encryptionType << input.length() << key.length() );

    std::string output;
    switch(m_encryptionType)
    {
    case UNENCRYPTED:
        output = input;
        break;
    case QKDCRYPTO_OTP: 
        if(key.length() > input.length())
        {
            std::string otpKey = key.substr(0, input.length());
            return OTP(key.substr(0, input.length()), input);   
        }
        return output = OTP(key, input);
        break;
    case QKDCRYPTO_AES:
        output = AESDecrypt(key, input);
        break;
    }
    return output;
}

std::string
QKDEncryptor::Authenticate(std::string& inputString, std::string key)
{
    NS_LOG_FUNCTION(this << inputString.length() << key.length());
    switch(m_authenticationType)
    {
        case UNAUTHENTICATED:
            break;
        case QKDCRYPTO_AUTH_VMAC:
            return VMAC(key, inputString);
            break;
        case QKDCRYPTO_AUTH_MD5:
            return MD5(inputString);
            break;
        case QKDCRYPTO_AUTH_SHA1:
            return SHA1(inputString);
            break;
    }
    std::string temp;
    return temp;
}

bool
QKDEncryptor::CheckAuthentication(std::string payload, std::string authTag, std::string key)
{
    //@toDo: authentication tag is different even though key and received tag are good, and payload seems to be correct!
    std::string genAuthTag = Authenticate(payload, key);
    NS_LOG_FUNCTION( this << key << authTag << genAuthTag );
    return (genAuthTag == authTag);
}


/***************************************************************
*           CRYPTO++ CRYPTOGRAPHIC FUNCTIONS
***************************************************************/

std::string
QKDEncryptor::Base64Encode(std::string input){

  std::string output;
  CryptoPP::StringSource(input, true,
    new CryptoPP::Base64Encoder(
      new CryptoPP::StringSink(output)
    ) // Base64Encoder
  ); // StringSource
  return output;
}

std::string
QKDEncryptor::Base64Decode(std::string input){

  std::string output;
  CryptoPP::StringSource(input, true,
    new CryptoPP::Base64Decoder(
      new CryptoPP::StringSink(output)
    ) // Base64Dencoder
  ); // StringSource
  return output;
}

std::string
QKDEncryptor::OTP(const std::string& key, const std::string& cipherText)
{

  NS_LOG_FUNCTION(this << cipherText.length() << key.length() );
  std::string output;

  if(key.size() != cipherText.size()){
      NS_FATAL_ERROR("KEY SIZE DO NOT MATCH FOR OTP! \nKeySize:" << key.size() << "\nCipterText:" << cipherText.size() << "\n" );
      output = cipherText;
  }else{

    for(std::size_t i = 0; i < cipherText.size(); i++){
      output.push_back(key[i] ^ cipherText[i]);
    }

  }

  return output;
}

static inline unsigned int value(char c)
{
    if(c >= '0' && c <= '9') { return c - '0';      }
    if(c >= 'a' && c <= 'z') { return c - 'a' + 10; }
    if(c >= 'A' && c <= 'Z') { return c - 'A' + 36; }
    if(c == '*') {return 62; }
    if(c == '$') {return 63; }
    return -1;
}

std::string
QKDEncryptor::COTP(const std::string& key, const std::string& input)
{
    NS_LOG_FUNCTION(this << input.length() << key.length());
    static const char alphanum[] =
          "0123456789"
          "abcdefghijklmnopqrstuvwxyz"
          "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
          "*$"; //additional characters

    std::string output;
    output.reserve(key.length());
    if(key.size() == input.size()){
        for(std::size_t i = 0; i < input.size(); i++){
            unsigned int v = value(key[i]) ^ value(input[i]);
            NS_ASSERT(v < sizeof alphanum);
            output.push_back(alphanum[v]);
        }

    }else
        NS_FATAL_ERROR(this << "key size != input size");

    NS_LOG_FUNCTION(this << "\nKey:\t" << key << "\nInput:\t" << input << "\nOutput:\t" << output);
    return output;
}



std::string
QKDEncryptor::AESEncrypt(const std::string& key, const std::string& data)
{
    NS_LOG_FUNCTION( this << data.size() <<  key.length() );

    memset( m_iv,  0x00, CryptoPP::AES::BLOCKSIZE );
    std::string encryptData;

    // Encryption
    CryptoPP::CTR_Mode< CryptoPP::AES >::Encryption encryptor;
    encryptor.SetKeyWithIV((unsigned char*) key.c_str(), key.length(), m_iv);
    //encryptor.SetKeyWithIV( key, CryptoPP::AES::DEFAULT_KEYLENGTH, m_iv );

    CryptoPP::StreamTransformationFilter stf( encryptor, new CryptoPP::StringSink( encryptData ) );
    stf.Put((unsigned char*)data.c_str(), data.size() );
    stf.MessageEnd();

    return encryptData;
}

std::string
QKDEncryptor::AESDecrypt(const std::string& key, const std::string& data)
{
    NS_LOG_FUNCTION (this << data.size());
    memset( m_iv,  0x00, CryptoPP::AES::BLOCKSIZE );
    std::string decryptData;

    // Decryption
    CryptoPP::CTR_Mode< CryptoPP::AES >::Decryption decryptor;
    decryptor.SetKeyWithIV((unsigned char*) key.c_str(), key.length(), m_iv);
    //decryptor.SetKeyWithIV( key, CryptoPP::AES::DEFAULT_KEYLENGTH, m_iv );

    CryptoPP::StreamTransformationFilter stf( decryptor, new CryptoPP::StringSink( decryptData ) );
    stf.Put((unsigned char*)data.c_str(), data.size() );
    stf.MessageEnd();

    return decryptData;
}


std::string
QKDEncryptor::HexEncode(const std::string& data)
{
    NS_LOG_FUNCTION (this << data.size());

    std::string encoded;
    CryptoPP::StringSource ss(
       (unsigned char*)data.data(), data.size(), true,
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded))
    );
    return encoded;
}

std::string
QKDEncryptor::HexDecode(const std::string& data)
{
    NS_LOG_FUNCTION (this << data.size());

    std::string decoded;
    CryptoPP::StringSource ss(
       (unsigned char*)data.data(), data.size(), true,
        new CryptoPP::HexDecoder(new CryptoPP::StringSink(decoded))
    );
    return decoded;
}

std::string
QKDEncryptor::VMAC(std::string& key, std::string& inputString)
{
    NS_LOG_FUNCTION(this << inputString.length() << key.length());

    std::string outputString;
    memset(m_iv, 0x00, CryptoPP::AES::BLOCKSIZE);
    CryptoPP::VMAC<CryptoPP::AES> vmac;
    vmac.SetKeyWithIV(
        reinterpret_cast<const CryptoPP::byte*>(key.data()),
        key.size(),
        m_iv,
        CryptoPP::AES::BLOCKSIZE
    );

    const size_t tagSize = vmac.DigestSize();  // â† OVO JE ISPRAVNO
    std::vector<CryptoPP::byte> digestBytes(tagSize);

    vmac.CalculateDigest(
        digestBytes.data(),
        reinterpret_cast<const CryptoPP::byte*>(inputString.data()),
        inputString.size()
    );

    CryptoPP::HexEncoder encoder;
    encoder.Attach(new CryptoPP::StringSink(outputString));
    encoder.Put(digestBytes.data(), digestBytes.size());
    encoder.MessageEnd();

    return outputString;
}

std::string
QKDEncryptor::MD5(std::string& inputString)
{
    NS_LOG_FUNCTION(this << inputString.length() );

    unsigned char digestBytes[CryptoPP::Weak::MD5::DIGESTSIZE];

    CryptoPP::Weak1::MD5 md5;
    md5.CalculateDigest(digestBytes,(unsigned char *) inputString.c_str(), inputString.length());

    std::string outputString;
    CryptoPP::HexEncoder encoder;

    encoder.Attach(new CryptoPP::StringSink(outputString));
    encoder.Put(digestBytes, sizeof(digestBytes));
    encoder.MessageEnd();

    outputString = outputString.substr(0, m_authenticationTagLengthInBits);
    return outputString;
}

std::string
QKDEncryptor::SHA1(std::string& inputString)
{
    NS_LOG_FUNCTION(this << inputString.length() );

    unsigned char digestBytes[CryptoPP::SHA1::DIGESTSIZE];

    CryptoPP::SHA1 sha1;
    sha1.CalculateDigest(digestBytes,(unsigned char *) inputString.c_str(), inputString.length());

    std::string outputString;
    CryptoPP::HexEncoder encoder;

    encoder.Attach(new CryptoPP::StringSink(outputString));
    encoder.Put(digestBytes, sizeof(digestBytes));
    encoder.MessageEnd();

    outputString = outputString.substr(0, m_authenticationTagLengthInBits/8);
    return outputString;
}

} // namespace ns3

/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 * Author: Miralem Mehic <miralem.mehic@etf.unsa.ba>
 */

#include "ns3/log.h"
#include "ns3/object-vector.h"
#include "ns3/pointer.h"
#include "ns3/uinteger.h"
#include "qkd-app-header.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("QKDAppHeader");

NS_OBJECT_ENSURE_REGISTERED(QKDAppHeader);

QKDAppHeader::QKDAppHeader():m_valid(true)
{
    m_length = 0;
    m_messageId = 0;
    m_encryped = 0;
    m_authenticated = 0;
}

TypeId
QKDAppHeader::GetTypeId()
{
  static TypeId tid = TypeId("ns3::QKDAppHeader")
    .SetParent<Header>()
    .AddConstructor<QKDAppHeader>()
  ;
  return tid;
}

TypeId
QKDAppHeader::GetInstanceTypeId() const
{
  return GetTypeId();
}

uint32_t
QKDAppHeader::GetSerializedSize() const
{
  return 2  * sizeof(uint32_t)
       + 2  * sizeof(uint8_t)
       + 3 * 32 * sizeof(uint8_t); //@toDo: AuthTag is variable length!
}

void
QKDAppHeader::Serialize(Buffer::Iterator i) const
{
    i.WriteHtonU32((uint32_t) m_length);
    i.WriteHtonU32((uint32_t) m_messageId);
    i.WriteU8((uint8_t) m_encryped);
    i.WriteU8((uint8_t) m_authenticated);

    std::vector<uint8_t> tmpBuffer1(m_encryptionKeyId.begin(), m_encryptionKeyId.end());
    i.Write(tmpBuffer1.data(), tmpBuffer1.size());

    std::vector<uint8_t> tmpBuffer2(m_authenticationKeyId.begin(), m_authenticationKeyId.end());
    i.Write(tmpBuffer2.data(), tmpBuffer2.size());

    std::vector<uint8_t> tmpBuffer3(m_authTag.begin(), m_authTag.end());
    i.Write(tmpBuffer3.data(), tmpBuffer3.size());
}

uint32_t
QKDAppHeader::Deserialize(Buffer::Iterator start)
{

    Buffer::Iterator i = start;
    m_valid = false;

    m_length = i.ReadNtohU32();
    m_messageId = i.ReadNtohU32();
    m_encryped = i.ReadU8();
    m_authenticated = i.ReadU8();

    uint32_t len1 = 32;
    std::vector<uint8_t> tmpBuffer1(len1);
    i.Read(tmpBuffer1.data(), len1);
    m_encryptionKeyId = std::string(tmpBuffer1.begin(), tmpBuffer1.end());

    uint32_t len2 = 32;
    std::vector<uint8_t> tmpBuffer2(len2);
    i.Read(tmpBuffer2.data(), len2);
    m_authenticationKeyId = std::string(tmpBuffer2.begin(), tmpBuffer2.end());

    uint32_t len3 = 32;
    std::vector<uint8_t> tmpBuffer3(len3);
    i.Read(tmpBuffer3.data(), len3);
    m_authTag = std::string(tmpBuffer3.begin(), tmpBuffer3.end());

    NS_LOG_DEBUG("Deserialize m_length: " <<(uint32_t) m_length
                << " m_messageId: " <<(uint32_t) m_messageId
                << " m_encryptionKeyId: " << m_encryptionKeyId
                << " m_authenticationKeyId: " << m_authenticationKeyId
                << " m_valid: " <<(uint32_t) m_valid
                << " m_authTag: " << m_authTag
    );

    uint32_t dist = i.GetDistanceFrom(start);
    NS_LOG_FUNCTION( this << dist << GetSerializedSize() );
    NS_ASSERT(dist == GetSerializedSize());
    return dist;
}

void
QKDAppHeader::Print(std::ostream &os) const
{
    os << "\n"
       << "MESSAGE ID: "    <<(uint32_t) m_messageId << "\t"
       << "Length: "        <<(uint32_t) m_length << "\t"

       << "Authenticated: " <<(uint32_t) m_authenticated << "\t"
       << "Encrypted: "     <<(uint32_t) m_encryped << "\t"

       << "EncryptKeyID: "  << m_encryptionKeyId << "\t"
       << "AuthKeyID: "     << m_authenticationKeyId << "\t"

       << "AuthTag: "       << m_authTag << "\t\n";

}

bool
QKDAppHeader::operator==(QKDAppHeader const & o) const
{
    return(m_messageId == o.m_messageId && m_authenticationKeyId == o.m_authenticationKeyId && m_authTag == o.m_authTag);
}

std::ostream &
operator<<(std::ostream & os, QKDAppHeader const & h)
{
    h.Print(os);
    return os;
}


void
QKDAppHeader::SetLength(uint32_t value){

    NS_LOG_FUNCTION (this << value);
    m_length = value;
}
uint32_t
QKDAppHeader::GetLength() const{

    NS_LOG_FUNCTION (this << m_length);
    return m_length;
}

void
QKDAppHeader::SetMessageId(uint32_t value){

    NS_LOG_FUNCTION (this << value);
    m_messageId = value;
}
uint32_t
QKDAppHeader::GetMessageId() const{

    NS_LOG_FUNCTION (this << m_messageId);
    return m_messageId;
}

void
QKDAppHeader::SetEncryptionKeyId(std::string  value){

    NS_LOG_FUNCTION (this << value);

    NS_ASSERT(value.size() <= 32);
    if(value.size() < 32) {
        uint32_t diff = 32-value.size();
        std::string newValue = std::string(diff, '0') + value;
        m_encryptionKeyId = newValue;
    } else
        m_encryptionKeyId = value;
}

std::string
QKDAppHeader::GetEncryptionKeyId() const{

    NS_LOG_FUNCTION (this << m_encryptionKeyId);
    return m_encryptionKeyId;
}


void
QKDAppHeader::SetAuthenticationKeyId(std::string  value){

    NS_LOG_FUNCTION (this << value);

    NS_ASSERT(value.size() <= 32);
    if(value.size() < 32) {
        uint32_t diff = 32-value.size();
        std::string newValue = std::string(diff, '0') + value;
        m_authenticationKeyId = newValue;
    } else
        m_authenticationKeyId = value;
}

std::string
QKDAppHeader::GetAuthenticationKeyId() const{

    NS_LOG_FUNCTION (this << m_authenticationKeyId);
    return m_authenticationKeyId;
}

void
QKDAppHeader::SetAuthTag(std::string value){

    NS_LOG_FUNCTION (this << value << value.size());
    m_authTag = value;
}

std::string
QKDAppHeader::GetAuthTag() const{

    NS_LOG_FUNCTION (this << m_authTag << m_authTag.size());
    return m_authTag;
}

void
QKDAppHeader::SetEncrypted(uint32_t value){

    NS_LOG_FUNCTION (this << value);
    m_encryped = value;
}
uint32_t
QKDAppHeader::GetEncrypted() const{

    NS_LOG_FUNCTION (this << m_encryped);
    return(uint32_t) m_encryped;
}

void
QKDAppHeader::SetAuthenticated(uint32_t value){

    NS_LOG_FUNCTION (this << value);
    m_authenticated = value;
}
uint32_t
QKDAppHeader::GetAuthenticated() const{

    NS_LOG_FUNCTION (this << m_authenticated);
    return(uint32_t) m_authenticated;
}


} // namespace ns3

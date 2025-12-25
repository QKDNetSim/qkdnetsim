/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 * Author: Miralem Mehic <miralem.mehic@etf.unsa.ba>,
 *         Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 *         Oliver Mauhart <oliver.maurhart@ait.ac.at>
 */

#ifndef QKD_APP_HEADER_H
#define QKD_APP_HEADER_H

#include <queue>
#include <string>
#include "ns3/packet.h"
#include "ns3/header.h"
#include "ns3/object.h"

namespace ns3 {

/**
 * @ingroup qkd
 * @class QKDAppHeader
 * @brief QKD app packet header that carries info about used encryption, auth tag and other.
 *
 * @note
 *      0       4       8               16              24              32
 *      0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0
 *   0  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                            Length                             |
 *   4  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                            Msg-Id                             |
 *   8  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |   E   |   A   |
 *  16  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                       Encryption Key Id                       |
 *  20  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                     Authentication Key Id                     |
 *  24  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                             A-Tag ...                         |
 *  28  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                          ... A-Tag                            |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * with:
 *
 *      Length:         total size of packet, including the length field itself
 *      Msg-Id:         message number (inside a channel)
 *      E:              Type of used encryption cipher where value 0 means unencrypted packet
 *      A:              Type of used authentication algorithm where value 0 means non-authenticated packet
 *      E-KeyId:        Encryption Key Id
 *      A-KeyId:        Authentication Key Id
 *      A-Tag:          Authentication tag
 *
 */

class QKDAppHeader : public Header
{
    public:

        /**
        * @brief Constructor
        */
        QKDAppHeader ();

        /**
        * @brief Get the type ID.
        * @return the object TypeId
        */
        static TypeId GetTypeId ();
        /**
        * @brief Get the type ID.
        * @return the object TypeId
        */
        TypeId      GetInstanceTypeId () const override;

        void        Print (std::ostream &os) const override;
        bool        operator== (QKDAppHeader const & o) const;

        uint32_t    GetSerializedSize () const override;

        void        Serialize (Buffer::Iterator start) const override;
        uint32_t    Deserialize (Buffer::Iterator start) override;
        
        /**
        * @param authenticated Set the message length
        */
        void 		SetLength (uint32_t value);

        /**
        * @return Get the message length
        */
        uint32_t 	GetLength () const;

        /**
        * @param authenticated Set the message ID
        */
        void 		SetMessageId (uint32_t value);

        /**
        * @return Get the message ID
        */
        uint32_t 	GetMessageId () const;

        /**
        * @param authenticated Set the encryption flag
        */
        void 		SetEncrypted (uint32_t value);

        /**
        * @return Get the encryption flag
        */
        uint32_t  	GetEncrypted () const;

        /**
        * @param authenticated Set the authentication flag
        */
        void 		SetAuthenticated (uint32_t value);

        /**
        * @return Get the authentication flag
        */
        uint32_t 	GetAuthenticated () const;

        /**
        * @param keyID Set the encryption QKD Key ID
        */
        void 		SetEncryptionKeyId (std::string  value);

        /**
        * @return Get the encryption QKD Key ID
        */
        std::string GetEncryptionKeyId () const;

        /**
        * @param keyID Set the authentication QKD Key ID
        */
        void 		SetAuthenticationKeyId (std::string  keyID);

        /**
        * @return Get the authentication QKD Key ID
        */
        std::string GetAuthenticationKeyId () const;

        /**
        * @param keyID Set the authentication tag
        */
        void 		SetAuthTag (std::string value);

        /**
        * @param keyID Get the authentication tag
        */
        std::string GetAuthTag () const;

        /// Check that type if valid
        bool IsValid () const
        {
        return m_valid;
        }

    private:

        uint32_t        m_length;                   //!< message length field
        uint32_t        m_messageId;                //!< message id field

        uint8_t         m_encryped;                 //!< is packet encrypted or not
        uint8_t         m_authenticated;            //!< is packet authenticated or not

        std::string     m_encryptionKeyId;          //!< encryption key id
        std::string     m_authenticationKeyId;      //!< authentication key id
        std::string     m_authTag;                  //!< authentication tag of the packet

        bool            m_valid;                    //!< Is header valid or corrupted

    };


}
// namespace ns3

#endif /* QKD_APP_HEADER_H */



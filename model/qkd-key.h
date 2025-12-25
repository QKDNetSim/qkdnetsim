/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 *
 *
 * Author:  Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 *          Miralem Mehic <miralem.mehic@etf.unsa.ba>
 */
#ifndef QKD_KEY_H
#define QKD_KEY_H

#include <stdint.h>
#include <algorithm>
#include <stdint.h>

#include "ns3/packet.h"
#include "ns3/object.h"
#include "ns3/callback.h"
#include "ns3/assert.h"
#include "ns3/ptr.h"
#include "ns3/simulator.h"
#include <time.h>
#include "ns3/nstime.h"
#include "ns3/traced-callback.h"
#include "ns3/deprecated.h"
#include <string>
#include <iomanip>
#include <vector>
#include <bitset>
/*
#include <crypto++/iterhash.h>
#include <crypto++/secblock.h>
*/
namespace ns3 {

/**
 * @ingroup qkd
 * @brief The QKD key is an elementary class of QKDNetSim. It is used
 *  to describe the key that is established in the QKD process.

 *  @noteIn the QKD process, keys are stored as blocks.
 *  Later, some part of the block is taken and used for encryption,
 *  while others remain in the buffer. Operations regarding QKD
 *  Key management(merge, split and other) are under construction.
 *  Each QKDKey is identified using a unique 32 long character identifier.
 *  The key is also marked with the timestamp of its origin, its length,
 *  and the condition in which the key is located. QKDKey can be found
 *  in one of the following states:
 *      INIT - the call for the establishment of the key record is initiated
 *      READY - the key is successfully created and stored
 *      SERVED - the key is served for usage on request
 *      USED - the key is used for cryptographic operations(under construction)
 *      OBSOLETE - the key validity has expired(under construction)
 *      RESTORED - the key is restored for further usage(under construction)
 */
class QKDKey : public Object
{
    public:

        /**
         * @brief QKD Key States
         */
        enum QKDKeyState_e {
            INIT,
            READY,
            SERVED,
            USED,
            OBSOLETE,
            RESTORED,
            RESERVED
        };

        /**
        * @brief Get the TypeId
        *
        * @return The TypeId for this class
        */
        static TypeId GetTypeId();

        /**
        * @brief Create an empty QKD key of a key size
        */
        QKDKey();
        
        QKDKey(uint64_t keySize);

        /**
        * @brief Create an empty QKD key of a key size
        */
        QKDKey(std::string keyId, uint64_t keyIdnum, uint64_t keySize);

        QKDKey(std::string keyId, uint64_t keyIdnum, std::string key);

        QKDKey(std::string keyId, std::string key); //KMS key generation!

        std::string        GetId() const;
        void               SetId(std::string);

        /**
        *   @brief Help function - Copy key
        *   @return Ptr<QKDKey>
        */
        Ptr<QKDKey>     Copy() const;

        /**
        * Return key in byte* which is necessery for encryption or authentication
        * Convert key from std::String to byte*
        * @return byte*
        */
        uint8_t *       GetKey();

        /**
         * @brief Get QKD key
         * @return string key
         */
        std::string     GetKeyString();

        void            SetValue(std::string);

        /**
        * Return key in bits which is necessery for encryption or authentication
        * @return string
        */
        std::string GetKeyBinary();

        /**
        *   @brief Get the size of the key
        *   @return uint64_t
        */
        uint64_t        GetSize() const;

        /**
         * @brief Get the size of the key in bits
         * @return uint64_t
         */
        uint64_t        GetSizeInBits() const;

        /**
        *   @brief Set the size of the key
        *   @param uint64_t
        */
        void            SetSize(uint64_t);

        void            MarkReady();

        void            MarkUsed();

        void            MarkRestored();

        void            MarkServed();

        void            MarkReserved();

        /**
        *   @brief Return the raw key in std::string format and switch to SERVED state
        *   @return std::string
        */
        std::string     ConsumeKeyString();

        /**
        *   @brief Return the raw key in std::string format
        *   @return std::string
        */
        std::string     ToString();

        /**
         * @brief Return random string
         * @param len length of string to generate
         * @return string random string
         */
        std::string     GenerateRandomString(const int len);

        /**
        * Returns the current state of the key.
        * @return The current state of the key.
        */
        QKDKeyState_e GetState() const;

        /**
        * Returns the current state of the key in string format.
        * @return The current state of the key in string format.
        */
        std::string GetStateString() const;

        /**
        * Returns the given state in string format.
        * @param state An arbitrary state of a key.
        * @return The given state equivalently expressed in string format.
        */
        static std::string GetStateString(QKDKeyState_e state);

        /**
        * Change the state of the key. Fires the `StateTransition` trace source.
        * @param state The new state.
        */
        void SwitchToState(QKDKeyState_e state);

        /**
        * Get timestamp of the key
        * @return Time key timestamp
        */
        Time GetKeyTimestamp();

        /**
        * Save details about the QKD module that generated key
        * @param QKDModuleId.
        */
        void SetModuleId(std::string);

        /**
        * Returns the id of the QKD module that generated key
        * @return The id of the QKD module that generated key
        */
        std::string GetModuleId();

        /// The `StateTransition` trace source.
        ns3::TracedCallback<const std::string &, const std::string &> m_stateTransitionTrace;

    protected:
        std::string         m_id;       //<! QKDKeyID
        std::string         m_key;  //<! QKDKey raw value
        uint64_t            m_size; //<! QKDKey size
    private:
        uint64_t            m_internalID;
        static uint64_t     m_globalUid; //<! Global static QKDKeyID
        Time                m_timestamp; //<! QKDKey generation timestamp
        QKDKeyState_e       m_state; //!< state of the key
        std::string         m_moduleId; //!< id of QKD module that generated key

    };

} // namespace ns3

#endif /* QKD_KEY_H */

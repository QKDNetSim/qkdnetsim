/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 *
 * Authors: Miralem Mehic <miralem.mehic@etf.unsa.ba>
 *          Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 */

#ifndef SBUFFER_H
#define SBUFFER_H

#include <queue>
#include "ns3/packet.h"
#include "ns3/object.h"
#include "ns3/ipv4-header.h"
#include "ns3/traced-value.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/event-id.h"
#include "qkd-key.h"
#include "ns3/node.h"
#include <vector>
#include <map>
#include <unordered_map>
#include "q-buffer.h"

namespace ns3 {

  /**
   * @defgroup qkd Quantum Key Distribution(QKD)
   * This section documents the API of the ns-3 QKD Network Simulation Module(QKDNetSim).
   *
   * Be sure to read the manual BEFORE going down to the API.
   */

  /**
   * @ingroup qkd
   * @class SBuffer
   * @brief Sbuffer is a working buffer from which keys are served.
   *
   * @note  Each QBuffer has a pair of SBuffers, one dedicated for the
   *        outbound(enc) and other for the inbound(dec) connection.
   *
   * The SBuffer is filled with certain amount of key material from QBuffer,
   * and is accessed to serve cryptographic application request.
   *
   */
  class SBuffer: public QBuffer {
    public:

      /**
       * @brief S-Buffer Type
      */
      enum Type {
        LOCAL_SBUFFER,
        RELAY_SBUFFER,
        STREAM_SBUFFER,
        E2E_SESSION,
        LOCAL_SESSION
      };

      /**
       * @brief Get the TypeId
       * @return The TypeId for this class
       */
      static TypeId GetTypeId();

      /**
       * @brief QBuffer constructor
       */
      SBuffer();

      /**
       * @brief SBuffer constructor
       * @param type SBuffer type
       * @param size SBuffer default key size
       */
      SBuffer(SBuffer::Type type, uint32_t size);

      /**
       * @brief QBuffer destructor
       */
      ~SBuffer() override;

      virtual void DoInitialize() override;

      /**
       * @brief Set s-buffer type
       * @param type the s-buffer type
       */
      void SetType(Type type);

      /**
       * @brief Get s-buffer type
       * @return SBufferType s-buffer type
       */
      Type GetType();

      /**
       * @brief Get servable key count
       * @return uint32_t servable key count
       *
       * Get number of keys from s-buffer that are in READY state
       */
      uint32_t GetSKeyCount();

      /**
       * @brief Get servable bit count
       * @return uint32_t servable bit count
       *
       * Get amount of key material that is in READY state
       */
      uint32_t GetSBitCount();

      /**
       * @brief Get number of keys that are in default size
       * @param uint32_t a target number of required keys
       * @return uint32_t number of key in default size
       *
       * This function is important when cosidereing the RELAY operation.
       * The RELAY procedure can not make desicion based on available key count,
       * because it does not include the transform operation in parallel.
       */
      uint32_t GetDefaultKeyCount(uint32_t number = 0);

      /**
       * @brief Get key candidate
       * @param size target key size
       * @return Ptr on QKD key
       *
       * If the input size is equal to zero the function returns a random key
       * from s-buffer. Otherwise, the funtion returns a key of the requested size.
       * If such key is not available, larger key is modified and a portion of it
       * is returned from the function, while remaining portion remains in s-buffer.
       * Remaining key is marked as INIT, and is not servable until it gets in sync.
       * This function is always called on s-buffers("enc").
       */
      Ptr<QKDKey> GetTransformCandidate(uint32_t size);

      /**
       * @brief Get portion of key
       * @param keyId key identifier
       * @param size portion size
       * @return Ptr on QKD key
       *
       * This function is called on s-buffer("dec"), as a counterpart to conditioned
       * GetTransformCandidate function. It returns a portion of key, identified with
       * keyId. In this case, the remaining portion is s-buffer remains in READY state.
       */
      Ptr<QKDKey> GetHalfKey(std::string keyId, uint32_t size);

      /**
       * @brief store key in SBuffer
       * @param Ptr<QKey> key
       * @return true if the key is added to the storage; False otherwise
       */
      bool StoreKey(Ptr <QKDKey> key){
        return StoreKey(key, false);
      }

      /**
       * @brief get amount of stored key material in bits
       * @return int32_t amount of stored key material in bits
       */
      uint32_t GetBitCount() const override
      {
        return m_currentKeyBit;
      }

      /**
       * @brief store key in QBuffer
       * @param Ptr<QKey> key
       * @param bool fireTraces
       * @return true if the key is added to the storage; False otherwise
       */
      bool StoreKey(Ptr <QKDKey> key, bool fireTraces) override;


      /**
       * @brief Get key with given size
       * @param size size of the key
       * @return Ptr on QKD key
       *
       * For relay purposes. We want to relay keys in default sizes!
       * However, the LOCAL_SBUFFER contains keys in vaious sizes!
       * Therefore, it is important to assure that we are getting the
       * key which is in given size!
       */
      Ptr<QKDKey> GetKey(uint32_t size);

      /**
       * @brief Store supply key
       * @param key key
       */
      void StoreSupplyKey(Ptr<QKDKey> key);

      /**
       * @brief Get supply key
       * @param keyId key identifier
       */
      Ptr<QKDKey> GetSupplyKey(std::string keyId);

      /**
       * @brief Mark key
       * @param keyId key identifier
       * @param state new state
       */
      void MarkKey(
        std::string keyId,
        QKDKey::QKDKeyState_e state
      );

      /**
       * @brief Returns key chunk with lowest index.
       * @return QKDKey secret key chunk
       */
      Ptr<QKDKey> GetStreamKey();

      /**
       * @brief Insert key to key stream session
       * @param key secret key
       *
       * An input key may be reformated to create multiple key_chunks
       * based on QoS criteria.
       */
      void InsertKeyToStreamSession(Ptr<QKDKey> key);

      uint32_t GetStreamKeyCount();

      uint32_t GetStreamIndex();

      uint32_t GetNextIndex();

      /**
       * @brief Assign a lifetime to a key
       * @param keyId key identifier
       */
      void SetKeyLifetime(std::string keyId);

      void SetRelayState(bool relayActive);

      bool IsRelayActive();
  

      /**
       * @brief get key from QBuffer
       * @param keyID key identifier
       * @return Ptr to the key
       */
      Ptr<QKDKey> GetKey(std::string keyID = "", bool fireTraces = true) override;

      /**
       * @brief Log key consumption
       * @param diffValue key consumption in bits
       * @param positive increment or negative
       *
       * It is utilized from derived class S-Buffer when a portion of key is
       * obtained from m_keys, to account for this key usage.
       */
      void LogUpdate(uint32_t diffValue, bool positive) override;
 
    private:
      
      SBuffer::Type    m_type; //!< S-Buffer type

      uint32_t    m_currentStreamIndex; //!< The last index when the S-Buffer is used for key stream sessions.

      uint32_t    m_notReadyKeyCount; //!< Number of keys stored which are not in READY state

      uint32_t    m_notReadyBitCount; //!< Amount of key material stored that are not in READY state

      bool        m_relayActive; //!< The state of S-Buffer will not trigger relay if relay is active

      std::map<uint32_t, Ptr<QKDKey> >      m_stream_keys; //!< Key stream session

      std::map<std::string, Ptr<QKDKey> >   m_supply_keys; //!< Created keys which are ready for supply to crypto applications

      uint32_t m_minKeyBitSBufferDefault;         //<! The minimal amount of key material in QKD key storage (SBuffer default)

      uint32_t m_maxKeyBitSBufferDefault;         //<! The maximal amount of key material in QKD key storage (SBuffer default)
 
      uint32_t m_thresholdKeyBitSBufferDefault;   //<! The threshold amount of key material in QKD key storage (SBuffer default)

      uint32_t m_defaultKeySizeSBufferDefault;    //<! Default key size for this QKD Buffer (SBuffer default)

  };
}

#endif /* SBUFFER_H */

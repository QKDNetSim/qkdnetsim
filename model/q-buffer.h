/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 *
 * Authors: Miralem Mehic <miralem.mehic@etf.unsa.ba>
 *          Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 */

#ifndef QBUFFER_H
#define QBUFFER_H

#include <queue>
#include "ns3/packet.h"
#include "ns3/object.h"
#include "ns3/ipv4-header.h"
#include "ns3/traced-value.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/event-id.h"
#include "qkd-key.h"
#include "ns3/node.h"
#include <map>
#include <vector>
#include <unordered_map>

namespace ns3 {

  /**
   * @defgroup qkd Quantum Key Distribution(QKD)
   * This section documents the API of the ns-3 QKD Network Simulation Module(QKDNetSim).
   *
   * Be sure to read the manual BEFORE going down to the API.
   */

  /**
   * @ingroup qkd
   * @class QBuffer
   * @brief Qbuffer is a secure storage for QKD keys. QBuffer is assigned
   * for each connection using QKDControl on each peer.
   *
   * @note The two QKD nodes that establish one or more logical QKD connections
   * will implement QBuffer on each side which will be assigned by QKDControl entity.
   * The purpose of the QBuffer is to collect enough key material for its
   * subsequent use for cryptographic purposes. Due to the limited charging key
   * rate of QKD protocols, QKD post-processing applications strive to save keys in
   * QBuffers to generate as many keys in advance. However, warehouses have a
   * limited capacity that is defined with a maximum value. They also have a minimum
   * capacity that describes the minimum amount of key required to establish initial
   * post-processing operations. Also, the buffer implements a threshold value that
   * may indicate that the necessary actions are being taken before the buffer
   * is completely emptied.
   *
   * It is important to note that a QKD link has full application only when there are
   * enough keys to apply for cryptographic purposes. Therefore, constant monitoring
   * of the state of the QKD buffer is necessary to identify the statuses in which the
   * QBuffer can be found:
   *    READY - Amount of key is larger than threshold Mthr
   *    WARNING  - Amount of key is lower then threshold and the amount of keys
   *    in the buffer is decreasing
   *    CHARGING - Amount of key is lower then threshold and the amount of keys
   *    in the buffer is increasing
   *    EMPTY - The amount of keys in the buffer is lower than the minimal value
   *
   *    The states of the QBuffer do not directly affect the communication, but it
   *    can be used for  easier prioritization of traffic depending on the state of
   *    the buffer. For example, in EMPTY state, QKD post-processing applications used
   *    to establish a new key material should have the highest priority in traffic processing.
   */
  class QBuffer: public Object {
    public:

      static const uint32_t QSTATUS_READY = 0; //!< QStatus READY
      static const uint32_t QSTATUS_WARNING = 1; //!< QStatus WARNING
      static const uint32_t QSTATUS_CHARGING = 2; //!< QStatus CHARGING
      static const uint32_t QSTATUS_EMPTY = 3; //!< QStatus EMPTY

      struct data {
        uint32_t value;
        uint32_t position;
      };

      /**
       * @brief Get the TypeId
       * @return The TypeId for this class
       */
      static TypeId GetTypeId();

      /**
       * @brief QBuffer constructor
       */
      QBuffer();

      //@ToDo add new constructors to avoid calling for Init!

      /**
       * @brief QBuffer destructor
       */
      ~QBuffer() override;

      /**
       * @brief initialize QBuffer
       * @param dstKmNodeId remote key manager node identifier
       * @param Mmin minimum amount(bits) of key material QBuffer should maintain
       * @param Mthr thresold amount(bits) of key material
       * @param Mmax maximum amount(bits) of key material QBuffer can store
       * @param Mcurr current amount(bits) of key material QBuffer maintain
       * @param defaultKeySize default size of stored keys
       */
      void Init(
        uint32_t dstKmNodeId,
        uint32_t Mmin,
        uint32_t Mthr,
        uint32_t Mmax,
        uint32_t Mcurrent,
        uint32_t defaultKeySize
      );

      /**
       * @brief create QKD buffer configuration
       * @param Mmin minimum amount(bits) of key material QKD buffer should maintain
       * @param Mmax maximum amount(bits) of key material QKD buffer can store
       * @param Mthr thresold amount(bits) of key material
       * @param Mcurr current amount(bits) of key material QKD buffer maintain
       * @param defaultKeySize default size of stored keys
       */
      virtual void Configure(
        uint32_t Mmin,
        uint32_t Mthr,
        uint32_t Mmax,
        uint32_t Mcurrent,
        uint32_t defaultKeySize
      );

      /**
       * @brief destroy a QBuffer
       *
       * This is the pre-destructor function of the QBuffer.
       */
      void Dispose();

      /**
       * @brief store key in QBuffer
       * @param Ptr<QKey> key
       * @return true if the key is added to the storage; False otherwise
       */
      virtual bool StoreKey(Ptr <QKDKey> key = nullptr, bool fireTraces = true);

      /**
       * @brief get key from QBuffer
       * @param keyID key identifier
       * @return Ptr to the key
       */
      virtual Ptr<QKDKey> GetKey(std::string keyID = "", bool fireTraces = true);

      /**
       * @brief get number of stored keys
       * @return int32_t key count
       */
      uint32_t GetKeyCount() const;

      /**
       * @brief get amount of stored key material in bits
       * @return int32_t amount of stored key material in bits
       */
      virtual uint32_t GetBitCount() const
      {
        return m_currentKeyBit;
      }

      uint64_t GetMinKeySizeBit() const
      {
        return m_minKeyBit;
      }

      uint64_t  GetMaxKeySizeBit() const
      {
        return m_maxKeyBit;
      }

      void SetDescription(std::string val)
      {
        m_description = val;
      }

      std::string GetDescription() const
      {
        return m_description;
      }


      /**
       *   @brief Get default size of keys stored in QBuffer
       *   @return int32_t default key size
       */
      uint32_t GetKeySize() const;

      /**
       * @brief Log key consumption
       * @param diffValue key consumption in bits
       * @param positive increment or negative
       *
       * It is utilized from derived class S-Buffer when a portion of key is
       * obtained from m_keys, to account for this key usage.
       */
      virtual void LogUpdate(uint32_t diffValue, bool positive);

      /**
       *   Fetch the current state of the QBuffer
       *
       *   QBuffer can be in one of the following states:
       *   – READY—when Mcur(t) ≥ Mthr ,
       *   – WARNING—when Mthr > Mcur(t) > Mmin and the previous state was READY,
       *   – CHARGING—when Mthr > Mcur(t) and the previous state was EMPTY,
       *   – EMTPY—when Mmin ≥ Mcur(t) and the previous state was WARNING or CHARGING
       */
      uint32_t GetState();

      /**
       *   Fetch the previous state of the QBuffer. Help function used for ploting graphs
       *
       *   @return int32_t integer representation of QKD Storage state
       */
      uint32_t GetPreviousState();

      /**
       *   Update the state after some changes on the QBuffer
       */
      void CheckState();

      /**
       *   Help function used for ploting graphs
       */
      void KeyCalculation();

      /*
       *   Return time difference between the current time and time at which
       *   last key charging process finished
       *
       *   @return int64_t deltaTime
       */
      int64_t GetDeltaTime();

      /**
       *   Return time value about the time duration of last key charging process
       *
       *   @return int64_t lastKeyChargingTimeDuration
       */
      int64_t GetLastKeyChargingTimeDuration();

      /**
       *   Return average duration of key charging process in the long run
       *
       *   @return double average duration of key charging period
       */
      double GetAverageKeyChargingTimePeriod();

      /**
       *   Return the maximal number of values which are used
       *   for calculation of average key charging time period
       *
       *   @return int32_t maximal number of recorded key charging time periods; default value 5
       */
      uint32_t GetMaxNumberOfRecordedKeyChargingTimePeriods() const;

      /**
       *   Help function used for ploting graphs; Previous - before latest change
       *
       *   @return int32_t integer representation of the previous QKD storage key material;
       */
      uint32_t GetMCurrentPrevious() const;

      uint32_t GetMmin() const;

      uint32_t GetMmax() const;

      /**
       *   Get the threshold value of QKD storage
       *   The threshold value Mthr(t) at the time of measurement t is used to indicate the
       *   state of QKD buffer where it holds that Mthr(t) ≤ Mmax .
       *
       *   @return int32_t integer representation of the threshold value of the QKD storage
       */
      uint32_t GetMthr() const;

      /**
       *   Set the threshold value of QKD storage
       *
       *   @param int32_t integer set the threshold value of the QKD storage
       */
      void SetMthr(uint32_t thr);

      /**
       * Set default key size
       *
       * @param size key size
       */
      void SetKeySize(uint32_t size);

      /**
       *   Help function for total graph ploting
       */
      void InitTotalGraph() const;

      /**
       *   Get the QKD Storage/Buffer ID
       *
       *   @return int32_t buffer unique ID
       */
      uint32_t GetId() const;

      /**
       *   Assign operator
       *
       *   @param o Other QBuffer
       *   @return True if buffers are identical; False otherwise
       */
      bool operator ==(QBuffer const & o) const;

      /**
       *   Set the index of the buffer per local node
       *
       *   @param int32_t index
       */
      void SetIndex(uint32_t);

      /**
       *   Get the index of the buffer per local node
       *
       *   @return int32_t index
       */
      uint32_t GetIndex();

      /**
       *   Get the index of the remote node id
       *
       *   @return int32_t index
       */
      uint32_t GetRemoteNodeId() const 
      {
        return m_dstKmNodeId;
      }

      /**
       *   Set the index of the remote node id
       *
       *   @param int32_t value
       */
      void SetRemoteNodeId(uint32_t value)
      {
        m_dstKmNodeId = value;
      }

      void SetSrcKMSApplicationIndex(uint32_t& value)
      {
        m_srcKMSApplicationIndex = value;
      }

      uint32_t GetSrcKMSApplicationIndex() const 
      {
        return m_srcKMSApplicationIndex;
      }


    protected:

      /**
       * @brief destroy key from the QBuffer
       * @param keyId key identifier
       * @return bool function status
       */
      bool DestroyKey(std::string keyId);

      uint32_t          m_dstKmNodeId;    //<! Remote KM node ID

      //std::string       m_id;             //<! @toDo UUID id for each Q-Buffer

      uint32_t          m_bufferID; //!< unique buffer ID

      static uint32_t   nBuffers; //!< number of created buffers - static value

      std::unordered_map< std::string, Ptr <QKDKey> > m_keys; //!< key database

      uint32_t m_srcKMSApplicationIndex;

      std::string m_description;

      /**
       *   ID of the next key to be generated
       */
      uint32_t m_nextKeyID;

      /**
       *   Help value used for graph ploting
       */
      uint32_t m_noEntry;

      /**
       *   Help value used for graph ploting
       */
      uint32_t m_period;

      /**
       *   Help value used for graph ploting
       */
      uint32_t m_noAddNewValue;

      /**
       *   Help value used for graph ploting and calculation of average
       *   post-processing duration
       */
      uint32_t m_bitsChargedInTimePeriod;

      /**
       *   Help value used for detection of average key usage
       */
      uint32_t m_bitsUsedInTimePeriod;

      /**
       *   The period of time(in seconds) to calculate average amount of the key in the buffer
       *   Default value 5 - used in routing protocols for detection of information freshness
       */
      uint32_t m_recalculateTimePeriod;

      /**
       *   Help vector used for graph ploting
       */
      std::vector < struct QBuffer::data > m_previousValues;

      double m_c;                   //!< average amount of key in the buffer during the recalculate time period

      bool m_isRisingCurve;         //!< whether curve on graph is rising or not

      uint32_t m_previousStatus;    //<! Holds previous status; important for deciding about further status that can be selected

      uint32_t m_minKeyBit;         //<! The minimal amount of key material in QKD key storage

      uint32_t m_maxKeyBit;         //<! The maximal amount of key material in QKD key storage

      uint32_t m_maxValueGraph;     //<! The maximal value of the graph

      uint32_t m_thresholdKeyBit;   //<! The threshold amount of key material in QKD key storage

      uint32_t m_defaultKeySize;    //<! Default key size for this QKD Buffer

      TracedCallback < uint32_t > m_thresholdKeyBitChangeTrace; 

      /**
       * The current amount of key material in QKD key storage
       */
      uint32_t m_currentKeyBit;

      /**
       * The previous value of current amount of key material in QKD key storage
       */
      uint32_t m_currentKeyBitPrevious;

      /**
       * The timestamp of last key charging(when the new key material was added)
       */
      int64_t m_lastKeyChargingTimeStamp;

      /**
       * The timestamp of last key usage
       */
      int64_t m_lastKeyChargingTimeDuration;

      /**
       *   The maximal number of values which are used for stored for calculation
       *   of average key charging time period
       */
      uint32_t m_maxNumberOfRecordedKeyChargingTimePeriods;

      /**
       *   Vector of durations of several last charging time periods
       */
      std::vector < int64_t > m_chargingTimePeriods;

      /**
       * The state of the Net Device transmit state machine.
       */
      uint32_t m_status;

      /**
       *   The average duration of key charging time period
       */
      double m_averageKeyChargingTimePeriod;

      EventId m_calculateRoutingMetric;

      TracedCallback < Ptr<QKDKey> > m_newKeyAddedTrace;
      TracedCallback < Ptr<QKDKey> > m_keyServedTrace;

      TracedCallback < uint32_t > m_currentKeyBitChangeTrace;
      TracedCallback < uint32_t > m_currentKeyBitIncreaseTrace;
      TracedCallback < uint32_t > m_currentKeyBitDecreaseTrace;
      TracedCallback < uint32_t > m_StatusChangeTrace;
      TracedCallback < double > m_CMetricChangeTrace;
      TracedCallback < double > m_averageKeyChargingTimePeriodTrace;

      uint32_t m_srcNodeBufferListIndex;

  };
}

#endif /* QBUFFER_H */

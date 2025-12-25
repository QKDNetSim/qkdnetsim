/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 *
 * Authors: Miralem Mehic <miralem.mehic@etf.unsa.ba>
 *          Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 */


#include <algorithm>
#include <numeric>
#include <random>
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/log.h"
#include "ns3/boolean.h"
#include "ns3/double.h"
#include "ns3/uinteger.h"

#include "q-buffer.h"

namespace ns3 {

    NS_LOG_COMPONENT_DEFINE("QBuffer");

    NS_OBJECT_ENSURE_REGISTERED(QBuffer);

    TypeId
    QBuffer::GetTypeId()
    {
      static TypeId tid = TypeId("ns3::QBuffer")
        .SetParent<Object>()
        .AddConstructor<QBuffer>()
        .AddAttribute("Minimal",
                       "The minimal amount of key material in QKD storage(bits)",
                       UintegerValue(1000000), //1Mb
                       MakeUintegerAccessor(&QBuffer::m_minKeyBit),
                       MakeUintegerChecker<uint32_t>())
        .AddAttribute("Maximal",
                       "The maximal amount of key material in QKD storage(bits)",
                       UintegerValue(1000000000), //1Gb
                       MakeUintegerAccessor(&QBuffer::m_maxKeyBit),
                       MakeUintegerChecker<uint32_t>())
        .AddAttribute("Threshold",
                       "The threshold amount of key material in QKD(bits)",
                       UintegerValue(2000000), //2Mb
                       MakeUintegerAccessor(&QBuffer::m_thresholdKeyBit),
                       MakeUintegerChecker<uint32_t>())

        .AddAttribute("CalculationTimePeriod",
                       "The period of time(in seconds) to calculate average amount of the key in the buffer",
                       UintegerValue(5), // in seconds
                       MakeUintegerAccessor(&QBuffer::m_recalculateTimePeriod),
                       MakeUintegerChecker<uint32_t>())
        .AddAttribute("MaxNumberOfRecordedKeyCharingTimePeriods",
                       "The maximal number of values which are stored for calculation of average key charging time period",
                       UintegerValue(5),
                       MakeUintegerAccessor(&QBuffer::m_maxNumberOfRecordedKeyChargingTimePeriods),
                       MakeUintegerChecker<uint32_t>())
        .AddAttribute("DefaultKeySize",
                       "The default key size",
                       UintegerValue(512),
                       MakeUintegerAccessor(&QBuffer::m_defaultKeySize),
                       MakeUintegerChecker<uint32_t>())

        .AddTraceSource("ThresholdChange",
                         "The change trace for threshold amount of key material in QKD storage",
                         MakeTraceSourceAccessor(&QBuffer::m_thresholdKeyBitChangeTrace),
                         "ns3::QBuffer::ThresholdChange")

        .AddTraceSource("CurrentChange",
                        "The change trace for current amount of key material in QKD storage",
                         MakeTraceSourceAccessor(&QBuffer::m_currentKeyBitChangeTrace),
                         "ns3::QBuffer::CurrentChange")

        .AddTraceSource("CurrentIncrease",
                        "The increase trace for current amount of key material in QKD storage - TOTAL GRAPH",
                         MakeTraceSourceAccessor(&QBuffer::m_currentKeyBitIncreaseTrace),
                         "ns3::QBuffer::CurrentIncrease")
        .AddTraceSource("CurrentDecrease",
                        "The decrease trace for current amount of key material in QKD storage - TOTAL GRAPH",
                         MakeTraceSourceAccessor(&QBuffer::m_currentKeyBitDecreaseTrace),
                         "ns3::QBuffer::CurrentDecrease")

        .AddTraceSource("StatusChange",
                        "The change trace for current status of QKD storage",
                         MakeTraceSourceAccessor(&QBuffer::m_StatusChangeTrace),
                         "ns3::QBuffer::StatusChange")
        .AddTraceSource("CMetricChange",
                        "The change trace for current status of QKD storage",
                         MakeTraceSourceAccessor(&QBuffer::m_CMetricChangeTrace),
                         "ns3::QBuffer::CMetricChange")
        .AddTraceSource("AverageKeyChargingTimePeriod",
                        "The change trace for current status of QKD storage",
                         MakeTraceSourceAccessor(&QBuffer::m_averageKeyChargingTimePeriodTrace),
                         "ns3::QBuffer::AverageKeyChargingTimePeriod")

        .AddTraceSource("NewKeyAdded",
                        "The trace to monitor adding new key material to the buffer",
                         MakeTraceSourceAccessor(&QBuffer::m_newKeyAddedTrace),
                         "ns3::QBuffer::AverageKeyChargingTimePeriod")
        .AddTraceSource("KeyServed", //toDo: this should be monitored maybe on KMS! Due to transform functions!
                        "The threce to monitor key usage",
                         MakeTraceSourceAccessor(&QBuffer::m_keyServedTrace),
                         "ns3::QBuffer::AverageKeyChargingTimePeriod")
        ;
      return tid;
    }

    QBuffer::QBuffer()
    {
        NS_LOG_FUNCTION(this);
    }

    void
    QBuffer::Configure(
        uint32_t Mmin,
        uint32_t Mthr,
        uint32_t Mmax,
        uint32_t Mcurr,
        uint32_t defaultKeySize
    )
    {
        NS_LOG_FUNCTION(this);
        m_minKeyBit = Mmin;
        m_thresholdKeyBit = Mthr;
        m_maxKeyBit = Mmax;
        m_currentKeyBit = Mcurr;
        m_defaultKeySize = defaultKeySize;
    }

    void
    QBuffer::Init(
        uint32_t dstKmNodeId,
        uint32_t Mmin,
        uint32_t Mthr,
        uint32_t Mmax,
        uint32_t Mcurrent,
        uint32_t defaultKeySize
    )
    {
        NS_LOG_FUNCTION(this
            << "\nDestination KM Node Id:" << dstKmNodeId
            << "\nMmin:" << Mmin << "\nMthr:" << Mthr
            << "\nMmax:" << Mmax << "\nMcurr:" << Mcurrent
            << "\nDefault key size:" << defaultKeySize
        );
        m_dstKmNodeId = dstKmNodeId;
        m_minKeyBit = Mmin;
        m_thresholdKeyBit = Mthr;
        m_maxKeyBit = Mmax;
        m_currentKeyBit = Mcurrent;
        m_defaultKeySize = defaultKeySize;

        m_bufferID = ++nBuffers;
        m_currentKeyBitPrevious = 0;
        m_noEntry = 0;
        m_period = 5;
        m_noAddNewValue = 0;
        m_lastKeyChargingTimeDuration = 0;

        m_bitsChargedInTimePeriod = 0;
        m_bitsUsedInTimePeriod = 0;
        m_c = 0;
        m_lastKeyChargingTimeStamp = 0;
        m_previousStatus = 0; 
        CheckState();
    }

    uint32_t QBuffer::nBuffers = 0;


    QBuffer::~QBuffer()
    {
        NS_LOG_FUNCTION(this);
        m_keys.clear();
    }

    void
    QBuffer::Dispose()
    {
        NS_LOG_FUNCTION(this);
        Simulator::Cancel(m_calculateRoutingMetric);
    }

    uint32_t
    QBuffer::GetKeySize() const
    {
        return m_defaultKeySize;
    }

    bool compareByData(const QBuffer::data &a, const QBuffer::data &b)
    {
        return a.value > b.value;
    }

    void
    QBuffer::KeyCalculation()
    {
        NS_LOG_FUNCTION(this);
        m_currentKeyBitPrevious = m_currentKeyBit;

        struct QBuffer::data q;
        q.value = m_currentKeyBit;
        q.position = m_noEntry;

        while( m_previousValues.size() > m_period )
            m_previousValues.pop_back();

        m_previousValues.insert( m_previousValues.begin() ,q);

        //sort elements in descending order, first element has the maximum value
        std::sort(m_previousValues.begin(), m_previousValues.end(), compareByData);


        /*
        *   If maximal value is on the current location then it means that the current value is the highest in the period => function is rising
        *   Otherwise, function is going down
        */
        m_isRisingCurve =(m_previousValues[0].position == m_noEntry);
        CheckState();

        m_noEntry++;
    }

    void
    QBuffer::LogUpdate(uint32_t diffValue, bool positive)
    {
        NS_LOG_FUNCTION(this << m_currentKeyBit << diffValue << positive);

        ///////////////////////////////// TEMP TEMP TEMP /////////////////////////////////
        // Collect all keys in READY state
        /*
        NS_LOG_FUNCTION(this << "m_keys.size(): " << m_keys.size()); 
        uint32_t totalReadyKeyCount = 0; 
        for (auto it = m_keys.begin(); it != m_keys.end(); ++it) {
            if (it->second->GetState() == QKDKey::READY) { 
                totalReadyKeyCount += it->second->GetSizeInBits();
                NS_LOG_FUNCTION(this << "id:" << it->second->GetId() << "\t size:" << it->second->GetSizeInBits());
            }
        }
        NS_LOG_FUNCTION(this << "m_currentKeyBit: " << m_currentKeyBit);
        NS_LOG_FUNCTION(this << "totalReadyKeyCount: " << totalReadyKeyCount);
        */
        ///////////////////////////////// TEMP TEMP TEMP /////////////////////////////////



        if(positive)
        {
            m_currentKeyBit += diffValue;
            m_currentKeyBitChangeTrace(m_currentKeyBit);
            m_bitsUsedInTimePeriod += diffValue;
        }else{
            m_currentKeyBit -= diffValue;
            m_currentKeyBitChangeTrace(m_currentKeyBit);
            m_bitsUsedInTimePeriod -= diffValue;
        }

        NS_LOG_FUNCTION(this << "m_currentKeyBit: " << m_currentKeyBit);
        CheckState();
    }
    

    uint32_t
    QBuffer::GetMmin() const {
        return m_minKeyBit;
    }

    uint32_t
    QBuffer::GetMmax() const {
        return m_maxKeyBit;
    }

    uint32_t
    QBuffer::GetKeyCount() const
    {
        return m_keys.size();
    }
 
    bool
    QBuffer::StoreKey(Ptr<QKDKey> key, bool fireTraces)
    {
        NS_ASSERT(!key->GetId().empty()); //Unknown bug! 

        NS_LOG_FUNCTION(this
            << "\nKey ID:\t" << key->GetId()
            << "\nKey Size:\t" << key->GetSizeInBits()
            << "\nKey Value:\t" << key->ToString() 
            << "\nGetBitCount():\t" << GetBitCount()
        );
 
        if(GetBitCount() + key->GetSizeInBits() > GetMmax()){
            NS_LOG_FUNCTION(this << "Buffer is full! Not able to add new "
                << key->GetSizeInBits() << "bits, since the current is "
                << GetBitCount() << " and max is " << GetMmax()
            );
            m_currentKeyBitChangeTrace(m_currentKeyBit);
            m_currentKeyBitIncreaseTrace(0); 
            return false;
        }

        m_keys.insert( std::make_pair(  key->GetId() ,  key) );
        NS_LOG_FUNCTION(this << "Key" << key->GetId() << "added to QBuffer");

        if(fireTraces){
            LogUpdate(key->GetSizeInBits(), true);
            //Fire total graph traces
            m_currentKeyBitIncreaseTrace(key->GetSizeInBits());
            
            
            /*
            * First CALCULATE AVERAGE TIME PERIOD OF KEY CHARGING VALUE
            */
            if(!m_chargingTimePeriods.empty()){
              m_averageKeyChargingTimePeriod = accumulate(
                m_chargingTimePeriods.begin(),
                m_chargingTimePeriods.end(), 0.0
              ) / m_chargingTimePeriods.size();
            }else
              m_averageKeyChargingTimePeriod = 0;

            m_averageKeyChargingTimePeriodTrace(m_averageKeyChargingTimePeriod);
            NS_LOG_DEBUG(this << " m_averageKeyChargingTimePeriod: " << m_averageKeyChargingTimePeriod );
            NS_LOG_DEBUG(this << " m_chargingTimePeriods.size(): " << m_chargingTimePeriods.size() );

            /**
            * Second, add new value to vector of previous values
            */
            if(!m_chargingTimePeriods.empty() && m_maxNumberOfRecordedKeyChargingTimePeriods){
                while( m_chargingTimePeriods.size() > m_maxNumberOfRecordedKeyChargingTimePeriods ){
                    m_chargingTimePeriods.pop_back();
                }
            }

            int64_t currentTime = Simulator::Now().GetMilliSeconds();
            int64_t tempPeriod = currentTime - m_lastKeyChargingTimeStamp;
            m_chargingTimePeriods.insert( m_chargingTimePeriods.begin(), tempPeriod );
            m_lastKeyChargingTimeDuration = tempPeriod;
            m_lastKeyChargingTimeStamp = currentTime;
            NS_LOG_DEBUG(this << " m_lastKeyChargingTimeStamp: " << m_lastKeyChargingTimeStamp );
            NS_LOG_DEBUG(this << " m_lastKeyChargingTimeDuration: " << m_lastKeyChargingTimeDuration );

            //////////////////////////////////////////////////////////////////////////////////

            m_period = m_noEntry - m_noAddNewValue;
            m_noAddNewValue = m_noEntry;
            m_bitsChargedInTimePeriod += key->GetSizeInBits();
            KeyCalculation();
        }

        return true;
    }

    //NOTE: Function is allowed to return NULL value. Processing is left to the KM.
    Ptr<QKDKey>
    QBuffer::GetKey(std::string keyId, bool fireTraces)
    {
        Ptr<QKDKey> key {NULL};
        if(!keyId.empty()){ //Return requested key if found
            NS_LOG_FUNCTION(this << "keyId:\t" << keyId);
            auto a = m_keys.find(keyId);
            if(a != m_keys.end()){
                key = a->second;
                DestroyKey(keyId);
                //Fire traces
                NS_LOG_FUNCTION(this << key->GetId() << key->GetSizeInBits());
                if(fireTraces) {
                    LogUpdate(key->GetSizeInBits(), false);
                    //Fire total graph traces
                    m_currentKeyBitDecreaseTrace(key->GetSizeInBits());
                }
            }else
                NS_LOG_DEBUG(this << "not found " << keyId);

        }else{ //Return random key from QBuffer
            NS_LOG_FUNCTION(this << "keyId:\t" << keyId <<  "\t *random" << GetKeyCount());
            std::unordered_map< std::string, Ptr <QKDKey> >::iterator random_it;
            uint32_t keyCount = GetKeyCount();
            if(keyCount  >= 1)
            {   //If QBuffer is not empty select a random key
                if(keyCount == 1)
                {
                    random_it = m_keys.begin();
                } else{
                    random_it = std::next(std::begin(m_keys), std::rand()%keyCount);
                }
                key = random_it->second;
                DestroyKey(key->GetId());
                //Fire traces
                NS_LOG_FUNCTION(this << key->GetId() << key->GetSizeInBits());
                if(fireTraces) {
                    LogUpdate(key->GetSizeInBits(), false); 
                    //Fire total graph traces
                    m_currentKeyBitDecreaseTrace(key->GetSizeInBits());
                }
            }else
                NS_LOG_FUNCTION(this << "QBuffer is empty");

        }

        return key;
    }

    bool
    QBuffer::DestroyKey(std::string keyId)
    {
        NS_LOG_FUNCTION(this << keyId);
        auto it = m_keys.find(keyId);
        if(it != m_keys.end()){
            m_keys.erase(it);
            return true;
        }else{
            NS_LOG_FUNCTION(this << "Key" << keyId << "does not exist");
            return false;
        }
    }

    uint32_t
    QBuffer::GetMaxNumberOfRecordedKeyChargingTimePeriods() const
    {
        return m_maxNumberOfRecordedKeyChargingTimePeriods;
    }

    void
    QBuffer::CheckState()
    {
        NS_LOG_FUNCTION(this << m_minKeyBit << m_currentKeyBit << m_currentKeyBitPrevious << m_thresholdKeyBit << m_maxKeyBit << m_status << m_previousStatus );

    	if(m_currentKeyBit >= m_thresholdKeyBit){
             NS_LOG_FUNCTION("case 1");
    		 m_status = QBuffer::QSTATUS_READY;

    	}else if(m_currentKeyBit < m_thresholdKeyBit && m_currentKeyBit > m_minKeyBit &&
         ((m_isRisingCurve && m_previousStatus != QBuffer::QSTATUS_READY) || m_previousStatus == QBuffer::QSTATUS_EMPTY )
        ){
             NS_LOG_FUNCTION("case 2");
    		 m_status = QBuffer::QSTATUS_CHARGING;

    	}else if(m_currentKeyBit < m_thresholdKeyBit && m_currentKeyBit > m_minKeyBit &&
         (m_previousStatus != QBuffer::QSTATUS_CHARGING)
        ){
             NS_LOG_FUNCTION("case 3");
    		 m_status = QBuffer::QSTATUS_WARNING;

    	}else if(m_currentKeyBit <= m_minKeyBit){
             NS_LOG_FUNCTION("case 4");
    		 m_status  = QBuffer::QSTATUS_EMPTY;
    	}else{
             NS_LOG_FUNCTION("case UNDEFINED"     << m_minKeyBit << m_currentKeyBit << m_currentKeyBitPrevious << m_thresholdKeyBit << m_maxKeyBit << m_status << m_previousStatus );
        }

        if(m_previousStatus != m_status){
            NS_LOG_FUNCTION(this << "STATUS IS NOT EQUAL TO PREVIOUS STATUS" << m_previousStatus << m_status);
            NS_LOG_FUNCTION(this << m_minKeyBit << m_currentKeyBit << m_currentKeyBitPrevious << m_thresholdKeyBit << m_maxKeyBit << m_status << m_previousStatus );

            m_StatusChangeTrace(m_previousStatus);
            m_StatusChangeTrace(m_status);
            m_previousStatus = m_status;
        }
    }

    bool
    QBuffer::operator==(QBuffer const & o) const
    {
        return(m_bufferID == o.m_bufferID);
    }


    uint32_t
    QBuffer::GetId() const{
        NS_LOG_FUNCTION(this << m_bufferID);
        return m_bufferID ;
    }

    void
    QBuffer::InitTotalGraph() const
    {
        NS_LOG_FUNCTION(this);
        m_currentKeyBitIncreaseTrace(m_currentKeyBit); 
    }

    /**
    *   Return time value about the time duration of last key charging process
    */
    int64_t
    QBuffer::GetLastKeyChargingTimeDuration()
    {
        NS_LOG_FUNCTION(this);
        return m_lastKeyChargingTimeDuration;
    }

    /*
    *   Return time difference between the current time and time at which
    *   last key charging process finished
    */
    int64_t
    QBuffer::GetDeltaTime()
    {
        NS_LOG_FUNCTION(this);
        int64_t currentTime = Simulator::Now().GetMilliSeconds();
        return currentTime - m_lastKeyChargingTimeStamp;
    }

    double
    QBuffer::GetAverageKeyChargingTimePeriod() //@toDo nema smisla ovdje to pratiti!
    {
        NS_LOG_FUNCTION(this << m_averageKeyChargingTimePeriod);
        return m_averageKeyChargingTimePeriod;
    }

    uint32_t
    QBuffer::GetState()
    {
        NS_LOG_FUNCTION(this << m_status);
        return m_status;
    }

    uint32_t
    QBuffer::GetPreviousState()
    {
        NS_LOG_FUNCTION(this << m_previousStatus);
        return m_previousStatus;
    }

    uint32_t
    QBuffer::GetMCurrentPrevious() const
    {
        NS_LOG_FUNCTION(this << m_currentKeyBitPrevious);
        return m_currentKeyBitPrevious;
    }

    uint32_t
    QBuffer::GetMthr() const
    {
        NS_LOG_FUNCTION(this << m_thresholdKeyBit);
        return m_thresholdKeyBit;
    }
    void
    QBuffer::SetMthr(uint32_t thr)
    {
        NS_LOG_FUNCTION(this << thr);
        m_thresholdKeyBit = thr;
        m_thresholdKeyBitChangeTrace(m_thresholdKeyBit);
    }

    void
    QBuffer::SetIndex(uint32_t index){
        NS_LOG_FUNCTION(this << index);
        m_srcNodeBufferListIndex = index;
    }

    void
    QBuffer::SetKeySize(uint32_t size){
        m_defaultKeySize = size;
    }

    uint32_t
    QBuffer::GetIndex(){
        NS_LOG_FUNCTION(this << m_srcNodeBufferListIndex);
        return m_srcNodeBufferListIndex;
    }

} // namespace ns3

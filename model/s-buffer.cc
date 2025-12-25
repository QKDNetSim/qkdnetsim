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

#include "s-buffer.h"

namespace ns3 {

    NS_LOG_COMPONENT_DEFINE("SBuffer");

    NS_OBJECT_ENSURE_REGISTERED(SBuffer);

    TypeId
    SBuffer::GetTypeId()
    {
      static TypeId tid = TypeId("ns3::SBuffer")
        .SetParent<QBuffer>()
        .AddConstructor<SBuffer>() 
        .AddAttribute("SMinimal",
                       "The minimal amount of key material in Sbuffer (bits)",
                       UintegerValue(10),
                       MakeUintegerAccessor(&SBuffer::m_minKeyBitSBufferDefault),
                       MakeUintegerChecker<uint32_t>())
        .AddAttribute("SMaximal",
                       "The maximal amount of key material in Sbuffer (bits)",
                       UintegerValue(128000),
                       MakeUintegerAccessor(&SBuffer::m_maxKeyBitSBufferDefault),
                       MakeUintegerChecker<uint32_t>())
        .AddAttribute("SThreshold",
                       "The threshold amount of key material in Sbuffer (bits)",
                       UintegerValue(32000),
                       MakeUintegerAccessor(&SBuffer::m_thresholdKeyBitSBufferDefault),
                       MakeUintegerChecker<uint32_t>())
        .AddAttribute("SDefaultKeySize",
                       "The default key size of Sbuffer",
                       UintegerValue(512),
                       MakeUintegerAccessor(&SBuffer::m_defaultKeySizeSBufferDefault),
                       MakeUintegerChecker<uint32_t>())
 
        ;
      return tid;
    }
 
    SBuffer::SBuffer()
    {
        NS_LOG_FUNCTION(this);
        m_notReadyKeyCount = 0;
        m_notReadyBitCount = 0;
        m_currentStreamIndex = 0;
        m_relayActive = false; 
    }

    void
    SBuffer::DoInitialize()
    { 
        Object::DoInitialize();

        NS_LOG_FUNCTION(this << m_minKeyBit << m_maxKeyBit << m_thresholdKeyBit << m_defaultKeySize );

        m_minKeyBit = m_minKeyBitSBufferDefault;
        m_maxKeyBit = m_maxKeyBitSBufferDefault;
        m_thresholdKeyBit = m_thresholdKeyBitSBufferDefault;
        m_defaultKeySize = m_defaultKeySizeSBufferDefault; 

        NS_LOG_FUNCTION(this << m_minKeyBit << m_maxKeyBit << m_thresholdKeyBit << m_defaultKeySize );

        QBuffer::Init(
            m_dstKmNodeId,
            m_minKeyBit,
            m_thresholdKeyBit,
            m_maxKeyBit,
            0,
            m_defaultKeySize
        );
        m_notReadyKeyCount = 0;
        m_notReadyBitCount = 0;
        m_currentStreamIndex = 0;
        m_relayActive = false; 
    }

    SBuffer::SBuffer(SBuffer::Type type, uint32_t size)
    {
        NS_LOG_FUNCTION(this << size);
        SetKeySize(size);
        SetType(type);
        if(type == STREAM_SBUFFER) //Must be able to store keys
            Configure(
                0,
                500000000,
                500000000,
                0,
                size
            );
        m_notReadyKeyCount = 0;
        m_notReadyBitCount = 0;
        m_currentStreamIndex = 0;
        m_relayActive = false;
    }


    SBuffer::~SBuffer()
    {
        NS_LOG_FUNCTION (this);
        m_keys.clear();
        m_stream_keys.clear();
        m_supply_keys.clear();
    }

    void
    SBuffer::SetType(SBuffer::Type type)
    {
        NS_LOG_FUNCTION(this);
        m_type = type;
    }

    SBuffer::Type
    SBuffer::GetType()
    {
        NS_LOG_FUNCTION(this);
        return m_type;
    }
 

    uint32_t
    SBuffer::GetDefaultKeyCount(uint32_t number)
    {
        NS_LOG_FUNCTION(this << number); 
        uint32_t keyCount {0}; 

        for(auto it = m_keys.begin(); it != m_keys.end(); ++it)
        {   
            /*
            NS_LOG_FUNCTION(this
                << "\nKey ID:\t" << it->second->GetId()
                << "\nKey State:\t" << it->second->GetState()
                << "\nKey Size:\t" << it->second->GetSizeInBits()
                << "\nGetKeySize():\t" << GetKeySize()
            );
            */

            if(it->second->GetSizeInBits() == GetKeySize() && it->second->GetState() == QKDKey::READY)
                keyCount++;

            if(number && keyCount == number)
                break;
        }

        NS_LOG_FUNCTION(this << number << keyCount << m_keys.size());
        return keyCount;
    }

    uint32_t
    SBuffer::GetSKeyCount()
    {
        NS_LOG_FUNCTION(this << GetKeyCount() << m_notReadyKeyCount);
        //Note 'state' is cosidered READY. We are requesting number of keys in READY state
        if(GetKeyCount() > m_notReadyKeyCount) 
            return GetKeyCount() - m_notReadyKeyCount;
        return 0;
    }

    uint32_t
    SBuffer::GetSBitCount()
    {
        NS_LOG_FUNCTION(this << GetBitCount() << m_notReadyBitCount);
        //Note 'state' is cosidered READY. We are requesting amount of key in READY state
        if(GetBitCount() > m_notReadyBitCount) 
            return GetBitCount() - m_notReadyBitCount;
        return GetBitCount();
    }


    bool
    SBuffer::StoreKey(Ptr<QKDKey> key, bool fireTraces)
    {
        NS_LOG_FUNCTION(this
            << "\nKey ID:\t" << key->GetId()
            << "\nKey Size:\t" << key->GetSizeInBits()
            << "\nKey State:\t" << key->GetStateString()
            << "\nKey Value:\t" << key->ToString()
            << "\nGetBitCount():\t" << GetBitCount()
            << "\nfireTraces:\t" << fireTraces
        );
        //Sbuffer should never fire traces in Qbuffer! 
        bool output = QBuffer::StoreKey(key, false); 
        if(output && key->GetState() == QKDKey::READY && fireTraces)
        {
            LogUpdate(key->GetSizeInBits(), true);
        }
        return output; 
    }

    void
    SBuffer::LogUpdate(uint32_t diffValue, bool positive)
    {
        NS_LOG_FUNCTION(this << m_currentKeyBit << diffValue << positive);

        if(positive)
        {
            m_currentKeyBit += diffValue;
            m_currentKeyBitChangeTrace(m_currentKeyBit); 
            m_bitsUsedInTimePeriod += diffValue;
        }else{

            if(diffValue > m_currentKeyBit)
                diffValue = 0;

            m_currentKeyBit -= diffValue;
            m_currentKeyBitChangeTrace(m_currentKeyBit); 
            m_bitsUsedInTimePeriod -= diffValue;
        }

        NS_LOG_FUNCTION(this << "m_currentKeyBit: " << m_currentKeyBit); 
        uint32_t sbitcount = GetSBitCount(); 
        NS_LOG_FUNCTION(this << "GetSBitCount(): " << sbitcount);
        //NS_ASSERT(m_currentKeyBit == sbitcount);

        uint32_t keycount = GetKeyCount(); 
        NS_LOG_FUNCTION(this << "keyCount: " << keycount);
        uint32_t keySize = GetKeySize();
        NS_LOG_FUNCTION(this << "keySize: " << keySize); 
        //NS_ASSERT(m_currentKeyBit == keycount* keySize);


        ///////////////////////////////// TEMP TEMP TEMP /////////////////////////////////
        // Collect all keys in READY state
        
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


        NS_LOG_FUNCTION(this << "m_stream_keys.size(): " << m_stream_keys.size());  
        for (auto it = m_stream_keys.begin(); it != m_stream_keys.end(); ++it) {
            if (it->second->GetState() == QKDKey::READY) { 
                totalReadyKeyCount += it->second->GetSizeInBits();
                NS_LOG_FUNCTION(this << "id:" << it->second->GetId() << "\t size:" << it->second->GetSizeInBits());
            }
        }
        NS_LOG_FUNCTION(this << "m_currentKeyBit: " << m_currentKeyBit);
        NS_LOG_FUNCTION(this << "totalReadyKeyCount: " << totalReadyKeyCount);


        NS_LOG_FUNCTION(this << "m_supply_keys.size(): " << m_supply_keys.size());  
        for (auto it = m_supply_keys.begin(); it != m_supply_keys.end(); ++it) {
            if (it->second->GetState() == QKDKey::READY) { 
                totalReadyKeyCount += it->second->GetSizeInBits();
                NS_LOG_FUNCTION(this << "id:" << it->second->GetId() << "\t size:" << it->second->GetSizeInBits());
            }
        }
        NS_LOG_FUNCTION(this << "m_currentKeyBit: " << m_currentKeyBit);
        NS_LOG_FUNCTION(this << "totalReadyKeyCount: " << totalReadyKeyCount);
 
        NS_ASSERT(totalReadyKeyCount == m_currentKeyBit);
        
        ///////////////////////////////// TEMP TEMP TEMP /////////////////////////////////


        CheckState();
    }

    Ptr<QKDKey>
    SBuffer::GetTransformCandidate(uint32_t size)
    {
        NS_LOG_FUNCTION(this << size );
        NS_LOG_FUNCTION(this << GetSBitCount());

        //return random key from s-buffer(key must be READY)
        if(size == 0)
        { 
            uint32_t keyCount = GetKeyCount(); 
            NS_LOG_FUNCTION(this << "keyCount: " << keyCount);
            if (!keyCount) {
                NS_LOG_DEBUG("Not enough keys in SBuffer to select a transform candidate");
                return nullptr;
            }

            // Collect all keys in READY state
            NS_LOG_FUNCTION(this << "m_keys.size(): " << m_keys.size()); 
            uint32_t totalReadyKeyCount = 0;
            std::vector<decltype(m_keys)::iterator> readyKeys;
            for (auto it = m_keys.begin(); it != m_keys.end(); ++it) {
                if (it->second->GetState() == QKDKey::READY) {
                    readyKeys.push_back(it);
                    totalReadyKeyCount += it->second->GetSizeInBits();
                    NS_LOG_FUNCTION(this << "id:" << it->second->GetId() << "\t size:" << it->second->GetSizeInBits());
                }
            }

            NS_LOG_FUNCTION(this << "totalReadyKeyCount: " << totalReadyKeyCount);
            NS_LOG_FUNCTION(this << "m_currentKeyBit: " << m_currentKeyBit);
            NS_ASSERT(totalReadyKeyCount == m_currentKeyBit);


            if (readyKeys.empty()) {
                NS_LOG_DEBUG("No READY keys available in SBuffer!");
                // Alternatively:
                return nullptr;
            }

            // Pick random READY key
            auto chosenIt = readyKeys[std::rand() % readyKeys.size()]; 
            NS_LOG_FUNCTION(this << "get a key " << chosenIt->second->GetId() << " of size " << chosenIt->second->GetSizeInBits() );

            return GetKey(chosenIt->second->GetId());

        } else {

            Ptr<QKDKey> optimalKey = nullptr;         // Smallest ready key ≥ size
            Ptr<QKDKey> largestReadyKey = nullptr;    // Largest ready key

            NS_LOG_FUNCTION(this << "m_keys.size(): " << m_keys.size()); 
            uint32_t totalReadyKeyCount = 0;
            std::vector<decltype(m_keys)::iterator> readyKeys;
            for (auto it = m_keys.begin(); it != m_keys.end(); ++it) {
                if (it->second->GetState() == QKDKey::READY) {
                    readyKeys.push_back(it);
                    totalReadyKeyCount += it->second->GetSizeInBits();
                    NS_LOG_FUNCTION(this << "id:" << it->second->GetId() << "\t size:" << it->second->GetSizeInBits());
                }
            }
            NS_LOG_FUNCTION(this << "totalReadyKeyCount: " << totalReadyKeyCount);
            NS_LOG_FUNCTION(this << "m_currentKeyBit: " << m_currentKeyBit);
            NS_ASSERT(totalReadyKeyCount == m_currentKeyBit);


            for (const auto& [id, key] : m_keys) 
            {
                if (key->GetState() != QKDKey::READY)
                    continue;

                // Track largest ready key
                if (!largestReadyKey || key->GetSizeInBits() > largestReadyKey->GetSizeInBits())
                    largestReadyKey = key;

                // Track smallest ready key ≥ size
                if (key->GetSizeInBits() >= size) {
                    if (!optimalKey || key->GetSizeInBits() < optimalKey->GetSizeInBits())
                        optimalKey = key;
                }
            }

            if (!optimalKey && !largestReadyKey) {
                return nullptr;
            }
 
            if(!optimalKey)
            {   
                NS_LOG_FUNCTION(this << "largestReadyKey size: " <<  largestReadyKey->GetSizeInBits() );

                NS_ASSERT(largestReadyKey);
                return GetKey(largestReadyKey->GetId()); //This will remove key from s-buffer and fire traces
            }

            if(optimalKey->GetSizeInBits() == size)
            {
                NS_LOG_FUNCTION(this << "optimalKey size: " <<  largestReadyKey->GetSizeInBits() );
                return GetKey(optimalKey->GetId()); //This will remove key from s-buffer and fire traces
            }

            NS_LOG_FUNCTION(this << ">>>>>>>>>>>>>>>>>>>>");
            LogUpdate(0, true);
            NS_LOG_FUNCTION(this << "<<<<<<<<<<<<<<<<<<<<");

            NS_LOG_FUNCTION(this << "optimalKey keyId: " <<  optimalKey->GetId() << " of size " << optimalKey->GetSizeInBits() << " bits");
            //Optimal key in this case is not removed, its value is updated and it is marked as INIT
            std::string keyId = optimalKey->GetId();
            std::string value = optimalKey->GetKeyString();
            std::string rKeyValue = value.substr(0, size/8);

            uint32_t oldKeySizeInBits = optimalKey->GetSizeInBits();
            NS_LOG_FUNCTION(this << "oldKeySizeInBits1: " << oldKeySizeInBits);
            value.erase(0, size/8);
 
            Ptr<QKDKey> key = CreateObject<QKDKey>(keyId, rKeyValue);
            key->SwitchToState(QKDKey::INIT);

            auto it = m_keys.find(optimalKey->GetId());     //Find the key in s-buffer
            it->second->SetValue(value);                    //Set the key value
            NS_LOG_FUNCTION(this << key->GetId() << " of size " << key->GetSizeInBits()<< " bits is reduced to size " << key->GetSizeInBits() << " bits");

            oldKeySizeInBits -= key->GetSizeInBits();
            NS_LOG_FUNCTION(this << "oldKeySizeInBits2: " << oldKeySizeInBits); 

            NS_LOG_FUNCTION(this << "Update graphs to include details about key reduction!");
            LogUpdate(key->GetSizeInBits(), false); 
             
            MarkKey(optimalKey->GetId(), QKDKey::INIT);

            return key;
        }
    }

    Ptr<QKDKey>
    SBuffer::GetHalfKey(std::string keyId, uint32_t size)
    {
        NS_LOG_FUNCTION(this << keyId << size);
        auto it = m_keys.find(keyId);
        if(it!=m_keys.end()){
            if(it->second->GetSizeInBits() > size)
            {
                uint32_t oldKeySizeInBits = it->second->GetSizeInBits();
                NS_LOG_FUNCTION(this << "oldKeySizeInBits1: " << oldKeySizeInBits);
                std::string value = it->second->GetKeyString();
                std::string rValue = value.substr(0, size/8);
                value.erase(0, size/8);
                NS_LOG_FUNCTION(this << value);

                Ptr<QKDKey> key = CreateObject<QKDKey>(keyId, rValue);
                NS_LOG_FUNCTION(this << key->GetId() << key->GetSizeInBits());
                it->second->SetValue(value);

                NS_LOG_FUNCTION(this << key->GetId() << " of size " << key->GetSizeInBits()<< " bits is reduced to size " << key->GetSizeInBits() << " bits"); 
                oldKeySizeInBits -= key->GetSizeInBits();
                NS_LOG_FUNCTION(this << "oldKeySizeInBits2: " << oldKeySizeInBits); 

                NS_LOG_FUNCTION(this << "Update graphs to include details about key reduction!");
                LogUpdate(key->GetSizeInBits(), false);

                //Key remains in READY state!
                return key;
            }else if(it->second->GetSizeInBits() == size){

                return GetKey(keyId);
            }
        }else{
            NS_FATAL_ERROR(this << "Key " << keyId << " was not found!");
        }

        return nullptr;
    }

    Ptr<QKDKey>
    SBuffer::GetKey(uint32_t size)
    {
        NS_LOG_FUNCTION(this << size);
        Ptr<QKDKey> key;
        //for(auto it : m_keys.begin())
        for(auto it = m_keys.begin(); it != m_keys.end(); ++it)
            if(it->second->GetSizeInBits() == size && it->second->GetState() == QKDKey::READY){
                key = GetKey(it->second->GetId()); //This will fire traces and remove the key!
                break;
            }

        return key;
    }


    //NOTE: Function is allowed to return NULL value. Processing is left to the KM.
    Ptr<QKDKey>
    SBuffer::GetKey(std::string keyId, bool fireTraces)
    {
        Ptr<QKDKey> key = QBuffer::GetKey(keyId, false);
        if(key && key->GetState() == QKDKey::READY && fireTraces) 
            LogUpdate(key->GetSizeInBits(), false);

        CheckState();
        return key; 
    }

    void
    SBuffer::StoreSupplyKey(Ptr<QKDKey> key)
    {
        NS_LOG_FUNCTION(this << key->GetId() << key->GetSizeInBits());

        if(GetType() == SBuffer::STREAM_SBUFFER)
        {
            NS_LOG_FUNCTION(this << "Store in m_stream_keys!");
            m_stream_keys.insert(std::make_pair(std::stoi(key->GetId()), key));
        } else { 
            NS_LOG_FUNCTION(this << "Store in m_supply_keys!");
            m_supply_keys.insert(std::make_pair(key->GetId(), key));
        }

        if(key->GetState() == QKDKey::READY)
            LogUpdate(key->GetSizeInBits(), true);
    }

    Ptr<QKDKey>
    SBuffer::GetSupplyKey(std::string keyId)
    {
        NS_LOG_FUNCTION(this << keyId);
        auto it = m_supply_keys.find(keyId);
        if(it != m_supply_keys.end()){
            Ptr<QKDKey> sKey = it->second;
            m_supply_keys.erase(it); //Remove Key
            if(sKey && sKey->GetState() == QKDKey::READY) {
                LogUpdate(sKey->GetSizeInBits(), false);
                CheckState();
            }
            return sKey;
        }else{
            NS_LOG_ERROR(this);
            return nullptr;
        }
    }

    Ptr<QKDKey>
    SBuffer::GetStreamKey()
    {
        NS_LOG_FUNCTION(this);
        auto it = m_stream_keys.begin();
        Ptr<QKDKey> streamKey {NULL};
        if(it != m_stream_keys.end())
        {// && it->second->GetSizeInBits() == GetKeySize())
            streamKey = it->second;
            NS_LOG_FUNCTION(this << it->second->GetId() << streamKey->GetSizeInBits() );
            m_stream_keys.erase(it);
            if(streamKey && streamKey->GetState() == QKDKey::READY) 
            {
                LogUpdate(streamKey->GetSizeInBits(), false);
                CheckState();
            }
        }else
            NS_LOG_ERROR(this << "No chunk key available!");

        return streamKey;
    }

    void
    SBuffer::InsertKeyToStreamSession(Ptr<QKDKey> key)
    {
         NS_LOG_FUNCTION(this
            << "\nKey ID:\t" << key->GetId()
            << "\nKey Size:\t" << key->GetSizeInBits()
            << "\nKey State:\t" << key->GetStateString()
            << "\nKey Value:\t" << key->ToString()
            << "\nGetBitCount():\t" << GetBitCount()
            << "\nm_currentStreamIndex:\t" << m_currentStreamIndex
        );

        //Take last stored index m_currentStreamIndex
        bool startingInReady {true};
        uint32_t startingIndex = m_currentStreamIndex;
        if(m_stream_keys.rbegin() != m_stream_keys.rend())
        {
            startingIndex = m_stream_keys.rbegin()->first;
            NS_LOG_FUNCTION(this << "\nLast key index:" << m_stream_keys.rbegin()->second->GetId()
                                 << "\nLast key value:" << m_stream_keys.rbegin()->second->GetKeyString()
                            );
            if(m_stream_keys.rbegin()->second->GetSizeInBits() != GetKeySize())
                startingInReady = false;
            else
                startingIndex++;
        }

        //NS_LOG_FUNCTION(this << "Chunk size(bytes), Start Index, Start Ready" << GetKeySize()/8 << startingIndex << startingInReady);
        //copy
        std::string keyValue = key->GetKeyString();
        while(!keyValue.empty())
        {
            if(!startingInReady)
            {     
                    NS_LOG_FUNCTION(this << "!startingInReady");
                    uint32_t diff = GetKeySize()/8 -(m_stream_keys.rbegin()->second)->GetSize(); //In bytes
                    //Check the size of the keyValue, is it enough to fill the diff
                    std::string incompleteChunkKey =(m_stream_keys.rbegin()->second)->GetKeyString();
                    if(keyValue.size() >= diff)
                    {   
                        std::string initKeyValue = keyValue;
                        std::string diffKey = keyValue.substr(0, diff);
                        std::string temp = keyValue.substr(diff);
                        keyValue = temp;
                        std::string completeKey = incompleteChunkKey + diffKey;
                        (m_stream_keys.rbegin()->second)->SetValue(completeKey); //Set the value of the key

                        NS_LOG_FUNCTION(this << "initKeyValue.size()" << initKeyValue.size() * 8);
                        NS_LOG_FUNCTION(this << "diffKey.size()" << diffKey.size() * 8);
                        NS_LOG_FUNCTION(this << "keyValue.size()" << keyValue.size() * 8 );
                        NS_LOG_FUNCTION(this << "incompleteChunkKey.size()" << incompleteChunkKey.size() * 8 );
                        NS_LOG_FUNCTION(this << "completeKey.size()" << completeKey.size() * 8);

                        if(key->GetState() == QKDKey::READY)
                            LogUpdate(diffKey.size() * 8, true);

                        startingIndex++;
                        startingInReady = true;
                    }else{
                        std::string completeKey = incompleteChunkKey + keyValue;
                        (m_stream_keys.rbegin()->second)->SetValue(completeKey); //Set the value of the key
                        LogUpdate(keyValue.size() * 8, true);
                        keyValue.clear();
                        startingIndex++; //Increase index
                    }

            }else{

                NS_LOG_FUNCTION(this << "startingInReady == TRUE");
                uint32_t len; //len is in bytes
                if(keyValue.size() >= GetKeySize()/8)
                len = GetKeySize()/8;
                else
                len = keyValue.size();

                std::string keyTemp {keyValue.substr(0, len)};
                std::string temp {keyValue.substr(len)};
                keyValue = temp;

                Ptr<QKDKey> tempKey = CreateObject<QKDKey>(std::to_string(startingIndex), keyTemp);
                StoreSupplyKey(tempKey);
                startingIndex++; //Increase index
            
            }
        }

        m_currentStreamIndex = startingIndex - 1;
        NS_LOG_FUNCTION( this << "Last index stored is " << m_currentStreamIndex );

    }

    uint32_t
    SBuffer::GetStreamKeyCount()
    {
        NS_LOG_FUNCTION(this << m_stream_keys.size());
        uint32_t streamKeyCount {0};
        if(!m_stream_keys.empty()){
            streamKeyCount = m_stream_keys.size();
            if( m_stream_keys.rbegin()->second->GetSizeInBits() != GetKeySize() )
                streamKeyCount--;
        }

        return streamKeyCount;
    }

    uint32_t
    SBuffer::GetStreamIndex()
    {
        NS_LOG_FUNCTION(this);
        return m_currentStreamIndex;
    }

    uint32_t
    SBuffer::GetNextIndex()
    {
        NS_LOG_FUNCTION(this);
        uint32_t nextIndex {0};
        if(!m_stream_keys.empty())
            nextIndex = m_stream_keys.begin()->first;

        return nextIndex;
    }

    void
    SBuffer::MarkKey(
        std::string keyId,
        QKDKey::QKDKeyState_e state
    )
    {
        NS_LOG_FUNCTION(this << keyId << state);

        auto it = m_keys.find(keyId);
        if(it != m_keys.end())
        {
            NS_LOG_FUNCTION(this << "we found the key with id " << keyId << " and it was in state: " << it->second->GetStateString());
            //Fire traces
            if(it->second->GetState() == QKDKey::READY && state != QKDKey::READY)
            {
                m_notReadyKeyCount++;
                m_notReadyBitCount += it->second->GetSizeInBits();
                it->second->SwitchToState(state);
                NS_LOG_FUNCTION(this << "1 Switching key with id " << keyId << " to NEW state: " << it->second->GetStateString());
                LogUpdate(it->second->GetSizeInBits(), false);
            }else if(it->second->GetState() != QKDKey::READY && state == QKDKey::READY){
                NS_LOG_FUNCTION(this << "2 previous" << m_notReadyBitCount << m_notReadyKeyCount << it->second->GetSizeInBits() << "to READY 0  ");
                if(m_notReadyBitCount < it->second->GetSizeInBits() || m_notReadyKeyCount == 0) NS_FATAL_ERROR(this << "to READY 0 - not ready");
                m_notReadyKeyCount--;
                m_notReadyBitCount -= it->second->GetSizeInBits();
                it->second->SwitchToState(state);
                NS_LOG_FUNCTION(this << "2 Switching key with id " << keyId << " to NEW state: " << it->second->GetStateString());
                LogUpdate(it->second->GetSizeInBits(), true);
            }else if(state == QKDKey::OBSOLETE){
                NS_LOG_FUNCTION(this << "3 previous" << m_notReadyBitCount << m_notReadyKeyCount << it->second->GetSizeInBits() << "to OBSOLETE 0 ");
                if(m_notReadyBitCount < it->second->GetSizeInBits() || m_notReadyKeyCount == 0) NS_FATAL_ERROR(this << "to OBSOLETE 0 - not ready");
                m_notReadyKeyCount--;
                m_notReadyBitCount -= it->second->GetSizeInBits();
                GetKey(keyId);
            }

            NS_LOG_FUNCTION(this << "m_notReadyKeyCount:" << m_notReadyKeyCount << m_notReadyBitCount);
            NS_LOG_FUNCTION(this << "m_notReadyBitCount:" << m_notReadyBitCount << m_notReadyBitCount);
        }else
            NS_FATAL_ERROR(this << "Key not found for marking!" << keyId << state);
    }

    void
    SBuffer::SetKeyLifetime(std::string keyId)
    {
        NS_LOG_FUNCTION(this);
    }

    void
    SBuffer::SetRelayState(bool relayActive)
    {
        NS_LOG_FUNCTION(this);
        m_relayActive = relayActive;
    }

    bool
    SBuffer::IsRelayActive()
    {
        NS_LOG_FUNCTION(this);
        return m_relayActive;
    }

} // namespace ns3

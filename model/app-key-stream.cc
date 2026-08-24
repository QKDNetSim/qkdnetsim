/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 *
 *
 * Authors:  Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 *           Miralem Mehic <miralem.mehic@etf.unsa.ba>
 */

#include <string>
#include <queue>

#include <cmath>
#include <algorithm>
#include <numeric>
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/log.h"
#include "ns3/boolean.h"
#include "ns3/double.h"
#include "ns3/uinteger.h"

#include "app-key-stream.h"
#include <map>

namespace ns3 {

    NS_LOG_COMPONENT_DEFINE("AppKeyStream");

    TypeId KeyStreamSession::GetTypeId (void)
    {
      static TypeId tid = TypeId ("ns3::KeyStreamSession")
        .SetParent<Object> () 
        .AddConstructor<KeyStreamSession> ();
      return tid;
    }
     
    KeyStreamSession::KeyStreamSession() : m_id(""), m_type(Type::ENCRYPTION), m_size(0), m_verified(false), m_stream({}) {}

    void KeyStreamSession::SetId(std::string ksid) {
        m_id = ksid;
    }

    std::string KeyStreamSession::GetId() const {
        return m_id;
    }

    void KeyStreamSession::SetVerified(bool isVerified) {
        m_verified = isVerified;
    }

    bool KeyStreamSession::IsVerified() const {
        return m_verified;
    }

    void KeyStreamSession::AddKey(Ptr<AppKey> key) {
        m_stream.insert(std::make_pair(key->GetIndex(), key));
    }

    Ptr<AppKey> KeyStreamSession::GetKey(uint32_t packetSize) {
        Ptr<AppKey> key;
        auto it {m_stream.begin()};
        if(it != m_stream.end()) {
            key = it->second;
            if(GetType() == ENCRYPTION){
                it->second->UseLifetime(packetSize);
                if(it->second->GetLifetime() == 0)
                    m_stream.erase(it);
            }else{
                m_stream.erase(it);
            }
        }

        return key;
    }

    uint32_t KeyStreamSession::GetKeyCount() const {
        return m_stream.size();
    }

    void KeyStreamSession::SetSize(uint32_t size) {
        m_size = size;
    }

    uint32_t KeyStreamSession::GetSize() const {
        return m_size;
    }

    bool KeyStreamSession::SyncStream(uint32_t index) {
        auto it = m_stream.find(index);
        bool inSync {m_stream.begin() == it};
        if(it != m_stream.end()){
            while(m_stream.begin() != it)
                m_stream.erase(m_stream.begin());
        }

        return inSync;
    }

    void KeyStreamSession::SetType(KeyStreamSession::Type type) {
        m_type = type;
    }

    KeyStreamSession::Type KeyStreamSession::GetType() const {
        return m_type;
    }

    void KeyStreamSession::ClearStream() {
        m_id.clear();
        m_stream.clear();
        m_verified = false;
    } 

} // namespace ns3


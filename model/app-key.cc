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

#include "app-key.h"

namespace ns3 {

    NS_LOG_COMPONENT_DEFINE("AppKey");
 

    TypeId AppKey::GetTypeId (void)
    {
      static TypeId tid = TypeId ("ns3::AppKey")
        .SetParent<QKDKey> () 
        .AddConstructor<AppKey> ();
      return tid;
    }
     
    AppKey::AppKey(
        std::string id,
        std::string value,
        Type type,
        uint32_t lifetime
    ) : QKDKey(id, value) {
        m_type = type;
        m_lifetime = lifetime;

    }

    AppKey::AppKey(
        uint32_t index,
        std::string value,
        Type type,
        uint32_t lifetime
    ) : QKDKey("", value) {
        m_index = index;
        m_type = type;
        m_lifetime = lifetime;
    }

    uint32_t AppKey::GetLifetime() const {
        return m_lifetime;
    }

    void AppKey::SetLifetime(uint32_t lifetime) {
        m_lifetime = lifetime;
    }

    void AppKey::UseLifetime(uint32_t amount) {
        if(m_lifetime >= amount)
            m_lifetime -= amount;
        else
            m_lifetime = 0;
    }

    AppKey::Type AppKey::GetType() const {
        return m_type;
    }

    void AppKey::SetType(AppKey::Type type) {
        m_type = type;
    }

    void AppKey::SetIndex(uint32_t index){
        m_index = index;
    }

    uint32_t AppKey::GetIndex() const {
        return m_index;
    } 

} // namespace ns3 
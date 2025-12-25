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
#ifndef APP_KEY_H
#define APP_KEY_H

#include <stdint.h>
#include <algorithm>
#include <stdint.h>

#include "ns3/packet.h"
#include "ns3/object.h"
#include "ns3/callback.h"
#include "ns3/assert.h"
#include "ns3/ptr.h"
#include "ns3/simulator.h"
#include "ns3/nstime.h"
#include "ns3/traced-callback.h"
#include "ns3/deprecated.h"
#include "qkd-key.h"
#include <map>


namespace ns3 {

/**
 * @ingroup qkd
 * @brief The key at the application layer. It has lifetime and type attributes in addition
 * to QKD key class attributes.
 */
    class AppKey : public QKDKey {
        public:

            /**
            * @brief Get the TypeId
            *
            * @return The TypeId for this class
            */
            static TypeId GetTypeId();
            
            enum Type
            {
                ENCRYPTION,
                AUTHENTICATION
            };

            AppKey (){

            }

            AppKey(
                std::string id,
                std::string value,
                Type type,
                uint32_t lifetime
            );

            AppKey(
                uint32_t index,
                std::string value,
                Type type,
                uint32_t lifetime
            );

            uint32_t GetLifetime() const;

            void SetLifetime(uint32_t lifetime);

            void UseLifetime(uint32_t amount);

            Type GetType() const;

            void SetType(Type type);

            void SetIndex(uint32_t index);

            uint32_t GetIndex() const ;

        private:

            Type        m_type;     //<!Key type
            uint32_t    m_index;    //<!Key index(for ETSI 004 clients)
            uint32_t    m_lifetime; //<!Key lifetime value in bytes

    };

} // namespace ns3

#endif /* APP_KEY_H */

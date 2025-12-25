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
#ifndef KEY_STREAM_H
#define KEY_STREAM_H

#include <stdint.h>
#include <algorithm>
#include <stdint.h>
#include <string.h>

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
#include "app-key.h"
#include <map>


namespace ns3 {

/**
 * @ingroup qkd
 * @brief key stream session
 */
    class KeyStreamSession : public Object {
        public:

            /**
            * @brief Get the TypeId
            *
            * @return The TypeId for this class
            */
            static TypeId GetTypeId();

            enum Type
            {
                EMPTY,
                ENCRYPTION,
                AUTHENTICATION
            };

            KeyStreamSession();

            void SetId(std::string ksid);

            std::string GetId() const;

            void SetVerified(bool isVerified);

            bool IsVerified() const;

            void AddKey(Ptr<AppKey> key);

            Ptr<AppKey> GetKey(uint32_t packetSize = 0);

            uint32_t GetKeyCount() const;

            void SetSize(uint32_t size);

            uint32_t GetSize() const;

            bool SyncStream(uint32_t index);

            void SetType(Type type);

            Type GetType() const;

            void ClearStream();


        private:

            std::string m_id;
            Type        m_type;                         //<!Session type
            uint32_t    m_size;                         //<!Key stream size at the application layer
            bool        m_verified;                     //<!Is verified
            std::map<uint32_t, Ptr<AppKey> > m_stream;    //<!Key stream

    };

} // namespace ns3

#endif /* KEY_STREAM_H */

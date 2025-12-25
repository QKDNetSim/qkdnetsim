/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 * Author:  Miralem Mehic <miralem.mehic@etf.unsa.ba>
 *          Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 */

#include "ns3/log.h"
#include "ns3/pointer.h"
#include "ns3/object-factory.h"
#include "ns3/drop-tail-queue.h"
#include "qkd-kms-queue-logic.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("QKDKMSQueueLogic");

NS_OBJECT_ENSURE_REGISTERED(QKDKMSQueueLogic);

TypeId QKDKMSQueueLogic::GetTypeId()
{
  static TypeId tid = TypeId("ns3::QKDKMSQueueLogic")
    .SetParent<Object>()
    .AddConstructor<QKDKMSQueueLogic>()
    .AddAttribute("MaxSize", "The maximum number of packets accepted by this queue disc.",
                   UintegerValue(10),
                   MakeUintegerAccessor(&QKDKMSQueueLogic::m_maxSize),
                   MakeUintegerChecker<uint32_t>())
    .AddAttribute("NumberOfQueues", "The number of priority queues used.",
                   UintegerValue(3),
                   MakeUintegerAccessor(&QKDKMSQueueLogic::m_numberOfQueues),
                   MakeUintegerChecker<uint32_t>())
    .AddTraceSource("EnqueueKMS", "Enqueue a packet in the queue disc",
                     MakeTraceSourceAccessor(&QKDKMSQueueLogic::m_traceEnqueue),
                     "ns3::QueueItem::TracedCallback")
    .AddTraceSource("DequeueKMS", "Dequeue a packet from the queue disc",
                     MakeTraceSourceAccessor(&QKDKMSQueueLogic::m_traceDequeue),
                     "ns3::QueueItem::TracedCallback")
    .AddTraceSource("DropKMS", "Drop a packet from the queue disc",
                     MakeTraceSourceAccessor(&QKDKMSQueueLogic::m_traceDroped),
                     "ns3::QueueItem::TracedCallback")
    .AddTraceSource("PacketsInQueue", "Number of packets currently stored in the queue disc",
                     MakeTraceSourceAccessor(&QKDKMSQueueLogic::m_nPackets),
                     "ns3::TracedValueCallback::Uint32")
  ;
  return tid;
}

QKDKMSQueueLogic::QKDKMSQueueLogic()
{
  NS_LOG_FUNCTION(this);

  for(uint32_t i = 0; i < m_numberOfQueues; i++){
    std::vector<QKDKMSQueueEntry> nv;
    m_queues.push_back(nv);
  }
}

QKDKMSQueueLogic::~QKDKMSQueueLogic()
{
  NS_LOG_FUNCTION(this);
}

bool
QKDKMSQueueLogic::Enqueue(QKDKMSQueueEntry item)
{
  NS_LOG_FUNCTION(this << m_nPackets << m_maxSize);

  if(m_nPackets >= m_maxSize)
  {
    m_traceDroped(item.httpMessage);
    NS_LOG_LOGIC("Queue disc limit exceeded -- dropping packet");
    return false;
  }

  std::string payload = item.httpMessage.GetMessageBodyString();
  nlohmann::json jOpenConnectRequest;

  try{
      jOpenConnectRequest = nlohmann::json::parse(payload);
  }catch(...) {
      NS_FATAL_ERROR( this << "JSON parse error!" << payload );
  }

  uint32_t priority = 0;
  if(jOpenConnectRequest.contains("QoS")) {
    if(jOpenConnectRequest["QoS"].contains("priority")){
      priority = jOpenConnectRequest["QoS"]["priority"];
    }
  }

  if(priority > m_numberOfQueues || priority < 0){ //Primitive validation of priority value
    priority = 0;
  }

  m_queues[priority].push_back(item);
  m_traceEnqueue(item.httpMessage);
  m_nPackets++;

  for(uint32_t i = 0; i < m_numberOfQueues; i++){
    NS_LOG_LOGIC("Number of packets in queue " << i << ": " << m_queues[i].size() );
  }

  return true;
}

QKDKMSQueueLogic::QKDKMSQueueEntry
QKDKMSQueueLogic::Dequeue()
{
  NS_LOG_FUNCTION(this << m_nPackets << m_maxSize);

  QKDKMSQueueEntry item;
  for(uint32_t i = 0; i < m_numberOfQueues; i++)
  {
    if(m_queues[i].size() > 0)
    {
      item = m_queues[i].back();
      m_queues[i].pop_back();
      m_traceDequeue(item.httpMessage);
      m_nPackets--;
      NS_LOG_LOGIC("Popped from queue " << i);
      NS_LOG_LOGIC("Number of packets in queue " << i << ": " << m_queues[i].size());
      return item;
    }
  }

  NS_LOG_LOGIC("Queue empty");
  return item;
}

} // namespace ns3

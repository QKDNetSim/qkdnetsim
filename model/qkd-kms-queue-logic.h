/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 * Author:  Miralem Mehic <miralem.mehic@etf.unsa.ba>
 *          Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 */

#ifndef QKD_KMS_QUEUE_LOGIC_H
#define QKD_KMS_QUEUE_LOGIC_H

#include <queue>
#include "ns3/packet.h"
#include "ns3/object.h"
#include "http.h"
#include "ns3/socket.h"
#include "json.h"

namespace ns3 {


/**
 * @ingroup traffic-control
 *
 * Linux pfifo_fast is the default priority queue enabled on Linux
 * systems. Packets are enqueued in three FIFO droptail queues according
 * to three priority bands based on the packet priority.
 *
 * The system behaves similar to three ns3::DropTail queues operating
 * together, in which packets from higher priority bands are always
 * dequeued before a packet from a lower priority band is dequeued.
 *
 * The queue disc capacity, i.e., the maximum number of packets that can
 * be enqueued in the queue disc, is set through the limit attribute, which
 * plays the same role as txqueuelen in Linux. If no internal queue is
 * provided, three DropTail queues having each a capacity equal to limit are
 * created by default. User is allowed to provide queues, but they must be
 * three, operate in packet mode and each have a capacity not less
 * than limit.
 *
 * @note Additional waiting queues are installed between the L3
 * and  ISO/OSI layer to avoid conflicts in decision making
 * which could lead to inaccurate routing. Experimental testing and usage!
 */
class QKDKMSQueueLogic: public Object {
public:

  struct QKDKMSQueueEntry
  {
      std::string ksid;
      Ptr<Socket> socket;
      HTTPMessage httpMessage;
      Ptr<Packet> packet;
  };

  /**
   * @brief Get the type ID.
   * @return the object TypeId
   */
  static TypeId GetTypeId();
  /**
   * @brief QKDKMSQueueLogic constructor
   *
   * Creates a queue with a depth of 1000 packets per band by default
   */
  QKDKMSQueueLogic();

  ~QKDKMSQueueLogic() override;

  bool Enqueue(QKDKMSQueueEntry item);
  QKDKMSQueueLogic::QKDKMSQueueEntry Dequeue();

private:

  /// Traced callback: fired when a packet is enqueued
  TracedCallback<const HTTPMessage > m_traceEnqueue;
    /// Traced callback: fired when a packet is dequeued
  TracedCallback<const HTTPMessage > m_traceDequeue;
    /// Traced callback: fired when a packet is dropped
  TracedCallback<const HTTPMessage > m_traceDroped;

  TracedValue<uint32_t> m_nPackets; //!< Number of packets in the queue

  uint32_t m_maxSize;
  
  uint32_t m_numberOfQueues;

  std::vector<std::vector<QKDKMSQueueEntry> > m_queues;

};

} // namespace ns3

#endif /* QKD_KMS_QUEUE_LOGIC_H */

.. _qkdnetsim_doc:

QKDNetSim: Quantum Key Distribution Network Simulator
======================================================

.. contents::
   :local:
   :depth: 2


Introduction
------------

In contrast to popular, computationally secure cryptographic solutions for the fundamental task of modern cryptography – secret key agreement – Quantum Key Distribution (QKD) offers **Information-Theoretical Security (ITS)** [Ben84].  
It has no true competitor and it paved the road towards practical ITS communications in combination with long-known Vernam, i.e., One-Time Pad (OTP) cipher [Ver26, Sha49].

QKD requires a logical QKD link, which consists of a direct physical (optical) connection, i.e., a quantum channel, and an authenticated public channel.  
The quantum channel is used to transmit a random sequence of bits encoded in non-orthogonal states of a quantum system.  
This transmission is unique in that it cannot be reliably read or copied, and such attempts are highly likely to be detected.  
It enables the establishment of correlated, partially secret data between two remote users, which is subsequently checked, error-free [Ben92, Bra93, Meh20], and privacy amplified [Ben86, Ben88] using traditional methods that require a reliable, authenticated public channel.  
Because of the nature of quantum transmission, the QKD is a distance-limited point-to-point technology [Luc18, Yua18, Zha20].  
To scale technology to a multi-user, distance-independent secret key agreement, several networks of QKD links and nodes, i.e., QKD networks, have been realized [Meh20].

The major challenge is to structure, organize, and manage this unique network that utilizes both quantum and classical communications to establish ITS secret keys between arbitrary nodes.  

However, the pace of progress is slow because even a small-scale QKD network is highly expensive and inaccessible for a large community of researchers.  
Therefore, there is an undeniable need for highly accurate and scalable simulation technology that will spur future development and teachings.  
While there is a plethora of simulation tools [Dah18, Coo21, Wu21, Sat21, Dia21, Bar18] dealing with emerging quantum technologies, none address the networking aspects of QKD networks and instead focus on quantum phenomena to achieve some cryptographic tasks.

However, the challenges associated with practical QKD networks extend beyond the quantum world, and include sophisticated aspects of key and network management to efficiently manage scarce key material and provide a reliable service with Quality of Service (QoS) assurance [Meh22].

As a result, here we present a vastly expanded model of the **Quantum Key Distribution Network Simulation module (QKDNetSim)** [Meh17].  
It is set to become the essential tool for testing novel network management methodologies applied to QKD networks.  
It is capable of simulating large-scale QKD networks, i.e., networks with arbitrary number of nodes, links, and consumers.  
The module was designed with existing practices and standards in mind, but it goes above and beyond by proposing new solutions and communication methods.  
As a result, this document is more than just a description of a simulation tool; it also offers valuable comments on design and approaches to management and communication within the framework of the QKD network.

QKD Networks
~~~~~~~~~~~~

To some extent, the limitations of standalone QKD technology can be overcome by constructing a network of individual QKD links [Ell02, Ell03]. The resulting network is called a QKD network. In the QKD network, arbitrary nodes can establish ITS keys provided there is a chain of QKD links connecting them. This fundamental requirement of the QKD network is known as *key relay* [ITU3802] and can be accomplished in a variety of ways [ITU3803], as shown in the figure below.  
All approaches require OTP encryption at each node in the connected chain known as the relay path. This is the most common QKD network architecture in real-world applications, and it is referred to as a *trusted-repeater QKD network* because it requires all nodes in the network to be trusted.

.. figure:: figures/key-relay-land.*
   :alt: Different approaches to key relay
   :width: 100%
   :name: key-relay-land

   Different approaches to key relay

Selecting the best path, or route, is a fundamental requirement for a functional QKD network [Meh20]. The tendency to keep the circle of trust as small as possible goes hand in hand with the desire to keep key network resource consumption as low as possible. However, there are occasions when the shortest path is not the best option because the performance of the QKD process falls short of the required key relay’s throughput across the given QKD link [Tan16, Yan17].


Layered Structure
~~~~~~~~~~~~~~~~~

The QKD network is defined as an add-on technology and service to conventional telecommunications networks [ITU3800]. The sole purpose of the QKD network is to generate, manage, and distribute cryptographic keys among arbitrary QKD nodes, as well as to provide keys as a service to standard communication network users or applications [Dianati07]. The main goal and motivation is to increase security of communications. The functional requirements [ITU3801] of the QKD network are distinctly divided into several layers, which are:

- Quantum layer
- Key management layer
- QKD network control layer
- QKD network management layer
- Service layer

.. figure:: figures/layered-structure.*
   :alt: Layered structure of QKD network
   :width: 80%

   Layered structure of QKD network

Key-Supply Interfaces
~~~~~~~~~~~~~~~~~~~~~

The key-supply interface describes access to the QKD network services by defining communication between cryptographic applications and KMs. ETSI has recently standardized two such interfaces: ETSI GS QKD 014 [ETSI014] and ETSI GS QKD 004 [ETSI004]. Through the ETSI specification cryptographic applications are also referred to as *Secure Application Entities (SAEs)*, while KMs are referred to as *Key Management Entities (KMEs)*.

ETSI QKD 014 defines an interface based on the HTTPS protocol and JSON-encoded data. 
ETSI QKD 004 introduces the concept of sessions with QoS capabilities.

.. figure:: figures/etsi-014.*
   :alt: Use-case of ETSI QKD 014 key-delivery interface
   :width: 60%

   Use-case of ETSI QKD 014 key-delivery interface

.. figure:: figures/etsi-004.*
   :alt: Use-case of ETSI QKD 004 key-delivery interface
   :width: 60%

   Use-case of ETSI QKD 004 key-delivery interface


QKDNetSim Module
----------------

QKDNetSim [Meh17] was introduced in 2017 as the first computing simulation environment for QKD networks that focuses on the public channel performance and networking in the classical domain with a maximum simplification of QKD process. It is developed in NS-3 to meet requirements of accuracy, extensibility, usability, and availability.  The original design of QKDNetSim offered a rather simplified view of the QKD network and its resources, with no key management and limited network management.

Here we describe a new, significantly improved version of QKDNetSim that meets the major functional requirements of QKD networks.

.. figure:: figures/sim-functional.*
   :alt: Implemented functions at each layer
   :width: 70%

   Implemented functions at each layer

During the development of QKDNetSim, many methods had to be proposed and implemented that are not discussed in other research papers. For example, QKDNetSim defines a horizontal interface between peer KMs to perform key management tasks such as supply key creation and synchronization, key stream establishment, and key relay across the network of KM links.


.. figure:: figures/sim-components1.*
   :alt: Essential components of QKDNetSim
   :width: 70%

   Essential components of QKDNetSim

QKDNetSim components include:

- **QKD Key**
- **Q-Buffer**

  .. figure:: figures/sim-qbuffer.*
     :alt: Q-buffer

     Q-buffer overview

- **S-Buffer**

  .. figure:: figures/sim-sbuffer.*
     :alt: S-buffer

     S-buffer overview

- **QKD Control**
- **QKD Encryptor**
- **QKD Helpers**
- **QKD Post-Processing Application**

   .. figure:: figures/qkdpp.*
     :alt: QKD Post-Processing

  UML QKDNetSim Sequence diagram - Post-processing application

- **QKD Cryptographic Applications**
- **QKD Key Manager System (KMS)**



Cryptographic Applications
--------------------------

The general purpose of the QKD cryptographic applications is to imitate the applications consuming cryptographic keys. It also evaluates the performance of the system as a whole under various conditions and illustrates which end-user services can be supported within the QKD network.

.. figure:: figures/sim-app-use.*
   :alt: Use-case of QKD cryptographic applications
   :width: 70%

   Use-case of QKD cryptographic applications

.. figure:: figures/sim-header.*
   :alt: QKD Application header
   :width: 70%

   QKD Application header

QKDNetSim implements two cryptographic applications:

- **App014**: communicates with KMS via ETSI QKD 014 interface.  
  Implements key stores and key-id notification.  

.. figure:: figures/sim-app014-stores.*
  :alt: App014 key stores
  :width: 70%

     App014 key stores

- **App004**: communicates with KMS via ETSI QKD 004 interface.  
  Implements per-session key queues and uses JSON/HTTP.

.. note::

   The communication between applications and KMSs is, in general, over HTTPS.
   In QKDNetSim, HTTP is used instead for simplicity, but all defined methods map to HTTPS in real implementations.

QKD Graph
---------

QKD graphs are implemented to allow straightforward access to QKD buffers' state and convenient monitoring of key material consumption. QKD graph is associated with QKD buffer, allowing graph plotting on each node with associated QKD link and QKD buffer. QKD Graph creates separate PLT and DAT files suitable for plotting using a popular Gnuplot tool in PNG, SVG, or EPSLATEX format. QKDNetSim supports the plotting of the QKD Total Graph, which shows the overall consumption of key material in the QKD Network. The QKD total graph shows summarized consumption/generation of the keys in the whole network on both sides (Alice and Bob). That is, it includes keys that have been generated/consumed on Alice's and Bob's node.

QKD Key Manager System Application
----------------------------------

KMS is one of the essential components of the QKD networks' overall framework. It provides simple access to the QKD network's services for ITS key provisioning. Because the supply of keys is limited, the method of completing these tasks is critical. This component demanded the majority of our attention, particularly because methods at this layer are frequently overlooked in research papers, or are intentionally omitted. In this paper, we describe our implementation of the KMS and how it communicates with other components of the QKD network. We followed ITU-T guidelines and relied on standardized interfaces where possible (ETSI QKD 014 and ETSI QKD 004 in particular). The functionalities and interfaces of our custom KMS are described in the following sections.

Key Storage Function
~~~~~~~~~~~~~~~~~~~~

This section describes a key storage function, which includes a description of the K_q-1 interface (see figure of components), a reformat function, and the FILL method specification.

STORE_KEY Method
^^^^^^^^^^^^^^^^

First, we define the STORE_KEY method, which is defined for the K_q-1 interface and is used to transfer keys from QKD modules to KMS. It is defined as an HTTP request submitted through POST method. The parameters adhere to the ITU-T recommendation. We added a QKD module ID and matching QKD module ID, both in UUID format, to the list of mandatory parameters, which are optional by ITU-T recommendation. A QKD module ID will be used to identify the Q-buffer where the keys will be stored. In conjunction with the matching QKD module ID, the KMS pair will be able to generate a unique set of IDs for reformatted keys. Finally, the STORE_KEY body contains the value of the QKD key, which is in string format (in practice some may opt for Base64 encoded value).

Reformat Function
^^^^^^^^^^^^^^^^^

Our novel KMS design assumes that for any pair of connecting KMS systems (each housing a paired QKD module), a KMS with a higher node ID within the simulation experiment is chosen as the master. In practice, this can be accomplished by comparing KMS unique identifiers or IPv4 addresses. The QKD key received from the layer below is split into defined-size blocks by KMS, and unique IDs are generated that must be synchronized with the remote KMS. The master KMS generates IDs in the following manner:

.. math::

   HASH\_SHA \bigl( QKD\_key\_ID \mid QKD\ module\ ID \mid matching\ QKD\ module\ ID \mid chunk\ number \bigr)

where the chunk number is a sequence number of the key block. To generate the same IDs, the remote KMS (which is not in the role of a master) only switches the position of QKD module ID and matching QKD module ID values. A hash function's output is truncated to 8 character strings. We currently use SHA1 as a hash function, but we are looking into other options.

FILL Method
^^^^^^^^^^^

We define the FILL method at the KM link to pour keys from Q-buffer to LOCAL as well as STREAM S-buffers. It is an HTTP POST request. It enables the master KMS to instruct the slave KMS on which keys to transfer and to which type of S-buffer. The available keys from the Q-buffer are distributed evenly for the enc and dec LOCAL S-buffers. The STREAM S-buffer is always filled with up to six times the size of the key chunk. When KMS sends a request to fill the STREAM S-buffer, it includes the KSID value. The response includes a key IDs array of objects containing keys from the proposal that were accepted.

Key Validation
^^^^^^^^^^^^^^

KMS is required to synchronize and validate keys obtained from QKD modules, such as by exchanging hash values. The key material verification procedure is not implemented in QKDNetSim's KMS currently. Keys are marked as READY. As a result, QKD Post-Processing applications must be installed in such a way that a master application is always connected to the slave KMS. By supplying keys first to the slave KMS, we avoid situations in which the master KMS tries to use key material that does not exist at the slave KMS. This procedure can be implemented along the lines of the LOAD subprotocol of the Q3P design.

Key Relay Function
~~~~~~~~~~~~~~~~~~

Our novel KMS design supports key relay function across trusted-repeater QKD nodes in large-scale QKD networks. The key relay procedure is illustrated below, and corresponds to case a) of the key relay figure.

.. figure:: figures/sim-key-relay.*
   :alt: The key relay procedure
   :width: 100%

   The key relay procedure

The full procedure is explained step by step in the original document, covering initialization, next-hop determination, relay S-buffer population, encryption/decryption at each hop, and final confirmation.

The RELAY request data model is summarized below:

.. list-table:: RELAY Request Data Model
   :header-rows: 1
   :widths: 25 20 55

   * - Item
     - Type
     - Description
   * - source_node_id
     - uint32_t
     - Source KMS node ID.
   * - destination_node_id
     - uint32_t
     - Destination KMS node ID.
   * - repeater_node_id
     - uint32_t
     - Previous hop KMS node ID (optional).
   * - keys.key_ID
     - string
     - UUID of the key being relayed.
   * - keys.ekey_ID
     - string
     - UUID of the OTP encryption key.
   * - keys.ekey
     - string
     - Encrypted key material.

Key Supply Function
~~~~~~~~~~~~~~~~~~~

This section describes ETSI QKD 014 and ETSI QKD 004 API methods (GET_STATUS, GET_KEY, GET_KEY_WITH_KEY_IDS, OPEN_CONNECT, GET_KEY, CLOSE), their purpose, data flows, and how they interact with S-buffers and peer KMS instances.


Installation
------------

Installation instructions are available at QKDNetSim Github repository: https://github.com/QKDNetSim/qkdnetsim


Examples
--------

The examples are in the ``contrib/qkdnetsim/examples`` directory. 


ETSI 014 - Point-to-point example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Execlute file ``examples_qkdnetsim_etsi_014.cc`` from ``contrib/qkdnetsim/examples`` 

::
 
 $ ./ns3 run examples_qkdnetsim_etsi_014.cc


If you wish to obtain more detailed info about the work of some particular module you can execute NS_LOG commands to track code execution. In example:

::

 $ export NS_LOG=QKDApp014:QKDKeyManagerSystemApplication

The ``examples_qkdnetsim_etsi_014.cc`` establishes a network topology with nine nodes. QKD link is installed on nodes n0 and n2, while KMSs are installed on nodes n3 and n4. Finally, ETSI014 applications (client and server) are installed on node n7 and n8. QKD link generate keys which are pushed to KMSs and delivered to ETSI014 application (TCP traffic).

The output result should be:

::

CRYPTOGRAPHIC APPLICATION PAIR INSTALLED
   Master ID:  8304d62c-7206-11f0-8f8a-54bf64747a05   Local KMS node:   3
   Slave ID:   8304d62d-7206-11f0-8f8a-54bf64747a05   Local KMS node:   4
   Data rate:  100000bps   Packet size:   800

CRYPTOGRAPHIC APPLICATION PAIR INSTALLED
   Master ID:  8304d62e-7206-11f0-8f8a-54bf64747a05   Local KMS node:   4
   Slave ID:   8304d62f-7206-11f0-8f8a-54bf64747a05   Local KMS node:   3
   Data rate:  100000bps   Packet size:   800ADD GRAPHS! 
simTime: 500
appStartTime:  50
appStopTime:   500
qkdStartTime:  0
qkdStopTime:   500
encryptionType:   1
authenticationType:  1
aesLifetime:   10000
useCrypto:  0
trace:   0


APPLICATION STATS:

   APP-APP Data Packets Sent:
      Application ID:   8304d62c-7206-11f0-8f8a-54bf64747a05   Number:  1455     Bytes:   1318230
      Application ID:   8304d62e-7206-11f0-8f8a-54bf64747a05   Number:  3     Bytes:   2718

   APP-APP Data Packets Received:
      Application ID:   8304d62d-7206-11f0-8f8a-54bf64747a05   Number:  1455     Bytes:   1318230
      Application ID:   8304d62f-7206-11f0-8f8a-54bf64747a05   Number:  3     Bytes:   2718

   Missed Send Packet Calls:
      Application ID:   8304d62c-7206-11f0-8f8a-54bf64747a05   Number:  5577
      Application ID:   8304d62e-7206-11f0-8f8a-54bf64747a05   Number:  7029

   APP-APP Signaling Packets Sent:
      Application ID:   8304d62c-7206-11f0-8f8a-54bf64747a05   Number:  1103     Bytes:   587899
      Application ID:   8304d62d-7206-11f0-8f8a-54bf64747a05   Number:  1103     Bytes:   301119
      Application ID:   8304d62e-7206-11f0-8f8a-54bf64747a05   Number:  3     Bytes:   1599
      Application ID:   8304d62f-7206-11f0-8f8a-54bf64747a05   Number:  3     Bytes:   819

   APP-APP Signaling Packets Received:
      Application ID:   8304d62c-7206-11f0-8f8a-54bf64747a05   Number:  1103     Bytes:   301119
      Application ID:   8304d62d-7206-11f0-8f8a-54bf64747a05   Number:  1103     Bytes:   587899
      Application ID:   8304d62e-7206-11f0-8f8a-54bf64747a05   Number:  3     Bytes:   819
      Application ID:   8304d62f-7206-11f0-8f8a-54bf64747a05   Number:  3     Bytes:   1599

   APP-KM Packets Sent:
      Application ID:   8304d62c-7206-11f0-8f8a-54bf64747a05   Number:  1623     Bytes:   698616
      Application ID:   8304d62d-7206-11f0-8f8a-54bf64747a05   Number:  1103     Bytes:   637534
      Application ID:   8304d62e-7206-11f0-8f8a-54bf64747a05   Number:  1416     Bytes:   608862
      Application ID:   8304d62f-7206-11f0-8f8a-54bf64747a05   Number:  3     Bytes:   1734

   APP-KM Packets Received:
      Application ID:   8304d62c-7206-11f0-8f8a-54bf64747a05   Number:  1623     Bytes:   1666664
      Application ID:   8304d62d-7206-11f0-8f8a-54bf64747a05   Number:  1103     Bytes:   1419634
      Application ID:   8304d62e-7206-11f0-8f8a-54bf64747a05   Number:  1416     Bytes:   623250
      Application ID:   8304d62f-7206-11f0-8f8a-54bf64747a05   Number:  3     Bytes:   8309

QKD LINK STATS:

   Link (8304d62b-7206-11f0-8f8a-54bf64747a05-8304d630-7206-11f0-8f8a-54bf64747a05) Generated (bits):131072
   Link (8304d62b-7206-11f0-8f8a-54bf64747a05-8304d631-7206-11f0-8f8a-54bf64747a05) Generated (bits):131072
   Link (8304d62b-7206-11f0-8f8a-54bf64747a05-8304d632-7206-11f0-8f8a-54bf64747a05) Generated (bits):131072
   Link (8304d62b-7206-11f0-8f8a-54bf64747a05-8304d633-7206-11f0-8f8a-54bf64747a05) Generated (bits):131072
   Link (8304d62b-7206-11f0-8f8a-54bf64747a05-8304d634-7206-11f0-8f8a-54bf64747a05) Generated (bits):131072

Since QKDApp014 included encryption (OTP, encryptionType:   1) and authentication (VMAC, authenticationType:  1), QKDNetSim implemented two independent sessions to peer KMSs to fetch needed keys. That is, in total there are four application IDs, two for master (Alice) and two for slave (Bob). The results show the amount of key fetched, consumed, and exchanged signaling packets between QKD network entities. 

You can plot and analyze the output graphs using gnuplot:

::

 $ gnuplot *.plt

One can notice there are graphs for QBuffers, SBuffers and one total graph. In case of ETSI014, QKDNetSim generates two SBuffers (type LOCAL) per KMS connection for encryption and decryption purposes. More details about those buffers can be found in our paper (https://doi.org/doi.org/10.1364/JOCN.503356). In general, keys are stored in QBuffers, and moved to SBuffers. The graphs show higher fluctuations in SBuffers since those buffers are intensively used for ETSI014 traffic.

.. QKD Graph - QBuffer:
 
.. figure:: figures/014_QKD_keys_34.*
   :align: center


.. QKD Total Graph:
 
.. figure:: figures/014_QKD_Total_Graph.*
   :align: center


.. QKD Graph - SBuffer (LOCAL) - encryption:
 
.. figure:: figures/014_SBUFFER_LOCAL_etween_3_and_4_Encryption.*
   :align: center


Remove all generate plots and execute the ``examples_qkdnetsim_etsi_014.cc`` by using AES256 encryption instead of OTP. Plot new graphs and compere results.

:: 

 $ ./ns3 run "examples_qkdnetsim_etsi_014.cc --encryptionType=2"
 $ gnuplot *.plt


ETSI 004 - Point-to-point example
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Execlute file ``examples_qkdnetsim_etsi_004.cc`` from ``contrib/qkdnetsim/examples`` 

::
 
 $ ./ns3 run "examples_qkdnetsim_etsi_004.cc"


If you wish to obtain more detailed info about the work of some particular module you can execute NS_LOG commands to track code execution. In example:

::

 $ export NS_LOG=QKDApp004:QKDKeyManagerSystemApplication

The ``examples_qkdnetsim_etsi_004.cc`` establishes a network topology with nine nodes. QKD link is installed on nodes n0 and n2, while KMSs are installed on nodes n3 and n4. Finally, ETSI004 applications (client and server) are installed on node n7 and n8. QKD link generate keys which are pushed to KMSs and delivered to ETSI014 application (TCP traffic).


The output result should be:

::


CRYPTOGRAPHIC APPLICATION PAIR INSTALLED
   Master ID:  9ca6f954-7209-11f0-8f8a-54bf64747a05   Local KMS node:   3
   Slave ID:   9ca6f955-7209-11f0-8f8a-54bf64747a05   Local KMS node:   4
   Data rate:  100000bps   Packet size:   800ADD GRAPHS! 
simTime: 500
appStartTime:  50
appStopTime:   500
qkdStartTime:  0
qkdStopTime:   500
encryptionType:   1
authenticationType:  1
aesLifetime:   10000
keyBufferLengthEncryption: 3
keyBufferLengthAuthentication:   6
useCrypto:  0
trace:   0


APPLICATION STATS:

   APP-APP Data Packets Sent:

   APP-APP Data Packets Received:

   Missed Send Packet Calls:

   APP-APP Signaling Packets Sent:
      Application ID:   9ca6f954-7209-11f0-8f8a-54bf64747a05   Number:  3     Bytes:   1344
      Application ID:   9ca6f955-7209-11f0-8f8a-54bf64747a05   Number:  2     Bytes:   835

   APP-APP Signaling Packets Received:
      Application ID:   9ca6f954-7209-11f0-8f8a-54bf64747a05   Number:  2     Bytes:   835
      Application ID:   9ca6f955-7209-11f0-8f8a-54bf64747a05   Number:  3     Bytes:   1344

   APP-KM Packets Sent:
      Application ID:   9ca6f954-7209-11f0-8f8a-54bf64747a05   Number:  16642    Bytes:   7805261
      Application ID:   9ca6f955-7209-11f0-8f8a-54bf64747a05   Number:  18153    Bytes:   8513971

   APP-KM Packets Received:
      Application ID:   9ca6f954-7209-11f0-8f8a-54bf64747a05   Number:  16642    Bytes:   6552736
      Application ID:   9ca6f955-7209-11f0-8f8a-54bf64747a05   Number:  18153    Bytes:   7037935

QKD LINK STATS:

    QKDSystem link: 9ca6f953-7209-11f0-8f8a-54bf64747a05  keyId: 9ca6f956-7209-11f0-8f8a-54bf64747a05  Size: 65536 (bits)
    QKDSystem link: 9ca6f953-7209-11f0-8f8a-54bf64747a05  keyId: 9ca6f957-7209-11f0-8f8a-54bf64747a05  Size: 65536 (bits)
    QKDSystem link: 9ca6f953-7209-11f0-8f8a-54bf64747a05  keyId: 9ca6f958-7209-11f0-8f8a-54bf64747a05  Size: 65536 (bits)
    QKDSystem link: 9ca6f953-7209-11f0-8f8a-54bf64747a05  keyId: 9ca6f959-7209-11f0-8f8a-54bf64747a05  Size: 65536 (bits)
    QKDSystem link: 9ca6f953-7209-11f0-8f8a-54bf64747a05  keyId: 9ca6f95a-7209-11f0-8f8a-54bf64747a05  Size: 65536 (bits)
    QKDSystem link: 9ca6f953-7209-11f0-8f8a-54bf64747a05  keyId: 9ca6f95b-7209-11f0-8f8a-54bf64747a05  Size: 65536 (bits)
    QKDSystem link: 9ca6f953-7209-11f0-8f8a-54bf64747a05  keyId: 9ca6f95c-7209-11f0-8f8a-54bf64747a05  Size: 65536 (bits)
    QKDSystem link: 9ca6f953-7209-11f0-8f8a-54bf64747a05  keyId: 9ca6f95f-7209-11f0-8f8a-54bf64747a05  Size: 65536 (bits)


You can plot and analyze the output graphs using gnuplot:

::

 $ gnuplot *.plt

One can notice there are graphs for QBuffers, SBuffers and one total graph. However, in case of ETSI004, QKDNetSim generates additional two SBuffers (type STREAM) that are dedicated for ETSI004 application session. More details about those buffers can be found in our paper (https://doi.org/doi.org/10.1364/JOCN.503356).  

.. QKD Graph - QBuffer:
 
.. figure:: figures/004_QKD_keys_34.*
   :align: center


.. QKD Total Graph:
 
.. figure:: figures/004_QKD_Total_Graph.*
   :align: center


.. QKD Graph - SBuffer (STREAM):
 
.. figure:: figures/004_SBUFFER_STREAM_3-SAE_9ca6f954-7209-11f0-8f8a-54bf64747a05-4-SAE_9ca6f955-7209-11f0-8f8a-54bf64747a05.*
   :align: center


Remove all generate plots and execute the ``examples_qkdnetsim_etsi_004.cc`` by using AES256 encryption instead of OTP. Plot new graphs and compere results.

:: 

 $ ./ns3 run "examples_qkdnetsim_etsi_004.cc --encryptionType=2"
 $ gnuplot *.plt


SECOQC QKD Network
~~~~~~~~~~~~~~~~~~


Execute file ``examples_qkdnetsim_secoqc.cc`` from ``contrib/qkdnetsim/examples`` 

::
 
 $ ./ns3 run "examples_qkdnetsim_secoqc.cc"


This example creats six QKD links and one ETSI014 application pair. 

::

QKDsiteA: 0 IP address: 10.1.1.1
QKDsiteB: 2 IP address: 10.1.1.2
QKDsiteC: 4 IP address: 10.1.5.2
KMsiteA: 1 IP address: 10.1.3.1
KMsiteB: 3 IP address: 10.1.3.2
KMsiteC: 5 IP address: 10.1.7.2


CRYPTOGRAPHIC APPLICATION PAIR INSTALLED
   Master ID:  e7bf595a-720c-11f0-8f8a-54bf64747a05   Local KMS node:   1
   Slave ID:   e7bf595b-720c-11f0-8f8a-54bf64747a05   Local KMS node:   11
   Data rate:  100000bps   Packet size:   800ADD GRAPHS! 
simTime: 500
appStartTime:  50
appStopTime:   500
qkdStartTime:  0
qkdStopTime:   500
encryptionType:   1
authenticationType:  1
aesLifetime:   10000
useCrypto:  0
trace:   0


APPLICATION STATS:

   APP-APP Data Packets Sent:
      Application ID:   e7bf595a-720c-11f0-8f8a-54bf64747a05   Number:  6     Bytes:   5436

   APP-APP Data Packets Received:
      Application ID:   e7bf595b-720c-11f0-8f8a-54bf64747a05   Number:  6     Bytes:   5436

   Missed Send Packet Calls:
      Application ID:   e7bf595a-720c-11f0-8f8a-54bf64747a05   Number:  7026

   APP-APP Signaling Packets Sent:
      Application ID:   e7bf595a-720c-11f0-8f8a-54bf64747a05   Number:  4     Bytes:   2136
      Application ID:   e7bf595b-720c-11f0-8f8a-54bf64747a05   Number:  4     Bytes:   1096

   APP-APP Signaling Packets Received:
      Application ID:   e7bf595a-720c-11f0-8f8a-54bf64747a05   Number:  4     Bytes:   1096
      Application ID:   e7bf595b-720c-11f0-8f8a-54bf64747a05   Number:  4     Bytes:   2136

   APP-KM Packets Sent:
      Application ID:   e7bf595a-720c-11f0-8f8a-54bf64747a05   Number:  2827     Bytes:   1217002
      Application ID:   e7bf595b-720c-11f0-8f8a-54bf64747a05   Number:  4     Bytes:   2316

   APP-KM Packets Received:
      Application ID:   e7bf595a-720c-11f0-8f8a-54bf64747a05   Number:  2827     Bytes:   1235435
      Application ID:   e7bf595b-720c-11f0-8f8a-54bf64747a05   Number:  4     Bytes:   5721

QKD LINK STATS:

    QKDSystem link: e7bf594f-720c-11f0-8f8a-54bf64747a05  keyId: e7bf595c-720c-11f0-8f8a-54bf64747a05  Size: 65536 (bits)
    QKDSystem link: e7bf594f-720c-11f0-8f8a-54bf64747a05  keyId: e7bf5962-720c-11f0-8f8a-54bf64747a05  Size: 65536 (bits)
    QKDSystem link: e7bf594f-720c-11f0-8f8a-54bf64747a05  keyId: e7bf5968-720c-11f0-8f8a-54bf64747a05  Size: 65536 (bits)
    QKDSystem link: e7bf594f-720c-11f0-8f8a-54bf64747a05  keyId: e7bf596d-720c-11f0-8f8a-54bf64747a05  Size: 65536 (bits)
    QKDSystem link: e7bf594f-720c-11f0-8f8a-54bf64747a05  keyId: e7bf5973-720c-11f0-8f8a-54bf64747a05  Size: 65536 (bits)
    QKDSystem link: e7bf594f-720c-11f0-8f8a-54bf64747a05  keyId: e7bf5979-720c-11f0-8f8a-54bf64747a05  Size: 65536 (bits)
    QKDSystem link: e7bf594f-720c-11f0-8f8a-54bf64747a05  keyId: e7bf597e-720c-11f0-8f8a-54bf64747a05  Size: 65536 (bits)
    QKDSystem link: e7bf594f-720c-11f0-8f8a-54bf64747a05  keyId: e800463a-720c-11f0-8f8a-54bf64747a05  Size: 65536 (bits)
    QKDSystem link: e7bf594f-720c-11f0-8f8a-54bf64747a05  keyId: e8004640-720c-11f0-8f8a-54bf64747a05  Size: 65536 (bits)
    QKDSystem link: e7bf594f-720c-11f0-8f8a-54bf64747a05  keyId: e8004646-720c-11f0-8f8a-54bf64747a05  Size: 65536 (bits)
    QKDSystem link: e7bf594f-720c-11f0-8f8a-54bf64747a05  keyId: e800464b-720c-11f0-8f8a-54bf64747a05  Size: 65536 (bits)
    QKDSystem link: e7bf594f-720c-11f0-8f8a-54bf64747a05  keyId: e8004651-720c-11f0-8f8a-54bf64747a05  Size: 65536 (bits)
    QKDSystem link: e7bf594f-720c-11f0-8f8a-54bf64747a05  keyId: e8004657-720c-11f0-8f8a-54bf64747a05  Size: 65536 (bits)
    QKDSystem link: e7bf594f-720c-11f0-8f8a-54bf64747a05  keyId: e800465c-720c-11f0-8f8a-54bf64747a05  Size: 65536 (bits)
    QKDSystem link: e7bf594f-720c-11f0-8f8a-54bf64747a05  keyId: e8004662-720c-11f0-8f8a-54bf64747a05  Size: 65536 (bits)
    QKDSystem link: e7bf594f-720c-11f0-8f8a-54bf64747a05  keyId: e8004668-720c-11f0-8f8a-54bf64747a05  Size: 65536 (bits)



You can plot and analyze the output graphs using gnuplot:

::

 $ gnuplot *.plt

One can notice there are additional two SBuffers (type RELAY) that are dedicated for key-relay operation on key management layer. More details about those buffers can be found in our paper (https://doi.org/doi.org/10.1364/JOCN.503356).  

.. QKD Graph - SBuffer (RELAY):
 
.. figure:: figures/secoqc_SBUFFER_RELAY_1_11.*
   :align: center


Remove all generate plots and execute the ``examples_qkdnetsim_secoqc.cc`` by using AES256 encryption instead of OTP. Plot new graphs and compere results.

:: 

 $ ./ns3 run "examples_qkdnetsim_secoqc.cc --encryptionType=2"
 $ gnuplot *.plt


Custom QKD Netork Topology
~~~~~~~~~~~~~~~~~~~~~~~~~~

The easiest way to create your own custom QKD network topology is to use QKDNetSim web interface via www.open-qkd.eu. There, you can create your network, simulate it, and download the configuration settings. Then, store the "input.json" configuration file in the root of QKDNetSim (``contrib/qkdnetsim/examples``), and execute

::
 
 $ ./ns3 run "examples_qkdnetsim_etsi_combined_input.cc" 


You can plot and analyze the output graphs using gnuplot:

::

 $ gnuplot *.plt

.. QKD web-interface (www.open-qkd.eu)
 
.. figure:: figures/qkdnetsim_web.*
   :align: center

Emulation Mode
------------

NS-3 with proper building instructions can emulate real network traffic. This functionality can be used within QKDNetSim for simulating specific parts of QKD technology separated by a real network. For emulation purposes in ns-3 we can use two devices. The first device is called TapBridge NetDevice; this device allows the real host to be included in ns-3 simulation. In other words, the real host is one of the simulated nodes. The second device is FdNetDevice. This device can read and write network traffic using a file descriptor. FdNetDevice can be used in two different modes, Emu and Tap. Tap device, which can appear in kernel as virtual net device after creation. The packets forwarded to this TAP device will appear in the running simulation. Emu  device will create a raw socket, which will be forwarded to the real network interface. The real network interface must be running in promiscuous mode, and the IP address of the Emu device must be from the same network as the real network interface \footnote{More specific information interested readers can find on (https://www.nsnam.org/docs/models/html/emulation-overview.html). In addition, in order for the communication to be recognized on devices in the real domain, it is necessary that all protocols are properly implemented. Since there is no HTTP protocol in the NS-3 core, we had to implement HTTP headers, parsers and protocol to be able to communicate with real devices. In our QKDNetSim emulation experiments[Meh24][Meh25], we used EmuFdNetDevice. 

Figure below shows an example emulation topology with specific addresses used during the experiment. Every part of the QKD system has been running on a separate virtual machine in the same network subnet. The experiment included a QKD link (two QKD systems), two KMS systems, and two ETSI applications. Every part of emulated systems (QKD node, KMS, ETSI applications) has a dedicated interface for communication with related nodes. IP addresses shown in the figure are addresses of \textit{EmuFdNetDevice}. For example, \textit{QKD Node Alice} used the sifting interface 192.168.1.10 just for establishing the key material and the interface 192.168.1.4 for communication and storage of the key material with KMS Alice. 

.. Simple P2P emulation topology.
 
.. figure:: figures/emulationQKD.*
   :align: center


.. Screenshots of emulated environment of QKDNetSim emulation scheme on UNSA server.
 
.. figure:: figures/qkdnetsim_emu_screenshots.*
   :align: center


The emulation mode of QKDNetSim represents a significant step forward that enables the realization of the QKD ecosystem under controlled conditions. In addition to the possibility of emulating networks with a larger number of nodes, the emulation mode enables the realization of experiments with commercial devices and applications, as well as testing the use of QKD technology in existing telecommunication networks.  

Experiment Setup
~~~~~~~~~~~~~~~~

To enable emulation mode and creation of raw sockets, it is necessary to reconfigure NS-3 with ``sudo`` permission:

::
 
 $ ./ns3 configure --enable-mpi --enable-sudo && ./ns3

Next, the host device must be set to promiscuous mode:
::
 
 $ sudo ip link set ens160 promisc on
   apt-get install ethtool -y
   sudo ethtool -K ens160 rx off tx off

Then, enable IPv4 forwarding:

::
 
 $ sudo sysctl -w net.ipv4.icmp_echo_ignore_all=0 
 sudo sysctl -w net.ipv4.ip_forward=1



You will need to assign an IP address to the ns-3 simulation node that is consistent with the subnet that is active on the host device's link. That is, you will have to assign an IP address to the ns-3 node as if it were on your real subnet.  

You will need to configure a default route in the ns-3 node to tell it how to get off of your subnet. One thing you could do is a ``netstat -rn`` command and find the IP address of the default gateway on your host. 

Execute:

:: 
 $  ./ns3 run "examples_qkdnetsim_etsi_014_emulation.cc"

 
The ``examples_qkdnetsim_etsi_014_emulation.cc`` establishes a network topology with nine nodes. QKD link is installed on nodes n0 and n2, while KMSs are installed on nodes n3 and n4. Finally, ETSI004 applications (client and server) are installed on nodes n7 and n8. QKD link generates keys which are pushed to KMSs and delivered to the ETSI014 application (TCP traffic). The output result should be:
 
It establishes the topology as described in the ETSI014 example above. The only difference is that on nodes with KMSs two EmuFdNetDevices are installed. The implementaton of KMS was realized such that it listens on IP 0.0.0.0, which means it will accept all connections on all IPs of the node as long as they match the defined port. Thus, connection to EmuFdNetDevice on KMS nodes (n3 and n4) will be accepted and processed.

 
// n7 ---------p2p------- n8 (app)
// | |
// n3 (kms) -- p2p ------- n4 (kms)
// | |
// n0 ---p2p-- n1 --p2p-- n2
// |<----qkd--x----------->|
 

QKD nodes establish keys (n0 and n2) and send them to the KMSs. You can request keys from KMSs using the following code in terminal:

 
KMS (n3) - MASTER:
::
 
 $ wget http://10.250.0.2/api/v1/keys/aaac7de9-5826-11ef-8057-9b39f247aaa/enc_keys/number/1/size/128
 
 
If there are available keys, you will get a response like: 

``{"keys":[{"key":"VkpWelpvQVdkTXN5UEZOYQ==\n","key_ID":"443450cc-792c-11f0-9f2d-096e1cfd0a37"}]}``

You can already notice from the URL that it is possible to change the number of keys you are obtaining and their size in bits.
However, if you get a 400 Bad Request response, this means that there are not enough keys available at the moment. Try again after a few seconds.

::
 
 $ wget http://10.250.0.2/api/v1/keys/aaac7de9-5826-11ef-8057-9b39f247aaa/enc_keys/number/1/size/128 

``
--2025-08-14 18:20:32-- 
http://10.250.0.2/api/v1/keys/aaac7de9-5826-11ef-8057-9b39f247aaa/
enc_keys/number/1/size/128 
Connecting to 10.250.0.2:80... connected. 
HTTP request sent, awaiting response... 400 Bad Request  
``

To fetch decryption keys on n4 (peer KMS):

::
 
 $ wget \ 
 --method=POST \ 
 --header='Content-Type: application/json' \ 
 --header='Accept: application/json' \ 
 --body-data='{"key_IDs":[{"key_ID":"443450cc-792c-11f0-9f2d-096e1cfd0a37"}]}' \ 
 'http://10.250.1.2/api/v1/keys/bbbc7de9-5826-11ef-8057-9b39f247bbb/dec_keys' \ 
 -O -


Update
------
Last Update: December 2025

Cite
----

* .. Dervisevic, E., Voznak, M. and Mehic, M., 2024. Large-Scale Quantum Key Distribution Network Simulator. Journal of Optical Communications and Networking, doi: https://www.doi.org/10.1364/JOCN.503356
* .. Dervisevic, E., Tankovic, A., Kaljic, E., Voznak, M. and Mehic, M., 2025. Design of a Key Management System for Efficient Key Supply in Quantum Key Distribution Networks. Journal of Optical Communications and Networking, doi: https://www.doi.org/10.1364/JOCN.577670
* .. Dervisevic, E., Tankovic, A., Fazel, E., Kompella, R., Fazio, P., Voznak, M. and Mehic, M., 2025. Quantum Key Distribution Networks – Key Management: A Survey. ACM Computing Surveys, 57(10), pp. 1–36, doi: https://www.doi.org/10.1145/3730575
* .. Mehic, M., Dervisevic, E., Burdiak, P., Lipovac, V., Fazio, P. and Voznak, M., 2024. Emulation of quantum key distribution networks. IEEE Network, 39(1), pp.116-123. doi: https://www.doi.org/10.1109/MNET.2024.3398404
* .. Mehic, M., Dervisevic, E., Fazio, P. and Voznak, M., 2025. Virtual Quantum Key Distribution Network Ecosystem: The National Czech QKD Network. IEEE Network., 39(3), pp.173-179. doi: https://www.doi.org/10.1109/MNET.2025.3540705

References
----------

* .. [Ben84] C. H. Bennett and G. Brassard, *Quantum cryptography: Public key distribution and coin tossing*, in Proceedings of IEEE International Conference on Computers, Systems and Signal Processing, 1984.

* .. [Ver26] G. S. Vernam, *Cipher printing telegraph systems for secret wire and radio telegraphic communications*, J. Amer. Inst. Elect. Eng., vol. 45, pp. 109–115, 1926.

* .. [Sha49] C. E. Shannon, *Communication theory of secrecy systems*, Bell Syst. Tech. J., vol. 28, no. 4, pp. 656–715, 1949.

* .. [Ben92] C. H. Bennett et al., *Experimental quantum cryptography*, Journal of Cryptology, vol. 5, no. 1, pp. 3–28, 1992.

* .. [Bra93] G. Brassard and L. Salvail, *Secret key reconciliation by public discussion*, Advances in Cryptology — EUROCRYPT’93, pp. 410–423, 1993.

* .. [Meh20] D. Mehic et al., *Quantum key distribution networks: from theory to practice*, IEEE Communications Surveys & Tutorials, vol. 22, no. 4, pp. 2114–2144, 2020.

* .. [Ben86] C. H. Bennett et al., *Reduction of error rates in quantum cryptography*, IBM Research Report, 1986.

* .. [Ben88] C. H. Bennett et al., *Privacy amplification by public discussion*, SIAM J. Comput., vol. 17, no. 2, pp. 210–229, 1988.

* .. [Luc18] M. Lucamarini et al., *Overcoming the rate–distance limit of quantum key distribution without quantum repeaters*, Nature, vol. 557, pp. 400–403, 2018.

* .. [Yua18] Z. Yuan et al., *10-Mb/s quantum key distribution*, npj Quantum Information, vol. 4, 2018.

* .. [Zha20] Q. Zhang et al., *Long-distance quantum key distribution: Technologies and challenges*, Quantum Science and Technology, vol. 5, 2020.

* .. [Meh17] M. Mehic et al., *Implementation of QKDNetSim: a quantum key distribution network simulator in NS-3*, 2017.

* .. [Dah18] A. Dahlberg et al., *SimulaQron: a simulator for developing quantum internet software*, Quantum Science and Technology, vol. 4, 2018.

* .. [Coo21] T. Coopmans et al., *NetSquid: a discrete-event simulator for quantum networks*, Quantum Science and Technology, vol. 6, 2021.

* .. [Wu21] C. Wu et al., *Sequence simulation in quantum networks*, IEEE Access, vol. 9, 2021.

* .. [Sat21] T. Satoh et al., *QuISP: simulation framework for quantum networks*, 2021.

* .. [Dia21] S. Diadamo et al., *QuneSim: quantum network simulator*, 2021.

* .. [Bar18] B. Bartlett, *A distributed simulation framework for quantum networks and channels*, arXiv:1808.07047, 2018.

* .. [Meh22] M. Mehic et al., *Modern challenges in quantum key distribution network management*, 2022.

* .. [Ell02] C. Elliott, *Building the quantum network*, New J. Phys., vol. 4, 2002.

* .. [Ell03] C. Elliott et al., *Current status of the DARPA Quantum Network*, 2003.

* .. [Tan16] K. Tanizawa et al., *Routing in QKD networks*, IEICE Transactions, 2016.

* .. [Yan17] X. Yang et al., *QKD routing based on key rate constraints*, IEEE Access, 2017.

* .. [ITU3800] ITU-T Recommendation X.3800, *Overview of Quantum Key Distribution Network*, 2019.

* .. [ITU3801] ITU-T Recommendation X.3801, *Functional requirements of Quantum Key Distribution Networks*, 2019.

* .. [ITU3802] ITU-T Recommendation X.3802, *Key management in QKD networks*, 2020.

* .. [ITU3803] ITU-T Recommendation X.3803, *Detailed key relay procedures in QKD networks*, 2021.

* .. [ITU3804] ITU-T Recommendation X.3804, *Control and management of QKD networks*, 2021.

* .. [ETSI014] ETSI GS QKD 014 V1.1.1, *Quantum Key Distribution (QKD); Protocol and data model for QKD key delivery interface*, 2020.

* .. [ETSI004] ETSI GS QKD 004 V1.1.1, *Quantum Key Distribution (QKD); Interface and key delivery for secure applications*, 2020.
 
* .. [Meh24] M. Mehic et al. Emulation of quantum key distribution networks. Ieee network. 2024 May 8;39(1):116-23.

* .. [Meh25] M. Mehic et al. Virtual Quantum Key Distribution Network Ecosystem: The National Czech QKD Network. IEEE network. 2025 Feb 10.


Acknowledgment
--------------

Development of QKDNetSim was supporty within project #VJ01010008 “Network Cybersecurity in Post-Quantum Era” by the Ministry of the Interior of Czech Republic in program Impakt.
 
   .. figure:: figures/cz.*  
      :alt: Ministry of the Interior of Czech Republic

Development of QKDNetSim was also supporty by the Ministry of Science, Higher Education and Youth of Canton Sarajevo, Bosnia and Herzegovina (27-02-35-37082-1/23).
 
   .. figure:: figures/monks.*  
      :alt: Ministry of Science, Higher Education and Youth of Canton Sarajevo, Bosnia and Herzegovina

## Quantum Key Distribution Network Simulation Module (v2.0)

As research in Quantum Key Distribution (QKD) technology grows larger and more complex, the need for highly accurate and scalable simulation technologies becomes important to assess the practical feasibility and foresee difficulties in the practical implementation of theoretical achievements. Due to the specificity of QKD link which requires optical and Internet connection between the network nodes, it is very costly to deploy a complete testbed containing multiple network hosts and links to validate and verify a certain network algorithm or protocol. The network simulators in these circumstances save a lot of money and time in accomplishing such task. A simulation environment offers the creation of complex network topologies, a high degree of control and repeatable experiments, which in turn allows researchers to conduct exactly the same experiments and confirm their results.

The aim of Quantum Key Distribution Network Simulation Module (QKDNetSim) project was not to develop the entire simulator from scratch but to develop the QKD simulation module in some of the already existing well-proven simulators. QKDNetSim is intended to facilitate additional understanding of QKD technology with respect to the existing network solutions. It seeks to serve as the natural playground for taking the further steps into this research direction (even towards practical exploitation in subsequent projects or product design).

Here, we provide the LIMITED PUBLIC VERSION of QKDNetSim source code which was developed in the network simulator of version 3 (NS-3). 

## Deployment

The code is periodically updated in accordance with the NS-3 dev version of the NS-3 simulator. The latest code corresponds to the NS-3 version 3.41.
Platform

QKDNetSim has been successfully tested on linux distributions:

    Ubuntu 22.04

## Installation

- **The latest version of the code is compatible with NS-3 version 3.41.**  
- Thus, one should follow installation requirements from the NS-3 official website (https://www.nsnam.org/wiki/Installation).   
- The code has been successfully tested on Ubuntu 22.04. 
- QKDNetSim v2.0 module is not compatible with QKDNetSim version 1.0 (https://v1.qkdnetsim.info). This module is written independently and from scratch.

QKDNetSim includes QKDEncryptor class that relies on cryptographic algorithms and schemes from Crypto++ open-source C++ class cryptographic library. Currently, QKD crypto supports several cryptographic algorithms and cryptographic hashes, including One-Time Pad (OTP) cipher, Advanced Encryption Standard (AES) block cipher, VMAC message authentication code (MAC) algorithm, and others.

In addition to NS-3 v3.41 requirements, it is necessary to install crypto++ (libcryptopp) and Universally Unique Identifiers (UUIDs) libraries:

```bash
sudo apt-get install libcrypto++-dev libcrypto++-doc libcrypto++-utils gnuplot uuid-dev
```

Execute:

```bash
cd  
git clone https://github.com/QKDNetSim/qkdnetsim-v2.git
cd qkdnetsim-v2
./ns3 configure --enable-mpi
./ns3 
```

Execute the test script:

```bash
./ns3 run scratch/qkd_etsi_014.cc
```
 


## Authors

QKDNetSim is maintained by:

Department of Telecommunications (www.tk.etf.unsa.ba)  
Faculty of Electrical Engineering  
University of Sarajevo  
Zmaja od Bosne bb  
71000 Sarajevo  
Bosnia and Herzegovina  

Department of Telecommunications (www.comtech.vsb.cz)  
VSB Technical University of Ostrava  
17 . listopadu 15/2172  
Ostrava-Poruba 708 33  
Czech Republic  

**Main developers:**

- Emir Dervisevic
- Miroslav Voznak
- Miralem Mehic

Contact us via email (miralem.mehic[at]ieee.org).

## Cite 

Dervisevic, E., Voznak, M. and Mehic, M., 2024. Large-Scale Quantum Key Distribution Network Simulator. Journal of Optical Communications and Networking, doi: https://www.doi.org/10.1364/JOCN.503356

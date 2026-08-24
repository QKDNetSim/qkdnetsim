/*
 * Copyright (c) 2022 www.tk.etf.unsa.ba
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author:  Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 *          Miralem Mehic <miralem.mehic@ieee.org>
 */

#include <fstream>
#include "ns3/core-module.h"
#include "ns3/applications-module.h"
#include "ns3/internet-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/mobility-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/gnuplot.h"

#include "ns3/qkd-link-helper.h"
#include "ns3/qkd-app-helper.h"
#include "ns3/qkd-app-014.h"

#include "ns3/network-module.h"
#include "ns3/internet-apps-module.h"
#include "ns3/netanim-module.h"
//#include "ns3/mpi-module.h"

#include <iostream>
#include <random>
#include <utility>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("QKD_ETSI014");

uint32_t m_tx_count = 0;
uint32_t m_tx_bits = 0;
uint32_t m_rx_count = 0;
uint32_t m_rx_bits = 0;

uint32_t showKeyAdded = 1;
uint32_t showKeyServed = 1;
std::map<std::string, Ipv4InterfaceContainer> m_interfaces;

std::string outputFileType ("json");
std::ofstream logFile;
nlohmann::json outputLogFile;

struct LinkDetails
{
    std::string title;
    std::string nodes;
    uint32_t type; //0-PP; 1-ETSI004; 2-ETSI014

    uint32_t m_linkDistance = 0;
    uint32_t m_keyRate = 0;
    uint32_t m_keysGenerated = 0;
    uint32_t m_keysGeneratedBits = 0;
    uint32_t m_keysConsumed = 0;
    uint32_t m_keysConsumedBits = 0;

    uint32_t m_keysConsumed_PQC = 0;
    uint32_t m_keysConsumedBits_PQC = 0;

    uint32_t m_bufferCapacityBits = 0;
    double m_avgSizeOfGeneratedKeys = 0;
    double m_avgSizeOfConsumedKeys = 0;
    double m_avgSizeOfConsumedKeys_PQC = 0;

    uint32_t m_appPacketsSent = 0;
    uint32_t m_appPacketsReceived = 0;
    uint32_t m_bytes_sent = 0;  
    uint32_t m_bytes_received = 0; 
    uint32_t m_missedSendPacketCalls = 0;

    uint32_t m_encryptionType;
    uint32_t m_authenticationType;
    uint32_t m_aesLifeTime = 0;
    uint32_t m_packetSize = 0;
    uint32_t m_trafficRate = 0;
    uint32_t m_sizeOfKeyBufferForEncryption = 0;
    uint32_t m_sizeOfKeyBufferForAuthentication = 0;
    uint32_t m_numberOfKeysToFetchFromKMS = 0;
    uint32_t m_startTime = 0;
    uint32_t m_stopTime = 0;

    uint32_t m_appSigPacketsSent = 0;
    uint32_t m_appSigPacketsReceived = 0;
    uint32_t m_sig_bytes_sent = 0;  
    uint32_t m_sig_bytes_received = 0;

    uint32_t m_kmsPacketsSent = 0;
    uint32_t m_kmsPacketsReceived = 0;
    uint32_t m_bytes_sent_to_kms = 0;  
    uint32_t m_bytes_received_from_kms = 0; 
    
    uint32_t m_keysWasted = 0;
    uint32_t m_keysWastedBits = 0;

    uint32_t m_keysRelayed = 0;
    uint32_t m_keysRelayedBits = 0;
    
    uint32_t srcNodeId = 0;
    uint32_t dstNodeId = 0;  

    uint32_t srcKMSNodeId = 0;
    uint32_t dstKMSNodeId = 0;   

    uint32_t m_printed = 0;

    std::map<std::string, uint32_t> m_keyIDConsumedByKMS;
    std::map<std::string, uint32_t> m_keyIDConsumedInBuffers;
    std::map<std::string, uint32_t> m_keyIDConsumedInBuffers_PQC;
    std::map<std::string, uint32_t> m_keyIDGeneratedInBuffers;

    Ptr<QKDApp004> etsi004srcApp = nullptr;
    Ptr<QKDApp004> etsi004dstApp = nullptr;
    std::string m_etsi014Ksid;

};

std::map<std::string, LinkDetails*> m_nodePairs;

void 
write_csv(std::string filename,
          std::vector<std::pair<std::string, std::vector<uint32_t>>> dataset)
{
    std::ofstream myFile(filename);

    // =========================
    // SAFETY: empty dataset
    // =========================
    if (dataset.empty())
    {
        NS_LOG_WARN("write_csv: dataset is empty -> writing empty file");
        myFile.close();
        return;
    }

    // =========================
    // SAFETY: ensure at least one column has data
    // =========================
    size_t rowCount = 0;
    bool hasData = false;

    for (const auto &col : dataset)
    {
        if (!col.second.empty())
        {
            rowCount = col.second.size();
            hasData = true;
            break;
        }
    }

    if (!hasData)
    {
        NS_LOG_WARN("write_csv: all columns empty -> writing only headers");
    }

    // =========================
    // OPTIONAL SAFETY: verify equal column sizes
    // =========================
    for (const auto &col : dataset)
    {
        if (!col.second.empty() && col.second.size() != rowCount)
        {
            NS_LOG_ERROR("write_csv: column size mismatch detected!");
            myFile.close();
            return;
        }
    }

    // =========================
    // Write headers
    // =========================
    for (size_t j = 0; j < dataset.size(); ++j)
    {
        myFile << dataset[j].first;
        if (j != dataset.size() - 1)
            myFile << ",";
    }
    myFile << "\n";

    // =========================
    // Write data
    // =========================
    for (size_t i = 0; i < rowCount; ++i)
    {
        for (size_t j = 0; j < dataset.size(); ++j)
        {
            if (i < dataset[j].second.size())
                myFile << dataset[j].second[i];
            else
                myFile << ""; // safe fallback

            if (j != dataset.size() - 1)
                myFile << ",";
        }
        myFile << "\n";
    }

    myFile.close();
}


std::vector<std::pair<std::string, std::vector<uint32_t>>> 
read_csv(std::string filename){
    // Reads a CSV file into a vector of <string, vector<uint32_t>> pairs where
    // each pair represents <column name, column values>

    // Create a vector of <string, uint32_t vector> pairs to store the result
    std::vector<std::pair<std::string, std::vector<uint32_t> > > result;

    // Create an input filestream
    std::ifstream myFile(filename);

    // Make sure the file is open
    if(!myFile.is_open()) throw std::runtime_error("Could not open file");

    // Helper vars
    std::string line, colname;
    uint32_t val;

    // Read the column names
    if(myFile.good())
    {
        // Extract the first line in the file
        std::getline(myFile, line);

        // Create a stringstream from line
        std::stringstream ss(line);

        // Extract each column name
        while(std::getline(ss, colname, ',')){
            
            // Initialize and add <colname, uint32_t vector> pairs to result
            result.push_back({colname, std::vector<uint32_t> {}});
        }
    }

    // Read data, line by line
    while(std::getline(myFile, line))
    {
        // Create a stringstream of the current line
        std::stringstream ss(line);
        
        // Keep track of the current column index
        uint32_t colIdx = 0;
        
        // Extract each integer
        while(ss >> val){
            
            // Add the current integer to the 'colIdx' column's values vector
            result.at(colIdx).second.push_back(val);
            
            // If the next token is a comma, ignore it and move on
            if(ss.peek() == ',') ss.ignore();
            
            // Increment the column index
            colIdx++;
        }
    }

    // Close file
    myFile.close();
    return result;
}


//////////
void
KeyGenerated(std::string context, const std::string& appId, const std::string& keyId, const uint32_t& amountInBits){

    std::map<std::string, LinkDetails* >::iterator it = m_nodePairs.find(appId);
    if (it == m_nodePairs.end()) {
        NS_LOG_ERROR("KeyGenerated: appId not found: " << appId
                     << " (context=" << context << ")");
        return; // ili NS_ASSERT_MSG(false, "Unknown appId");
    }
    LinkDetails* ld = it->second;
    if (!ld) {
        NS_LOG_ERROR("KeyGenerated: LinkDetails* is null for appId=" << appId);
        return; // ili assert
    }

    std::string linkId = it->second->nodes;

    std::map<std::string, uint32_t>::iterator it2 = it->second->m_keyIDGeneratedInBuffers.find ( keyId );
    if (it2 == it->second->m_keyIDGeneratedInBuffers.end ()){ 
        it->second->m_keyIDGeneratedInBuffers.insert( std::make_pair( keyId, amountInBits));
    }else{
        it->second->m_keysGeneratedBits += amountInBits;  
        it->second->m_keysGenerated++;
 
        if(showKeyAdded){ 
            if(outputFileType == "csv"){
                logFile << (double)Simulator::Now().GetSeconds() << ",+," << linkId << "," << amountInBits;
                logFile << std::endl;
            }else if(outputFileType == "json"){
                if(outputLogFile.size() > 0){ 
                    logFile << ',';
                }
                nlohmann::json jsonRecord;
                jsonRecord["time"] = (double)Simulator::Now().GetSeconds();
                jsonRecord["id"] = linkId;
                jsonRecord["action"] = "+";
                jsonRecord["keysize"] = amountInBits;     
                outputLogFile.push_back(jsonRecord);
                logFile << jsonRecord.dump();;
                logFile << std::endl;
            }
        }
    }  
}

/**
 * Keys fetched from qkdBuffers for transformation before delivery to end-user application
 */
void
KeyConsumedLink (std::string context, const uint32_t& srcNodeId, const uint32_t& dstNodeId, const uint32_t& amountInBits)
{   
    //std::cout << context << "\tsrcNodeId:" << srcNodeId << "\t dstNodeId:" << dstNodeId  << "\tamountInBits:" <<  amountInBits  << "\n";  

    for (std::map<std::string, LinkDetails* >::iterator it = m_nodePairs.begin(); it != m_nodePairs.end(); ++it) 
    { 
        /*
        std::cout << it->second->type << "\t" 
        << it->second->srcNodeId << "\t" 
        << it->second->dstNodeId << "\t" 
        << it->second->srcKMSNodeId << "\t" 
        << it->second->dstKMSNodeId << "\n";
        */

        if(it->second->type == 0 && it->second->srcKMSNodeId == srcNodeId && it->second->dstKMSNodeId == dstNodeId){

            std::string linkId = it->second->nodes;
 
            it->second->m_keysConsumed++;
            it->second->m_keysConsumedBits += amountInBits; 

            if(showKeyAdded){ 
                if(outputFileType == "csv"){
                    logFile << (double)Simulator::Now().GetSeconds() << ",-," << linkId << "," << amountInBits;
                    logFile << std::endl;
                }else if(outputFileType == "json"){
                    if(outputLogFile.size() > 0){ 
                        logFile << ',';
                    }
                    nlohmann::json jsonRecord;
                    jsonRecord["time"] = (double)Simulator::Now().GetSeconds();
                    jsonRecord["id"] = linkId;
                    jsonRecord["action"] = "-";
                    jsonRecord["keysize"] = amountInBits;     
                    outputLogFile.push_back(jsonRecord);
                    logFile << jsonRecord.dump();;
                    logFile << std::endl;
                }
            }  
            break;
        }
    } 

}


void
TxKMSs (std::string context, Ptr<const Packet> p, const uint32_t& srcNodeId)
{  
    m_tx_count++;
    m_tx_bits += p->GetSize();
}

void
RxKMSs (std::string context, Ptr<const Packet> p, const Ipv4Address &addr,  const uint32_t& srcNodeId)
{
    m_rx_count++;
    m_rx_bits += p->GetSize(); 
}


/**
 * Keys served from KMS to end-user application
 */
void
KeyServedMixed (
    std::string context, 
    const std::string& ksid, 
    const std::string& srcSaeId, 
    const std::string& dstSaeId, 
    const uint32_t& srcNodeId, 
    const uint32_t& dstNodeId, 
    const std::string& keyId, 
    const uint32_t& amountInBits, 
    const std::string& type
){    

    std::map<std::string, LinkDetails* >::iterator it = m_nodePairs.find(ksid);
    if(it == m_nodePairs.end())
    {
        for (std::map<std::string, LinkDetails* >::iterator it2 = m_nodePairs.begin(); it2 != m_nodePairs.end(); ++it2) 
        { 
            //std::cout << " check " << appId << " with " << it2->second->m_etsi014Ksid << "\n";
            if(  
                //it2->second->type == 1 && 
                (
                    it2->second->m_etsi014Ksid == ksid || 
                    (it2->second->etsi004srcApp != nullptr && it2->second->etsi004srcApp->GetId() == srcSaeId ) || 
                    (it2->second->etsi004srcApp != nullptr && it2->second->etsi004dstApp->GetId() == dstSaeId) ||
                    (it2->second->etsi004srcApp != nullptr && it2->second->etsi004srcApp->GetId() == dstSaeId ) || 
                    (it2->second->etsi004srcApp != nullptr && it2->second->etsi004dstApp->GetId() == srcSaeId) ||
                    (it2->second->srcKMSNodeId == srcNodeId && it2->second->dstKMSNodeId == dstNodeId) ||
                    (it2->second->srcKMSNodeId == dstNodeId && it2->second->dstKMSNodeId == srcNodeId)
                )
            )
            {
                it = it2;
                break;
            }
        }
    }

    if(it != m_nodePairs.end())
    {
        std::string linkId = it->second->nodes;
        std::string jointKeyId = keyId + std::to_string(amountInBits);

        std::map<std::string, uint32_t>::iterator it2;
        if(type == "pqc") {
            it2 = it->second->m_keyIDConsumedInBuffers_PQC.find ( jointKeyId );
        } else {
            //std::cout << "First time QKD Key " << jointKeyId << "\n";
            it2 = it->second->m_keyIDConsumedInBuffers.find ( jointKeyId );
        }

        //std::cout << "Second time QKD Key " << jointKeyId << "\n";
        if (type == "qkd" && it2 == it->second->m_keyIDConsumedInBuffers.end ())
        {  
            it->second->m_keyIDConsumedInBuffers.insert( std::make_pair( jointKeyId, amountInBits) );
        }
        else if (type == "pqc" && it2 == it->second->m_keyIDConsumedInBuffers_PQC.end ())
        {  
            it->second->m_keyIDConsumedInBuffers_PQC.insert( std::make_pair( jointKeyId, amountInBits) );        
        }


        //std::cout << "KeyServedMixed:" << it->second->nodes << "\t" <<  it->second->m_keysConsumed << "\n";

        if(type == "pqc") {
            it->second->m_keysConsumedBits_PQC += amountInBits;   
            it->second->m_keysConsumed_PQC++;
            //std::cout << appId << ";" << srcNodeId  << ";" <<  dstNodeId  << ";" << keyId << ";" << amountInBits << "\t" << type << "\n";
            //std::cout << "***********" << it->second->title << "\t" << it->second->m_keysConsumed_PQC << "\n";
        }else if(type == "qkd") {
            it->second->m_keysConsumedBits += amountInBits;   
            it->second->m_keysConsumed++;
            //std::cout << appId << ";" << srcNodeId  << ";" <<  dstNodeId  << ";" << keyId << ";" << amountInBits << "\t" << type << "\n";
            //std::cout << "***********" << it->second->title << "\t" << it->second->m_keysConsumedBits << "\n";
        }

        if(showKeyServed){ 
            if(outputFileType == "csv"){
                logFile << (double)Simulator::Now().GetSeconds() << ",-," << linkId << "," << amountInBits;
                logFile << std::endl;
            }else if(outputFileType == "json"){
                if(outputLogFile.size() > 0){
                    logFile << ',';
                }
                nlohmann::json jsonRecord;
                jsonRecord["time"] = (double)Simulator::Now().GetSeconds();
                jsonRecord["id"] = linkId;
                jsonRecord["action"] = "-";
                jsonRecord["keysize"] = amountInBits;     
                outputLogFile.push_back(jsonRecord);
                logFile << jsonRecord.dump();;
                logFile << std::endl;
            }
        }
        
    } else {
        std::cout << "Unable to find m_nodePair! " << ksid << ";" << srcSaeId << ";" << dstSaeId << ";" << srcNodeId  << ";" <<  dstNodeId  << ";" << keyId << ";" << amountInBits << "\t" << type << "\n";

    }
}

void
Etsi004KSIDGenerated( 
    std::string context, 
    const std::string& ksid,
    const std::string& srcSaeId,
    const std::string& dstSaeId,
    const uint32_t& chunkSize
){
    for (std::map<std::string, LinkDetails* >::iterator it = m_nodePairs.begin(); it != m_nodePairs.end(); ++it) 
    {   

        if(
            it->second->type == 1 && 
            it->second->etsi004srcApp &&
            it->second->etsi004dstApp &&
            it->second->etsi004srcApp->GetId() == srcSaeId && 
            it->second->etsi004dstApp->GetId() == dstSaeId &&
            it->second->m_etsi014Ksid.empty() && 
            (
                (it->second->etsi004srcApp->GetEncryptionKeySize() ==  chunkSize && it->second->etsi004dstApp->GetEncryptionKeySize() ==  chunkSize) || 
                (it->second->etsi004srcApp->GetAuthenticationKeySize() ==  chunkSize && it->second->etsi004dstApp->GetAuthenticationKeySize() ==  chunkSize)
            )
        ){  
            //std::cout << " Update ksid value to " << ksid << " of record " << srcSaeId << " and " << dstSaeId << "\n";
            it->second->m_etsi014Ksid = ksid;
            //m_nodePairs.insert( std::make_pair( ksid,  it->second) );
            //m_nodePairs.erase(it);
            break;
        }
    }  
}

void
RelayKeyTrace(
    std::string context, 
    const uint32_t& nodeId,  
    const uint32_t& srcNodeId,
    const uint32_t& dstNodeId,
    const uint32_t& amountInBits
){
 
    for (std::map<std::string, LinkDetails* >::iterator it = m_nodePairs.begin(); it != m_nodePairs.end(); ++it) 
    { 
        if(it->second->type == 0 && ( (it->second->srcKMSNodeId == srcNodeId && it->second->dstKMSNodeId == dstNodeId)
                                || (it->second->srcKMSNodeId == dstNodeId && it->second->dstKMSNodeId == srcNodeId))){

            std::string linkId = it->second->nodes;
 
            it->second->m_keysRelayed++;
            it->second->m_keysRelayedBits += amountInBits; 

            if(showKeyAdded){ 
                if(outputFileType == "csv"){
                    logFile << (double)Simulator::Now().GetSeconds() << ",r," << linkId << "," << amountInBits;
                    logFile << std::endl;
                }else if(outputFileType == "json"){
                    if(outputLogFile.size() > 0){ 
                        logFile << ',';
                    }
                    nlohmann::json jsonRecord;
                    jsonRecord["time"] = (double)Simulator::Now().GetSeconds();
                    jsonRecord["id"] = linkId;
                    jsonRecord["action"] = "r";
                    jsonRecord["keysize"] = amountInBits;     
                    outputLogFile.push_back(jsonRecord);
                    logFile << jsonRecord.dump();;
                    logFile << std::endl;
                }
            }  
            break;
        }
    } 
}
 
void
SentPacket(std::string context, const std::string& appId, Ptr<const Packet> p)
{   
    std::map<std::string, LinkDetails* >::iterator it = m_nodePairs.find(appId);
    std::string linkId = it->second->nodes;

    it->second->m_bytes_sent += p->GetSize();  
    it->second->m_appPacketsSent++;

    if(outputFileType == "csv"){
        logFile << (double)Simulator::Now().GetSeconds() << ",app2app_data," << linkId << "," << p->GetSize();
        logFile << std::endl;
    }else if(outputFileType == "json"){
        if(outputLogFile.size() > 0){
            logFile << ',';
        }
        nlohmann::json jsonRecord;
        jsonRecord["time"] = (double)Simulator::Now().GetSeconds();
        jsonRecord["id"] = linkId;
        jsonRecord["action"] = "app2app_data";
        jsonRecord["keysize"] = p->GetSize();     
        outputLogFile.push_back(jsonRecord);
        logFile << jsonRecord.dump();;
        logFile << std::endl;
    } 
}

bool DoesLinkExist(
    std::string linkName,  
    Ipv4InterfaceContainer &interfacesToApp
){
    //std::cout << "check link exist " << linkName << "\n";
    //std::map<std::string, Ipv4InterfaceContainer>::iterator it2;
    //for (it2 = m_interfaces.begin(); it2 != m_interfaces.end(); ++it2) std::cout << it2->first << "\n";

    //check whether p2p link between srcNode and dstNode is already established
    std::map<std::string, Ipv4InterfaceContainer>::iterator it = m_interfaces.find(linkName);
    if(it != m_interfaces.end()){
        interfacesToApp = it->second;
        return true;
    }
    return false;
}

void MissedSendPacketCall (std::string context, const std::string& appId, Ptr<const Packet> p)
{
    std::map<std::string, LinkDetails* >::iterator it = m_nodePairs.find(appId);
    if(it != m_nodePairs.end())
    {
        it->second->m_missedSendPacketCalls++;
    }else{
        std::cout << context << "\t Unknown appId: " << appId << "\n";
    }
}

void
ReceivedPacket(std::string context, const std::string& appId, Ptr<const Packet> p)
{
    std::map<std::string, LinkDetails* >::iterator it = m_nodePairs.find(appId);
    if(it != m_nodePairs.end())
    {
        it->second->m_bytes_received += p->GetSize();   
        it->second->m_appPacketsReceived++;
    }else{
        std::cout << context << "\t Unknown appId: " << appId << "\n";
    }
}

void
SentPacketSig(std::string context, const std::string& appId, Ptr<const Packet> p)
{
    std::map<std::string, LinkDetails* >::iterator it = m_nodePairs.find(appId);
    if(it != m_nodePairs.end())
    {
        it->second->m_sig_bytes_sent += p->GetSize();  
        it->second->m_appSigPacketsSent++;
        std::string linkId = it->second->nodes;
     
        if(outputFileType == "csv"){
            logFile << (double)Simulator::Now().GetSeconds() << ",app2app_sig," << linkId << "," << p->GetSize();
            logFile << std::endl;
        }else if(outputFileType == "json"){
            if(outputLogFile.size() > 0){
                logFile << ',';
            }
            nlohmann::json jsonRecord;
            jsonRecord["time"] = (double)Simulator::Now().GetSeconds();
            jsonRecord["id"] = linkId;
            jsonRecord["action"] = "app2app_sig";
            jsonRecord["keysize"] = p->GetSize();     
            outputLogFile.push_back(jsonRecord);
            logFile << jsonRecord.dump();;
            logFile << std::endl;
        } 
    }else{
        std::cout << context << "\t Unknown appId: " << appId << "\n";
    }
}

void
ReceivedPacketSig(std::string context, const std::string& appId, Ptr<const Packet> p)
{
    std::map<std::string, LinkDetails* >::iterator it = m_nodePairs.find(appId);
    if(it != m_nodePairs.end())
    {
        it->second->m_sig_bytes_received += p->GetSize();   
        it->second->m_appSigPacketsReceived++;
    }else{
        std::cout << context << "\t Unknown appId: " << appId << "\n";
    }
}

void
SentPacketToKMS(std::string context, const std::string& appId, Ptr<const Packet> p)
{
    std::map<std::string, LinkDetails* >::iterator it = m_nodePairs.find(appId);
    if(it != m_nodePairs.end())
    {
        it->second->m_bytes_sent_to_kms += p->GetSize();
        it->second->m_kmsPacketsSent++; 
        std::string linkId = it->second->nodes;

        if(showKeyAdded){ 
            if(outputFileType == "csv"){
                logFile << (double)Simulator::Now().GetSeconds() << ",app2kms," << linkId << "," << p->GetSize();
                logFile << std::endl;
            }else if(outputFileType == "json"){
                if(outputLogFile.size() > 0){
                    logFile << ',';
                }
                nlohmann::json jsonRecord;
                jsonRecord["time"] = (double)Simulator::Now().GetSeconds();
                jsonRecord["id"] = linkId;
                jsonRecord["action"] = "app2kms";
                jsonRecord["keysize"] = p->GetSize();     
                outputLogFile.push_back(jsonRecord);
                logFile << jsonRecord.dump();;
                logFile << std::endl;
            }
        }
    }else{
        std::cout << context << "\t Unknown appId: " << appId << "\n";
    }
}

void
ReceivedPacketFromKMS(std::string context, const std::string& appId, Ptr<const Packet> p)
{     
    std::map<std::string, LinkDetails* >::iterator it = m_nodePairs.find(appId);
    if(it != m_nodePairs.end())
    {
        it->second->m_bytes_received_from_kms += p->GetSize();   
        it->second->m_kmsPacketsReceived++;
        std::string linkId = it->second->nodes;

        if(showKeyServed){ 
            if(outputFileType == "csv"){
                logFile << (double)Simulator::Now().GetSeconds() << ",kms2app," << linkId << "," << p->GetSize();
                logFile << std::endl;
            }else if(outputFileType == "json"){
                if(outputLogFile.size() > 0){
                    logFile << ',';
                }
                nlohmann::json jsonRecord;
                jsonRecord["time"] = (double)Simulator::Now().GetSeconds();
                jsonRecord["id"] = linkId;
                jsonRecord["action"] = "kms2app";
                jsonRecord["keysize"] = p->GetSize();     
                outputLogFile.push_back(jsonRecord);
                logFile << jsonRecord.dump();;
                logFile << std::endl;
            }
        }
    }else{
        std::cout << context << "\t Unknown appId: " << appId << "\n";
    }
}

void 
CreateOutputForCPU(std::string outputStatsName)
{
    std::vector<std::pair<std::string, std::vector<uint32_t> > > output;

    for (std::map<std::string, LinkDetails* >::iterator it = m_nodePairs.begin(); it != m_nodePairs.end(); ++it) {

        if(it->second->m_printed)continue;

        std::vector<uint32_t> temp(45,0);
        temp[0] = it->second->type;

        double avgSizeOfConsumedKeys = 0;
        for (std::map<std::string, uint32_t>::iterator it2 = it->second->m_keyIDConsumedInBuffers.begin(); 
            it2 != it->second->m_keyIDConsumedInBuffers.end(); ++it2) {
            avgSizeOfConsumedKeys += it2->second;
        }
        avgSizeOfConsumedKeys = avgSizeOfConsumedKeys/it->second->m_keyIDConsumedInBuffers.size();
        it->second->m_avgSizeOfConsumedKeys = avgSizeOfConsumedKeys;


        double avgSizeOfConsumedKeys_PQC = 0;
        for (std::map<std::string, uint32_t>::iterator it2 = it->second->m_keyIDConsumedInBuffers_PQC.begin(); 
            it2 != it->second->m_keyIDConsumedInBuffers_PQC.end(); ++it2) {
            avgSizeOfConsumedKeys_PQC += it2->second;
        }
        avgSizeOfConsumedKeys_PQC = avgSizeOfConsumedKeys_PQC/it->second->m_keyIDConsumedInBuffers_PQC.size();
        it->second->m_avgSizeOfConsumedKeys_PQC = avgSizeOfConsumedKeys_PQC;
        
        if(it->second->type == 0)
        { 
            double avgSizeOfGeneratedKeys = 0;
            for (std::map<std::string, uint32_t>::iterator it2 = it->second->m_keyIDGeneratedInBuffers.begin(); 
                it2 != it->second->m_keyIDGeneratedInBuffers.end(); ++it2) {
                avgSizeOfGeneratedKeys += it2->second;
            }
            avgSizeOfGeneratedKeys = avgSizeOfGeneratedKeys/it->second->m_keyIDGeneratedInBuffers.size();
            it->second->m_avgSizeOfGeneratedKeys = avgSizeOfGeneratedKeys;
            
            temp[1] = it->second->m_linkDistance;
            temp[2] = it->second->m_keyRate;
            temp[3] = it->second->m_keysGenerated;
            temp[4] = it->second->m_keysGeneratedBits;
            temp[5] = it->second->m_keysConsumed;
            temp[6] = it->second->m_keysConsumedBits;
            temp[7] = it->second->m_avgSizeOfGeneratedKeys;
            temp[8] = it->second->m_avgSizeOfConsumedKeys;
            temp[9] = it->second->m_bufferCapacityBits;
            temp[23] = it->second->m_startTime;
            temp[24] = it->second->m_stopTime;

            temp[36] = it->second->m_keysRelayed;
            temp[37] = it->second->m_keysRelayedBits;

            temp[38] = it->second->m_keysConsumed_PQC;
            temp[39] = it->second->m_keysConsumedBits_PQC;
            temp[40] = it->second->m_avgSizeOfConsumedKeys_PQC;

            //temp[38] = it->second->m_keysWasted;
            //temp[39] = it->second->m_keysWastedBits;

        }else{

            temp[10] = it->second->m_bytes_sent;
            temp[11] = it->second->m_bytes_received;
            temp[12] = it->second->m_appPacketsSent;
            temp[13] = it->second->m_appPacketsReceived;
            temp[14] = it->second->m_missedSendPacketCalls;
            temp[15] = it->second->m_encryptionType;
            temp[16] = it->second->m_authenticationType;
            temp[17] = it->second->m_aesLifeTime;
            temp[18] = it->second->m_packetSize;
            temp[19] = it->second->m_trafficRate;
            temp[20] = it->second->m_sizeOfKeyBufferForEncryption;
            temp[21] = it->second->m_sizeOfKeyBufferForAuthentication;
            temp[22] = it->second->m_numberOfKeysToFetchFromKMS;
            temp[23] = it->second->m_startTime;
            temp[24] = it->second->m_stopTime;

            temp[5] = it->second->m_keysConsumed;
            temp[6] = it->second->m_keysConsumedBits;
            temp[8] = it->second->m_avgSizeOfConsumedKeys;

            temp[25] = it->second->m_sig_bytes_sent;
            temp[26] = it->second->m_sig_bytes_received;
            temp[27] = it->second->m_appSigPacketsSent;
            temp[28] = it->second->m_appSigPacketsReceived;

            temp[29] = it->second->m_bytes_sent_to_kms;
            temp[30] = it->second->m_bytes_received_from_kms;
            temp[31] = it->second->m_kmsPacketsSent;
            temp[32] = it->second->m_kmsPacketsReceived;
 
            temp[38] = it->second->m_keysConsumed_PQC;
            temp[39] = it->second->m_keysConsumedBits_PQC;
            temp[40] = it->second->m_avgSizeOfConsumedKeys_PQC;  

        } 

        //std::cout << "CreateOutputForCPU:" << it->second->nodes << "\t" <<  it->second->m_keysConsumed << "\n";

        output.push_back( std::make_pair( it->second->nodes, temp) );
        it->second->m_printed = 1;
    }

    write_csv( outputStatsName, output );
}

void
Ratio(std::string outputStatsName, uint32_t cpuCounter){


    // prepare a JSON file
    nlohmann::json output;

    //Initialize JSON file
    for (std::map<std::string, LinkDetails* >::iterator it = m_nodePairs.begin(); it != m_nodePairs.end(); ++it) {

        //if(it->second->m_printed)continue;
        std::string nodes = it->second->nodes;

        //std::cout << "******** ID:" << it->first << "\n";
        //std::cout << "******** it->second->type:" << it->second->type << "\n";
            
        if(it->second->type == 0){
            output["qkd_links"][nodes]["Link distance (meters)"] = 0;
            output["qkd_links"][nodes]["Key rate (bit/sec)"] = 0;
            output["qkd_links"][nodes]["Key-pairs generated"] = 0;
            output["qkd_links"][nodes]["Key-pairs generated (bits)"] = 0;
            output["qkd_links"][nodes]["Key-pairs consumed QKD"] = 0;
            output["qkd_links"][nodes]["Key-pairs consumed QKD (bits)"] = 0;
            output["qkd_links"][nodes]["Key-pairs consumed PQC"] = 0;
            output["qkd_links"][nodes]["Key-pairs consumed PQC (bits)"] = 0;
            output["qkd_links"][nodes]["Key-pairs relayed"] = 0;
            output["qkd_links"][nodes]["Key-pairs relayed (bits)"] = 0;
            //output["qkd_links"][nodes]["Key-pairs wasted"] = 0;
            //output["qkd_links"][nodes]["Key-pairs wasted (bits)"] = 0;
            output["qkd_links"][nodes]["Average size of generated key-pairs (bits)"] = 0;
            output["qkd_links"][nodes]["Average size of consumed key-pairs (bits)"] = 0;
            output["qkd_links"][nodes]["Start Time (sec)"] = 0;
            output["qkd_links"][nodes]["Stop Time (sec)"] = 0;
            output["qkd_links"][nodes]["QKDBuffer Capacity (bits)"] = 0;
        }else{         

            std::string type = (it->second->type == 1) ? "etsi_004": "etsi_014";
            output[type][nodes]["QKDApps Statistics"]["ID"] = it->first;
            output[type][nodes]["QKDApps Statistics"]["Bytes Sent"] = 0;
            output[type][nodes]["QKDApps Statistics"]["Bytes Received"] = 0;
            output[type][nodes]["QKDApps Statistics"]["Packets Sent"] = 0;
            output[type][nodes]["QKDApps Statistics"]["Packets Received"] = 0;
            output[type][nodes]["QKDApps Statistics"]["Missed send packet calls"] = 0; 
            output[type][nodes]["QKDApps Statistics"]["Key/Data utilization (%)"] = 0; 

            output[type][nodes]["QKDApps Statistics"]["Encryption"] = 0;
            output[type][nodes]["QKDApps Statistics"]["Authentication"] = 0;
            output[type][nodes]["QKDApps Statistics"]["AES Key Lifetime (bytes)"] = 0;
            output[type][nodes]["QKDApps Statistics"]["Size of Key Buffer for Encryption"] = 0;
            output[type][nodes]["QKDApps Statistics"]["Size of Key Buffer for Authentication"] = 0;            
            output[type][nodes]["QKDApps Statistics"]["Number of Keys to Fetch From KMS"] = 0;    
            output[type][nodes]["QKDApps Statistics"]["Packet Size (bytes)"] = 0;
            output[type][nodes]["QKDApps Statistics"]["Traffic Rate (bit/sec)"] = 0;
            output[type][nodes]["QKDApps Statistics"]["Start Time (sec)"] = 0;
            output[type][nodes]["QKDApps Statistics"]["Stop Time (sec)"] = 0;
 
            output[type][nodes]["Signaling Statistics"]["Bytes Sent"] = 0;
            output[type][nodes]["Signaling Statistics"]["Bytes Received"] = 0;
            output[type][nodes]["Signaling Statistics"]["Packets Sent"] = 0;
            output[type][nodes]["Signaling Statistics"]["Packets Received"] = 0;
  
            output[type][nodes]["QKDApps-KMS Statistics"]["Bytes Sent"] = 0;
            output[type][nodes]["QKDApps-KMS Statistics"]["Bytes Received"] = 0;
            output[type][nodes]["QKDApps-KMS Statistics"]["Packets Sent"] = 0;
            output[type][nodes]["QKDApps-KMS Statistics"]["Packets Received"] = 0;

            output[type][nodes]["Key Consumption Statistics"]["Key-pairs consumed QKD"] = 0;
            output[type][nodes]["Key Consumption Statistics"]["Key-pairs consumed QKD (bits)"] = 0;
            output[type][nodes]["Key Consumption Statistics"]["Average size of consumed key-pairs QKD (bits)"] = 0;

            output[type][nodes]["Key Consumption Statistics"]["Key-pairs consumed PQC"] = 0;
            output[type][nodes]["Key Consumption Statistics"]["Key-pairs consumed PQC (bits)"] = 0;
            output[type][nodes]["Key Consumption Statistics"]["Average size of consumed key-pairs PQC (bits)"] = 0;
        }  
    }
    
    //merge values from CPU results
    std::vector<std::vector<std::pair<std::string, std::vector<uint32_t>>>> cpuValues;
    for(uint32_t i = 0; i<cpuCounter; i++){
        std::string tempStatsFile = "temp_stats_" + std::to_string(i);
        std::vector<std::pair<std::string, std::vector<uint32_t>>>  temp = read_csv(tempStatsFile);
        cpuValues.push_back(temp);
        remove(tempStatsFile.c_str());
    }

    //write merged values to JSON file
    //for each cpu value
    for(uint32_t i = 0; i<cpuValues.size(); i++)
    {
        //for each column in cpu value file
        for(uint32_t j=0; j<cpuValues.at(i).size(); j++ )
        {   
            if(i>0){
                //for each value in column
                for(uint32_t k=1; k<cpuValues.at(i).at(j).second.size(); k++ ){
                    cpuValues.at(0).at(j).second.at(k) += cpuValues.at(i).at(j).second.at(k);
                }
            }

            if(i+1 == cpuValues.size()){
                std::string type = "qkd_links";
                std::string nodes = cpuValues.at(i).at(j).first;

                if(cpuValues.at(i).at(j).second.at(0) == 1) {
                    type = "etsi_004";
                }else if(cpuValues.at(i).at(j).second.at(0) == 2){
                    type = "etsi_014";
                }

                std::cout << "********************************** \n\n";



                //std::cout << "Ratio:" << nodes << "\t" <<  cpuValues.at(0).at(j).second.at(5) << "\n";

                if(type == "qkd_links"){
                    output[type][nodes]["Link distance (meters)"]                   = cpuValues.at(0).at(j).second.at(1);
                    output[type][nodes]["Key rate (bit/sec)"]                       = cpuValues.at(0).at(j).second.at(2);
                    output[type][nodes]["Key-pairs generated"]                      = cpuValues.at(0).at(j).second.at(3);
                    output[type][nodes]["Key-pairs generated (bits)"]               = cpuValues.at(0).at(j).second.at(4);
                    output[type][nodes]["Key-pairs consumed QKD"]                       = cpuValues.at(0).at(j).second.at(5);
                    output[type][nodes]["Key-pairs consumed QKD (bits)"]                = cpuValues.at(0).at(j).second.at(6); 
                    output[type][nodes]["Key-pairs consumed PQC"]                       = cpuValues.at(0).at(j).second.at(38);
                    output[type][nodes]["Key-pairs consumed PQC (bits)"]                = cpuValues.at(0).at(j).second.at(39); 
 
                    output[type][nodes]["Key-pairs relayed"]                        = cpuValues.at(0).at(j).second.at(36);
                    output[type][nodes]["Key-pairs relayed (bits)"]                 = cpuValues.at(0).at(j).second.at(37);
                    //output[type][nodes]["Key-pairs wasted"]                       = cpuValues.at(0).at(j).second.at(38);
                    //output[type][nodes]["Key-pairs wasted (bits)"]                = cpuValues.at(0).at(j).second.at(39);
                    output[type][nodes]["Average size of generated key-pairs (bits)"]    = cpuValues.at(0).at(j).second.at(7); 
                    output[type][nodes]["Average size of consumed key-pairs (bits)"]     = cpuValues.at(0).at(j).second.at(8);
                    output[type][nodes]["QKDBuffer Capacity (bits)"] = cpuValues.at(0).at(j).second.at(9);
                    output[type][nodes]["Start Time (sec)"]     = cpuValues.at(0).at(j).second.at(23); 
                    output[type][nodes]["Stop Time (sec)"]     = cpuValues.at(0).at(j).second.at(24); 


                    std::cout << "QKD LINK: " << nodes << "\n"
                    << "\nQKDBuffer_Capacity_(bits):\t" << output[type][nodes]["QKDBuffer Capacity (bits)"]
                    << "\nLink_distance_(meters):\t\t" << output[type][nodes]["Link distance (meters)"]
                    << "\nKey_rate_(bit/sec):\t\t" << output[type][nodes]["Key rate (bit/sec)"]
                    << "\nKey-pairs_generated:\t" << output[type][nodes]["Key-pairs generated"]
                    << "\tKey-pairs_generated (bits):\t" << output[type][nodes]["Key-pairs generated (bits)"]
                    << "\nKey-pairs_consumed QKD:\t"  << output[type][nodes]["Key-pairs consumed QKD"]
                    << "\tKey-pairs_consumed QKD (bits):\t" << output[type][nodes]["Key-pairs consumed QKD (bits)"] 
                    << "\nKey-pairs_consumed PQC:\t"  << output[type][nodes]["Key-pairs consumed PQC"]
                    << "\tKey-pairs_consumed PQC (bits):\t" << output[type][nodes]["Key-pairs consumed PQC (bits)"] 
                    << "\nKey-pairs_relayed:\t" << output[type][nodes]["Key-pairs relayed"]
                    << "\tKey-pairs_relayed (bits):\t" << output[type][nodes]["Key-pairs relayed (bits)"]
                    //<< "\nKey-pairs wasted:\t" << output[type][nodes]["Key-pairs wasted"]
                    //<< "\tKey-pairs wasted (bits):\t" << output[type][nodes]["Key-pairs wasted (bits)"]
                    << "\nAvg_size_of_generated keys_(bits):\t" << output[type][nodes]["Average size of generated key-pairs (bits)"]
                    << "\nAvg_size_of_consumed keys_(bits):\t" << output[type][nodes]["Average size of consumed key-pairs (bits)"]
                    << "\nStart Time (sec):\t\t" << output[type][nodes]["Start Time (sec)"]
                    << "\nStop Time (sec):\t\t" << output[type][nodes]["Stop Time (sec)"]
                    << "\n\n";

                }else{

                    output[type][nodes]["QKDApps Statistics"]["Bytes Sent"]          = cpuValues.at(0).at(j).second.at(10);
                    output[type][nodes]["QKDApps Statistics"]["Bytes Received"]      = cpuValues.at(0).at(j).second.at(11);
                    output[type][nodes]["QKDApps Statistics"]["Packets Sent"]        = cpuValues.at(0).at(j).second.at(12);
                    output[type][nodes]["QKDApps Statistics"]["Packets Received"]    = cpuValues.at(0).at(j).second.at(13);
                    output[type][nodes]["QKDApps Statistics"]["Missed send packet calls"] = cpuValues.at(0).at(j).second.at(14);

                    double utilization = 0;
                    if(cpuValues.at(0).at(j).second.at(12) && (cpuValues.at(0).at(j).second.at(13) || cpuValues.at(0).at(j).second.at(14)))
                    {
                        utilization = (double) cpuValues.at(0).at(j).second.at(12) / (double) (cpuValues.at(0).at(j).second.at(13)); 
                        utilization *= 100;
                        utilization = std::ceil(utilization * 100.0) / 100.0;
                    }
                    output[type][nodes]["QKDApps Statistics"]["Key/Data utilization (%)"] = utilization;

                    output[type][nodes]["QKDApps Statistics"]["Encryption"] = cpuValues.at(0).at(j).second.at(15);
                    if(output[type][nodes]["QKDApps Statistics"]["Encryption"] == 0){
                        output[type][nodes]["QKDApps Statistics"]["Encryption"] = "Unencrypted";
                    }else if(output[type][nodes]["QKDApps Statistics"]["Encryption"] == 1){
                        output[type][nodes]["QKDApps Statistics"]["Encryption"] = "OTP";
                    }else if(output[type][nodes]["QKDApps Statistics"]["Encryption"] == 2){
                        output[type][nodes]["QKDApps Statistics"]["Encryption"] = "AES-256";
                        output[type][nodes]["QKDApps Statistics"]["AES Key Lifetime (bytes)"] = cpuValues.at(0).at(j).second.at(17);
                    }

                    output[type][nodes]["QKDApps Statistics"]["Authentication"]    = cpuValues.at(0).at(j).second.at(16);
                    if(output[type][nodes]["QKDApps Statistics"]["Authentication"] == 0){
                        output[type][nodes]["QKDApps Statistics"]["Authentication"] = "Unauthenticated";
                    }else if(output[type][nodes]["QKDApps Statistics"]["Authentication"] == 1){
                        output[type][nodes]["QKDApps Statistics"]["Authentication"] = "VMAC"; 
                    }else{
                        output[type][nodes]["QKDApps Statistics"]["Authentication"] = "SHA-1";
                    }

                    output[type][nodes]["QKDApps Statistics"]["Packet Size (bytes)"] = cpuValues.at(0).at(j).second.at(18);
                    output[type][nodes]["QKDApps Statistics"]["Traffic Rate (bit/sec)"] = cpuValues.at(0).at(j).second.at(19);

                    if(type == "etsi_004"){
                        output[type][nodes]["QKDApps Statistics"]["Size of Key Buffer for Encryption"] = cpuValues.at(0).at(j).second.at(20);
                        output[type][nodes]["QKDApps Statistics"]["Size of Key Buffer for Authentication"] = cpuValues.at(0).at(j).second.at(21);
                    }else{
                        output[type][nodes]["QKDApps Statistics"]["Number of Keys to Fetch From KMS"] = cpuValues.at(0).at(j).second.at(22);
                    }

                    output[type][nodes]["QKDApps Statistics"]["Start Time (sec)"]     = cpuValues.at(0).at(j).second.at(23);
                    output[type][nodes]["QKDApps Statistics"]["Stop Time (sec)"]      = cpuValues.at(0).at(j).second.at(24);

                    output[type][nodes]["Signaling Statistics"]["Bytes Sent"]         = cpuValues.at(0).at(j).second.at(25);
                    output[type][nodes]["Signaling Statistics"]["Bytes Received"]     = cpuValues.at(0).at(j).second.at(26);
                    output[type][nodes]["Signaling Statistics"]["Packets Sent"]       = cpuValues.at(0).at(j).second.at(27);
                    output[type][nodes]["Signaling Statistics"]["Packets Received"]   = cpuValues.at(0).at(j).second.at(28);
          
                    output[type][nodes]["QKDApps-KMS Statistics"]["Bytes Sent"]       = cpuValues.at(0).at(j).second.at(29);
                    output[type][nodes]["QKDApps-KMS Statistics"]["Bytes Received"]   = cpuValues.at(0).at(j).second.at(30);
                    output[type][nodes]["QKDApps-KMS Statistics"]["Packets Sent"]     = cpuValues.at(0).at(j).second.at(31);
                    output[type][nodes]["QKDApps-KMS Statistics"]["Packets Received"] = cpuValues.at(0).at(j).second.at(32);

                    //std::cout << "--------------------" << cpuValues.at(0).at(j).second.at(5) << "----------------------- \n";

                    output[type][nodes]["Key Consumption Statistics"]["Key-pairs consumed QKD"] = cpuValues.at(0).at(j).second.at(5);
                    output[type][nodes]["Key Consumption Statistics"]["Key-pairs consumed QKD (bits)"]  = cpuValues.at(0).at(j).second.at(6);
                    output[type][nodes]["Key Consumption Statistics"]["Average size of consumed key-pairs QKD (bits)"] = cpuValues.at(0).at(j).second.at(8); 

                    output[type][nodes]["Key Consumption Statistics"]["Key-pairs consumed PQC"] = cpuValues.at(0).at(j).second.at(38);
                    output[type][nodes]["Key Consumption Statistics"]["Key-pairs consumed PQC (bits)"]  = cpuValues.at(0).at(j).second.at(39);
                    output[type][nodes]["Key Consumption Statistics"]["Average size of consumed key-pairs PQC (bits)"] = cpuValues.at(0).at(j).second.at(40); 

                    std::cout << "QKDApps " << type << ": " << nodes << "\n";
                    std::cout << "ID: " <<  output[type][nodes]["QKDApps Statistics"]["ID"] << "\n\n"
                    << "Encryption:\t" << output[type][nodes]["QKDApps Statistics"]["Encryption"];
                    if(output[type][nodes]["QKDApps Statistics"]["Encryption"] == "AES-256"){
                        std::cout << "\nAES Key Lifetime (bytes):\t" << output[type][nodes]["QKDApps Statistics"]["AES Key Lifetime (bytes)"];
                    }
                    std::cout 
                    << "\nAuthentication:\t" << output[type][nodes]["QKDApps Statistics"]["Authentication"]
                    << "\nPacket Size (bytes):\t" << output[type][nodes]["QKDApps Statistics"]["Packet Size (bytes)"]
                    << "\nTraffic Rate (bit/sec):\t" << output[type][nodes]["QKDApps Statistics"]["Traffic Rate (bit/sec)"];
                    
                    if(type == "etsi_004"){
                        std::cout 
                        << "\nSize of Key Buffer for Encryption:\t" << output[type][nodes]["QKDApps Statistics"]["Size of Key Buffer for Encryption"]
                        << "\nSize of Key Buffer for Authentication:\t" << output[type][nodes]["QKDApps Statistics"]["Size of Key Buffer for Authentication"];
                    }else{
                        std::cout 
                        << "\nNumber of Keys to Fetch From KMS:" << output[type][nodes]["QKDApps Statistics"]["Number of Keys to Fetch From KMS"];
                    }

                    std::cout
                    << "\nMissed_send_packet_calls:" << output[type][nodes]["QKDApps Statistics"]["Missed send packet calls"]
                    << "\nQKDApps Statistics_Sent_(bytes):" <<  output[type][nodes]["QKDApps Statistics"]["Bytes Sent"]
                    << "\nQKDApps Statistics_Received_(bytes):" << output[type][nodes]["QKDApps Statistics"]["Bytes Received"]
                    << "\nQKDApps Statistics_Sent_(Packets):" <<  output[type][nodes]["QKDApps Statistics"]["Packets Sent"]
                    << "\nQKDApps Statistics_Received_(Packets):" << output[type][nodes]["QKDApps Statistics"]["Packets Received"]
                    << "\nKey/Data_utilization (%):" << output[type][nodes]["QKDApps Statistics"]["Key/Data utilization (%)"]
                    
                    << "\nRatio_(bytes):" << (float)output[type][nodes]["QKDApps Statistics"]["Bytes Received"]/(float)output[type][nodes]["QKDApps Statistics"]["Bytes Sent"]
                    << "\nRatio_(packets):" << (float)output[type][nodes]["QKDApps Statistics"]["Packets Received"]/(float)output[type][nodes]["QKDApps Statistics"]["Packets Sent"]
                    << "\nStart Time_(sec):" << output[type][nodes]["QKDApps Statistics"]["Start Time (sec)"]
                    << "\nStop_Time_(sec):" << output[type][nodes]["QKDApps Statistics"]["Stop Time (sec)"]
                    << "\n"

                    << "\n- Signaling stats:"
                    << "\nSignaling_stats_Sent_(bytes):" <<  output[type][nodes]["Signaling Statistics"]["Bytes Sent"]
                    << "\nSignaling_stats_Received_(bytes):" << output[type][nodes]["Signaling Statistics"]["Bytes Received"]
                    << "\nSignaling_stats_Sent_(Packets):" <<  output[type][nodes]["Signaling Statistics"]["Packets Sent"]
                    << "\nSignaling_stats_Received_(Packets):" << output[type][nodes]["Signaling Statistics"]["Packets Received"] 
                    << "\n";

                    std::cout << "\n- QKDApps to KMS stats:"
                    << "\nQKDApps_to_KMS_stats_Sent_(bytes):" <<  output[type][nodes]["QKDApps-KMS Statistics"]["Bytes Sent"]
                    << "\nQKDApps_to_KMS_stats_Received_(bytes):" << output[type][nodes]["QKDApps-KMS Statistics"]["Bytes Received"]
                    << "\nQKDApps_to_KMS_stats_Sent_(Packet):" <<  output[type][nodes]["QKDApps-KMS Statistics"]["Packets Sent"]
                    << "\nQKDApps_to_KMS_stats_Received_(Packet):" << output[type][nodes]["QKDApps-KMS Statistics"]["Packets Received"] 
                    << "\n";

                    std::cout << "\n- Key Consumption Statistics:"
                    << "\nKey-pairs_consumed:" <<  output[type][nodes]["Key Consumption Statistics"]["Key-pairs consumed QKD"]
                    << "\nKey-pairs_consumed (bits):" << output[type][nodes]["Key Consumption Statistics"]["Key-pairs consumed QKD (bits)"] 
                    << "\nAverage_size_of_consumed_key-pairs_(bits):" << output[type][nodes]["Key Consumption Statistics"]["Average size of consumed key-pairs QKD (bits)"]

                    << "\nKey-pairs_consumed_PQC:" <<  output[type][nodes]["Key Consumption Statistics"]["Key-pairs consumed PQC"]
                    << "\nKey-pairs_consumed_(bits)_PQC:" << output[type][nodes]["Key Consumption Statistics"]["Key-pairs consumed PQC (bits)"] 
                    << "\nAverage_size_of_consumed_key-pairs_(bits)_PQC:" << output[type][nodes]["Key Consumption Statistics"]["Average size of consumed key-pairs PQC (bits)"]

                    << "\n\n";
                }
            }

        }
    } 

    std::cout << "m_tx_count:" << m_tx_count << "\n";
    std::cout << "m_tx_bits:" << m_tx_bits << "\n";
    std::cout << "m_rx_count:" << m_rx_count << "\n";
    std::cout << "m_rx_bits:" << m_rx_bits << "\n"; 
        
    std::ofstream statFile; 
    statFile.open(outputStatsName, std::ofstream::out | std::ofstream::trunc);
    statFile << output.dump(); 
}

std::string
CalculateAverageDelayBasedOnDistance(uint32_t distanceInMeters){

    return "2ms";
    //distance in meter
    double distance = distanceInMeters;
    //distance in kilometer
    distance = distance / 1000;
    //apply ITU-T Rec. M.2301 (07/2002) - Table 6 (page 15)
    if(distance < 1000) {
        distance *= 1.5;
    }else if(distance > 1000 && distance < 1200) {
        distance = 1500;
    }else{
        distance *= 1.2;
    }
    uint32_t avgDelay = 1;
    if(distance > 5){
      avgDelay = ceil((double)distance/5.0);
    }
    std::string delayString = std::to_string(avgDelay) + "us";
    return delayString;
}


int main (int argc, char *argv[])
{
    Packet::EnablePrinting();
    PacketMetadata::Enable ();

    uint64_t execTime = 0;
    struct timespec tick{}, tock{};
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tick);

    // Sequential fallback values
    uint32_t systemId = 0;
    uint32_t systemCount = 1;
    uint32_t maliciousApplications = 0; //True
    double   attackIntensity = 0.1; //Seconds
    uint32_t numberOfNodes = 0;
    uint32_t numberOfQKDLinks = 1;
    uint32_t numberOfETSI004ApplicationLinks = 0;
    uint32_t numberOfETSI014ApplicationLinks = 0;
    uint32_t seedValue = 0;
 
    double  appHoldTime = 0.5;
    uint16_t simulationTime = 100;
    uint16_t appStartTime = 50;
    uint16_t appStopTime = 500;
    uint16_t qkdStartTime = 0;
    uint16_t qkdStopTime = 500;
    uint32_t authenticationType = 1; //0-unauthenticated, 1-VMAC, 2,3-MD5,SHA1
    uint32_t encryptionType = 1; //0-unencrypted, 1-OTP, 2-AES256
    uint32_t numberOfKeyToFetchFromKMS = 3;
    uint32_t aesLifetime = 10000; //In bytes! 64GB = 68719476736B
    uint32_t keyBufferLengthEncryption = 3;
    uint32_t keyBufferLengthAuthentication = 6;
    uint32_t useCrypto = 0;
    uint32_t randInt = 0;
    NS_LOG_DEBUG(appHoldTime);
    NS_LOG_DEBUG(simulationTime);
    NS_LOG_DEBUG(encryptionType);
    NS_LOG_DEBUG(numberOfKeyToFetchFromKMS);
    NS_LOG_DEBUG(aesLifetime);
    NS_LOG_DEBUG(keyBufferLengthEncryption);
    NS_LOG_DEBUG(authenticationType);
    NS_LOG_DEBUG(keyBufferLengthAuthentication);
    NS_LOG_DEBUG(useCrypto);

    uint32_t appRate = 100000; //In bps
    uint32_t appPacketSize =  800; //In bytes
    uint32_t ppKeyRate = 10000; //In bps
    uint32_t ppKeySize = 8192; //In bytes
    uint32_t ppPacketSize = 100; //In bytes
    uint32_t ppRate = 1000;
    NS_LOG_DEBUG(appRate);
    NS_LOG_DEBUG(appPacketSize);
    NS_LOG_DEBUG(ppKeyRate);
    NS_LOG_DEBUG(ppKeySize);
    NS_LOG_DEBUG(ppPacketSize);
    NS_LOG_DEBUG(ppRate);

    std::string outputFileName ("output.json");
    std::string outputStatsName("stats.json");
    std::string inputFileName("input.json");
 
    double pqc_c = 0; 
    double pqc_enabled = 0; 
    bool trace = false;

    /*
    MpiInterface::Enable (&argc, &argv);
    systemId = MpiInterface::GetSystemId ();
    systemCount = MpiInterface::GetSize ();
    
    std::cout << "SystemId: " << systemId << std::endl;
    GlobalValue::Bind ("SimulatorImplementationType", StringValue ("ns3::DistributedSimulatorImpl"));
    */

    //
    // Explicitly create the nodes required by the topology (shown above).
    //
    NS_LOG_INFO ("Create nodes.");
    NodeContainer n;

    numberOfNodes = (numberOfQKDLinks + numberOfETSI004ApplicationLinks + numberOfETSI014ApplicationLinks + maliciousApplications)*2 + 20; //extra 2 for KMSs + 2 Control
    n.Create (numberOfNodes);
 
    // Configure command line parameters
    CommandLine cmd;
    cmd.AddValue ("simTime", "Simulation time (seconds)", simulationTime);
    cmd.AddValue ("appHoldTime", "How long (seconds) should QKDApp004 wait to close socket to KMS after receiving REST response?", appHoldTime);
    cmd.AddValue ("appStartTime", "Application start time (seconds)", appStartTime);
    cmd.AddValue ("appStopTime", "Application stop time (seconds)", appStopTime);
    cmd.AddValue ("appPacketSize", "Application packet size", appPacketSize);
    cmd.AddValue ("qkdStartTime", "QKD start time (seconds)", qkdStartTime);
    cmd.AddValue ("qkdStopTime", "QKD stop time (seconds)", qkdStopTime);
    cmd.AddValue ("encryptionType", "Type of encryption to be used", encryptionType);
    cmd.AddValue ("authenticationType", "Type of authentication to be used", authenticationType);
    cmd.AddValue ("aesLifetime", "How many packets to encrypt with the same AES key?", aesLifetime);
    cmd.AddValue ("numberOfKeyToFetchFromKMS", "How many keys to fetch from KMS in a query?", numberOfKeyToFetchFromKMS);
    cmd.AddValue ("keyBufferLengthEncryption", "How many keys to store in local buffer of QKDApp004 for encryption?", keyBufferLengthEncryption);
    cmd.AddValue ("keyBufferLengthAuthentication", "How many keys to store in local buffer of QKDApp004 for authentication?", keyBufferLengthAuthentication);
    cmd.AddValue ("useCrypto", "Perform crypto functions?", useCrypto);
    cmd.AddValue ("seed", "Random seed value", seedValue);
    cmd.AddValue ("trace", "Enable datapath stats and pcap traces", trace); 
    cmd.AddValue ("pqc_c", "pqc_c", pqc_c); 
    cmd.AddValue ("pqc_enabled", "pqc_enabled", pqc_enabled);
    cmd.AddValue ("numberOfQKDLinks", "Number of QKD Links", numberOfQKDLinks); 
    cmd.AddValue ("numberOfETSI004ApplicationLinks", "Number of ETSI 004 Application Links", numberOfETSI004ApplicationLinks); 
    cmd.AddValue ("numberOfETSI014ApplicationLinks", "Number of ETSI 014 Application Links", numberOfETSI014ApplicationLinks); 
    cmd.AddValue ("maliciousApplications", "Number of malicious applications", maliciousApplications);
    cmd.AddValue ("attackIntensity", "DoS attackIntensity", attackIntensity);
    cmd.Parse (argc, argv);

    GlobalValue::Bind ("SimulatorImplementationType", StringValue ("ns3::DistributedSimulatorImpl"));
    //Config::SetDefault ("ns3::QKDKeyManagerSystemApplication::pqc_enabled", UintegerValue (pqc_enabled));  
    //Config::SetDefault ("ns3::QKDKeyManagerSystemApplication::pqc_c", DoubleValue (pqc_c));
 
 
    uint32_t systemID0 = 0;
    if(systemId == systemID0){
        logFile.open(outputFileName, std::ofstream::out | std::ofstream::trunc);
        if(outputFileType == "json" && (showKeyAdded || showKeyServed)) logFile << '[';
    }

    ns3::RngSeedManager::SetSeed(1000 + seedValue );
    RngSeedManager::SetRun (seedValue); 
    srand( 1000 + seedValue ); //seeding for the first time only!
    
    Ptr<Node> n0 = CreateObject<Node> (systemID0);
    Ptr<Node> n1 = CreateObject<Node> (systemID0);
    Ptr<Node> n2 = CreateObject<Node> (systemID0);
    Ptr<Node> n3 = CreateObject<Node> (systemID0);
    n.Add (n0);
    n.Add (n1);
    n.Add (n2);
    n.Add (n3);
    
    for(uint32_t i=0; i<numberOfQKDLinks; i++){
        Ptr<Node> node1 = CreateObject<Node> (systemID0);
        n.Add (node1);
        Ptr<Node> node2 = CreateObject<Node> (systemID0);
        n.Add (node2);
    } 
    for(uint32_t i=0; i<numberOfETSI014ApplicationLinks; i++){
        Ptr<Node> node1 = CreateObject<Node> (systemID0);
        n.Add (node1);
        Ptr<Node> node2 = CreateObject<Node> (systemID0);
        n.Add (node2);
    } 
    for(uint32_t i=0; i<numberOfETSI004ApplicationLinks; i++){
        Ptr<Node> node1 = CreateObject<Node> (systemID0);
        n.Add (node1);
        Ptr<Node> node2 = CreateObject<Node> (systemID0);
        n.Add (node2);
    }  
    for(uint32_t i=0; i<maliciousApplications; i++){
        Ptr<Node> node1 = CreateObject<Node> (systemID0);
        n.Add (node1);
        Ptr<Node> node2 = CreateObject<Node> (systemID0);
        n.Add (node2);
    }

    if(systemId == systemID0) {
        std::cout << "Number of CPUs:\t" << systemCount << "\n";
        std::cout << "Number of QKD Links:\t" << numberOfQKDLinks << "\n";
        std::cout << "Number of ETSI 004 Application Links:\t" << numberOfETSI004ApplicationLinks << "\n";
        std::cout << "Number of ETSI 014 Application Links:\t" << numberOfETSI014ApplicationLinks << "\n";
        std::cout << "Number of maliciousApplications:\t" << maliciousApplications << "\n\n";
        std::cout << "Number of Nodes:\t" << numberOfNodes << "\n\n";
    }


    NodeContainer n0n2 = NodeContainer (n.Get(0), n.Get (2));
    NodeContainer n0n1 = NodeContainer (n.Get(0), n.Get (1));
    NodeContainer n1n3 = NodeContainer (n.Get(1), n.Get (3));
    NodeContainer n2n3 = NodeContainer (n.Get(2), n.Get (3));

    NodeContainer n2n4 = NodeContainer (n.Get(2), n.Get (4));
    NodeContainer n2n6 = NodeContainer (n.Get(2), n.Get (6));
    NodeContainer n3n5 = NodeContainer (n.Get(3), n.Get (5));
    NodeContainer n3n7 = NodeContainer (n.Get(3), n.Get (7));

    NodeContainer n4n5 = NodeContainer (n.Get(4), n.Get (5));
    NodeContainer n4n8 = NodeContainer (n.Get(4), n.Get (8));
    NodeContainer n5n9 = NodeContainer (n.Get(5), n.Get (9));
    NodeContainer n6n7 = NodeContainer (n.Get(6), n.Get (7));
    NodeContainer n6n8 = NodeContainer (n.Get(6), n.Get (8));
    NodeContainer n7n9 = NodeContainer (n.Get(7), n.Get (9));

    NodeContainer n8n10 = NodeContainer (n.Get(8), n.Get (10));
    NodeContainer n8n9 = NodeContainer (n.Get(8), n.Get (9));
    NodeContainer n9n11 = NodeContainer (n.Get(9), n.Get (11));
    NodeContainer n10n11 = NodeContainer (n.Get(10), n.Get (11));  

    InternetStackHelper internet; 
    internet.Install (n);

    // Set Mobility for all nodes
    MobilityHelper mobility;
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(n);

    // We create the channels first without any IP addressing information
    NS_LOG_INFO ("Create channels.");
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute ("DataRate", StringValue ("50Mbps"));
    p2p.SetChannelAttribute ("Delay", StringValue ("2ms"));

    NetDeviceContainer d0d2 = p2p.Install (n0n2);
    NetDeviceContainer d0d1 = p2p.Install (n0n1);
    NetDeviceContainer d1d3 = p2p.Install (n1n3);
    NetDeviceContainer d2d3 = p2p.Install (n2n3);

    NetDeviceContainer d2d4 = p2p.Install (n2n4);
    NetDeviceContainer d2d6 = p2p.Install (n2n6);
    NetDeviceContainer d3d5 = p2p.Install (n3n5);
    NetDeviceContainer d3d7 = p2p.Install (n3n7);

    NetDeviceContainer d4d5 = p2p.Install (n4n5);
    NetDeviceContainer d4d8 = p2p.Install (n4n8);
    NetDeviceContainer d5d9 = p2p.Install (n5n9);
    NetDeviceContainer d6d7 = p2p.Install (n6n7);
    NetDeviceContainer d6d8 = p2p.Install (n6n8);
    NetDeviceContainer d7d9 = p2p.Install (n7n9);

    NetDeviceContainer d8d10 = p2p.Install (n8n10);
    NetDeviceContainer d8d9 = p2p.Install (n8n9);
    NetDeviceContainer d9d11 = p2p.Install (n9n11);
    NetDeviceContainer d10d11 = p2p.Install (n10n11);

    //
    // We've got the "hardware" in place.  Now we need to add IP addresses.
    //
    NS_LOG_INFO ("Assign IP Addresses.");
    Ipv4AddressHelper ipv4;

    ipv4.SetBase ("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer i0i2 = ipv4.Assign (d0d2);
    ipv4.SetBase ("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer i0i1 = ipv4.Assign (d0d1);
    ipv4.SetBase ("10.1.3.0", "255.255.255.0");
    Ipv4InterfaceContainer i1i3 = ipv4.Assign (d1d3);
    ipv4.SetBase ("10.1.4.0", "255.255.255.0");
    Ipv4InterfaceContainer i2i3 = ipv4.Assign (d2d3);

    ipv4.SetBase ("10.1.5.0", "255.255.255.0");
    Ipv4InterfaceContainer i2i4 = ipv4.Assign (d2d4);
    ipv4.SetBase ("10.1.6.0", "255.255.255.0");
    Ipv4InterfaceContainer i2i6 = ipv4.Assign (d2d6);
    ipv4.SetBase ("10.1.7.0", "255.255.255.0");
    Ipv4InterfaceContainer i3i5 = ipv4.Assign (d3d5);
    ipv4.SetBase ("10.1.8.0", "255.255.255.0");
    Ipv4InterfaceContainer i3i7 = ipv4.Assign (d3d7);

    ipv4.SetBase ("10.1.9.0", "255.255.255.0");
    Ipv4InterfaceContainer i4i5 = ipv4.Assign (d4d5);
    ipv4.SetBase ("10.1.10.0", "255.255.255.0");
    Ipv4InterfaceContainer i4i8 = ipv4.Assign (d4d8);
    ipv4.SetBase ("10.1.11.0", "255.255.255.0");
    Ipv4InterfaceContainer i5i9 = ipv4.Assign (d5d9);
    ipv4.SetBase ("10.1.12.0", "255.255.255.0");
    Ipv4InterfaceContainer i6i7 = ipv4.Assign (d6d7);
    ipv4.SetBase ("10.1.13.0", "255.255.255.0");
    Ipv4InterfaceContainer i6i8 = ipv4.Assign (d6d8);
    ipv4.SetBase ("10.1.14.0", "255.255.255.0");
    Ipv4InterfaceContainer i7i9 = ipv4.Assign (d7d9);

    ipv4.SetBase ("10.1.15.0", "255.255.255.0");
    Ipv4InterfaceContainer i8i10 = ipv4.Assign (d8d10);
    ipv4.SetBase ("10.1.16.0", "255.255.255.0");
    Ipv4InterfaceContainer i8i9 = ipv4.Assign (d8d9);
    ipv4.SetBase ("10.1.17.0", "255.255.255.0");
    Ipv4InterfaceContainer i9i11 = ipv4.Assign (d9d11);
    ipv4.SetBase ("10.1.18.0", "255.255.255.0");
    Ipv4InterfaceContainer i10i11 = ipv4.Assign (d10d11);

    QKDAppHelper QAHelper;
    QKDLinkHelper QLinkHelper;

    Ptr<QKDControl> controlSiteA = QLinkHelper.InstallQKDNController ( n.Get(12) );
    Ptr<QKDControl> controlSiteB = QLinkHelper.InstallQKDNController ( n.Get(13) );
    Ptr<QKDControl> controlSiteC = QLinkHelper.InstallQKDNController ( n.Get(14) );
    Ptr<QKDControl> controlSiteD = QLinkHelper.InstallQKDNController ( n.Get(15) );
    Ptr<QKDControl> controlSiteE = QLinkHelper.InstallQKDNController ( n.Get(16) );
    Ptr<QKDControl> controlSiteF = QLinkHelper.InstallQKDNController ( n.Get(17) );
    QLinkHelper.ConfigureQBuffers ( //Configure Q-Buffers
        {controlSiteA, controlSiteB, controlSiteC, controlSiteD, controlSiteE, controlSiteF},
        1024,       //min_bits
        1800,       //thr_bits
        500000000,  //max_bits
        512         //default key size in bits
    );
    QLinkHelper.ConfigureRSBuffers ( //Configure S-Buffers for relay (RBuffers)!
        {controlSiteA, controlSiteB, controlSiteC, controlSiteD, controlSiteE, controlSiteF},
        0,     //min_bits
        16000, //thr_bits
        64000, //max_bits
        512    //default key size in bits
    );

    //  install KMs on nodes 3 and 4
    QAHelper.InstallKeyManager(//Install key manager for site A
        n.Get(1),           //Node KM-A
        i1i3.GetAddress(0), //IP address KM-A
        80,                 //Port
        controlSiteA        //Assigned controller A
    );
    QAHelper.InstallKeyManager( //Install key manager for site B
        n.Get(3),           //Node KM-B
        i1i3.GetAddress(1), //IP address KM-B
        80,                 //Port
        controlSiteB        //Assigned controller B
    );
    QAHelper.InstallKeyManager(
        n.Get(5),
        i3i5.GetAddress(1),
        80,
        controlSiteC
    );
    QAHelper.InstallKeyManager(
        n.Get(7),
        i3i7.GetAddress(1),
        80,
        controlSiteD
    );
    QAHelper.InstallKeyManager(
        n.Get(9),
        i9i11.GetAddress(0),
        80,
        controlSiteE
    );
    QAHelper.InstallKeyManager(
        n.Get(11),
        i9i11.GetAddress(1),
        80,
        controlSiteF
    );

    NS_LOG_INFO ("Create Applications.");
    uint32_t temp = 0;

    std::cout << "QKDsiteA: " << n.Get(0)->GetId() << " IP address: " << i0i2.GetAddress(0) << std::endl;
    std::cout << "QKDsiteB: " << n.Get(2)->GetId() << " IP address: " << i0i2.GetAddress(1) << std::endl;
    std::cout << "QKDsiteC: " << n.Get(4)->GetId() << " IP address: " << i2i4.GetAddress(1) << std::endl;
    std::cout << "KMsiteA: "  << n.Get(1)->GetId() << " IP address: " << i1i3.GetAddress(0) << std::endl;
    std::cout << "KMsiteB: "  << n.Get(3)->GetId() << " IP address: " << i1i3.GetAddress(1) << std::endl;
    std::cout << "KMsiteC: "  << n.Get(5)->GetId() << " IP address: " << i3i5.GetAddress(1) << std::endl;

    ApplicationContainer postprocessingApplications;
    postprocessingApplications.Add(
        QAHelper.InstallPostProcessing(
            n.Get(0),   //QKD module A
            n.Get(2),   //QKD module B
            InetSocketAddress (i0i2.GetAddress(0), 102),    //Address A
            InetSocketAddress (i0i2.GetAddress(1), 102),    //Address B
            n.Get(12),  //Controller-A
            n.Get(13),  //Controller-B
            ppKeySize,   //size of key to be added to QKD buffer
            DataRate (ppKeyRate), //average QKD key rate
            ppPacketSize,    //average data packet size
            DataRate (ppRate) //average data traffic rate
        )
    );

    uint32_t srcNodeId = 0;
    uint32_t dstNodeId = 2;
    uint32_t maxBufferCapacity = 0;
    LinkDetails* linkD02 = new LinkDetails;
    //linkD02->nodes = std::to_string(n.Get(i)->GetId()) + "-" + std::to_string(n.Get(j)->GetId());
    linkD02->nodes = std::to_string(srcNodeId) + "-" + std::to_string(dstNodeId);
    linkD02->title = "QKD link: " + linkD02->nodes; 
    linkD02->type = 0; 
    linkD02->m_avgSizeOfGeneratedKeys = 0; 
    linkD02->m_avgSizeOfConsumedKeys = 0; 
    linkD02->m_keyRate = ppKeyRate;
    linkD02->m_linkDistance = 0;
    linkD02->m_startTime = qkdStartTime;
    linkD02->m_stopTime = qkdStopTime;
    linkD02->m_bufferCapacityBits = maxBufferCapacity;
    linkD02->srcNodeId = srcNodeId;
    linkD02->dstNodeId = dstNodeId;
    linkD02->srcKMSNodeId = 1;
    linkD02->dstKMSNodeId = 3;    
    Ptr<QKDPostprocessingApplication> ppA = DynamicCast<QKDPostprocessingApplication> (postprocessingApplications.Get(0));
    m_nodePairs.insert( std::make_pair( ppA->GetId(),  linkD02) );
    temp = linkD02->srcNodeId;
    linkD02->srcNodeId = linkD02->dstNodeId;
    linkD02->dstNodeId = temp;
    Ptr<QKDPostprocessingApplication> ppB = DynamicCast<QKDPostprocessingApplication> (postprocessingApplications.Get(1));
    m_nodePairs.insert( std::make_pair( ppB->GetId(),  linkD02) );

    postprocessingApplications.Add(
        QAHelper.InstallPostProcessing(
            n.Get(2),
            n.Get(4),
            InetSocketAddress (i2i4.GetAddress(0), 104),
            InetSocketAddress (i2i4.GetAddress(1), 104),
            n.Get(13),
            n.Get(14),
            ppKeySize,
            DataRate (ppKeyRate),
            ppPacketSize,
            DataRate (ppRate)
        )
    );
    srcNodeId = 2;
    dstNodeId = 4;
    LinkDetails* linkD24 = new LinkDetails;
    //linkD24->nodes = std::to_string(n.Get(i)->GetId()) + "-" + std::to_string(n.Get(j)->GetId());
    linkD24->nodes = std::to_string(srcNodeId) + "-" + std::to_string(dstNodeId);
    linkD24->title = "QKD link: " + linkD24->nodes; 
    linkD24->type = 0; 
    linkD24->m_avgSizeOfGeneratedKeys = 0; 
    linkD24->m_avgSizeOfConsumedKeys = 0; 
    linkD24->m_keyRate = ppKeyRate;
    linkD24->m_linkDistance = 0;
    linkD24->m_startTime = qkdStartTime;
    linkD24->m_stopTime = qkdStopTime;
    linkD24->m_bufferCapacityBits = maxBufferCapacity;
    linkD24->srcNodeId = srcNodeId;
    linkD24->dstNodeId = dstNodeId;
    linkD24->srcKMSNodeId = 3;
    linkD24->dstKMSNodeId = 5;
    ppA = DynamicCast<QKDPostprocessingApplication> (postprocessingApplications.Get(2));
    m_nodePairs.insert( std::make_pair( ppA->GetId(),  linkD24) );
    temp = linkD24->srcNodeId;
    linkD24->srcNodeId = linkD24->dstNodeId;
    linkD24->dstNodeId = temp;
    ppB = DynamicCast<QKDPostprocessingApplication> (postprocessingApplications.Get(3));
    m_nodePairs.insert( std::make_pair( ppB->GetId(),  linkD24) );



    postprocessingApplications.Add(
        QAHelper.InstallPostProcessing(
            n.Get(2),
            n.Get(6),
            InetSocketAddress (i2i6.GetAddress(0), 106),
            InetSocketAddress (i2i6.GetAddress(1), 106),
            n.Get(13),
            n.Get(15),
            ppKeySize,
            DataRate (ppKeyRate),
            ppPacketSize,
            DataRate (ppRate)
        )
    );
    srcNodeId = 2;
    dstNodeId = 6;
    LinkDetails* linkD26 = new LinkDetails;
    //linkD26->nodes = std::to_string(n.Get(i)->GetId()) + "-" + std::to_string(n.Get(j)->GetId());
    linkD26->nodes = std::to_string(srcNodeId) + "-" + std::to_string(dstNodeId);
    linkD26->title = "QKD link: " + linkD26->nodes; 
    linkD26->type = 0; 
    linkD26->m_avgSizeOfGeneratedKeys = 0; 
    linkD26->m_avgSizeOfConsumedKeys = 0; 
    linkD26->m_keyRate = ppKeyRate;
    linkD26->m_linkDistance = 0;
    linkD26->m_startTime = qkdStartTime;
    linkD26->m_stopTime = qkdStopTime;
    linkD26->m_bufferCapacityBits = maxBufferCapacity;
    linkD26->srcNodeId = srcNodeId;
    linkD26->dstNodeId = dstNodeId;
    linkD26->srcKMSNodeId = 3;
    linkD26->dstKMSNodeId = 7;
    ppA = DynamicCast<QKDPostprocessingApplication> (postprocessingApplications.Get(4));
    m_nodePairs.insert( std::make_pair( ppA->GetId(),  linkD26) );
    temp = linkD26->srcNodeId;
    linkD26->srcNodeId = linkD26->dstNodeId;
    linkD26->dstNodeId = temp;
    ppB = DynamicCast<QKDPostprocessingApplication> (postprocessingApplications.Get(5));
    m_nodePairs.insert( std::make_pair( ppB->GetId(),  linkD26) );


    postprocessingApplications.Add(
        QAHelper.InstallPostProcessing(
            n.Get(4),
            n.Get(8),
            InetSocketAddress (i4i8.GetAddress(0), 108),
            InetSocketAddress (i4i8.GetAddress(1), 108),
            n.Get(14),
            n.Get(16),
            ppKeySize,
            DataRate (7000), //@testing relay errors, use different ppKeyRate: e.g., 7000
            ppPacketSize,
            DataRate (ppRate)
        )
    );
    srcNodeId = 4;
    dstNodeId = 8;
    LinkDetails* linkD48 = new LinkDetails;
    //linkD48->nodes = std::to_string(n.Get(i)->GetId()) + "-" + std::to_string(n.Get(j)->GetId());
    linkD48->nodes = std::to_string(srcNodeId) + "-" + std::to_string(dstNodeId);
    linkD48->title = "QKD link: " + linkD48->nodes; 
    linkD48->type = 0; 
    linkD48->m_avgSizeOfGeneratedKeys = 0; 
    linkD48->m_avgSizeOfConsumedKeys = 0; 
    linkD48->m_keyRate = ppKeyRate;
    linkD48->m_linkDistance = 0;
    linkD48->m_startTime = qkdStartTime;
    linkD48->m_stopTime = qkdStopTime;
    linkD48->m_bufferCapacityBits = maxBufferCapacity;
    linkD48->srcNodeId = srcNodeId;
    linkD48->dstNodeId = dstNodeId;
    linkD48->srcKMSNodeId = 5;
    linkD48->dstKMSNodeId = 9;
    ppA = DynamicCast<QKDPostprocessingApplication> (postprocessingApplications.Get(6));
    m_nodePairs.insert( std::make_pair( ppA->GetId(),  linkD48) );
    temp = linkD48->srcNodeId;
    linkD48->srcNodeId = linkD48->dstNodeId;
    linkD48->dstNodeId = temp;
    ppB = DynamicCast<QKDPostprocessingApplication> (postprocessingApplications.Get(7));
    m_nodePairs.insert( std::make_pair( ppB->GetId(),  linkD48) );


    postprocessingApplications.Add(
        QAHelper.InstallPostProcessing(
            n.Get(6),
            n.Get(8),
            InetSocketAddress (i6i8.GetAddress(0), 110),
            InetSocketAddress (i6i8.GetAddress(1), 110),
            n.Get(15),
            n.Get(16),
            ppKeySize,
            DataRate (ppKeyRate),
            ppPacketSize,
            DataRate (ppRate)
        )
    );
    srcNodeId = 6;
    dstNodeId = 8;
    LinkDetails* linkD68 = new LinkDetails;
    //linkD68->nodes = std::to_string(n.Get(i)->GetId()) + "-" + std::to_string(n.Get(j)->GetId());
    linkD68->nodes = std::to_string(srcNodeId) + "-" + std::to_string(dstNodeId);
    linkD68->title = "QKD link: " + linkD68->nodes; 
    linkD68->type = 0; 
    linkD68->m_avgSizeOfGeneratedKeys = 0; 
    linkD68->m_avgSizeOfConsumedKeys = 0; 
    linkD68->m_keyRate = ppKeyRate;
    linkD68->m_linkDistance = 0;
    linkD68->m_startTime = qkdStartTime;
    linkD68->m_stopTime = qkdStopTime;
    linkD68->m_bufferCapacityBits = maxBufferCapacity;
    linkD68->srcNodeId = srcNodeId;
    linkD68->dstNodeId = dstNodeId;
    linkD68->srcKMSNodeId = 7;
    linkD68->dstKMSNodeId = 9;
    ppA = DynamicCast<QKDPostprocessingApplication> (postprocessingApplications.Get(8));
    m_nodePairs.insert( std::make_pair( ppA->GetId(),  linkD68) );
    temp = linkD68->srcNodeId;
    linkD68->srcNodeId = linkD68->dstNodeId;
    linkD68->dstNodeId = temp;
    ppB = DynamicCast<QKDPostprocessingApplication> (postprocessingApplications.Get(9));
    m_nodePairs.insert( std::make_pair( ppB->GetId(),  linkD68) );


    postprocessingApplications.Add(
        QAHelper.InstallPostProcessing(
            n.Get(8),
            n.Get(10),
            InetSocketAddress (i8i10.GetAddress(0), 112),
            InetSocketAddress (i8i10.GetAddress(1), 112),
            n.Get(16),
            n.Get(17),
            ppKeySize,
            DataRate (ppKeyRate),
            ppPacketSize,
            DataRate (ppRate)
        )
    );
    srcNodeId = 8;
    dstNodeId = 10;
    LinkDetails* linkD810 = new LinkDetails;
    //linkD810->nodes = std::to_string(n.Get(i)->GetId()) + "-" + std::to_string(n.Get(j)->GetId());
    linkD810->nodes = std::to_string(srcNodeId) + "-" + std::to_string(dstNodeId);
    linkD810->title = "QKD link: " + linkD810->nodes; 
    linkD810->type = 0; 
    linkD810->m_avgSizeOfGeneratedKeys = 0; 
    linkD810->m_avgSizeOfConsumedKeys = 0; 
    linkD810->m_keyRate = ppKeyRate;
    linkD810->m_linkDistance = 0;
    linkD810->m_startTime = qkdStartTime;
    linkD810->m_stopTime = qkdStopTime;
    linkD810->m_bufferCapacityBits = maxBufferCapacity;
    linkD810->srcNodeId = srcNodeId;
    linkD810->dstNodeId = dstNodeId;
    linkD810->srcKMSNodeId = 9;
    linkD810->dstKMSNodeId = 11;
    ppA = DynamicCast<QKDPostprocessingApplication> (postprocessingApplications.Get(10));
    m_nodePairs.insert( std::make_pair( ppA->GetId(),  linkD810) );
    temp = linkD810->srcNodeId;
    linkD810->srcNodeId = linkD810->dstNodeId;
    linkD810->dstNodeId = temp;
    ppB = DynamicCast<QKDPostprocessingApplication> (postprocessingApplications.Get(11));
    m_nodePairs.insert( std::make_pair( ppB->GetId(),  linkD810) );


    postprocessingApplications.Start (Seconds (qkdStartTime));
    postprocessingApplications.Stop (Seconds (qkdStopTime));

    //////////////////////////////////////
    //  QKD APP ETSI 014
    //////////////////////////////////////

    if(systemId == systemID0) {
        std::cout << "\n*********\n*** ETSI 014 Configuration\n*********\n";
    }

    //Set default values for applications created below  
    std::vector<uint32_t> numberOfKeyToFetchFromKMSOptions = {3,5,8,10,15,20};
    std::vector<uint32_t> keyBufferLengthEncryptionValues = {1,3,5,10,15,20};
    std::vector<uint32_t> keyBufferLengthAuthenticationValues = {6,10,15,20,50}; 
    std::vector<double> appHoldTimeVlues = {0.5, 1, 3, 5}; 

    std::vector<uint32_t> AuthenticationTypes = {0,1,2};
    std::vector<uint32_t> EncryptionTypes = {1,2};
    std::vector<uint32_t> AESLifetimes = {100000,200000,300000,400000,500000};

    std::vector<uint32_t> appPacketSizes = {100,300,500,800,1100};
    std::vector<uint32_t> appRates = {30000, 50000, 100000, 150000}; //, 200000, 250000, 500000};

    ApplicationContainer cryptographicApplications; 
    for(uint32_t a=0; a<numberOfETSI014ApplicationLinks;a++)
    {    
        std::mt19937 rng(seedValue+a);

        // Dozvoljeni (i,j) parovi
        const std::vector<std::pair<int,int>> allowed = {
            {0,10}, {2,8}, {0,6}, {0,8}, {2,10}
        };
        std::uniform_int_distribution<size_t> pick(0, allowed.size() - 1);

        // Izaberi nasumičan dozvoljeni par
        int i, j;
        std::tie(i, j) = allowed[pick(rng)];
 
        int randValue = rand();
        randInt = randValue % appRates.size();
        appRate = appRates[randInt];

        randInt = randValue % appPacketSizes.size();
        appPacketSize = appPacketSizes[randInt];

        randInt = randValue % numberOfKeyToFetchFromKMSOptions.size();
        numberOfKeyToFetchFromKMS = numberOfKeyToFetchFromKMSOptions[randInt];

        randInt = randValue % AuthenticationTypes.size();
        authenticationType = AuthenticationTypes[randInt];

        randInt = randValue % EncryptionTypes.size();
        encryptionType = EncryptionTypes[randInt];

        randInt = randValue % AESLifetimes.size();
        aesLifetime = AESLifetimes[randInt];

            
        LinkDetails* linkD = new LinkDetails;
        //linkD->srcAddress = interfacesToKMSAlice.GetAddress(0);
        //linkD->dstAddress = interfacesToKMSBob.GetAddress(1);
        linkD->nodes = std::to_string(n.Get(i)->GetId()) + "-" + std::to_string(n.Get(j)->GetId());
        linkD->title = "ETSI 014 Connection: " + linkD->nodes;  
        linkD->type = 2;
        linkD->m_encryptionType = encryptionType;
        linkD->m_authenticationType = authenticationType;
        linkD->m_aesLifeTime = aesLifetime;
        linkD->m_packetSize = appPacketSize;
        linkD->m_trafficRate = appRate;
        linkD->m_sizeOfKeyBufferForEncryption = keyBufferLengthEncryption;
        linkD->m_sizeOfKeyBufferForAuthentication = keyBufferLengthAuthentication;
        linkD->m_startTime = appStartTime;
        linkD->m_stopTime = appStopTime;
        linkD->m_numberOfKeysToFetchFromKMS = numberOfKeyToFetchFromKMS;

        //Create APP to consume keys
        //ALICE sends user's data
        Ipv4Address address_i;
        Ipv4Address address_j;
        uint32_t control_i = 0;
        uint32_t control_j = 0;
 
        if(i==0) 
        {
            address_i = i0i2.GetAddress(0);
            control_i = 12;  
        }else if(i == 2)
        {
            address_i = i2i4.GetAddress(0);
            control_i = 13;  
        }else if(i == 4)
        {
            address_i = i4i8.GetAddress(0);
            control_i = 14;  
        }else if(i == 6) 
        {
            address_i = i6i8.GetAddress(0);
            control_i = 15;              
        }else if(i == 8) 
        {
            address_i = i8i10.GetAddress(0);
            control_i = 16; 
        }
 
        if(j==2) 
        {
            address_j = i0i2.GetAddress(1);
            control_j = 13; 
        }else if(j == 4) 
        {
            address_j = i2i4.GetAddress(1);
            control_j = 14; 
        }else if(j == 6) 
        {
            address_j = i2i6.GetAddress(1);
            control_j = 15; 
        }else if(j == 8) 
        {
            address_j = i4i8.GetAddress(1);
            control_j = 16; 
        }else if(j == 10) 
        {
            address_j = i8i10.GetAddress(1);
            control_j = 17; 
        }

        std::cout << "i: " << i << std::endl;
        std::cout << "j: " << j << std::endl;
        std::cout << "control_i: " << control_i << std::endl;
        std::cout << "control_j: " << control_j << std::endl;

        uint16_t communicationPort = 8081+a;

        //Set default values for applications created below
        QAHelper.SetAttribute("app014", "NumberOfKeyToFetchFromKMS", UintegerValue (numberOfKeyToFetchFromKMS));//Number of keys to obtain per request!
        QAHelper.SetAttribute("app014", "AuthenticationType", UintegerValue (authenticationType)); //(0-unauthenticated, 1-VMAC, 2-MD5, 3-SHA1)
        QAHelper.SetAttribute("app014", "EncryptionType", UintegerValue (encryptionType)); //(0-unencrypted, 1-OTP, 2-AES)
        QAHelper.SetAttribute("app014", "AESLifetime", UintegerValue (aesLifetime));
        QAHelper.SetAttribute("app014", "UseCrypto", UintegerValue (useCrypto));
        QAHelper.SetAttribute("app014", "WaitInsufficient", TimeValue (Seconds (appHoldTime)));

        ApplicationContainer Etsi014cryptographicApplications;
        Etsi014cryptographicApplications.Add(
            QAHelper.InstallQKDApplication(
                n.Get(i),
                n.Get(j),
                InetSocketAddress (address_i, communicationPort),    //Address A
                InetSocketAddress (address_j, communicationPort),    //Address B
                n.Get(control_i),  //Controller-A
                n.Get(control_j),  //Controller-B
                "tcp",      //Connection type
                appPacketSize, //Payload size
                DataRate (appRate), //Data rate
                "etsi014"   //Application type
            )
        ); 
        Ptr<QKDApp014> CA = DynamicCast<QKDApp014> (Etsi014cryptographicApplications.Get(0));
        Ptr<QKDApp014> CB = DynamicCast<QKDApp014> (Etsi014cryptographicApplications.Get(1));
        cryptographicApplications.Add(Etsi014cryptographicApplications);

        m_nodePairs.insert( std::make_pair( CA->GetId(),  linkD) ); 
        m_nodePairs.insert( std::make_pair( CB->GetId(),  linkD) );

        if(systemId == systemID0) {
            std::cout << "Alice NodeId: " << n.Get(i)->GetId() << " Alice App IP: " << address_i << std::endl;
            std::cout << "Bob NodeId: " << n.Get(j)->GetId() << " Bob App IP: " << address_j << std::endl;
            std::cout << "SrcKMSNode: " << n.Get(control_i)->GetId() << std::endl;
            std::cout << "DstKMSNode: " << n.Get(control_j)->GetId() << std::endl;
            std::cout << "EncryptionType: " << encryptionType << std::endl;
            std::cout << "AuthenticationType: " << authenticationType << std::endl;
            std::cout << "AESLifetime: " << aesLifetime << std::endl; 
            std::cout << "AppRate: " << appRate << std::endl; 
            std::cout << "AppPacketSize: " << appPacketSize << std::endl; 
            std::cout << "NumberOfKeyToFetchFromKMS: " << numberOfKeyToFetchFromKMS << std::endl;
        }
    }


    cryptographicApplications.Start (Seconds (appStartTime));
    cryptographicApplications.Stop (Seconds (appStopTime));

    //////////////////////////////////////
    //  QKD APP ETSI 004
    //////////////////////////////////////

    if(systemId == systemID0){
        std::cout << "\n*********\n*** ETSI 004 Configuration\n*********\n";
    }
 
    //Set default values for applications created below
    for(uint32_t a=0; a<numberOfETSI004ApplicationLinks ;a++)
    {   
        std::mt19937 rng(seedValue+a);

        // Dozvoljeni (i,j) parovi
        const std::vector<std::pair<int,int>> allowed = {
            {0,10}, {2,8}, {0,6}, {0,8}, {2,10}
        };
        std::uniform_int_distribution<size_t> pick(0, allowed.size() - 1);

        // Izaberi nasumičan dozvoljeni par
        int i, j;
        std::tie(i, j) = allowed[pick(rng)];

        int randValue = rand();
        std::cout << "Random value: " << randValue << "\n"; 
        
        randInt = randValue % appRates.size();
        appRate = appRates[randInt];

        randInt = randValue % appPacketSizes.size();
        appPacketSize = appPacketSizes[randInt];

        randInt = randValue % AuthenticationTypes.size();
        authenticationType = AuthenticationTypes[randInt];

        randInt = randValue % EncryptionTypes.size();
        encryptionType = EncryptionTypes[randInt];

        randInt = randValue % AESLifetimes.size();
        aesLifetime = AESLifetimes[randInt];

        randInt = randValue % keyBufferLengthEncryptionValues.size();
        keyBufferLengthEncryption = keyBufferLengthEncryptionValues[randInt];

        randInt = randValue % keyBufferLengthAuthenticationValues.size();
        keyBufferLengthAuthentication = keyBufferLengthAuthenticationValues[randInt];

        randInt = randValue % appHoldTimeVlues.size();
        appHoldTime = appHoldTimeVlues[randInt];
           
        LinkDetails* linkD = new LinkDetails;
        //linkD->srcAddress = interfacesToKMSAlice.GetAddress(0);
        //linkD->dstAddress = interfacesToKMSBob.GetAddress(1);
        linkD->nodes = std::to_string(n.Get(i)->GetId()) + "-" + std::to_string(n.Get(j)->GetId());
        linkD->title = "ETSI 004 Connection: " + linkD->nodes; 
        linkD->type = 1;
        linkD->m_encryptionType = encryptionType;
        linkD->m_authenticationType = authenticationType;
        linkD->m_aesLifeTime = aesLifetime;
        linkD->m_packetSize = appPacketSize;
        linkD->m_trafficRate = appRate; 
        linkD->m_sizeOfKeyBufferForEncryption = keyBufferLengthEncryption;
        linkD->m_sizeOfKeyBufferForAuthentication = keyBufferLengthAuthentication;
        linkD->m_startTime = appStartTime;
        linkD->m_stopTime = appStopTime;


        Ipv4Address address_i;
        Ipv4Address address_j;
        uint32_t control_i = 0;
        uint32_t control_j = 0; 

        if(i==0) 
        {
            address_i = i0i2.GetAddress(0);
            control_i = 12;  
        }else if(i == 2)
        {
            address_i = i2i4.GetAddress(0);
            control_i = 13;  
        }else if(i == 4)
        {
            address_i = i4i8.GetAddress(0);
            control_i = 14;  
        }else if(i == 6) 
        {
            address_i = i6i8.GetAddress(0);
            control_i = 15;              
        }else if(i == 8) 
        {
            address_i = i8i10.GetAddress(0);
            control_i = 16; 
        }
 
        if(j==2) 
        {
            address_j = i0i2.GetAddress(1);
            control_j = 13; 
        }else if(j == 4) 
        {
            address_j = i2i4.GetAddress(1);
            control_j = 14; 
        }else if(j == 6) 
        {
            address_j = i2i6.GetAddress(1);
            control_j = 15; 
        }else if(j == 8) 
        {
            address_j = i4i8.GetAddress(1);
            control_j = 16; 
        }else if(j == 10) 
        {
            address_j = i8i10.GetAddress(1);
            control_j = 17; 
        }

        //Create APP to consume keys
        //ALICE sends user's data
        uint16_t communicationPort = 8181+a;   

        //Set default values for applications created below         
        QAHelper.SetAttribute("app004", "EncryptionType", UintegerValue(encryptionType));
        QAHelper.SetAttribute("app004", "AuthenticationType", UintegerValue(authenticationType));
        QAHelper.SetAttribute("app004", "AESLifetime", UintegerValue(aesLifetime));
        QAHelper.SetAttribute("app004", "LengthOfKeyBufferForEncryption", UintegerValue(keyBufferLengthEncryption));
        QAHelper.SetAttribute("app004", "LengthOfKeyBufferForAuthentication", UintegerValue(keyBufferLengthAuthentication));
        QAHelper.SetAttribute("app004", "SocketToKMSHoldTime", TimeValue (Seconds (appHoldTime)));
        QAHelper.SetAttribute("app004","UseCrypto", UintegerValue (useCrypto)); 

        ApplicationContainer Etsi004cryptographicApplications;  
        Etsi004cryptographicApplications.Add(
            QAHelper.InstallQKDApplication(
                n.Get(i),
                n.Get(j),
                InetSocketAddress (address_i, communicationPort),    //Address A
                InetSocketAddress (address_j, communicationPort),    //Address B
                n.Get(control_i),  //Controller-A
                n.Get(control_j),  //Controller-B
                "tcp",      //Connection type
                appPacketSize, //Payload size
                DataRate (appRate), //Data rate
                "etsi004"   //Application type 
            )
        ); 
        Ptr<QKDApp004> CA = DynamicCast<QKDApp004> (Etsi004cryptographicApplications.Get(0));
        Ptr<QKDApp004> CB = DynamicCast<QKDApp004> (Etsi004cryptographicApplications.Get(1)); 
        cryptographicApplications.Add(Etsi004cryptographicApplications);

        linkD->etsi004srcApp = CA;
        linkD->etsi004dstApp = CB;
        auto ret =  m_nodePairs.insert( std::make_pair( CA->GetId(),  linkD) ); 
        NS_ABORT_MSG_IF(!ret.second, "Duplicate CA app ID " << CA->GetId());
        auto ret2 = m_nodePairs.insert( std::make_pair( CB->GetId(),  linkD) );
        NS_ABORT_MSG_IF(!ret2.second, "Duplicate CB app ID " << CB->GetId());

        if(systemId == systemID0) {
            std::cout << linkD->title << "\n";
            std::cout << "Alice NodeId: " << n.Get(i)->GetId() << " Alice App IP: " << address_i << " ID: " << CA->GetId() << std::endl;
            std::cout << "Bob NodeId: " << n.Get(j)->GetId() << " Bob App IP: " << address_j  << " ID: " << CB->GetId() << std::endl;
            std::cout << "SrcKMSNode: " << n.Get(control_i)->GetId() << std::endl;
            std::cout << "DstKMSNode: " << n.Get(control_j)->GetId() << std::endl;
            std::cout << "EncryptionType: " << encryptionType << std::endl;
            std::cout << "AuthenticationType: " << authenticationType << std::endl;
            std::cout << "AESLifetime: " << aesLifetime << std::endl; 
            std::cout << "AppRate: " << appRate << std::endl; 
            std::cout << "AppPacketSize: " << appPacketSize << std::endl; 
            std::cout << "LengthOfKeyBufferForEncryption: " << keyBufferLengthEncryption << std::endl;
            std::cout << "LengthOfKeyBufferForAuthentication: " << keyBufferLengthAuthentication << std::endl;
            std::cout << "AppHoldTime: " << appHoldTime << std::endl;
        }
    } 

    cryptographicApplications.Start (Seconds (appStartTime));
    cryptographicApplications.Stop (Seconds (appStopTime));

    Ipv4GlobalRoutingHelper::PopulateRoutingTables ();
    QLinkHelper.CreateTopologyGraph({controlSiteA, controlSiteB, controlSiteC, controlSiteD, controlSiteE, controlSiteF});
    QLinkHelper.PopulateRoutingTables();
    //QLinkHelper.AddGraphs();
 
    //////////////////////////////////////
    ////         STATISTICS
    //////////////////////////////////////
    if(numberOfETSI004ApplicationLinks > 0)
    {
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp004/Tx", MakeCallback(&SentPacket));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp004/Rx", MakeCallback(&ReceivedPacket));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp004/TxSig", MakeCallback(&SentPacketSig));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp004/RxSig", MakeCallback(&ReceivedPacketSig));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp004/TxKMS", MakeCallback(&SentPacketToKMS));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp004/RxKMS", MakeCallback(&ReceivedPacketFromKMS));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp004/Mx", MakeCallback(&MissedSendPacketCall)); 
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp004/KSIDUpdated", MakeCallback(&Etsi004KSIDGenerated));
    }
    
    if(numberOfETSI014ApplicationLinks > 0)
    {
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp014/Tx", MakeCallback(&SentPacket));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp014/Rx", MakeCallback(&ReceivedPacket));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp014/Mx", MakeCallback(&MissedSendPacketCall));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp014/TxSig", MakeCallback(&SentPacketSig));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp014/RxSig", MakeCallback(&ReceivedPacketSig));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp014/TxKMS", MakeCallback(&SentPacketToKMS));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp014/RxKMS", MakeCallback(&ReceivedPacketFromKMS));
    }

    //Connect Traces for KM key statistics
    //Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDKeyManagerSystemApplication/KeyServed", MakeCallback(&KeyServed));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDKeyManagerSystemApplication/KeyServedMixed", MakeCallback(&KeyServedMixed));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDKeyManagerSystemApplication/KeyConsumedLink", MakeCallback(&KeyConsumedLink));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDKeyManagerSystemApplication/QKDKeyGenerated", MakeCallback(&KeyGenerated));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDKeyManagerSystemApplication/RelayConsumption", MakeCallback(&RelayKeyTrace));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDKeyManagerSystemApplication/TxKMSs", MakeCallback(&TxKMSs));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDKeyManagerSystemApplication/RxKMSs", MakeCallback(&RxKMSs));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDKeyManagerSystemApplication/KSIDUpdated", MakeCallback(&Etsi004KSIDGenerated));
    
    if(trace){
        //if we need we can create pcap files
        AsciiTraceHelper ascii;
        p2p.EnableAsciiAll (ascii.CreateFileStream ("qkd_etis014.tr"));
        p2p.EnablePcapAll ("qkd_etis014");
        AnimationInterface anim ("qkd_etis014.xml");  // where "animation.xml" is any arbitrary filename
    }


    //Finally print the graphs
    //QLinkHelper.PrintGraphs();  

    if(systemId == systemID0){
        std::cout << "simTime:\t" << simulationTime << "\n";  
        std::cout << "useCrypto:\t" << useCrypto << "\n";
        std::cout << "trace:\t" << trace << "\n";
    }
 
    if(systemId == systemID0){
        if(showKeyAdded || showKeyServed) {
            if(outputFileType == "json") logFile << ']';
        }
    }        


    Simulator::Stop (Seconds (simulationTime));
    Simulator::Run ();

    if(systemId == systemID0){
        std::string tempStatsFile = "temp_stats_" + std::to_string(systemId);
        CreateOutputForCPU(tempStatsFile);
       Ratio(outputStatsName, systemCount);
    }

    Simulator::Destroy ();
    //MpiInterface::Disable (); 

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tock);

    execTime = 1000000000 * (tock.tv_sec - tick.tv_sec) + tock.tv_nsec - tick.tv_nsec;
    printf("elapsed process CPU time = %llu nanoseconds\n", (long long unsigned int) execTime);

    return 0;
}

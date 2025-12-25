/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba 
 *
 * Execute using ./waf --run scratch/qkd_etsi_combined_input.cc --command-template="mpirun -np 4 %s"
 *
 * Author:  Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 *          Miralem Mehic <miralem.mehic@etf.unsa.ba>
 */
#include <stdio.h>
#include <fstream>
#include "ns3/core-module.h" 
#include "ns3/applications-module.h"
#include "ns3/internet-module.h" 
#include "ns3/flow-monitor-module.h" 
#include "ns3/mobility-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/internet-apps-module.h"
#include "ns3/gnuplot.h" 

#include "ns3/qkd-link-helper.h" 
#include "ns3/qkd-app-helper.h"
#include "ns3/qkd-app-004.h"

#include "ns3/network-module.h" 
#include "ns3/internet-apps-module.h"
#include "ns3/netanim-module.h" 
#include "ns3/mpi-module.h"
 
using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("QKD_ETSI004");
 
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
    uint32_t m_bufferCapacityBits = 0;
    double m_avgSizeOfGeneratedKeys = 0;
    double m_avgSizeOfConsumedKeys = 0;

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

    std::map<std::string, uint32_t> m_keyIDGeneratedInBuffers;
    std::map<std::string, uint32_t> m_keyIDConsumedInBuffers;
    std::map<std::string, uint32_t> m_keyIDConsumedByKMS;
};

std::map<std::string, LinkDetails*> m_nodePairs;

void 
write_csv(std::string filename, std::vector<std::pair<std::string, std::vector<uint32_t>>> dataset)
{
    // Make a CSV file with one or more columns of integer values
    // Each column of data is represented by the pair <column name, column data>
    //   as std::pair<std::string, std::vector<int>>
    // The dataset is represented as a vector of these columns
    // Note that all columns should be the same size
    
    // Create an output filestream object
    std::ofstream myFile(filename);
    
    // Send column names to the stream
    for(uint32_t j = 0; j < dataset.size(); ++j)
    {
        myFile << dataset.at(j).first;
        if(j != dataset.size() - 1) myFile << ","; // No comma at end of line
    }
    myFile << "\n";
    
    // Send data to the stream
    for(uint32_t i = 0; i < dataset.at(0).second.size(); ++i)
    {
        for(uint32_t j = 0; j < dataset.size(); ++j)
        {
            myFile << dataset.at(j).second.at(i);
            if(j != dataset.size() - 1) myFile << ","; // No comma at end of line
        }
        myFile << "\n";
    }
    
    // Close the file
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

/**
 * Keys served from KMS to end-user application
 */
void
KeyServed (std::string context, const std::string& appId, const std::string& keyId, const uint32_t& amountInBits)
{    
    
    //std::cout << appId << ";" << keyId << ";" << amountInBits << "\n";
    std::map<std::string, LinkDetails* >::iterator it = m_nodePairs.find(appId);
    std::string linkId = it->second->nodes;
    std::string jointKeyId = keyId + std::to_string(amountInBits);

    std::map<std::string, uint32_t>::iterator it2 = it->second->m_keyIDConsumedInBuffers.find ( jointKeyId );

    if (it2 == it->second->m_keyIDConsumedInBuffers.end ()){ 
        it->second->m_keyIDConsumedInBuffers.insert( std::make_pair( jointKeyId, amountInBits) );
    
    }else{
        //std::cout << "consumed" << "\t" << it->second->nodes << "\n"; 
        it->second->m_keysConsumedBits += amountInBits;   
        it->second->m_keysConsumed++;

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
    it->second->m_missedSendPacketCalls++;
}

void
ReceivedPacket(std::string context, const std::string& appId, Ptr<const Packet> p)
{
    std::map<std::string, LinkDetails* >::iterator it = m_nodePairs.find(appId);
    it->second->m_bytes_received += p->GetSize();   
    it->second->m_appPacketsReceived++;
}

void
SentPacketSig(std::string context, const std::string& appId, Ptr<const Packet> p)
{
    std::map<std::string, LinkDetails* >::iterator it = m_nodePairs.find(appId);
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
}

void
ReceivedPacketSig(std::string context, const std::string& appId, Ptr<const Packet> p)
{
    std::map<std::string, LinkDetails* >::iterator it = m_nodePairs.find(appId);
    it->second->m_sig_bytes_received += p->GetSize();   
    it->second->m_appSigPacketsReceived++;
}

void
SentPacketToKMS(std::string context, const std::string& appId, Ptr<const Packet> p)
{
    std::map<std::string, LinkDetails* >::iterator it = m_nodePairs.find(appId);
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
}

void
ReceivedPacketFromKMS(std::string context, const std::string& appId, Ptr<const Packet> p)
{     
    std::map<std::string, LinkDetails* >::iterator it = m_nodePairs.find(appId);
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
}

void 
CreateOutputForCPU(std::string outputStatsName)
{
    std::vector<std::pair<std::string, std::vector<uint32_t> > > output;

    for (std::map<std::string, LinkDetails* >::iterator it = m_nodePairs.begin(); it != m_nodePairs.end(); ++it) {

        if(it->second->m_printed)continue;

        std::vector<uint32_t> temp(45,0);
        temp[0] = it->second->type;
        
        if(it->second->type == 0){

            double avgSizeOfConsumedKeys = 0;
            for (std::map<std::string, uint32_t>::iterator it2 = it->second->m_keyIDConsumedInBuffers.begin(); 
                it2 != it->second->m_keyIDConsumedInBuffers.end(); ++it2) {
                avgSizeOfConsumedKeys += it2->second;
            }
            avgSizeOfConsumedKeys = avgSizeOfConsumedKeys/it->second->m_keyIDConsumedInBuffers.size();
            it->second->m_avgSizeOfConsumedKeys = avgSizeOfConsumedKeys;

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
            //temp[38] = it->second->m_keysWasted;
            //temp[39] = it->second->m_keysWastedBits;

        }else{

            double avgSizeOfConsumedKeys = 0;
            for (std::map<std::string, uint32_t>::iterator it2 = it->second->m_keyIDConsumedInBuffers.begin(); 
                it2 != it->second->m_keyIDConsumedInBuffers.end(); ++it2) {
                avgSizeOfConsumedKeys += it2->second;
            }
            avgSizeOfConsumedKeys = avgSizeOfConsumedKeys/it->second->m_keyIDConsumedInBuffers.size();
            it->second->m_avgSizeOfConsumedKeys = avgSizeOfConsumedKeys;

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
 
 
        } 

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

        if(it->second->m_printed)continue;
        std::string nodes = it->second->nodes;

        if(it->second->type == 0){
            output["qkd_links"][nodes]["Link distance (meters)"] = 0;
            output["qkd_links"][nodes]["Key rate (bit/sec)"] = 0;
            output["qkd_links"][nodes]["Key-pairs generated"] = 0;
            output["qkd_links"][nodes]["Key-pairs generated (bits)"] = 0;
            output["qkd_links"][nodes]["Key-pairs consumed"] = 0;
            output["qkd_links"][nodes]["Key-pairs consumed (bits)"] = 0;
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

            output[type][nodes]["Key Consumption Statistics"]["Key-pairs consumed"] = 0;
            output[type][nodes]["Key Consumption Statistics"]["Key-pairs consumed (bits)"] = 0;
            output[type][nodes]["Key Consumption Statistics"]["Average size of consumed key-pairs (bits)"] = 0;
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

                if(type == "qkd_links"){
                    output[type][nodes]["Link distance (meters)"]                   = cpuValues.at(0).at(j).second.at(1);
                    output[type][nodes]["Key rate (bit/sec)"]                       = cpuValues.at(0).at(j).second.at(2);
                    output[type][nodes]["Key-pairs generated"]                      = cpuValues.at(0).at(j).second.at(3);
                    output[type][nodes]["Key-pairs generated (bits)"]               = cpuValues.at(0).at(j).second.at(4);
                    output[type][nodes]["Key-pairs consumed"]                       = cpuValues.at(0).at(j).second.at(5);
                    output[type][nodes]["Key-pairs consumed (bits)"]                = cpuValues.at(0).at(j).second.at(6); 
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
                    << "\nQKDBuffer Capacity (bits):\t" << output[type][nodes]["QKDBuffer Capacity (bits)"]
                    << "\nLink distance (meters):\t\t" << output[type][nodes]["Link distance (meters)"]
                    << "\nKey rate (bit/sec):\t\t" << output[type][nodes]["Key rate (bit/sec)"]
                    << "\nKey-pairs generated:\t" << output[type][nodes]["Key-pairs generated"]
                    << "\tKey-pairs generated (bits):\t" << output[type][nodes]["Key-pairs generated (bits)"]
                    << "\nKey-pairs consumed:\t"  << output[type][nodes]["Key-pairs consumed"]
                    << "\tKey-pairs consumed (bits):\t" << output[type][nodes]["Key-pairs consumed (bits)"] 
                    << "\nKey-pairs relayed:\t" << output[type][nodes]["Key-pairs relayed"]
                    << "\tKey-pairs relayed (bits):\t" << output[type][nodes]["Key-pairs relayed (bits)"]
                    //<< "\nKey-pairs wasted:\t" << output[type][nodes]["Key-pairs wasted"]
                    //<< "\tKey-pairs wasted (bits):\t" << output[type][nodes]["Key-pairs wasted (bits)"]
                    << "\nAvg size of generated keys (bits):\t" << output[type][nodes]["Average size of generated key-pairs (bits)"]
                    << "\nAvg size of consumed keys (bits):\t" << output[type][nodes]["Average size of consumed key-pairs (bits)"]
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
                    if(cpuValues.at(0).at(j).second.at(12) && cpuValues.at(0).at(j).second.at(14)){
                        utilization = (double) cpuValues.at(0).at(j).second.at(12) / (double) (cpuValues.at(0).at(j).second.at(12) + cpuValues.at(0).at(j).second.at(14)); 
                        utilization *= 100;
                        utilization = std::ceil(utilization * 100.0) / 100.0;
                    }
                    output[type][nodes]["QKDApps Statistics"]["Key/Data utilization (%)"] = utilization;

                    output[type][nodes]["QKDApps Statistics"]["Encryption"]        = cpuValues.at(0).at(j).second.at(15);
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

                    output[type][nodes]["Key Consumption Statistics"]["Key-pairs consumed"] = cpuValues.at(0).at(j).second.at(5);
                    output[type][nodes]["Key Consumption Statistics"]["Key-pairs consumed (bits)"]  = cpuValues.at(0).at(j).second.at(6);
                    output[type][nodes]["Key Consumption Statistics"]["Average size of consumed key-pairs (bits)"] = cpuValues.at(0).at(j).second.at(8); 

                    std::cout << "QKDApps " << type << ": " << nodes << "\n\n"
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
                        << "\nNumber of Keys to Fetch From KMS:\t" << output[type][nodes]["QKDApps Statistics"]["Number of Keys to Fetch From KMS"];
                    }

                    std::cout
                    << "\nMissed send packet calls:\t" << output[type][nodes]["QKDApps Statistics"]["Missed send packet calls"]
                    << "\nSent (bytes):\t" <<  output[type][nodes]["QKDApps Statistics"]["Bytes Sent"]
                    << "\tReceived (bytes):\t" << output[type][nodes]["QKDApps Statistics"]["Bytes Received"]
                    << "\nSent (Packets):\t" <<  output[type][nodes]["QKDApps Statistics"]["Packets Sent"]
                    << "\tReceived (Packets):\t" << output[type][nodes]["QKDApps Statistics"]["Packets Received"]
                    << "\nKey/Data utilization (%):\t" << output[type][nodes]["QKDApps Statistics"]["Key/Data utilization (%)"]
                    
                    << "\nRatio (bytes):\t" << (float)output[type][nodes]["QKDApps Statistics"]["Bytes Received"]/(float)output[type][nodes]["QKDApps Statistics"]["Bytes Sent"]
                    << "\tRatio (packets):\t" << (float)output[type][nodes]["QKDApps Statistics"]["Packets Received"]/(float)output[type][nodes]["QKDApps Statistics"]["Packets Sent"]
                    << "\nStart Time (sec):\t" << output[type][nodes]["QKDApps Statistics"]["Start Time (sec)"]
                    << "\nStop Time (sec):\t" << output[type][nodes]["QKDApps Statistics"]["Stop Time (sec)"]
                    << "\n"

                    << "\n- Signaling stats:"
                    << "\nSent (bytes):\t" <<  output[type][nodes]["Signaling Statistics"]["Bytes Sent"]
                    << "\tReceived (bytes):\t" << output[type][nodes]["Signaling Statistics"]["Bytes Received"]
                    << "\nSent (Packets):\t" <<  output[type][nodes]["Signaling Statistics"]["Packets Sent"]
                    << "\tReceived (Packets):\t" << output[type][nodes]["Signaling Statistics"]["Packets Received"] 
                    << "\n";

                    std::cout << "\n- QKDApps to KMS stats:"
                    << "\nSent (bytes):\t" <<  output[type][nodes]["QKDApps-KMS Statistics"]["Bytes Sent"]
                    << "\tReceived (bytes):\t" << output[type][nodes]["QKDApps-KMS Statistics"]["Bytes Received"]
                    << "\nSent (Packet):\t" <<  output[type][nodes]["QKDApps-KMS Statistics"]["Packets Sent"]
                    << "\tReceived (Packet):\t" << output[type][nodes]["QKDApps-KMS Statistics"]["Packets Received"] 
                    << "\n";

                    std::cout << "\n- Key Consumption Statistics:"
                    << "\nKey-pairs consumed:\t" <<  output[type][nodes]["Key Consumption Statistics"]["Key-pairs consumed"]
                    << "\nKey-pairs consumed (bits):\t" << output[type][nodes]["Key Consumption Statistics"]["Key-pairs consumed (bits)"] 
                    << "\nAverage size of consumed key-pairs (bits):\t" << output[type][nodes]["Key Consumption Statistics"]["Average size of consumed key-pairs (bits)"] 
                    << "\n\n";
                }
            }

        }
    } 
        
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
    uint64_t execTime;
    struct timespec tick, tock;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tick);

    // Sequential fallback values
    uint32_t systemId = 0;
    uint32_t systemCount = 1;

    MpiInterface::Enable (&argc, &argv);
    systemId = MpiInterface::GetSystemId ();
    systemCount = MpiInterface::GetSize ();

    std::cout << "SystemId: " << systemId << std::endl;
    GlobalValue::Bind ("SimulatorImplementationType", StringValue ("ns3::DistributedSimulatorImpl"));

    NS_LOG_INFO ("Create nodes.");
    NodeContainer n;
    NodeContainer KMSNodes;
    NodeContainer QControlNodes;
    double  appHoldTime = 0.5;
    uint16_t simulationTime = 150; 
    uint32_t encryptionType = 1; //0-unencrypted, 1-OTP, 2-AES256
    uint32_t numberOfKeyToFetchFromKMS = 3;
    uint32_t aesLifetime = 10000; //In bytes! 64GB = 68719476736B
    uint32_t keyBufferLengthEncryption = 3;
    uint32_t authenticationType = 1; //0-unauthenticated, 1-VMAC, 2-SHA1
    uint32_t keyBufferLengthAuthentication = 6; 
    uint32_t useCrypto = 0;

    uint32_t appRate = 100000; //In bps
    uint32_t appPacketSize =  800; //In bytes
    uint32_t ppKeyRate = 10000; //In bps
    uint32_t ppKeySize = 8192; //In bytes
    uint32_t ppPacketSize = 100; //In bytes
    uint32_t ppRate = 1000; 

    std::string outputFileName ("output.json");
    std::string outputStatsName("stats.json");
    std::string inputFileName("contrib/qkdnetsim/examples/input.json");
    std::string srcNodeId;
    std::string dstNodeId;

    bool trace = false;
    uint32_t numberOfNodes = 0;
    uint32_t numberOfQKDLinks = 0;
    uint32_t numberOfQKDNodes = 0; 
    uint32_t numberOfETSI004ApplicationLinks = 0;
    uint32_t numberOfETSI014ApplicationLinks = 0;
    uint32_t seedValue = 0; 
    double startTime = 0;
    double stopTime = 0;
    std::string linkName;

    // Configure command line parameters
    CommandLine cmd;
    cmd.AddValue ("showKeyServed", "Show trace when a key is served from KMS", showKeyServed); 
    cmd.AddValue ("showKeyAdded", "Show trace when a key is generated", showKeyAdded);  
    cmd.AddValue ("simTime", "Simulation time (seconds)", simulationTime);  
    cmd.AddValue ("useCrypto", "Perform crypto functions?", useCrypto);
    cmd.AddValue ("trace", "Enable datapath stats and pcap traces", trace);
    cmd.AddValue ("outputFile", "Name of the output file", outputFileName);
    cmd.AddValue ("outputType", "Type of the output file", outputFileType); 
    cmd.AddValue ("inputFile", "Type of the input file", inputFileName); 
    cmd.AddValue ("statsFile", "Name of the output json stats file", outputStatsName); 
    cmd.AddValue ("seed", "Random Seed Value", seedValue); 
    cmd.Parse (argc, argv);
 
    GlobalValue::Bind ("SimulatorImplementationType", StringValue ("ns3::DistributedSimulatorImpl"));

    uint32_t systemID0 = 0;
    uint32_t systemID1 = 1;
    uint32_t systemID2 = 2; 

    if(systemCount == 1){
        systemID0 = 0;
        systemID1 = 0;
        systemID2 = 0; 
    }else if(systemCount == 2){
        systemID0 = 0;
        systemID1 = 1;
        systemID2 = 0; 
    }else if(systemCount == 3){
        systemID0 = 0;
        systemID1 = 1;
        systemID2 = 2; 
    }

    // read a JSON file
    nlohmann::json inputParams;
    try {
        std::ifstream inputValues(inputFileName);
        inputValues >> inputParams;
        numberOfQKDLinks = inputParams["qkd_links"].size();
        numberOfETSI004ApplicationLinks = inputParams["etsi_004"].size();
        numberOfETSI014ApplicationLinks = inputParams["etsi_014"].size();
    } catch(...) {
      NS_LOG_FUNCTION( "JSON parse error!");
    } 

    if(systemId == systemID0){
        logFile.open(outputFileName, std::ofstream::out | std::ofstream::trunc);
        if(outputFileType == "json" && (showKeyAdded || showKeyServed)) logFile << '[';
    }

    //FILTER QKD NODES - make them unique
    std::vector<std::string> qkdNodesIDs;
    for(uint32_t a=0; a<numberOfQKDLinks;a++)
    {   
        srcNodeId = inputParams["qkd_links"][a]["srcNodeId"].dump();
        dstNodeId = inputParams["qkd_links"][a]["dstNodeId"].dump();
        qkdNodesIDs.push_back(srcNodeId);
        qkdNodesIDs.push_back(dstNodeId);
    }
    //fetch unique list of QKD nodes
    std::sort(qkdNodesIDs.begin(), qkdNodesIDs.end()); 
    auto last = std::unique(qkdNodesIDs.begin(), qkdNodesIDs.end());
    qkdNodesIDs.erase(last, qkdNodesIDs.end());

    numberOfQKDNodes = qkdNodesIDs.size();
    if(systemId == systemID0){
        std::cout << "Unique size of QKDNodes: " << qkdNodesIDs.size() << "\n";
    }

    //FILTER ETSI014 NODES
    for(uint32_t a=0; a<numberOfETSI004ApplicationLinks;a++)
    {   
        srcNodeId = inputParams["etsi_004"][a]["srcNodeId"].dump();
        dstNodeId = inputParams["etsi_004"][a]["dstNodeId"].dump();

        if (std::find(qkdNodesIDs.begin(), qkdNodesIDs.end(),srcNodeId)==qkdNodesIDs.end())
            NS_FATAL_ERROR ( "Independent application nodes are not supported! " << srcNodeId);
        if (std::find(qkdNodesIDs.begin(), qkdNodesIDs.end(),dstNodeId)==qkdNodesIDs.end())
            NS_FATAL_ERROR ( "Idependent application nodes are not supported! "  << dstNodeId);
    }

    //FILTER ETSI014 NODES
    std::vector<std::string> etsi004nodes;
    for(uint32_t a=0; a<numberOfETSI004ApplicationLinks;a++)
    {   
        srcNodeId = inputParams["etsi_004"][a]["srcNodeId"].dump();
        dstNodeId = inputParams["etsi_004"][a]["dstNodeId"].dump();

        if (std::find(qkdNodesIDs.begin(), qkdNodesIDs.end(),srcNodeId)==qkdNodesIDs.end())
            NS_FATAL_ERROR ( "Independent application nodes are not supported! " << srcNodeId);
        if (std::find(qkdNodesIDs.begin(), qkdNodesIDs.end(),dstNodeId)==qkdNodesIDs.end())
            NS_FATAL_ERROR ( "Independent application nodes are not supported! " << dstNodeId);
    }

    ns3::RngSeedManager::SetSeed(100);
    RngSeedManager::SetRun (seedValue); 
    srand( seedValue ); //seeding for the first time only!

    //In input.json nodes counter start from one while 
    Ptr<Node> zeroNode = CreateObject<Node> (systemID0);
    n.Add (zeroNode);
    QControlNodes.Add(zeroNode);
    KMSNodes.Add(zeroNode);
    
    //For each QKDNode, we have additional QKDControl and LKMS
    //Thus, for n QKD nodes, we have n*3 nodes (QKDnode + QKDControl + LKMS)
    numberOfNodes = numberOfQKDNodes*3;
    
    for(uint32_t i=1; i<=numberOfQKDNodes; i++){
        //QKDnode
        Ptr<Node> node1 = CreateObject<Node> (systemID0);
        n.Add (node1);
    }
    for(uint32_t i=1; i<=numberOfQKDNodes; i++){
        //LKMS
        Ptr<Node> node3 = CreateObject<Node> (systemID2);
        n.Add (node3);
        QControlNodes.Add(node3);
    } 
    for(uint32_t i=1; i<=numberOfQKDNodes; i++){
        //QKDControl
        Ptr<Node> node2 = CreateObject<Node> (systemID1);
        n.Add (node2);
        KMSNodes.Add(node2);
    }
     

    if(systemId == systemID0) {
        std::cout << "Number of CPUs:\t" << systemCount << "\n";
        std::cout << "Number of QKD Nodes:\t" << numberOfQKDNodes << "\n";
        std::cout << "Number of QKD Links:\t" << numberOfQKDLinks << "\n";
        std::cout << "Number of ETSI 004 Application Links:\t" << numberOfETSI004ApplicationLinks << "\n";
        std::cout << "Number of ETSI 014 Application Links:\t" << numberOfETSI014ApplicationLinks << "\n";
        std::cout << "Number of Nodes:\t" << numberOfNodes << "\n\n";
    }
    
    //install QKD Control the node (numberOfQKDNodes+i)
    QKDAppHelper QAHelper; 
    QKDLinkHelper QLinkHelper;  
    std::vector<Ptr<QKDControl> > m_qkdControl;
    for(uint32_t i=1; i<=numberOfQKDNodes;i++){
        Ptr<QKDControl> control = QLinkHelper.InstallQKDNController ( QControlNodes.Get(i) ); 
        m_qkdControl.push_back(control);
        if(systemId == systemID0) {
            std::cout << "Install QKDNControl on node: " << QControlNodes.Get(i)->GetId() << "\n";
        }
    }
    QLinkHelper.ConfigureQBuffers ( //Configure Q-Buffers
        {m_qkdControl},
        1024,       //min
        51200,      //thr
        500000000,  //max
        0,          //current
        512         //default key size in bits
    );
    QLinkHelper.ConfigureRSBuffers ( //Configure S-Buffers for relay (RBuffers)!
        {m_qkdControl},
        0,
        16000, //Treshold
        64000, //Mmax
        0,
        512
    );

    InternetStackHelper internet;
    internet.Install (n);

    // Set Mobility for all nodes  
    MobilityHelper mobility;
    mobility.SetPositionAllocator ("ns3::RandomRectanglePositionAllocator",
                                  "X", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=1000.0]"),
                                  "Y", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=1000.0]"));
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(n);

    // We create the channels first without any IP addressing information
    NS_LOG_INFO ("Create channels.");
    std::string p2pDataRate = "100Mbps";
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute ("DataRate", StringValue (p2pDataRate));
    p2p.SetChannelAttribute ("Delay", StringValue ("2ms")); 
 
 
    //
    // We've got the "hardware" in place.  Now we need to add IP addresses.
    // 
    NS_LOG_INFO ("Assign IP Addresses.");
    Ipv4AddressHelper ipv4;
    ipv4.SetBase ("10.1.0.0", "255.255.255.0");

    if(systemId == systemID0) 
        std::cout << "\n*********\n*** KMS Configuration\n*********\n";
 
    uint32_t maximalKeysPerRequest = 10;// inputParams["kms_nodes"]["maximalKeysPerRequest"];
    uint32_t minimalKeySize = 32;//inputParams["kms_nodes"]["minimalKeySize"];
    uint32_t maximalKeySize = 8192;//inputParams["kms_nodes"]["maximalKeySize"];
 
    Config::SetDefault ("ns3::QKDKeyManagerSystemApplication::MaximalKeySize", UintegerValue (maximalKeySize));
    Config::SetDefault ("ns3::QKDKeyManagerSystemApplication::MinimalKeySize", UintegerValue (minimalKeySize));
    Config::SetDefault ("ns3::QKDKeyManagerSystemApplication::MaximalKeysPerRequest", UintegerValue (maximalKeysPerRequest));

    if(systemId == systemID0) 
    {
        std::cout << "MaximalKeySize: " << maximalKeySize << std::endl; 
        std::cout << "MinimalKeySize: " << minimalKeySize << std::endl; 
        std::cout << "MaximalKeysPerRequest: " << maximalKeysPerRequest << std::endl; 
    }  
  
    for(uint32_t i=1; i<=numberOfQKDNodes; i++){
              
        //create p2p link qkdnode<->KMS
        Ipv4InterfaceContainer interfacesBetweenQNodeKMS;
        linkName = std::to_string(n.Get(i)->GetId()) + "_" + std::to_string(KMSNodes.Get(i)->GetId());
        if(!DoesLinkExist(linkName, interfacesBetweenQNodeKMS)){
 
            NodeContainer nodesToApp = NodeContainer (n.Get(i), KMSNodes.Get (i)); 
            NetDeviceContainer devicesToApp = p2p.Install (nodesToApp);            
            std::string ipV4Base = "10.1." + std::to_string(m_interfaces.size()+1) + ".0";
            ipv4.SetBase(ipV4Base.c_str(), "255.255.255.0");
            interfacesBetweenQNodeKMS = ipv4.Assign (devicesToApp);
            m_interfaces.insert( std::make_pair(  linkName ,  interfacesBetweenQNodeKMS) );

            std::cout  
            << "Create link QKDNode-KMS: " << n.Get(i)->GetId() << "(" << interfacesBetweenQNodeKMS.GetAddress(0) << ")" 
            << "-" 
            << KMSNodes.Get(i)->GetId() << "(" << interfacesBetweenQNodeKMS.GetAddress(1) << ")" 
            << "\n";

            if( !KMSNodes.Get(i)->GetObject<QKDKeyManagerSystemApplication>() ){
                
                if(systemId == systemID0) { 
                    std::cout << "Install KMS on node " << KMSNodes.Get(i)->GetId() << " with IP address: " << interfacesBetweenQNodeKMS.GetAddress(1) << std::endl;
                }

                //install KMs
                QAHelper.InstallKeyManager(//Install key manager for site A
                    KMSNodes.Get(i),//Node KM-A
                    interfacesBetweenQNodeKMS.GetAddress(1), //IP address KM-A
                    80,                 //Port
                    m_qkdControl[i-1]     //Assigned controller A
                );                  
            }
        }
 
    }

 

    if(systemId == systemID0) 
        std::cout << "\n*********\n*** Post-Processing Configuration\n*********\n";


    for(uint32_t i=0; i<KMSNodes.GetN();i++){
        std::cout << "KMSNode: " << KMSNodes.Get(i)->GetId() << "\n";
    }


    //////////////////////////////////////
    //  QKD LINKS
    //////////////////////////////////////
    std::vector<uint32_t> keySizes = {1024, 2048, 4096, 8192}; //, 16384};
    std::vector<uint32_t> keyRates = {5000, 10000, 15000}; //, 20000};
    std::vector<uint32_t> ppPacketSizes = {100,150,200,250,300,350};
    std::vector<uint32_t> ppRates = {1000, 1500, 2000, 2500, 3000};     
    uint32_t maxBufferCapacity = 50000000;
    for(uint32_t a=0; a<numberOfQKDLinks;a++)
    {   
        srcNodeId = inputParams["qkd_links"][a]["srcNodeId"].dump();
        dstNodeId = inputParams["qkd_links"][a]["dstNodeId"].dump();

        int i=std::stoi(srcNodeId);
        int j=std::stoi(dstNodeId);

        //std::string ipV4Base = "10.1." + std::to_string(i+1) + ".0";
        //Ipv4Address addressBase;
        //addressBase.Set(ipV4Base.c_str());

        //Create p2p connection between QKD nodes
        Ipv4InterfaceContainer interfaces;
        linkName = std::to_string(n.Get(i)->GetId()) + "_" + std::to_string(n.Get(j)->GetId());
        if(!DoesLinkExist(linkName,  interfaces)){
 
            //distance SrcToDst in meter  
            p2p.SetDeviceAttribute ("DataRate", StringValue (p2pDataRate));
            p2p.SetChannelAttribute ("Delay", StringValue ("2ms")); 
     
            NodeContainer nodesToApp = NodeContainer (n.Get(i), n.Get (j)); 
            NetDeviceContainer devicesToApp = p2p.Install (nodesToApp);
            std::string ipV4Base = "10.1." + std::to_string(m_interfaces.size()+1) + ".0";
            ipv4.SetBase(ipV4Base.c_str(), "255.255.255.0");
            interfaces = ipv4.Assign (devicesToApp);
            m_interfaces.insert( std::make_pair(  linkName ,  interfaces) );

            std::cout  
            << "Create link QKDNode-QKDNode: " << n.Get(i)->GetId() << "(" << interfaces.GetAddress(0) << ")" 
            << "-" 
            << n.Get(j)->GetId() << "(" << interfaces.GetAddress(1) << ")" 
            << "\n";
        }

        Ipv4InterfaceContainer interfacesBetweenKMSs;
        linkName = std::to_string(KMSNodes.Get(i)->GetId()) + "_" + std::to_string(KMSNodes.Get(j)->GetId());
        if(!DoesLinkExist(linkName,  interfacesBetweenKMSs)){

            //distance SrcToDst in meter  
            p2p.SetDeviceAttribute ("DataRate", StringValue (p2pDataRate));
            p2p.SetChannelAttribute ("Delay", StringValue ("2ms")); 
     
            NodeContainer nodesToApp = NodeContainer (KMSNodes.Get(i), KMSNodes.Get (j)); 
            NetDeviceContainer devicesToApp = p2p.Install (nodesToApp);
            std::string ipV4Base = "10.1." + std::to_string(m_interfaces.size()+1) + ".0";
            ipv4.SetBase(ipV4Base.c_str(), "255.255.255.0");
            interfacesBetweenKMSs = ipv4.Assign (devicesToApp);
            m_interfaces.insert( std::make_pair(  linkName ,  interfacesBetweenKMSs) );

            std::cout  
            << "Create link KMSNode-KMSNode: " << KMSNodes.Get(i)->GetId() << "(" << interfacesBetweenKMSs.GetAddress(0) << ")" 
            << "-" 
            << KMSNodes.Get(j)->GetId() << "(" << interfacesBetweenKMSs.GetAddress(1) << ")" 
            << "\n";
        }

        ppKeySize = inputParams["qkd_links"][a]["keySize"];
        ppKeyRate = inputParams["qkd_links"][a]["keyRate"];
        ppPacketSize = inputParams["qkd_links"][a]["ppPacketSize"];
        ppRate = inputParams["qkd_links"][a]["ppRate"]; 
        startTime = inputParams["qkd_links"][a]["startTime"];
        stopTime = inputParams["qkd_links"][a]["stopTime"]; 
 
        LinkDetails* linkD = new LinkDetails;
        //linkD->nodes = std::to_string(n.Get(i)->GetId()) + "-" + std::to_string(n.Get(j)->GetId());
        linkD->nodes = srcNodeId + "-" + dstNodeId;
        linkD->title = "QKD link: " + linkD->nodes; 
        linkD->type = 0; 
        linkD->m_avgSizeOfGeneratedKeys = 0; 
        linkD->m_avgSizeOfConsumedKeys = 0; 
        linkD->m_keyRate = ppKeyRate;
        linkD->m_linkDistance = inputParams["qkd_links"][a]["srcDstDistance"];
        linkD->m_startTime = startTime;
        linkD->m_stopTime = stopTime;
        linkD->m_bufferCapacityBits = maxBufferCapacity;
        linkD->srcNodeId = std::stoi(srcNodeId);
        linkD->dstNodeId = std::stoi(dstNodeId);
        linkD->srcKMSNodeId = KMSNodes.Get(i)->GetId();
        linkD->dstKMSNodeId = KMSNodes.Get(j)->GetId();

        if(systemId == systemID0) {
            std::cout << linkD->title << std::endl;
            std::cout << "SrcNode: " << n.Get(i)->GetId() << " Source IP address: " << interfaces.GetAddress(0) << std::endl;
            std::cout << "DstNode: " << n.Get(j)->GetId() << " Destination IP address: " << interfaces.GetAddress(1) << std::endl;
            std::cout << "Src controller: " << n.Get(numberOfQKDNodes+a)->GetId() << " Interface to Alice controller IP address: " << interfaces.GetAddress(0) << std::endl;
            std::cout << "Dst controller: " << n.Get(numberOfQKDNodes+a+1)->GetId() << " Interface to Bob controller IP address: " << interfaces.GetAddress(1) << std::endl;
            std::cout << "ppKeySize: " << ppKeySize << std::endl; 
            std::cout << "ppKeyRate: " << ppKeyRate << std::endl; 
            std::cout << "ppPacketSize: " << ppPacketSize << std::endl; 
            std::cout << "ppRate: " << ppRate << std::endl; 
        }
        
        //Create APP to generate keys
        ApplicationContainer postprocessingApplications;
        postprocessingApplications.Add( 
            QAHelper.InstallPostProcessing(
                n.Get(i),           //QKD module A
                n.Get(j),           //QKD module B
                InetSocketAddress (interfaces.GetAddress(0), 102+a),
                InetSocketAddress (interfaces.GetAddress(1), 102+a),
                QControlNodes.Get(i),   //Controller-A
                QControlNodes.Get(j), //Controller-B
                ppKeySize,   //size of key to be added to QKD buffer
                DataRate (ppKeyRate), //average QKD key rate
                ppPacketSize,    //average data packet size
                DataRate (ppRate) //average data traffic rate
            )
        ); 

        postprocessingApplications.Start (Seconds (startTime));
        postprocessingApplications.Stop (Seconds (stopTime)); 

        Ptr<QKDPostprocessingApplication> ppA = DynamicCast<QKDPostprocessingApplication> (postprocessingApplications.Get(0));
        m_nodePairs.insert( std::make_pair( ppA->GetId(),  linkD) );

        uint32_t temp = linkD->srcNodeId;
        linkD->srcNodeId = linkD->dstNodeId;
        linkD->dstNodeId = temp;

        Ptr<QKDPostprocessingApplication> ppB = DynamicCast<QKDPostprocessingApplication> (postprocessingApplications.Get(1));
        m_nodePairs.insert( std::make_pair( ppB->GetId(),  linkD) );
        
        if(systemId == systemID0) {
            std::cout << "startTime: " << startTime << std::endl; 
            std::cout << "stopTime: " << stopTime << std::endl; 
            std::cout << "\n";
        }
        
    }
 
    if(systemId == systemID0)
        std::cout << "\n";

    //////////////////////////////////////
    //  QKD APP ETSI 004
    //////////////////////////////////////

    if(systemId == systemID0)
        std::cout << "\n*********\n*** ETSI 004 Configuration\n*********\n";
    
    //Set default values for applications created below
    Config::SetDefault ("ns3::QKDApp004::UseCrypto", UintegerValue (useCrypto));
 
    std::vector<uint32_t> keyBufferLengthEncryptionValues = {1,3,5,10,15,20};
    std::vector<uint32_t> keyBufferLengthAuthenticationValues = {6,10,15,20,50};  
    
    std::vector<uint32_t> AuthenticationTypes = {0,1,2};
    std::vector<uint32_t> EncryptionTypes = {0,1,2};
    std::vector<uint32_t> AESLifetimes = {10000, 20000, 100000,200000,300000,400000,500000};

    std::vector<uint32_t> appPacketSizes = {100,300,500,800,1100};
    std::vector<uint32_t> appRates = {20000, 30000, 50000, 100000, 150000}; //, 200000, 250000, 500000};
     

    for(uint32_t a=0; a<numberOfETSI004ApplicationLinks ;a++)
    {   
        appRate = inputParams["etsi_004"][a]["appRate"];
        appPacketSize = inputParams["etsi_004"][a]["appPacketSize"];
        authenticationType = inputParams["etsi_004"][a]["authenticationType"];
        encryptionType = inputParams["etsi_004"][a]["encryptionType"];
        keyBufferLengthEncryption = inputParams["etsi_004"][a]["keyBufferLengthEncryptionValue"];
        keyBufferLengthAuthentication = inputParams["etsi_004"][a]["keyBufferLengthAuthenticationValues"];

        if (*find(appRates.begin(), appRates.end(), appRate) != appRate) 
            NS_FATAL_ERROR ( "appRate (" << appRate << ") is not supported!");

        if (*find(appPacketSizes.begin(), appPacketSizes.end(), appPacketSize) != appPacketSize) 
            NS_FATAL_ERROR ( "appPacketSize (" << appPacketSize << ") is not supported!");

        if (*find(AuthenticationTypes.begin(), AuthenticationTypes.end(), authenticationType) != authenticationType) 
            NS_FATAL_ERROR ( "authenticationType (" << authenticationType << ") is not supported!");

        if (*find(EncryptionTypes.begin(), EncryptionTypes.end(), encryptionType) != encryptionType) 
            NS_FATAL_ERROR ( "encryptionType (" << encryptionType << ") is not supported!");

        if (*find(keyBufferLengthEncryptionValues.begin(), keyBufferLengthEncryptionValues.end(), keyBufferLengthEncryption) != keyBufferLengthEncryption) 
            NS_FATAL_ERROR ( "keyBufferLengthEncryption (" << keyBufferLengthEncryption << ") is not supported!");

        if (*find(keyBufferLengthAuthenticationValues.begin(), keyBufferLengthAuthenticationValues.end(), keyBufferLengthAuthentication) != keyBufferLengthAuthentication) 
            NS_FATAL_ERROR ( "keyBufferLengthAuthentication (" << keyBufferLengthAuthentication << ") is not supported!");

        if(encryptionType == 2){
            aesLifetime = inputParams["etsi_004"][a]["aesLifetime"];
            if (*find(AESLifetimes.begin(), AESLifetimes.end(), aesLifetime) != aesLifetime) 
                NS_FATAL_ERROR ( "aesLifetime (" << aesLifetime << ") is not supported!");
        }
        
        startTime = inputParams["etsi_004"][a]["startTime"];
        stopTime = inputParams["etsi_004"][a]["stopTime"]; 

        //Set default values for applications created below 
        Config::SetDefault ("ns3::QKDApp004::LengthOfKeyBufferForEncryption", UintegerValue (keyBufferLengthEncryption));
        Config::SetDefault ("ns3::QKDApp004::LengthOfKeyBufferForAuthentication", UintegerValue (keyBufferLengthAuthentication));

        Config::SetDefault ("ns3::QKDApp004::AuthenticationType", UintegerValue (authenticationType)); //(0-unauthenticated, 1-VMAC, 2-SHA1)
        Config::SetDefault ("ns3::QKDApp004::EncryptionType", UintegerValue (encryptionType)); //(0-unencrypted, 1-OTP, 2-AES)

        if(encryptionType == 2){
            Config::SetDefault ("ns3::QKDApp004::AESLifetime", UintegerValue (aesLifetime));
        }

        srcNodeId = inputParams["etsi_004"][a]["srcNodeId"].dump();
        dstNodeId = inputParams["etsi_004"][a]["dstNodeId"].dump();

        int i=std::stoi(srcNodeId);
        int j=std::stoi(dstNodeId);
        
        Ipv4InterfaceContainer interfacesToApp;
        linkName = std::to_string(n.Get(i)->GetId()) + "_" + std::to_string(n.Get(j)->GetId());
        if(!DoesLinkExist(linkName, interfacesToApp)){
            //distance SrcToDst in meter 
            std::string delayStringSrcDst = CalculateAverageDelayBasedOnDistance(inputParams["etsi_004"][a]["srcDstDistance"]);
            p2p.SetDeviceAttribute ("DataRate", StringValue (p2pDataRate));
            p2p.SetChannelAttribute ("Delay", StringValue (delayStringSrcDst)); 

            std::cout << "Create link node-node: " << n.Get(i)->GetId() << "\t" << n.Get(j)->GetId() << "\n";
            NodeContainer nodesToApp = NodeContainer (n.Get(i), n.Get (j)); 
            NetDeviceContainer devicesToApp = p2p.Install (nodesToApp);
            std::string ipV4Base = "10.1." + std::to_string(m_interfaces.size()+1) + ".0";
            ipv4.SetBase(ipV4Base.c_str(), "255.255.255.0");
            interfacesToApp = ipv4.Assign (devicesToApp);
            m_interfaces.insert( std::make_pair(  linkName ,  interfacesToApp) );
        }

        Ipv4InterfaceContainer interfacesToKMSA;
        linkName = std::to_string(n.Get(i)->GetId()) + "_" + std::to_string(KMSNodes.Get(i)->GetId());
        if(!DoesLinkExist(linkName,  interfacesToKMSA)){
            p2p.SetDeviceAttribute ("DataRate", StringValue (p2pDataRate));
            p2p.SetChannelAttribute ("Delay", StringValue ("2ms")); 

            std::cout << "Create link node-KMSA: " << n.Get(i)->GetId() << "\t" << KMSNodes.Get(i)->GetId() << "\n";
            NodeContainer nodesToKMSA = NodeContainer (n.Get(i), KMSNodes.Get (i)); 
            NetDeviceContainer devicesToKMSA = p2p.Install (nodesToKMSA);
            std::string ipV4Base = "10.1." + std::to_string(m_interfaces.size()+1) + ".0";
            ipv4.SetBase(ipV4Base.c_str(), "255.255.255.0");
            interfacesToKMSA = ipv4.Assign (devicesToKMSA);            
            m_interfaces.insert( std::make_pair(  linkName ,  interfacesToKMSA) );
        }

        Ipv4InterfaceContainer interfacesToKMSB;
        linkName = std::to_string(n.Get(j)->GetId()) + "_" + std::to_string(KMSNodes.Get(j)->GetId());
        if(!DoesLinkExist(linkName,  interfacesToKMSB)){
            p2p.SetDeviceAttribute ("DataRate", StringValue (p2pDataRate));
            p2p.SetChannelAttribute ("Delay", StringValue ("2ms")); 

            std::cout << "Create link node-KMSB: " << n.Get(j)->GetId() << "\t" << KMSNodes.Get(j)->GetId() << "\n";
            NodeContainer nodesToKMSB = NodeContainer (n.Get(j), KMSNodes.Get (j)); 
            NetDeviceContainer devicesToKMSB = p2p.Install (nodesToKMSB);
            std::string ipV4Base = "10.1." + std::to_string(m_interfaces.size()+1) + ".0";
            ipv4.SetBase(ipV4Base.c_str(), "255.255.255.0");
            interfacesToKMSB = ipv4.Assign (devicesToKMSB);            
            m_interfaces.insert( std::make_pair(  linkName ,  interfacesToKMSB) );
        }


        LinkDetails* linkD = new LinkDetails;
        //linkD->nodes = std::to_string(n.Get(i)->GetId()) + "-" + std::to_string(n.Get(j)->GetId());
        linkD->nodes = srcNodeId + "-" + dstNodeId;
        linkD->title = "ETSI 004 Connection: " + linkD->nodes; 
        linkD->type = 1;
        linkD->m_encryptionType = encryptionType;
        linkD->m_authenticationType = authenticationType;
        linkD->m_aesLifeTime = aesLifetime;
        linkD->m_packetSize = appPacketSize;
        linkD->m_trafficRate = appRate;
        linkD->m_sizeOfKeyBufferForEncryption = keyBufferLengthEncryption;
        linkD->m_sizeOfKeyBufferForAuthentication = keyBufferLengthAuthentication;
        linkD->m_startTime = startTime;
        linkD->m_stopTime = stopTime;

        if(systemId == systemID0) {
            std::cout << linkD->title << "\n";
            std::cout << "Alice NodeId: " << n.Get(i)->GetId() << " Alice App IP: " << interfacesToApp.GetAddress(0) << std::endl;
            std::cout << "Bob NodeId: " << n.Get(j)->GetId() << " Bob App IP: " << interfacesToApp.GetAddress(1) << std::endl;
            std::cout << "EncryptionType: " << encryptionType << std::endl;
            std::cout << "AuthenticationType: " << authenticationType << std::endl;
            if(encryptionType == 2){
                std::cout << "AESLifetime: " << aesLifetime << std::endl; 
            }
            std::cout << "AppRate: " << appRate << std::endl; 
            std::cout << "AppPacketSize: " << appPacketSize << std::endl; 
            std::cout << "LengthOfKeyBufferForEncryption: " << keyBufferLengthEncryption << std::endl;
            std::cout << "LengthOfKeyBufferForAuthentication: " << keyBufferLengthAuthentication << std::endl;

            std::cout << "startTime: " << startTime << std::endl; 
            std::cout << "stopTime: " << stopTime << std::endl;
        }

        //Set default values for applications created below
        Config::SetDefault ("ns3::QKDApp004::AuthenticationType", UintegerValue (authenticationType)); //(0-unauthenticated, 1-VMAC, 2-SHA1)
        Config::SetDefault ("ns3::QKDApp004::EncryptionType", UintegerValue (encryptionType)); //(0-unencrypted, 1-OTP, 2-AES)
        Config::SetDefault ("ns3::QKDApp004::AESLifetime", UintegerValue (aesLifetime));
        Config::SetDefault ("ns3::QKDApp004::UseCrypto", UintegerValue (useCrypto));
        Config::SetDefault ("ns3::QKDApp004::LengthOfKeyBufferForEncryption", UintegerValue (keyBufferLengthEncryption));
        Config::SetDefault ("ns3::QKDApp004::LengthOfKeyBufferForAuthentication", UintegerValue (keyBufferLengthAuthentication));
        Config::SetDefault ("ns3::QKDApp004::SocketToKMSHoldTime", TimeValue (Seconds (appHoldTime)));

        Config::SetDefault ("ns3::TcpSocket::TcpNoDelay", BooleanValue (true));
        Config::SetDefault ("ns3::TcpSocketState::EnablePacing", BooleanValue (false));

        uint16_t communicationPort = 8081+a;
        ApplicationContainer cryptographicApplications;
        cryptographicApplications.Add(
            QAHelper.InstallQKDApplication(
                n.Get(i),   //Source Node
                n.Get(j),   //Destination Node 
                InetSocketAddress (interfacesToApp.GetAddress(0), communicationPort), //Source address
                InetSocketAddress (interfacesToApp.GetAddress(1), communicationPort), //Destination address
                QControlNodes.Get(i),   //Controller 1
                QControlNodes.Get(j),   //Controller 2
                "tcp",      //Connection type
                appPacketSize, //Payload size
                DataRate (appRate), //Data rate
                "etsi004"   //Application type
            )
        );
        cryptographicApplications.Start (Seconds (startTime));
        cryptographicApplications.Stop (Seconds (stopTime));

        if(systemId == systemID0)
            std::cout << "\n";

        Ptr<QKDApp004> CA = DynamicCast<QKDApp004> (cryptographicApplications.Get(0));
        m_nodePairs.insert( std::make_pair( CA->GetId(),  linkD) ); 
        Ptr<QKDApp004> CB = DynamicCast<QKDApp004> (cryptographicApplications.Get(1));
        m_nodePairs.insert( std::make_pair( CB->GetId(),  linkD) );
    }


    //////////////////////////////////////
    //  QKD APP ETSI 014
    //////////////////////////////////////

    if(systemId == systemID0)
        std::cout << "\n*********\n*** ETSI 014 Configuration\n*********\n";
    
    //Set default values for applications created below
    Config::SetDefault ("ns3::QKDApp014::UseCrypto", UintegerValue (useCrypto));

    std::vector<uint32_t> numberOfKeyToFetchFromKMSOptions = {3,5,8,10,15,20};
    std::vector<double> appHoldPenaltyTimeValues = {1, 3, 5}; 

    for(uint32_t a=0; a<numberOfETSI014ApplicationLinks;a++)
    {   
        appRate = inputParams["etsi_014"][a]["appRate"];
        appPacketSize = inputParams["etsi_014"][a]["appPacketSize"];
        authenticationType = inputParams["etsi_014"][a]["authenticationType"];
        encryptionType = inputParams["etsi_014"][a]["encryptionType"];
        numberOfKeyToFetchFromKMS = inputParams["etsi_014"][a]["numberOfKeyToFetchFromKMSOptions"]; 
        appHoldTime = 3; //inputParams["etsi_014"][a]["appHoldTimeValue"];

        if (*find(appRates.begin(), appRates.end(), appRate) != appRate) 
            NS_FATAL_ERROR ( "appRate (" << appRate << ") is not supported!");

        if (*find(appPacketSizes.begin(), appPacketSizes.end(), appPacketSize) != appPacketSize) 
            NS_FATAL_ERROR ( "appPacketSize (" << appPacketSize << ") is not supported!");

        if (*find(AuthenticationTypes.begin(), AuthenticationTypes.end(), authenticationType) != authenticationType) 
            NS_FATAL_ERROR ( "authenticationType (" << authenticationType << ") is not supported!");

        if (*find(EncryptionTypes.begin(), EncryptionTypes.end(), encryptionType) != encryptionType) 
            NS_FATAL_ERROR ( "encryptionType (" << encryptionType << ") is not supported!");

        if(encryptionType == 2){
            aesLifetime = inputParams["etsi_014"][a]["aesLifetime"];
            if (*find(AESLifetimes.begin(), AESLifetimes.end(), aesLifetime) != aesLifetime) 
                NS_FATAL_ERROR ( "aesLifetime (" << aesLifetime << ") is not supported!");
        }

        if (*find(numberOfKeyToFetchFromKMSOptions.begin(), numberOfKeyToFetchFromKMSOptions.end(), numberOfKeyToFetchFromKMS) != numberOfKeyToFetchFromKMS) 
            NS_FATAL_ERROR ( "numberOfKeyToFetchFromKMS (" << numberOfKeyToFetchFromKMS << ") is not supported!");

        if (*find(appHoldPenaltyTimeValues.begin(), appHoldPenaltyTimeValues.end(), appHoldTime) != appHoldTime) 
            NS_FATAL_ERROR ( "appHoldTime (" << appHoldTime << ") is not supported!");

        startTime = inputParams["etsi_014"][a]["startTime"];
        stopTime = inputParams["etsi_014"][a]["stopTime"]; 

        //Set default values for applications created below
        Config::SetDefault ("ns3::QKDApp014::NumberOfKeyToFetchFromKMS", UintegerValue (numberOfKeyToFetchFromKMS));//Number of keys to obtain per request!
        Config::SetDefault ("ns3::QKDApp014::AuthenticationType", UintegerValue (authenticationType)); //(0-unauthenticated, 1-VMAC, 2-SHA1)
        Config::SetDefault ("ns3::QKDApp014::EncryptionType", UintegerValue (encryptionType)); //(0-unencrypted, 1-OTP, 2-AES)
        Config::SetDefault ("ns3::QKDApp014::WaitInsufficient", TimeValue (Seconds (appHoldTime)));

        if(encryptionType == 2){
            Config::SetDefault ("ns3::QKDApp014::AESLifetime", UintegerValue (aesLifetime));
        }
         
        srcNodeId = inputParams["etsi_014"][a]["srcNodeId"].dump();
        dstNodeId = inputParams["etsi_014"][a]["dstNodeId"].dump();

        int i=std::stoi(srcNodeId);
        int j=std::stoi(dstNodeId);
        
        Ipv4InterfaceContainer interfacesToApp;
        linkName = std::to_string(n.Get(i)->GetId()) + "_" + std::to_string(n.Get(j)->GetId());
        if(!DoesLinkExist(linkName, interfacesToApp)){
            //distance SrcToDst in meter 
            std::string delayStringSrcDst = CalculateAverageDelayBasedOnDistance(inputParams["etsi_014"][a]["srcDstDistance"]);
            p2p.SetDeviceAttribute ("DataRate", StringValue (p2pDataRate));
            p2p.SetChannelAttribute ("Delay", StringValue (delayStringSrcDst)); 

            std::cout << "Create link node-node: " << n.Get(i)->GetId() << "\t" << n.Get(j)->GetId() << "\n";
            NodeContainer nodesToApp = NodeContainer (n.Get(i), n.Get (j)); 
            NetDeviceContainer devicesToApp = p2p.Install (nodesToApp);
            std::string ipV4Base = "10.1." + std::to_string(m_interfaces.size()+1) + ".0";
            ipv4.SetBase(ipV4Base.c_str(), "255.255.255.0");
            interfacesToApp = ipv4.Assign (devicesToApp);
            m_interfaces.insert( std::make_pair(  linkName ,  interfacesToApp) );
        }

        Ipv4InterfaceContainer interfacesToKMSA;
        linkName = std::to_string(n.Get(i)->GetId()) + "_" + std::to_string(KMSNodes.Get(i)->GetId());
        if(!DoesLinkExist(linkName,  interfacesToKMSA)){
            p2p.SetDeviceAttribute ("DataRate", StringValue (p2pDataRate));
            p2p.SetChannelAttribute ("Delay", StringValue ("2ms")); 

            std::cout << "Create link node-KMSA: " << n.Get(i)->GetId() << "\t" << KMSNodes.Get(i)->GetId() << "\n";
            NodeContainer nodesToKMSA = NodeContainer (n.Get(i), KMSNodes.Get (i)); 
            NetDeviceContainer devicesToKMSA = p2p.Install (nodesToKMSA);
            std::string ipV4Base = "10.1." + std::to_string(m_interfaces.size()+1) + ".0";
            ipv4.SetBase(ipV4Base.c_str(), "255.255.255.0");
            interfacesToKMSA = ipv4.Assign (devicesToKMSA);            
            m_interfaces.insert( std::make_pair(  linkName ,  interfacesToKMSA) );
        }

        Ipv4InterfaceContainer interfacesToKMSB;
        linkName = std::to_string(n.Get(j)->GetId()) + "_" + std::to_string(KMSNodes.Get(j)->GetId());
        if(!DoesLinkExist(linkName,  interfacesToKMSB)){
            p2p.SetDeviceAttribute ("DataRate", StringValue (p2pDataRate));
            p2p.SetChannelAttribute ("Delay", StringValue ("2ms")); 

            std::cout << "Create link node-KMSB: " << n.Get(j)->GetId() << "\t" << KMSNodes.Get(j)->GetId() << "\n";
            NodeContainer nodesToKMSB = NodeContainer (n.Get(j), KMSNodes.Get (j)); 
            NetDeviceContainer devicesToKMSB = p2p.Install (nodesToKMSB);
            std::string ipV4Base = "10.1." + std::to_string(m_interfaces.size()+1) + ".0";
            ipv4.SetBase(ipV4Base.c_str(), "255.255.255.0");
            interfacesToKMSB = ipv4.Assign (devicesToKMSB);            
            m_interfaces.insert( std::make_pair(  linkName ,  interfacesToKMSB) );
        }
 
        LinkDetails* linkD = new LinkDetails;
        //linkD->nodes = std::to_string(n.Get(i)->GetId()) + "-" + std::to_string(n.Get(j)->GetId());
        linkD->nodes = srcNodeId + "-" + dstNodeId;
        linkD->title = "ETSI 014 Connection: " + linkD->nodes; 
        linkD->type = 2;
        linkD->m_encryptionType = encryptionType;
        linkD->m_authenticationType = authenticationType;
        linkD->m_aesLifeTime = aesLifetime;
        linkD->m_packetSize = appPacketSize;
        linkD->m_trafficRate = appRate;
        linkD->m_numberOfKeysToFetchFromKMS = numberOfKeyToFetchFromKMS; 
        linkD->m_startTime = startTime;
        linkD->m_stopTime = stopTime;

        if(systemId == systemID0){
            std::cout << linkD->title << "\n";
            std::cout << "Alice NodeId: " << n.Get(i)->GetId() << " Alice App IP: " << interfacesToApp.GetAddress(0) << std::endl;
            std::cout << "Bob NodeId: " << n.Get(j)->GetId() << " Bob App IP: " << interfacesToApp.GetAddress(1) << std::endl; 
            std::cout << "EncryptionType: " << encryptionType << std::endl;
            std::cout << "AuthenticationType: " << authenticationType << std::endl;
            if(encryptionType == 2){
                std::cout << "AESLifetime: " << aesLifetime << std::endl; 
            }
            std::cout << "AppRate: " << appRate << std::endl; 
            std::cout << "AppPacketSize: " << appPacketSize << std::endl; 
            std::cout << "NumberOfKeyToFetchFromKMS: " << numberOfKeyToFetchFromKMS << std::endl;
            std::cout << "AppHoldTime: " << appHoldTime << std::endl;
            std::cout << "startTime: " << startTime << std::endl; 
            std::cout << "stopTime: " << stopTime << std::endl;
        }

        //Set default values for applications created below
        Config::SetDefault ("ns3::QKDApp014::NumberOfKeyToFetchFromKMS", UintegerValue (numberOfKeyToFetchFromKMS));//Number of keys to obtain per request!
        Config::SetDefault ("ns3::QKDApp014::AuthenticationType", UintegerValue (authenticationType)); //(0-unauthenticated, 1-VMAC, 2-SHA1)
        Config::SetDefault ("ns3::QKDApp014::EncryptionType", UintegerValue (encryptionType)); //(0-unencrypted, 1-OTP, 2-AES)
        Config::SetDefault ("ns3::QKDApp014::AESLifetime", UintegerValue (aesLifetime));
        Config::SetDefault ("ns3::QKDApp014::UseCrypto", UintegerValue (useCrypto));

        uint16_t communicationPort = 9081+a;
        ApplicationContainer cryptographicApplications;
        cryptographicApplications.Add(
            QAHelper.InstallQKDApplication(
                n.Get(i),   //Source Node
                n.Get(j),   //Destination Node
                InetSocketAddress (interfacesToApp.GetAddress(0), communicationPort), //Source address
                InetSocketAddress (interfacesToApp.GetAddress(1), communicationPort), //Destination address
                QControlNodes.Get(i),   //Controller 1
                QControlNodes.Get(j),   //Controller 2
                "tcp",      //Connection type
                appPacketSize, //Payload size
                DataRate (appRate), //Data rate
                "etsi014"   //Application type
            )
        );
        cryptographicApplications.Start (Seconds (startTime));
        cryptographicApplications.Stop (Seconds (stopTime));
   
        Ptr<QKDApp014> CA = DynamicCast<QKDApp014> (cryptographicApplications.Get(0));
        m_nodePairs.insert( std::make_pair( CA->GetId(),  linkD) ); 
        Ptr<QKDApp014> CB = DynamicCast<QKDApp014> (cryptographicApplications.Get(1));
        m_nodePairs.insert( std::make_pair( CB->GetId(),  linkD) );
    }

    Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

    QLinkHelper.CreateTopologyGraph({m_qkdControl});
    QLinkHelper.PopulateRoutingTables();

    if(systemId == systemID0){
        std::cout << "\n";
    }

    //////////////////////////////////////
    ////         STATISTICS
    //////////////////////////////////////


    if(numberOfETSI004ApplicationLinks){
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp004/Tx", MakeCallback(&SentPacket));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp004/Rx", MakeCallback(&ReceivedPacket));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp004/Mx", MakeCallback(&MissedSendPacketCall)); 
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp004/TxSig", MakeCallback(&SentPacketSig));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp004/RxSig", MakeCallback(&ReceivedPacketSig));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp004/TxKMS", MakeCallback(&SentPacketToKMS));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp004/RxKMS", MakeCallback(&ReceivedPacketFromKMS));
    }

    if(numberOfETSI014ApplicationLinks){
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp014/Tx", MakeCallback(&SentPacket));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp014/Rx", MakeCallback(&ReceivedPacket));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp014/Mx", MakeCallback(&MissedSendPacketCall)); 
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp014/TxSig", MakeCallback(&SentPacketSig));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp014/RxSig", MakeCallback(&ReceivedPacketSig));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp014/TxKMS", MakeCallback(&SentPacketToKMS));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp014/RxKMS", MakeCallback(&ReceivedPacketFromKMS));
    }

    //Connect Traces for KM key statistics 
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDKeyManagerSystemApplication/KeyServed", MakeCallback(&KeyServed));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDKeyManagerSystemApplication/KeyConsumedLink", MakeCallback(&KeyConsumedLink));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDKeyManagerSystemApplication/QKDKeyGenerated", MakeCallback(&KeyGenerated));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDKeyManagerSystemApplication/RelayConsumption", MakeCallback(&RelayKeyTrace));
    //Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDKeyManagerSystemApplication/WasteRelay", MakeCallback(&WasteKeyTrace));
    
    //@toDo: disable after debuging
    if(trace){
        //if we need we can create pcap files
        AsciiTraceHelper ascii;
        p2p.EnableAsciiAll (ascii.CreateFileStream ("qkd_etis004.tr"));
        p2p.EnablePcapAll ("qkd_etis004");  
        AnimationInterface anim ("qkd_etsi_combined.xml");  // where "animation.xml" is any arbitrary filename
    }

    Simulator::Stop (Seconds (simulationTime));
    Simulator::Run ();
 
    //Finally print the graphs
    //QLinkHelper.PrintGraphs();
    
    if(systemId == systemID0){
        std::cout << "simTime:\t" << simulationTime << "\n";  
        std::cout << "useCrypto:\t" << useCrypto << "\n";
        std::cout << "trace:\t" << trace << "\n";
    }

    //Finally print the graphs
    //QLinkHelper.PrintGraphs();

    if(systemId == systemID0){
        if(showKeyAdded || showKeyServed) {
            if(outputFileType == "json") logFile << ']';
        }
    }        

    std::string tempStatsFile = "temp_stats_" + std::to_string(systemId);
    CreateOutputForCPU(tempStatsFile);

    if(systemId == systemID0){
       Ratio(outputStatsName, systemCount);
    }

    Simulator::Destroy ();
    MpiInterface::Disable (); 

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tock);

    execTime = 1000000000 * (tock.tv_sec - tick.tv_sec) + tock.tv_nsec - tick.tv_nsec;
    printf("elapsed process CPU time = %llu nanoseconds\n", (long long unsigned int) execTime);

    return 0;
}
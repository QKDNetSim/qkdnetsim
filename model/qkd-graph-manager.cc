/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 *
 *
 * Author: Miralem Mehic <miralem.mehic@etf.unsa.ba>
 *
 * QKDGraphManager is a singleton class!
 */

#include "qkd-graph-manager.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("QKDGraphManager");

NS_OBJECT_ENSURE_REGISTERED(QKDGraphManager);

TypeId QKDGraphManager::GetTypeId()
{
  static TypeId tid = TypeId("ns3::QKDGraphManager")
    .SetParent<Object>()
    ;
  return tid;
}

bool QKDGraphManager::instanceFlag = false;
Ptr<QKDTotalGraph> QKDGraphManager::m_totalGraph = nullptr;
QKDGraphManager* QKDGraphManager::single = nullptr;
QKDGraphManager* QKDGraphManager::getInstance()
{
    if(!instanceFlag){
		m_totalGraph = CreateObject<QKDTotalGraph>("QKD Total Graph", "png");
		single = new QKDGraphManager();
		instanceFlag = true;
    }
    return single;
}

QKDGraphManager::~QKDGraphManager(){
	instanceFlag = false;
	delete single;

}

Ptr<QKDTotalGraph>
QKDGraphManager::GetTotalGraph(){
	return m_totalGraph;
}

void
QKDGraphManager::PrintGraphs(){

    NS_LOG_FUNCTION(this);
	m_totalGraph->PrintGraph();
	for(size_t i = 0; i < m_graphs.size(); ++i)
	{
    	for(size_t j = 0; j < m_graphs[i].size(); ++j)
    	{
    	    Ptr<QKDGraph> graph = m_graphs[i][j];
            graph->PrintGraph();
        }
	}
}


void
QKDGraphManager::SendCurrentChangeValueToGraph(const uint32_t& nodeID,const uint32_t& bufferPosition,const uint32_t& value){

    NS_LOG_FUNCTION(this << nodeID << bufferPosition << value);
	m_graphs[nodeID][bufferPosition]->ProcessMCurrent(value);
}

void
QKDGraphManager::SendStatusValueToGraph(const uint32_t& nodeID, const uint32_t& bufferPosition,const uint32_t& value){

    NS_LOG_FUNCTION(this << nodeID << bufferPosition << value);
	m_graphs[nodeID][bufferPosition]->ProcessMStatus(value);
}

void
QKDGraphManager::SendThresholdValueToGraph(const uint32_t& nodeID, const uint32_t& bufferPosition, const uint32_t& value){

    NS_LOG_FUNCTION(this << nodeID << bufferPosition << value);
	m_graphs[nodeID][bufferPosition]->ProcessMThrStatus(value);
}

void
QKDGraphManager::ProcessCurrentChange(std::string context, uint32_t value)
{
	//NS_LOG_FUNCTION(context << value);
	//std::cout << Simulator::Now() << "\t" << context << value << "\t\n" ;

	///NodeList/8/ApplicationList/0/$ns3::QKDKeyManagerSystemApplication/BufferList/1/CurrentChange
	int nodeId=0;
	int applicationId=0;
	int bufferPosition=0;
	std::sscanf(context.c_str(), "/NodeList/%d/ApplicationList/%d/$ns3::QKDKeyManagerSystemApplication/BufferList/%d/*", &nodeId, &applicationId, &bufferPosition);

	QKDGraphManager::single->SendCurrentChangeValueToGraph(nodeId, bufferPosition, value);
}

void
QKDGraphManager::ProcessStatusChange(std::string context, uint32_t value)
{
	//NS_LOG_FUNCTION(context << value);
	//NodeList/0/ApplicationList/%d/$ns3::QKDKeyManagerSystemApplication/BufferList/0/CurrentChange
	int nodeId=0;
	int applicationId=0;
	int bufferPosition=0;
	std::sscanf(context.c_str(), "/NodeList/%d/ApplicationList/%d/$ns3::QKDKeyManagerSystemApplication/BufferList/%d/*", &nodeId, &applicationId,  &bufferPosition);

	QKDGraphManager::single->SendStatusValueToGraph(nodeId, bufferPosition, value);
}

void
QKDGraphManager::ProcessThresholdChange(std::string context, uint32_t value)
{
	//NodeList/0/ApplicationList/%d/$ns3::QKDKeyManagerSystemApplication/BufferList/0/ThresholdChange
	int nodeId=0;
	int applicationId=0;
	int bufferPosition=0;
	std::sscanf(context.c_str(), "/NodeList/%d/ApplicationList/%d/$ns3::QKDKeyManagerSystemApplication/BufferList/%d/*", &nodeId, &applicationId, &bufferPosition);

	QKDGraphManager::single->SendThresholdValueToGraph(nodeId, bufferPosition, value);
}


// FOR QKD TOTAL GRAPH
void
QKDGraphManager::ProcessCurrentIncrease(std::string context, uint32_t value)
{
 	m_totalGraph->ProcessMCurrent(value, '+');
}

// FOR QKD TOTAL GRAPH
void
QKDGraphManager::ProcessCurrentDecrease(std::string context, uint32_t value)
{
	m_totalGraph->ProcessMCurrent(value, '-');
}
 

void
QKDGraphManager::CreateGraphForBuffer(
	Ptr<Node> srcKMSNode,
	Ptr<Node> dstKMSNode,
	uint32_t bufferPosition,
	uint32_t srcKMSApplicationIndex,
	std::string graphName = "",
	std::string graphType = "",
	Ptr<QBuffer> buff = nullptr
) {
    NS_LOG_FUNCTION(this << srcKMSNode->GetId() << dstKMSNode->GetId() << bufferPosition << srcKMSApplicationIndex << graphName);

  	uint32_t nodeMax = srcKMSNode->GetId();
  	uint32_t nodeID = nodeMax;
  	if(srcKMSNode->GetId() < dstKMSNode->GetId())
  		nodeMax = dstKMSNode->GetId();

	if(m_graphs.size() <= static_cast<size_t>(nodeMax))
	    m_graphs.resize(nodeMax + 1); // Resize based on nodeID directly, not nodeMax

	if(m_graphs[nodeID].size() <= static_cast<size_t>(bufferPosition))
	    m_graphs[nodeID].resize(bufferPosition + 1);

	if(m_graphs[nodeID].size() <= bufferPosition)
		m_graphs[nodeID].resize(bufferPosition+1);

	NS_LOG_FUNCTION(this << m_graphs.size() << m_graphs[nodeID].size() << bufferPosition);

	std::string graphTypeFilter =(graphType=="svg" || graphType=="png" || graphType=="tex") ? graphType : "png";
	Ptr<QKDGraph> graph = CreateObject<QKDGraph>(srcKMSNode, dstKMSNode, bufferPosition, graphName, graphTypeFilter, buff);
	m_graphs[nodeID][bufferPosition] = graph;

	std::ostringstream currentPath;
	currentPath << "/NodeList/" << nodeID << "/ApplicationList/" << srcKMSApplicationIndex << "/$ns3::QKDKeyManagerSystemApplication/BufferList/" << bufferPosition << "/CurrentChange";
	std::string query(currentPath.str());
 
    Config::Connect(query, MakeCallback(&QKDGraphManager::ProcessCurrentChange));
    NS_LOG_FUNCTION(this << query);

	std::ostringstream statusPath;
	statusPath << "/NodeList/" << nodeID << "/ApplicationList/" << srcKMSApplicationIndex << "/$ns3::QKDKeyManagerSystemApplication/BufferList/" << bufferPosition << "/StatusChange";
	std::string query2(statusPath.str());
    Config::Connect(query2, MakeCallback(&QKDGraphManager::ProcessStatusChange));
    NS_LOG_FUNCTION(this << query2);

	std::ostringstream MthrPath;
	MthrPath << "/NodeList/" << nodeID << "/ApplicationList/" << srcKMSApplicationIndex << "/$ns3::QKDKeyManagerSystemApplication/BufferList/" << bufferPosition << "/ThresholdChange";
	std::string query3(MthrPath.str());
    Config::Connect(query3, MakeCallback(&QKDGraphManager::ProcessThresholdChange));
    NS_LOG_FUNCTION(this << query3);

    //FOR QKD TOTAL GRAPH
	std::ostringstream currentPathIncrease;
	currentPathIncrease << "/NodeList/" << nodeID << "/ApplicationList/" << srcKMSApplicationIndex << "/$ns3::QKDKeyManagerSystemApplication/BufferList/" << bufferPosition << "/CurrentIncrease";
	std::string query4(currentPathIncrease.str());
    Config::Connect(query4, MakeCallback(&QKDGraphManager::ProcessCurrentIncrease));
    NS_LOG_FUNCTION(this << query4);

	std::ostringstream currentPathDecrease;
	currentPathDecrease << "/NodeList/" << nodeID << "/ApplicationList/" << srcKMSApplicationIndex << "/$ns3::QKDKeyManagerSystemApplication/BufferList/" << bufferPosition << "/CurrentDecrease";
	std::string query5(currentPathDecrease.str());
    Config::Connect(query5, MakeCallback(&QKDGraphManager::ProcessCurrentDecrease));
    NS_LOG_FUNCTION(this << query5);

    m_graphs[nodeID][bufferPosition]->InitTotalGraph();
}
}


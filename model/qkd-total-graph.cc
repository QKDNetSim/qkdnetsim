/*
 * Copyright(c) 2025 University of Sarajevo, Faculty of Electrical Engineering, 
 * Department of Telecommunications, Zmaja od Bosne bb, 71000 Sarajevo, Bosnia and Herzegovina
 * www.tk.etf.unsa.ba
 *
 *
 *
 * Author: Miralem Mehic <miralem.mehic@etf.unsa.ba>
 */

#include "qkd-total-graph.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE("QKDTotalGraph");

NS_OBJECT_ENSURE_REGISTERED(QKDTotalGraph);

TypeId QKDTotalGraph::GetTypeId()
{
  static TypeId tid = TypeId("ns3::QKDTotalGraph")
    .SetParent<Object>()
    ;
  return tid;
}

QKDTotalGraph::~QKDTotalGraph(){}

QKDTotalGraph::QKDTotalGraph(){
	Init("","");
}

QKDTotalGraph::QKDTotalGraph(
	std::string graphName,
	std::string graphType
){
	Init(graphName, graphType);
}

void
QKDTotalGraph::Init(
	std::string graphName,
	std::string graphType
)
{
	m_keymCurrent = 0;
	m_keymThreshold = 0;
	m_keymMax = 100;

    NS_LOG_FUNCTION(this <<  graphName);

	m_plotFileName =(graphName.empty()) ? "QKD Total Graph" : graphName;
	m_plotFileType =(graphType.empty()) ? "png" : graphType;;

	m_gnuplot.SetOutputFilename(m_plotFileName + "." + m_plotFileType);

	m_dataset.SetTitle("Keys (bits)");
	m_dataset.SetStyle(Gnuplot2dDataset::LINES_POINTS);
	m_dataset.SetExtra(" ls 1");
	//m_dataset.Add( 0, m_keymCurrent);
 
	std::string outputTerminalCommand;

	if(m_plotFileType=="png")
		outputTerminalCommand = "pngcair";
	else if(m_plotFileType=="tex")
		outputTerminalCommand = "epslatex";
	else
		outputTerminalCommand = m_plotFileType;

	m_gnuplot.AppendExtra("set autoscale y");
	m_gnuplot.AppendExtra("set border linewidth 2");

	if(m_plotFileType=="tex")
		m_gnuplot.AppendExtra("set terminal " + outputTerminalCommand);
	else
		m_gnuplot.AppendExtra("set terminal " + outputTerminalCommand + " size 1524,768 enhanced font 'Helvetica,18'");

	m_gnuplot.AppendExtra("set style line 1 linecolor rgb 'red' linetype 1 linewidth 1");
	m_gnuplot.AppendExtra("set style line 4 linecolor rgb \"#8A2BE2\" linetype 1 linewidth 1");

	m_gnuplot.AppendExtra("set style line 7 linecolor rgb 'gray' linetype 0 linewidth 1");
	m_gnuplot.AppendExtra("set style line 8 linecolor rgb 'gray' linetype 0 linewidth 1 ");

	m_gnuplot.AppendExtra("set grid ytics lt 0 lw 1 lc rgb \"#ccc\"");
	m_gnuplot.AppendExtra("set grid xtics lt 0 lw 1 lc rgb \"#ccc\"");

	m_gnuplot.AppendExtra("set mxtics 5");
	m_gnuplot.AppendExtra("set grid mxtics xtics ls 7, ls 8");

	m_gnuplot.AppendExtra("set arrow from graph 1,0 to graph 1.03,0 size screen 0.025,15,60 filled ls 3");
	m_gnuplot.AppendExtra("set arrow from graph 0,1 to graph 0,1.03 size screen 0.025,15,60 filled ls 3");

	m_gnuplot.AppendExtra("set style fill transparent solid 0.4 noborder");
	//m_gnuplot.AppendExtra("set logscale y 2");

	if(m_plotFileType=="tex") {
		m_gnuplot.AppendExtra("set key inside");
		m_gnuplot.AppendExtra("set key right top");
	}else{
		m_gnuplot.AppendExtra("set key outside");
		m_gnuplot.AppendExtra("set key right bottom");
	}

 	std::string plotTitle;

	if(graphName.empty()){
		plotTitle = "QKD Keys in the Whole Network";
	}else{
		 plotTitle = graphName;
	}

	m_gnuplot.SetTitle(plotTitle);
	//m_gnuplot.SetTerminal("png");
	// Set the labels for each axis.
	m_gnuplot.SetLegend("Time(seconds)", "Keys (bits)");

}


void
QKDTotalGraph::PrintGraph(){

    NS_LOG_FUNCTION(this << m_plotFileName);

	std::string tempPlotFileName1 = m_plotFileName;
	tempPlotFileName1 += "_data.dat";
	std::ofstream tempPlotFile1(tempPlotFileName1.c_str());

	uint32_t m_tempMax = m_keymMax * 1.1; //just to plot arrows on the graph 
	std::ostringstream yrange;
	yrange << "set yrange[1:" << m_tempMax << "];";
	m_gnuplot.AppendExtra(yrange.str());
	m_gnuplot.AddDataset(m_dataset);

	m_plotFileName += ".plt";
	// Open the plot file.
	std::ofstream plotFile(m_plotFileName.c_str());

	// Write the plot file.
	m_gnuplot.GenerateOutput(plotFile, tempPlotFile1, tempPlotFileName1);

	// Close the plot file.
	plotFile.close();
}

void
QKDTotalGraph::ProcessMCurrent(uint32_t newValue, char sign){

    NS_LOG_FUNCTION(this << newValue << sign);
	m_simulationTime = Simulator::Now().GetSeconds();

	if(sign == '+')
		m_keymCurrent += newValue;
	else if(sign == '-')
		m_keymCurrent -= newValue;

	m_dataset.Add( m_simulationTime, m_keymCurrent);
	if(m_keymCurrent > m_keymMax) m_keymMax = m_keymCurrent;
}
 

}

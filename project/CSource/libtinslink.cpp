//include the tins include file
#include "tins/tins.h"
#include "pcap.h"

//for librarylink
#include "WolframLibrary.h"

#include <map>
#include <atomic>
#include <future>
#include <vector>
#include <sstream>
using namespace Tins;

//map for individual packets
std::map<int,Packet * > hash_table = std::map<int,Packet *>();

//packetID for individual packet reading
static int currentPacketID = 0;



//for the continuous packet reading
std::atomic<int> nextPacketID(0);

//for determining when to stop the thread that copies packets
std::atomic<bool> keepRunning(true);

//map of all the packets gathered inside the background thread
std::map<int,PDU *> continuousPacketTable = std::map<int,PDU *>();




EXTERN_C DLLEXPORT mint WolframLibrary_getVersion()
{
  return WolframLibraryVersion;
}

EXTERN_C DLLEXPORT int WolframLibrary_initialize( WolframLibraryData libData)
{
	nextPacketID = 0;

	return 0;
}

EXTERN_C DLLEXPORT void WolframLibrary_uninitialize( WolframLibraryData libData)
{
	return;
}


int sniffeth_internal(int ms, char * interface, int port, char * ipaddress)
{	
	// int time = -1;

	SnifferConfiguration config;
	//add the port to the filter
	char portStr[10];
	snprintf(portStr,10,"port %d",port);
	config.set_filter(portStr);

	//set the config for the sniffer to be promiscous
	config.set_promisc_mode(true);

	//set the snap length
	config.set_snap_len(400);

	//set the ip address of the filter
	char ipStr[100];
	snprintf(ipStr,10,"ip src %s",ipaddress);
	config.set_filter(ipStr);

	//now make the sniffer object
	Sniffer snifferObject(interface,config);

	//set the timeout for the object
	snifferObject.set_timeout(ms);

	// Retrieve the next packet.
	Packet packet = snifferObject.next_packet();
	
	currentPacketID++;

	hash_table[currentPacketID] = &packet;

	// //try to find the IP packet internally for this PDU
	// if(packet.pdu()->find_pdu<IP>())
	// {
	// 	time = packet.timestamp().seconds();	
	// }

	return currentPacketID;
}


EXTERN_C DLLEXPORT int GetFullPacketMetadata(WolframLibraryData libData, mint Argc, MArgument *Args, MArgument Result)
{
   
	//the first argument is the milliseconds timeout to use
	int millisecond = (int) MArgument_getInteger(Args[0]);

	//the second argument is the interface to sniff on
	char * interface = MArgument_getUTF8String(Args[1]);

	//the third argument is the port to listen on
	int port = (int) MArgument_getInteger(Args[2]);

	//the fourth argument is the ip address to listen on for the source
	char * address = MArgument_getUTF8String(Args[3]);


	//get the time value from the function
	int timeRes = sniffeth_internal(millisecond,interface,port,address);

	//create an mtensor to return
	// MTensor returnTensor;
	// mint dims[] = {2};
	// int error = libData->MTensor_new(MType_Integer,1,dims,&returnTensor);

	//set that as the result
	MArgument_setInteger(Result,timeRes);

	return LIBRARY_NO_ERROR;
}

std::thread t;

EXTERN_C DLLEXPORT int listDefaultInterface(WolframLibraryData libData, mint Argc, MArgument *Args, MArgument Result)
{
	NetworkInterface iface = NetworkInterface::default_interface();
    // give out the guid
    std::string * copy = new std::string(iface.name());
	MArgument_setUTF8String(Result, (char *)copy->c_str());
	
	return LIBRARY_NO_ERROR;
}

EXTERN_C DLLEXPORT int listAllInterfaces(WolframLibraryData libData, mint Argc, MArgument *Args, MArgument Result)
{
	std::vector<NetworkInterface> interfaces = NetworkInterface::all();


	//create an mtensor to return
	MTensor returnTensor;
	mint dims = 0;
	for(size_t interfaceIndex = 0; interfaceIndex < interfaces.size(); interfaceIndex++)
	{
		//for the interface name string
		dims += interfaces[interfaceIndex].name().size();

		//for the null byte
		dims += 1;
	}
	
	//this mtensor is 1dimensional - each interface string will be delimited by a null byte
	int error = libData->MTensor_new(MType_Integer,1,&dims,&returnTensor);
	if(error) return error;

	//now we loop over all of the strings in the list of interfaces, appending each interface string
	//to the MTensor, with null bytes in between

	mint TensorPosition = 1;
	for (const NetworkInterface& iface : interfaces) {

		//get the length of this interface string
		mint strLength = iface.name().size();
		if(error) return error;

		//now copy all of the characters from the string into the mtensor
		for(mint charIndex = 0; charIndex < strLength; charIndex++)
		{
			int error = libData->MTensor_setInteger(returnTensor,&TensorPosition,iface.name()[charIndex]);
			if(error) return error;
			TensorPosition++;
		}

		//put in the null byte for this interface
		int error = libData->MTensor_setInteger(returnTensor,&TensorPosition,0);
		if (error) return error;
		TensorPosition++;
	}
    
    //finally return the MTensor
    MArgument_setMTensor(Result,returnTensor);

	return LIBRARY_NO_ERROR;
}


bool dnsSniff(const PDU &pdu) 
{
	//make a clone of the pdu and store it into the hash table

    continuousPacketTable[nextPacketID++] = pdu.clone();
    return keepRunning;
}

EXTERN_C DLLEXPORT int EmptyDNSSniffingHashTable(WolframLibraryData libData, mint Argc, MArgument *Args, MArgument Result)

{
	
	//create an mtensor to return
	MTensor returnTensor;
	mint dims = 0;


	for (int i = 0; i< continuousPacketTable.size(); i++){

		DNS dns = continuousPacketTable[i]->rfind_pdu<RawPDU>().to<DNS>();

		for (const auto& query : dns.queries()) {

			for(int j = 0; j < query.dname().length(); j++)
				dims++;

			dims +=1;
		}


	}	

	int error = libData->MTensor_new(MType_Integer,1,&dims,&returnTensor);
	if(error) return error;



	mint TensorPosition = 1;
	for (int x = 0; x<continuousPacketTable.size(); x++) {
		DNS dns = continuousPacketTable[x]->rfind_pdu<RawPDU>().to<DNS>();


		for (const auto& query : dns.queries()) {

			//get the length of this interface string
			mint strLength = query.dname().length();
			if(error) return error;

			//now copy all of the characters from the string into the mtensor
			for(mint charIndex = 0; charIndex < strLength; charIndex++)
			{
				int error = libData->MTensor_setInteger(returnTensor,&TensorPosition,query.dname()[charIndex]);
				if(error) return error;
				TensorPosition++;
			}

			//put in the null byte for this interface
			int error = libData->MTensor_setInteger(returnTensor,&TensorPosition,0);
			if (error) return error;
			TensorPosition++;
		}
	}

    MArgument_setMTensor(Result,returnTensor);
    return LIBRARY_NO_ERROR;
}
void sniff_dns_thread(std::string interface, WolframLibraryData libData)
{
	SnifferConfiguration config;
	// Only capture udp packets sent to port 53

	config.set_filter("udp and dst port 53");

	//set the config for the sniffer to be promiscous
	config.set_promisc_mode(true);

	//set the snap length
	config.set_snap_len(400);

	//now make the sniffer object
	try{
	Sniffer snifferObject(interface,config);
	snifferObject.sniff_loop(dnsSniff);
	}
	catch(...)
	{
		libData->evaluateExpression(libData,"Print[\"failed to open interface\"]",6,0,NULL);
		return;
	}
}

EXTERN_C DLLEXPORT int startDNSSniff(WolframLibraryData libData, mint Argc, MArgument *Args, MArgument Result)
{
	std::string interface(MArgument_getUTF8String(Args[0]));
	
	keepRunning = true;

	t = std::thread(sniff_dns_thread,interface, libData);

	t.detach();

	return LIBRARY_NO_ERROR;

}

EXTERN_C DLLEXPORT int stopDNSSniff(WolframLibraryData libData, mint Argc, MArgument *Args, MArgument Result)
{
	keepRunning = false;
	if(t.joinable())
	{
		t.join();
	}
	return LIBRARY_NO_ERROR;

}
bool tcpSniff(const PDU &pdu) 
{
	//make a clone of the pdu and store it into the hash table
    continuousPacketTable[nextPacketID++] = pdu.clone();
    return keepRunning;
}

void tcp_sniff_thread(std::string interface, WolframLibraryData libData)
{
	//now make the sniffer object
	try
	{
		Sniffer snifferObject(interface);
		snifferObject.sniff_loop(tcpSniff);

	}
	catch(...)
	{
		libData->evaluateExpression(libData,"Print[\"failed to open interface\"]",6,0,NULL);
		return;
	}
}

EXTERN_C DLLEXPORT int StartTCPSniffing(WolframLibraryData libData, mint Argc, MArgument *Args, MArgument Result)
{
	//the first argument is the interface to sniff on
	std::string interface(MArgument_getUTF8String(Args[0]));

	//mark the thread as start running
	keepRunning = true;

	//start the sniffer in a background thread
	t = std::thread(tcp_sniff_thread,interface,libData);

	t.detach();

	return LIBRARY_NO_ERROR;

}


EXTERN_C DLLEXPORT int StopTCPSniffing(WolframLibraryData libData, mint Argc, MArgument *Args, MArgument Result)
{
	//just mark the thread to stop running
	keepRunning = false;

	if(t.joinable())
	{
		t.join();
	}

	return LIBRARY_NO_ERROR;
}

EXTERN_C DLLEXPORT int EmptyTCPSniffingHashTable(WolframLibraryData libData, mint Argc, MArgument *Args, MArgument Result)
{

	MTensor returnTensor;
	mint dims = 0;


	for (int i = 0; i< continuousPacketTable.size(); i++){

		const IP &ip = continuousPacketTable[i]->rfind_pdu<IP>();
		const TCP &tcp = continuousPacketTable[i]->rfind_pdu<TCP>();
		const RawPDU& raw = tcp.rfind_pdu<RawPDU>();
		raw.payload();
		const RawPDU::payload_type& payload = raw.payload();
		

		// char * test = new char[raw.payload().size()];

		// std::copy(raw.payload().begin(), raw.payload().end(), test);
		// std::string payload (test);	
				// std::string payload(raw.payload()->begin(), raw.payload()->end());

		std::stringstream ss;

		ss << ip.src_addr() << ":" << tcp.sport() << "to" << ip.dst_addr() << ":" << tcp.dport() << "seq" << tcp.seq() << "ack_seq" << tcp.ack_seq() << "window" << tcp.window() << "checksum" << tcp.checksum() << "urgentpointer" << tcp.urg_ptr() << "dataoffset" << tcp.data_offset() << "flags" << tcp.flags()<< "headersize" << tcp.header_size();

		std::string s = ss.str();

		for (int k = 0; k < s.length();k++) {

			dims++;

			dims +=1; // size integer for the packet. 
		}

	}	

	int error = libData->MTensor_new(MType_Integer,1,&dims,&returnTensor);
	if(error) return error;



	mint TensorPosition = 1;




	for (int x = 0; x < continuousPacketTable.size(); x++) {

		const IP &ip = continuousPacketTable[x]->rfind_pdu<IP>();
		const TCP &tcp = continuousPacketTable[x]->rfind_pdu<TCP>();
		const RawPDU& raw = tcp.rfind_pdu<RawPDU>();
		// const RawPDU::payload_type& payload = raw.payload();
		// char * test = new char[raw.payload().size()];

		// std::copy(raw.payload().begin(), raw.payload().end(), test);
		// std::string payload (test);
		// std::string payload(raw.payload()->begin(), raw.payload()->end());
		std::stringstream ss;
		ss << ip.src_addr() << ":" << tcp.sport() << " to " <<ip.dst_addr() << ":" << tcp.dport() << "seq" << tcp.seq() << "ack_seq" << tcp.ack_seq() << "window" << tcp.window() << "checksum" << tcp.checksum() << "urgentpointer" << tcp.urg_ptr() << "dataoffset" << tcp.data_offset() << "flags" << tcp.flags() << "headersize" << tcp.header_size();
		std::string s = ss.str();

		mint totalSize = s.length() + raw.payload().size();


			//get the length of this interface string
			mint strLength = s.length();
			if(error) return error;

			libData->MTensor_setInteger(returnTensor,&TensorPosition, totalSize);
						//now copy all of the characters from the string into the mtensor

			for(mint charIndex = 0; charIndex < strLength; charIndex++)
			{
				int error = libData->MTensor_setInteger(returnTensor,&TensorPosition,s[charIndex]);
				if(error) return error;
				TensorPosition++;
			}

			for(mint idex = 0; idex < raw.payload().size(); idex ++){

				int error = libData->MTensor_setInteger(returnTensor,&TensorPosition,raw.payload()[idex]);
				if(error) return error;
				TensorPosition++;
			}

			// raw.payload()
			



			//put in the null byte for this interface
			// int error = libData->MTensor_setInteger(returnTensor,&TensorPosition,0);
			// if (error) return error;
			// TensorPosition++;



			}


    MArgument_setMTensor(Result,returnTensor);

    return LIBRARY_NO_ERROR;
}

EXTERN_C DLLEXPORT int GetPacketProtocolName(WolframLibraryData libData, mint Argc, MArgument *Args, MArgument Result)
{
	int packet_id = (int) MArgument_getInteger(Args[0]);

	Packet * packet = hash_table[packet_id];
	return 0;
	// packet->getProtocolName();
}



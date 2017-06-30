//include the tins include file
#include "tins/tins.h"
#include "pcap.h"

//for librarylink
#include "WolframLibrary.h"

#include <map>
#include <atomic>
#include <future>


using namespace Tins;

//map for individual packets
std::map<int,Packet * > hash_table;

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
	int time = -1;

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
	MTensor returnTensor;
	mint dims[] = {2};
	int error = libData->MTensor_new(MType_Integer,1,dims,&returnTensor);

	//set that as the result
	MArgument_setInteger(Result,timeRes);

	return LIBRARY_NO_ERROR;
}

bool tcpSniff(const PDU &pdu) 
{
	//make a clone of the pdu and store it into the hash table
    continuousPacketTable[nextPacketID++] = pdu.clone();

    return keepRunning;
}


void sniff_thread(std::string interface, int port, std::string ipaddress)
{
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
	snprintf(ipStr,10,"ip src %s",ipaddress.c_str());
	config.set_filter(ipStr);

	//now make the sniffer object
	Sniffer snifferObject(interface,config);
	snifferObject.sniff_loop(tcpSniff);
}


EXTERN_C DLLEXPORT int StartTCPSniffing(WolframLibraryData libData, mint Argc, MArgument *Args, MArgument Result)
{
	//the first argument is the interface to sniff on
	std::string interface(MArgument_getUTF8String(Args[0]));

	//the second argument is the port to sniff on
	int port = (int) MArgument_getInteger(Args[1]);

	//the third argument is the source ip address to sniff for
	std::string ipaddress(MArgument_getUTF8String(Args[2]));	

	//mark the thread as start running
	keepRunning = true;

	//start the sniffer in a background thread
	std::thread t(sniff_thread,interface,port,ipaddress);

	return 0;

}

EXTERN_C DLLEXPORT int StopTCPSniffing(WolframLibraryData libData, mint Argc, MArgument *Args, MArgument Result)
{
	//just mark the thread to stop running
	keepRunning = false;	

	return LIBRARY_NO_ERROR;

}

EXTERN_C DLLEXPORT int EmptyTCPSniffingHashTable(WolframLibraryData libData, mint Argc, MArgument *Args, MArgument Result)
{
	// const IP &ip = pdu.rfind_pdu<IP>();
    // const TCP &tcp = pdu.rfind_pdu<TCP>();

	// the below four calls give out what we want. they get called in a loop when test() gets called again and again
    // ip.src_addr();
    // tcp.sport();

    // tcp.dport();
    // ip.dst_addr();

    return LIBRARY_NO_ERROR;
}

EXTERN_C DLLEXPORT int TCPSniffingHashTableSize(WolframLibraryData libData, mint Argc, MArgument *Args, MArgument Result)
{
	// const IP &ip = pdu.rfind_pdu<IP>();
    // const TCP &tcp = pdu.rfind_pdu<TCP>();

	// the below four calls give out what we want. they get called in a loop when test() gets called again and again
    // ip.src_addr();
    // tcp.sport();

    // tcp.dport();
    // ip.dst_addr();

    MArgument_setInteger(Result,continuousPacketTable.size());

    return LIBRARY_NO_ERROR;
}
  



EXTERN_C DLLEXPORT int GetPacketProtocolName(WolframLibraryData libData, mint Argc, MArgument *Args, MArgument Result)
{
	int packet_id = (int) MArgument_getInteger(Args[0]);

	Packet * packet = hash_table[packet_id];
	return 0;
	// packet->getProtocolName();
}
bool dns(const PDU& pdu) {

    // EthernetII / IP / UDP / RawPDU is the packet encapsulated order
    

    DNS dns = pdu.rfind_pdu<RawPDU>().to<DNS>();
    
    // Retrieve the queries and print the domain name:
    for (const auto& query : dns.queries()) {
    	query.dname(); // gives the domain queried i think
    }
    return true;
}

int dnssniff(int argc, char* argv[]) {
  
    // add interface to the config somehow
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    // Only capture udp packets sent to port 53
    config.set_filter("udp and dst port 53"); // capture only on port 53
    Sniffer sniffer(argv[1], config);
    
    // Start the capture
    sniffer.sniff_loop(dns);
    return true;
}


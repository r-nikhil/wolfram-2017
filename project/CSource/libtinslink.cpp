//include the tins include file
#include "tins/tins.h"

//for librarylink
#include "WolframLibrary.h"

#include <map>


DLLEXPORT mint WolframLibrary_getVersion(){
  return WolframLibraryVersion;
}

DLLEXPORT int WolframLibrary_initialize( WolframLibraryData libData) \
{
	return 0;
}

DLLEXPORT void WolframLibrary_uninitialize( WolframLibraryData \
libData) {
	return;
}

using namespace Tins;


std::map<int,Packet * > hash_table;


static int currentPacketID = 0;

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
	int error = libData->MTensor_new(MType_MTensor,1,2);

	//set that as the result
	MArgument_setInteger(Result,timeRes);

	return LIBRARY_NO_ERROR;
}


int GetPacketProtocolName(WolframLibraryData libData, mint Argc, MArgument *Args, MArgument Result)
{
	int packet_id = (int) MArgument_getInteger(Args[0]);

	Packet * packet = hash_table[packet_id];

	packet->getProtocolName();
}


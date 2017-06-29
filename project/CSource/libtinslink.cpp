//include the tins include file
#include "tins/tins.h"

//for librarylink
#include "WolframLibrary.h"


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




int sniffeth_internal(int ms)
{
	SnifferConfiguration config;
	config.set_filter("port 80");
	config.set_promisc_mode(true);
	config.set_snap_len(400);

	Sniffer snifferObject("en0",config);

	snifferObject.set_timeout(ms);

	// Only retrieve IP datagrams which are sent from 192.168.0.1
	snifferObject.set_filter("ip src 141.133.96.135");
	// Retrieve the packet.
	Packet packet = snifferObject.next_packet();
	// Do something with some_pdu...
	
	int time = -1;

	//try to find the IP packet internally for this PDU
	if(packet.pdu()->find_pdu<IP>())
	{
		time = packet.timestamp().seconds();	
	}

	return time;
}


EXTERN_C DLLEXPORT int GetPacketTimestamp(WolframLibraryData libData, mint Argc, MArgument *Args, MArgument Result)
{
   
	//the first argument is the milliseconds timeout to use
	int millisecond = (int) MArgument_getInteger(Args[0]);

	//get the time value from the function
	int timeRes = sniffeth_internal(millisecond);

	//set that as the result
	MArgument_setInteger(Result,timeRes);

	return LIBRARY_NO_ERROR;
}



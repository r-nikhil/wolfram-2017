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




void sniffeth_internal(int ms)
{
	// We want to sniff on eth0. This will capture packets of at most 64 kb.
	Sniffer snifferObject("eth0");

	snifferObject.set_timeout(ms);

	// Only retrieve IP datagrams which are sent from 192.168.0.1
	snifferObject.set_filter("ip src 192.168.0.1");
	// Retrieve the packet.
	PDU *some_pdu = snifferObject.next_packet();
	// Do something with some_pdu...
	


	// Delete it.
	delete some_pdu;
}

EXTERN_C DLLEXPORT int sniffeth(WolframLibraryData libData, mint Argc, MArgument *Args, MArgument Res)
{
   
	//the first argument is the milliseconds timeout to use
	int millisecond = (int) MArgument_getInteger(Args[0]);

	// sniffeth_internal(millisecond);

	return LIBRARY_NO_ERROR;
}



EXTERN_C DLLEXPORT int constantzero(WolframLibraryData libData, mint Argc, MArgument *Args, MArgument Res)
{
   MArgument_setInteger(Res, 0);
   return LIBRARY_NO_ERROR;
}


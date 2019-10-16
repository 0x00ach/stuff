
// ------------------------------- DEF.IDL ----------------------------


[
    uuid(7a98c250-6808-11cf-b73b-00aa00b677a7),
    version(1.0)
]
interface hello
{
	typedef struct Struct_16_t
	{
	long 	StructMember0;
	short 	StructMember1;
	short 	StructMember2;
	byte 	StructMember3[8];
	}Struct_16_t;


    void HelloProc([in] handle_t hBinding, [in] struct Struct_16_t* testObj);
    void Shutdown([in] handle_t hBinding);
}










// ------------------------------- CLIENT.C ----------------------------


#include <Windows.h>
#include <stdio.h>
#include "def.h"
#pragma comment(lib,"rpcrt4.lib")

void main()
{
	RPC_STATUS status;
	unsigned char * pszUuid = NULL;
	 char * pszProtocolSequence = "ncacn_np";
	unsigned char * pszNetworkAddress = NULL;
	 char * pszEndpoint = "\\pipe\\hello";
	unsigned char * pszOptions = NULL;
	unsigned char * pszStringBinding = NULL;
	 char * pszString = "hello, world";
	unsigned long ulCode;
	Struct_16_t st16;

	status = RpcStringBindingComposeA((RPC_CSTR)pszUuid,
		(RPC_CSTR)pszProtocolSequence,
		pszNetworkAddress,
		(RPC_CSTR)pszEndpoint,
		pszOptions,
		&pszStringBinding);
	if (status) exit(status);

	status = RpcBindingFromStringBindingA(pszStringBinding, &hello_v1_0_c_ifspec);

	if (status) exit(status);

	RpcTryExcept
	{
		st16.StructMember0 = 0xDEAD;
		st16.StructMember1 = 0xBE;
		st16.StructMember2 = 0xEF;
		st16.StructMember3[0] = 0xCA;
		st16.StructMember3[1] = 0xFE;
		st16.StructMember3[2] = 0x00;
		HelloProc(hello_v1_0_c_ifspec, &st16);
		Shutdown(hello_v1_0_c_ifspec);
	}
		RpcExcept(1)
	{
		ulCode = RpcExceptionCode();
		printf("Runtime reported exception 0x%lx = %ld\n", ulCode, ulCode);
	}
	RpcEndExcept

		status = RpcStringFreeA(&pszStringBinding);

	if (status) exit(status);

	status = RpcBindingFree(&hello_v1_0_c_ifspec);

	if (status) exit(status);

	exit(0);
}

/******************************************************/
/*         MIDL allocate and free                     */
/******************************************************/

void __RPC_FAR * __RPC_USER midl_user_allocate(size_t len)
{
	return(malloc(len));
}

void __RPC_USER midl_user_free(void __RPC_FAR * ptr)
{
	free(ptr);
}








// ------------------------------- SERVER.C ----------------------------


#include <Windows.h>
#include <stdio.h>
#include "def.h"
#pragma comment(lib,"rpcrt4.lib")

void HelloProc(handle_t hBinding, struct Struct_16_t *testObj)
{
	printf("HelloProc : %x %x %x %x%x%x\n", testObj->StructMember0,
		testObj->StructMember1, 
		testObj->StructMember2,
		testObj->StructMember3[0],
		testObj->StructMember3[1],
		testObj->StructMember3[2]);
}
void Shutdown(handle_t hBinding)
{
	RPC_STATUS status;
	printf("Shutdown\n");

	status = RpcMgmtStopServerListening(NULL);

	if (status)
	{
		exit(status);
	}

	status = RpcServerUnregisterIf(NULL, NULL, FALSE);

	if (status)
	{
		exit(status);
	}
} //end Shutdown

void main()
{
	RPC_STATUS status;
	char * pszProtocolSequence = "ncacn_np";
	 char * pszSecurity = NULL;
	 char * pszEndpoint = "\\pipe\\hello";
	 int    cMinCalls = 1;
	 int    fDontWait = FALSE;

	status = RpcServerUseProtseqEpA((RPC_CSTR)pszProtocolSequence,
		RPC_C_LISTEN_MAX_CALLS_DEFAULT,
		(RPC_CSTR)pszEndpoint,
		pszSecurity);

	if (status){
		printf("RpcServerUseProtseqEpA failed!\n");
		exit(status);
	}

	status = RpcServerRegisterIf(hello_v1_0_s_ifspec,
		NULL,
		NULL);

	if (status){
		printf("RpcServerRegisterIf failed!\n");
		exit(status);
	}

	status = RpcServerListen(cMinCalls,
		RPC_C_LISTEN_MAX_CALLS_DEFAULT,
		fDontWait);

	if (status) {
		printf("RpcServerListen failed!\n");
		exit(status);
	}

	
}


/******************************************************/
/*         MIDL allocate and free                     */
/******************************************************/

void __RPC_FAR * __RPC_USER midl_user_allocate(size_t len)
{
	return(malloc(len));
}

void __RPC_USER midl_user_free(void __RPC_FAR * ptr)
{
	free(ptr);
}

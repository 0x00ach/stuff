#include <Windows.h>
#include <stdio.h>
#pragma comment(lib, "Rpcrt4.lib")

void* __RPC_USER midl_user_allocate(size_t size) {
	return malloc(size);
}
void __RPC_USER midl_user_free(void* p) {
	free(p);
}

int main(int argc, char** argv)
{
	handle_t hRpc = NULL;
	RPC_STATUS status;
	unsigned char* szStringBinding = NULL;

	if (argc != 3) {
		printf("Usage: %s <type> <interface name>\n", argv[0]);
		printf("\ttype : communication type, e.g ncalrpc, etc.\n");
		printf("\tinterface name: RPC interface name, e.g IMpService77BDAF73-B396-481F-9042-AD358843EC24\n");
		return 0;
	}

	status = RpcStringBindingComposeA(
		NULL,
		reinterpret_cast<unsigned char*>(argv[1]),
		NULL,
		reinterpret_cast<unsigned char*>(argv[2]),
		NULL,
		&szStringBinding);

	status = RpcBindingFromStringBindingA(
		szStringBinding,
		&hRpc);

	if (status != RPC_S_OK)
		hRpc = NULL;
	else {
		RPC_ASYNC_STATE Async;
		status = RpcAsyncInitializeHandle(&Async, sizeof(RPC_ASYNC_STATE));
		
		RPC_IF_HANDLE ifHandle = NULL;
		status = RpcBindingBind(&Async, hRpc, ifHandle);
		if (status == RPC_S_OK)
			printf("Connexion RPC OK\n");
		else
			printf("Connexion RPC echouee\n");

	}

	if (hRpc != NULL)
		RpcBindingFree(&hRpc);
	return 0;
}


#include <Windows.h>
#include <stdio.h>
#include <Exdisp.h>

int main(int argc, char** argv) {
	IWebBrowser2*    pBrowser2;
	VARIANT vEmpty;
	VARIANT vFlags;
	GUID CLSID_InternetExplorer = { 0xd5e8041d, 0x920f, 0x45e9, { 0xb8, 0xfb, 0xb1, 0xde, 0xb8, 0x2c, 0x6e, 0x5e } };
	GUID IID_IWebBrowser2 = { 0xd30c1661, 0xcdaf, 0x11d0, { 0x8a, 0x3e, 0x00, 0xc0, 0x4f, 0xc9, 0xe2, 0x6e } };
	
	CoInitialize(NULL);
	CoCreateInstance(&CLSID_InternetExplorer, NULL, CLSCTX_LOCAL_SERVER,
		&IID_IWebBrowser2, (void**)&pBrowser2);

	if (pBrowser2)
	{
		VariantInit(&vEmpty);
		V_VT(&vFlags) = VT_I4;
		V_I4(&vFlags) = navOpenInNewWindow;

		BSTR bstrURL = SysAllocString(L"http://microsoft.com");

		pBrowser2->lpVtbl->Navigate(pBrowser2, bstrURL, &vFlags, &vEmpty, &vEmpty, &vEmpty);
		pBrowser2->lpVtbl->Quit(pBrowser2);

		SysFreeString(bstrURL);
		pBrowser2->lpVtbl->Release(pBrowser2);
	}

	CoUninitialize();
}

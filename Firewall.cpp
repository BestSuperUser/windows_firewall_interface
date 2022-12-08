#include "Firewall.h"

HRESULT Firewall_Initialize(INetFwPolicy2* pNetFwPolicy2) {
	HRESULT hr = S_OK;

	hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(NetFwPolicy2), (void**)pNetFwPolicy2);
	if(FAILED(hr)) {
		cout << "Initialize NetFwPoliciy Failed.";
		goto Clear;
	}
Clear: {
	return hr;
	}
}

bool FireWall_Add_Application(const wchar_t* cwName, const wchar_t* cwFilePath,
	const wchar_t* cwDescription, const wchar_t* cwGroup,
	NET_FW_RULE_DIRECTION nfDirection, NET_FW_PROFILE_TYPE2_ nfProfileType,
	NET_FW_IP_PROTOCOL nfProtocal, NET_FW_ACTION_ nfAction) {

	return false;
};

bool FireWall_IsEnable() {
	HRESULT CreateInstance = S_OK;
	HRESULT CoInitialize = E_FAIL;

	VARIANT_BOOL fwEnable;

	INetFwMgr* fwMgr = NULL;
	INetFwPolicy* fwPolicy = NULL;
	INetFwProfile* fwProfile = NULL;

	_ASSERT(fwProfile != NULL);

	fwProfile = NULL;

	CoInitialize = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (CoInitialize != RPC_E_CHANGED_MODE)
		if (FAILED(CoInitialize)) {
			cout << "Initialize Failed.";
			goto Clear;
		}

	CreateInstance = CoCreateInstance(__uuidof(NetFwMgr), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwMgr), (void**) &fwMgr);
	if (FAILED(CreateInstance)) {
		cout << "Initialize Failed.";
		goto Clear;
	}

	CreateInstance = fwMgr->get_LocalPolicy(&fwPolicy);
	if (FAILED(CreateInstance)) {
		cout << "Get LocalPolicy Failed.";
		goto Clear;
	}
	
	CreateInstance = fwPolicy->get_CurrentProfile(&fwProfile);
	if (FAILED(CreateInstance)) {
		cout << "Get CurrentProfile Failed.";
		goto Clear;
	}

	CreateInstance = fwProfile->get_FirewallEnabled(&fwEnable);
	if (FAILED(CreateInstance)) {
		cout << "Get get_FirewallEnabled Failed.";
		goto Clear;
	}

	if (fwEnable != VARIANT_FALSE)
		return true;
	else
		return false;

Clear: {
		if (fwPolicy != NULL)
			fwPolicy->Release();

		if (fwMgr != NULL)
			fwMgr->Release();

		if (fwProfile != NULL)
			fwProfile->Release();

		if (SUCCEEDED(CoInitialize))
			CoUninitialize();

		return false;
	}
};

void FireWall_TurnOn() {
	HRESULT CreateInstance = S_OK;
	HRESULT CoInitialize = E_FAIL;

	VARIANT_BOOL fwEnable;

	INetFwMgr* fwMgr = NULL;
	INetFwPolicy* fwPolicy = NULL;
	INetFwProfile* fwProfile = NULL;

	_ASSERT(fwProfile != NULL);

	fwProfile = NULL;

	CoInitialize = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (CoInitialize != RPC_E_CHANGED_MODE)
		if (FAILED(CoInitialize)) {
			cout << "Initialize Failed.";
			goto Clear;
		}

	CreateInstance = CoCreateInstance(__uuidof(NetFwMgr), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwMgr), (void**)&fwMgr);
	if (FAILED(CreateInstance)) {
		cout << "Initialize Failed.";
		goto Clear;
	}

	CreateInstance = fwMgr->get_LocalPolicy(&fwPolicy);
	if (FAILED(CreateInstance)) {
		cout << "Get LocalPolicy Failed.";
		goto Clear;
	}

	CreateInstance = fwPolicy->get_CurrentProfile(&fwProfile);
	if (FAILED(CreateInstance)) {
		cout << "Get CurrentProfile Failed.";
		goto Clear;
	}

	if (!FireWall_IsEnable()) {
		CreateInstance = fwProfile->put_FirewallEnabled(VARIANT_TRUE);
		if (FAILED(CreateInstance)) {
			cout << "Get FirewallEnabled Failed.";
			goto Clear;
		}
	}

Clear: {
	if (fwPolicy != NULL)
		fwPolicy->Release();

	if (fwMgr != NULL)
		fwMgr->Release();

	if (fwProfile != NULL)
		fwProfile->Release();

	if (SUCCEEDED(CoInitialize))
		CoUninitialize();
	}
};

void FireWall_TurnOff() {
	HRESULT CreateInstance = S_OK;
	HRESULT CoInitialize = E_FAIL;

	VARIANT_BOOL fwEnable;

	INetFwMgr* fwMgr = NULL;
	INetFwPolicy* fwPolicy = NULL;
	INetFwProfile* fwProfile = NULL;

	_ASSERT(fwProfile != NULL);

	fwProfile = NULL;

	CoInitialize = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (CoInitialize != RPC_E_CHANGED_MODE)
		if (FAILED(CoInitialize)) {
			cout << "Initialize Failed.";
			goto Clear;
		}

	CreateInstance = CoCreateInstance(__uuidof(NetFwMgr), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwMgr), (void**)&fwMgr);
	if (FAILED(CreateInstance)) {
		cout << "Initialize Failed.";
		goto Clear;
	}

	CreateInstance = fwMgr->get_LocalPolicy(&fwPolicy);
	if (FAILED(CreateInstance)) {
		cout << "Get LocalPolicy Failed.";
		goto Clear;
	}

	CreateInstance = fwPolicy->get_CurrentProfile(&fwProfile);
	if (FAILED(CreateInstance)) {
		cout << "Get CurrentProfile Failed.";
		goto Clear;
	}

	if (FireWall_IsEnable()) {
		CreateInstance = fwProfile->put_FirewallEnabled(VARIANT_FALSE);
		if (FAILED(CreateInstance)) {
			cout << "FirewallDisable Failed.";
			goto Clear;
		}
	}

Clear: {
	if (fwPolicy != NULL)
		fwPolicy->Release();

	if (fwMgr != NULL)
		fwMgr->Release();

	if (fwProfile != NULL)
		fwProfile->Release();

	if (SUCCEEDED(CoInitialize))
		CoUninitialize();
	}
};
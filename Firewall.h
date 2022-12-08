#pragma once

#include <Windows.h>
#include <crtdbg.h>
#include <netfw.h>
#include <objbase.h>
#include <OleAuto.h>
#include <stdio.h>
#include <iostream>

using namespace std;

HRESULT Firewall_Initialize(INetFwPolicy2* pNetFwPolicy2);
bool FireWall_Add_Application(const wchar_t* cwName, const wchar_t* cwFilePath,
	const wchar_t* cwDescription, const wchar_t* cwGroup,
	NET_FW_RULE_DIRECTION nfDirection, NET_FW_PROFILE_TYPE2_ nfProfileType,
	NET_FW_IP_PROTOCOL nfProtocal, NET_FW_ACTION_ nfAction);
bool FireWall_IsEnable();
void FireWall_TurnOn();
void FireWall_TurnOff();
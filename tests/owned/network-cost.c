#define COBJMACROS
#include <initguid.h>
#include <windows.h>
#include <roapi.h>
#include <winstring.h>
#define WIDL_using_Windows_Networking_Connectivity
#include <windows.networking.connectivity.h>
#include <stdio.h>

int main(void)
{
    const WCHAR name[] = L"Windows.Networking.Connectivity.NetworkInformation";
    INetworkInformationStatics *network;
    IConnectionProfile *profile;
    IConnectionCost *cost;
    NetworkCostType type;
    HSTRING class_name;
    HRESULT hr;

    if (FAILED(RoInitialize(RO_INIT_MULTITHREADED))) return 1;
    if (FAILED(WindowsCreateString(name, ARRAYSIZE(name) - 1, &class_name))) return 2;
    hr = RoGetActivationFactory(class_name, &IID_INetworkInformationStatics, (void **)&network);
    WindowsDeleteString(class_name);
    if (FAILED(hr)) return 3;
    hr = INetworkInformationStatics_GetInternetConnectionProfile(network, &profile);
    INetworkInformationStatics_Release(network);
    if (FAILED(hr) || !profile) return 4;
    hr = IConnectionProfile_GetConnectionCost(profile, &cost);
    IConnectionProfile_Release(profile);
    printf("NETWORK_COST create=%lx\n", hr);
    if (FAILED(hr)) return 5;
    hr = IConnectionCost_get_NetworkCostType(cost, &type);
    IConnectionCost_Release(cost);
    RoUninitialize();
    if (FAILED(hr) || type < NetworkCostType_Unknown || type > NetworkCostType_Variable) return 6;
    printf("NETWORK_COST_RESULT type=%u PASS\n", type);
    return 0;
}

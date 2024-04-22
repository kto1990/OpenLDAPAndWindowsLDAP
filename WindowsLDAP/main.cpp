#include "WindowsLDAP.h"

void main()
{
    WCHAR host[256]{ 0 };
    WCHAR username[256]{ 0 };
    WCHAR password[256]{ 0 };

    GetPrivateProfileString(L"server", L"host", L"127.0.0.1", host, sizeof(host) / sizeof(WCHAR), L".\\settings.ini");
    GetPrivateProfileString(L"server", L"username", L"127.0.0.1", username, sizeof(username) / sizeof(WCHAR), L".\\settings.ini");
    GetPrivateProfileString(L"server", L"password", L"127.0.0.1", password, sizeof(password) / sizeof(WCHAR), L".\\settings.ini");

    WindowsLDAP* windowsLDAP_None = new WindowsLDAP(host, username, password, WindowsLDAP::ENCRYPTION::NONE);
    WindowsLDAP* windowsLDAP_SSL = new WindowsLDAP(host, username, password, WindowsLDAP::ENCRYPTION::SSL);

    std::cout << "Test connection without encryption" << std::endl;
    if (windowsLDAP_None->connect()) {
        std::cout << "Connected to server successfully" << std::endl;
    }
    
    std::cout << std::endl;

    std::cout << "Test connection using SSL encryption" << std::endl;
    if (windowsLDAP_SSL->connect()) {
        std::cout << "Connected to server successfully" << std::endl;
    }
}
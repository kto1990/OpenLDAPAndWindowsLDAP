#include "OpenLDAP.h"

void main()
{
    CHAR host[256]{ 0 };
    CHAR username[256]{ 0 };
    CHAR password[256]{ 0 };

    GetPrivateProfileString("server", "host", "", host, sizeof(host) / sizeof(WCHAR), ".\\settings.ini");
    GetPrivateProfileString("server", "username", "", username, sizeof(username) / sizeof(CHAR), ".\\settings.ini");
    GetPrivateProfileString("server", "password", "", password, sizeof(password) / sizeof(CHAR), ".\\settings.ini");

    OpenLDAP* openLDAP_None = new OpenLDAP(host, username, password, OpenLDAP::ENCRYPTION::NONE);
    OpenLDAP* openLDAP_SSL = new OpenLDAP(host, username, password, OpenLDAP::ENCRYPTION::SSL);

    std::cout << "Host: '" << host << "'" << std::endl << std::endl;

    std::cout << "Test connection without encryption" << std::endl;
    if (openLDAP_None->connect()) {
        std::cout << "Connected to server successfully" << std::endl;
    }
    
    std::cout << std::endl;

    std::cout << "Test connection using SSL encryption" << std::endl;
    if (openLDAP_SSL->connect()) {
        std::cout << "Connected to server successfully" << std::endl;
    }
}
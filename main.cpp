#include <Windows.h>
#include <vector>
#include "OpenLDAP.h"
#include "WindowsLDAP.h"

void main()
{
    CHAR host[256]{ 0 };
    CHAR username[256]{ 0 };
    CHAR password[256]{ 0 };

    GetPrivateProfileString("server", "host", "127.0.0.1", host, sizeof(host) / sizeof(WCHAR), ".\\settings.ini");
    GetPrivateProfileString("server", "username", "127.0.0.1", username, sizeof(username) / sizeof(CHAR), ".\\settings.ini");
    GetPrivateProfileString("server", "password", "127.0.0.1", password, sizeof(password) / sizeof(CHAR), ".\\settings.ini");

	BaseLDAP *openLDAP_None = new OpenLDAP(host, username, password, BaseLDAP::CONNECTION_TYPES::NONE);
    BaseLDAP *openLDAP_SSL = new OpenLDAP(host, username, password, BaseLDAP::CONNECTION_TYPES::SSL);
    BaseLDAP *winLDAP_None = new WindowsLDAP(host, username, password, BaseLDAP::CONNECTION_TYPES::NONE);
    BaseLDAP *winLDAP_SSL = new WindowsLDAP(host, username, password, BaseLDAP::CONNECTION_TYPES::SSL);

    std::vector<BaseLDAP*> ldap_connectors
    {
        openLDAP_None, openLDAP_SSL, winLDAP_None, winLDAP_SSL
    };

    for (auto& connector : ldap_connectors)
    {
        std::cout << connector->name() << std::endl;
        if (connector->connect()) {
            std::cout << "Connect to server successfully" << std::endl << std::endl;
        }
    }
}
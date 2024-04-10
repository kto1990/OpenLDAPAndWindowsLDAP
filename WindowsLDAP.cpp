#include "WindowsLDAP.h"
#include <Windows.h>
#include <winldap.h>
#include <stdio.h>

WindowsLDAP::WindowsLDAP(const std::string& _host_name, const std::string& _user_name, const std::string& _password, CONNECTION_TYPES _conn_type)
	:BaseLDAP(_host_name, _user_name, _password, _conn_type)
{
    this->class_name = "WindowsLDAP";
}

bool WindowsLDAP::connect()
{
    LDAP* pLdapConnection = NULL;

    std::wstring tmp_host_name = std::wstring(this->host_name.begin(), this->host_name.end());
    std::wstring tmp_user_name = std::wstring(this->user_name.begin(), this->user_name.end());
    std::wstring tmp_password = std::wstring(this->password.begin(), this->password.end());

    PWSTR w_host_name = const_cast<PWSTR>(tmp_host_name.c_str());
    PWCHAR w_user_name = const_cast<PWSTR>(tmp_user_name.c_str());
    PWCHAR w_password = const_cast<PWSTR>(tmp_password.c_str());
    
    if (this->conn_type == CONNECTION_TYPES::NONE) 
    {
        pLdapConnection = ldap_init(w_host_name, LDAP_PORT);
    }
    else
    {
        pLdapConnection = ldap_sslinit(w_host_name, LDAP_SSL_PORT, 1);
    }

    
    if (pLdapConnection == NULL)
    {
        printf("ldap_init failed with 0x%x.\n", LdapGetLastError());
        ldap_unbind(pLdapConnection);
        return false;
    }

    ULONG lRtn = 0;
    ULONG version = LDAP_VERSION3;

    lRtn = ldap_set_option(pLdapConnection, LDAP_OPT_PROTOCOL_VERSION, (void*)&version);
    if (lRtn != LDAP_SUCCESS)
    {
        printf("SetOption Error:%0lX\n", lRtn);
        ldap_unbind(pLdapConnection);
        return false;
    }

    if (this->conn_type == CONNECTION_TYPES::SSL)
    {
        LONG lv = 0;
        ldap_get_option(pLdapConnection, LDAP_OPT_SSL, (void*)&lv);
        if ((void*)lv != LDAP_OPT_ON) 
        {
            //printf("SSL not enabled.\n SSL being enabled...\n");
            lRtn = ldap_set_optionW(pLdapConnection, LDAP_OPT_SSL, LDAP_OPT_ON);
            if (lRtn != LDAP_SUCCESS)
            {
                printf("Enale SSL Error:%0lX\n", lRtn);
                ldap_unbind(pLdapConnection);
                return false;
            }
        }
    }   

    lRtn = ldap_connect(pLdapConnection, NULL);
    if (lRtn != LDAP_SUCCESS)
    {
        printf("ldap_connect failed with 0x%lx.\n", lRtn);
        ldap_unbind(pLdapConnection);
        return false;
    }

    lRtn = ldap_simple_bind_s(pLdapConnection, w_user_name, w_password);
    if (lRtn != LDAP_SUCCESS)
    {
        printf("Failed to connect to server. ErrorCode: 0x%lx.\n", lRtn);
        ldap_unbind(pLdapConnection);
        return false;
    }

    return true;
}

#include "WindowsLDAP.h"
#include <winldap.h>
#include <stdio.h>

WindowsLDAP::WindowsLDAP(const std::wstring& _host_name, const std::wstring& _user_name, const std::wstring& _password, ENCRYPTION _encryption_type)
    : host_name(_host_name), user_name(_user_name), password(_password), encryption_type(_encryption_type)
{}

bool WindowsLDAP::connect()
{
    LDAP* pLdapConnection = NULL;

    PWSTR w_host_name = const_cast<PWSTR>(this->host_name.c_str());
    PWSTR w_user_name = const_cast<PWSTR>(this->user_name.c_str());
    PWSTR w_password = const_cast<PWSTR>(this->password.c_str());
    
    if (this->encryption_type == ENCRYPTION::NONE) {
        pLdapConnection = ldap_init(w_host_name, LDAP_PORT);
    } else {
        pLdapConnection = ldap_sslinit(w_host_name, LDAP_SSL_PORT, 1);
    }

    if (pLdapConnection == NULL) {
        printf("Init failed. Error code 0x%x.\n", LdapGetLastError());
        ldap_unbind(pLdapConnection);
        return false;
    }

    ULONG lRtn = 0;
    ULONG version = LDAP_VERSION3;

    lRtn = ldap_set_option(pLdapConnection, LDAP_OPT_PROTOCOL_VERSION, (void*)&version);
    if (lRtn != LDAP_SUCCESS) {
        printf("Set option failed. Error code %0lX\n", lRtn);
        ldap_unbind(pLdapConnection);
        return false;
    }

    if (this->encryption_type == ENCRYPTION::SSL)  {
        LONG lv = 0;
        ldap_get_option(pLdapConnection, LDAP_OPT_SSL, (void*)&lv);
        if ((void*)lv != LDAP_OPT_ON) {
            //printf("SSL not enabled.\n SSL being enabled...\n");
            lRtn = ldap_set_optionW(pLdapConnection, LDAP_OPT_SSL, LDAP_OPT_ON);
            if (lRtn != LDAP_SUCCESS) {
                printf("Enale SSL Error:%0lX\n", lRtn);
                ldap_unbind(pLdapConnection);
                return false;
            }
        }
    }   

    lRtn = ldap_connect(pLdapConnection, NULL);
    if (lRtn != LDAP_SUCCESS) {
        printf("Failed to connect to server. Error code 0x%lx.\n", lRtn);
        ldap_unbind(pLdapConnection);
        return false;
    }

    lRtn = ldap_simple_bind_s(pLdapConnection, w_user_name, w_password);
    if (lRtn != LDAP_SUCCESS) {
        printf("Failed to authenticate. ErrorCode 0x%lx.\n", lRtn);
        ldap_unbind(pLdapConnection);
        return false;
    }

    return true;
}

#pragma once
#include "BaseLDAP.h"

class OpenLDAP : public BaseLDAP
{
public:
	OpenLDAP(const std::string& _host_name, const std::string& _user_name, const std::string& _password, CONNECTION_TYPES _conn_type);
	bool connect() override;
};


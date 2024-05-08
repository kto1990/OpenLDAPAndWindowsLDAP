#pragma once
#include <iostream>
#include <Windows.h>

class OpenLDAP
{
public:
	enum class ENCRYPTION {
		NONE = 0,
		SSL
	};

	OpenLDAP(const std::string& _host_name, const std::string& _user_name, const std::string& _password, ENCRYPTION _encryption_type);
	bool connect();

private:
	std::string host_name;
	std::string user_name;
	std::string password;
	ENCRYPTION encryption_type;
};

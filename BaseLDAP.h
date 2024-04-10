#pragma once
#include <iostream>

class BaseLDAP
{
public:
	static enum class CONNECTION_TYPES {
		NONE = 0,
		SSL
	};

	BaseLDAP(const std::string& _host_name, const std::string& _user_name, const std::string& _password, CONNECTION_TYPES _conn_type);
	virtual ~BaseLDAP();
	virtual bool connect() = 0;
	std::string name();

protected:
	std::string host_name;
	std::string user_name;
	std::string password;
	std::string class_name;
	CONNECTION_TYPES conn_type;
};

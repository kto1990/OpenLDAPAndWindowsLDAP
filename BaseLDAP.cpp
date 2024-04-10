#include "BaseLDAP.h"

BaseLDAP::BaseLDAP(const std::string& _host_name, const std::string& _user_name, const std::string& _password, CONNECTION_TYPES _conn_type)
	:host_name(_host_name), user_name(_user_name), password(_password), conn_type(_conn_type)
{}

BaseLDAP::~BaseLDAP()
{}

std::string BaseLDAP::name()
{
	if (this->conn_type == CONNECTION_TYPES::NONE) {
		return this->class_name + " - NONE";
	}

	return this->class_name + " - SSL";
}
#pragma once
#include <iostream>
#include <Windows.h>

class WindowsLDAP
{
public:
	static enum class ENCRYPTION {
		NONE = 0,
		SSL
	};

	WindowsLDAP(const std::wstring& _host_name, const std::wstring& _user_name, const std::wstring& _password, ENCRYPTION _encryption_type);
	bool connect();

private:
	std::wstring host_name;
	std::wstring user_name;
	std::wstring password;
	ENCRYPTION encryption_type;
};


#include "OpenLDAP.h"

#include "ldapcpp/LDAPConnection.h"
#include "ldapcpp/LDAPSearchResults.h"
#include "ldapcpp/LDAPEntry.h"
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/applink.c>
#include "OpenLDAP.h"

namespace {
	unsigned int getRootCAcertificatesforLdap(std::string path)
	{
		FILE* caCertsFile = nullptr;
		caCertsFile = fopen(path.c_str(), "w");

		if (!caCertsFile) {
			return 0;
		}

		HCERTSTORE hStore = CertOpenSystemStore(NULL, "ROOT");
		if (!hStore) {
			fclose(caCertsFile);
			return 0;
		}

		PCCERT_CONTEXT pContext = nullptr;
		X509* x509 = nullptr;
		X509_STORE* store = X509_STORE_new();

		unsigned int numOfCerts = 0;

		while (pContext = CertEnumCertificatesInStore(hStore, pContext)) {
			x509 = nullptr;
			x509 = d2i_X509(nullptr, (const unsigned char**)&pContext->pbCertEncoded, pContext->cbCertEncoded);
			if (x509) {
				if (X509_STORE_add_cert(store, x509) == 1) {
					++numOfCerts;
					PEM_write_X509(caCertsFile, x509);
				}
				X509_free(x509);
			}
		}

		fclose(caCertsFile);
		CertFreeCertificateContext(pContext);
		CertCloseStore(hStore, 0);
		X509_STORE_free(store);
		return numOfCerts;
	}
}

OpenLDAP::OpenLDAP(const std::string& _host_name, const std::string& _user_name, const std::string& _password, ENCRYPTION _encryption_type)
	: host_name(_host_name), user_name(_user_name), password(_password), encryption_type(_encryption_type)
{}

bool OpenLDAP::connect()
{
	try {
		if (this->encryption_type == ENCRYPTION::NONE) {
			this->host_name = "ldap://" + this->host_name + ":389";
		} else {
			this->host_name = "ldaps://" + this->host_name + ":636";
		}

		LDAPConnection* connection = new LDAPConnection(this->host_name, 0);

		if (this->encryption_type == ENCRYPTION::SSL) {
			std::string caCertFile = "RootCACert.cer";
			getRootCAcertificatesforLdap(caCertFile);

			TlsOptions tlsOptW = connection->getTlsOptions();
			tlsOptW.setOption(TlsOptions::CACERTFILE, caCertFile);
		}

		LDAPConstraints cons;
		LDAPControlSet ctrls;
		ctrls.add(LDAPCtrl(LDAP_CONTROL_MANAGEDSAIT));
		cons.setServerControls(&ctrls);

		connection->bind(this->user_name, this->password, &cons);

		return true;
	}
	catch (LDAPException& e) {
		int errorCode = e.getResultCode();
		std::string serverErrorMsg = e.getServerMsg();
		std::cout << "Failed to connect to server. ErrorCode: " << errorCode << ". ErrorString: " << serverErrorMsg << std::endl;

		return false;
	}
}


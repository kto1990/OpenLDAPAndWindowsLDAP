When updating ldapcpp source ocde follow thses steps:

1.) add original source

2.) apply the following changes in order for the code to compile on windows:
	- LDAPDeleteRequest.cpp, LDAPRequest.h: 
			rename static const int DELETE to DELLETE or sg. similar as this name causes name clash when building on windows

	- LDAPUrl.cpp:
			+#ifdef _WIN32
			+# include <ctype.h>
			+#endif
			
			in LDAPUrl::percentEncode()
			-                if (  std::isalnum(*i) ) {
			+#ifdef _WIN32
			+				if (  isalnum(*i) ) {
			+#else
			+				if (std::isalnum(*i)) {
			+#endif
			+
						
	- LdiffReader.cpp:
			+#include <memory>
			
			in LdifReader::splitLine()
			
			-        char outbuf[value.size()];
			+//        char outbuf[value.size()];  //note: this does not compile on windows
			+		std::unique_ptr<char[]> outbuf(new char[value.size()]);
			         int rc = sasl_decode64(value.c_str(), value.size(), 
			-                outbuf, value.size(), NULL);
			+                outbuf.get(), value.size(), NULL);
			         if( rc == SASL_OK )
			         {
			-            value = std::string(outbuf);
			+            value = std::string(outbuf.get());
			         }
			         

	- TlsOptions.cpp:
			+#ifdef HAVE_UNISTD_H
			 #include <unistd.h>
			+#endif			

			in TlsOptions::setOption()

			-                if ( !S_ISDIR(st.st_mode) ){
			+#ifdef _WIN32
			+				if ((st.st_mode & _S_IFMT) != S_IFDIR){
			+#else
			+                if ( !S_ISDIR(st.st_mode)){
			+#endif

	- ac/time.h
			 #else
 			 # include <time.h>
			+#ifdef _WIN32
			+# include <winsock2.h>
			+#endif
			 #endif			
			
	- config.h
			 /* Version number of package */
			 #define VERSION " "
			 
			+#ifdef _WIN32
			+#undef HAVE_TERMIOS_H
			+#undef HAVE_UNISTD_H
			+#undef TIME_WITH_SYS_TIME
			+#endif
			 /* Define to 1 ot enable debug logging */
			 /* #undef WITH_DEBUG */
			 
			 												         
3.) check if CmakeModules/OpenLDAP.cmake needs modification (ie: any new library dependency has been introduced)

4.) check if licence has changed and apply changes in licenses/openldap if need be

5.) check if any new dll should be added to any of the following files:
	wix-setup/centralmgmt/Product.wxs.in
	wix-setup/core/Product.wxs.in
	wix-setup/metadownloader/Product.wxs.in

6.) apply the following changes
	- TlsOptions.cpp
			in TlsOptions::setOption()
			
			+
			+        default:
			+            throw( LDAPException( LDAP_LOCAL_ERROR, "Unsupported TLS option in setOption()" ) );
			+        } //switch
			+				 

	- LDAPAsynConnection.cpp
			in LDAPAsynConnection::init()
			
			+    struct timeval socket_timeout;
			+    socket_timeout.tv_usec = 0;
			+    socket_timeout.tv_sec = 20;
			     ldap_set_option(cur_session, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
			     ldap_set_option(cur_session, LDAP_OPT_PROTOCOL_VERSION, &opt);
			+    ldap_set_option(cur_session, LDAP_OPT_NETWORK_TIMEOUT, &socket_timeout);						 
			 
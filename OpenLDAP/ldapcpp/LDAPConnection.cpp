// $OpenLDAP$
/*
 * Copyright 2000-2016 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "debug.h"

#include "LDAPResult.h"
#include "LDAPException.h"
#include "LDAPUrlList.h"

#include "LDAPConnection.h"
const int LDAPConnection::SEARCH_BASE = LDAPAsynConnection::SEARCH_BASE;
const int LDAPConnection::SEARCH_ONE = LDAPAsynConnection::SEARCH_ONE;
const int LDAPConnection::SEARCH_SUB = LDAPAsynConnection::SEARCH_SUB;

using namespace std;

//https://dagshub.com/suizhihao/Impala/src/473b533672f712efc6ff103c2a0fd0f0b0c7032f/thirdparty/openldap-2.4.25/tests/progs/slapd-common.c
void tester_ldap_error(LDAP* ld, int &err_code, std::string &err_msg)
{
    char* text = NULL;
    LDAPControl** ctrls = NULL;

    ldap_get_option(ld, LDAP_OPT_RESULT_CODE, (void*)&err_code);
    if (err_code != LDAP_SUCCESS) {
        ldap_get_option(ld, LDAP_OPT_DIAGNOSTIC_MESSAGE, (void*)&text);
    }

    err_msg = std::string(ldap_err2string(err_code));

    if (text) {
        err_msg += ". " + std::string(text);
        ldap_memfree(text);
        text = NULL;
    }

    ldap_get_option(ld, LDAP_OPT_MATCHED_DN, (void*)&text);
    if (text != NULL) {
        if (text[0] != '\0') {
            err_msg += ". " + std::string(text);
        }
        ldap_memfree(text);
        text = NULL;
    }

    ldap_get_option(ld, LDAP_OPT_SERVER_CONTROLS, (void*)&ctrls);
    if (ctrls != NULL) {
        int	i;

        err_msg += "\n\tControls:";
        for (i = 0; ctrls[i] != NULL; i++) {
            err_msg += "\n\t\t" + std::string(ctrls[i]->ldctl_oid);
        }
        ldap_controls_free(ctrls);
        ctrls = NULL;
    }

    if (err_code == LDAP_REFERRAL) {
        char** refs = NULL;

        ldap_get_option(ld, LDAP_OPT_REFERRAL_URLS, (void*)&refs);

        if (refs) {
            int	i;

            err_msg += "\n\tReferral:";
            for (i = 0; refs[i] != NULL; i++) {
                fprintf(stderr, "\t\t%s\n", refs[i]);
                err_msg += "\n\t\t" + std::string(refs[i]);
            }

            ber_memvfree((void**)refs);
        }
    }
}

LDAPConnection::LDAPConnection(const string& hostname, int port, 
        LDAPConstraints* cons) :
        LDAPAsynConnection(hostname, port, cons){
}

LDAPConnection::~LDAPConnection(){
}

void LDAPConnection::start_tls(){
    LDAPAsynConnection::start_tls();
}
   
void LDAPConnection::bind(const string& dn, const string& passwd,
        LDAPConstraints* cons){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPConnection::bind" << endl);
    LDAPMessageQueue* msg=0;
    LDAPResult* res=0;
    try{
        msg = LDAPAsynConnection::bind(dn,passwd,cons);
        res = (LDAPResult*)msg->getNext();
    }catch(LDAPException &){
        delete msg;
        delete res;

        int err = -1;
        std::string errMsg;
        tester_ldap_error(this->getSessionHandle(), err, errMsg);

        throw LDAPException(err, errMsg);
    }
    int resCode=res->getResultCode();
    if(resCode != LDAPResult::SUCCESS) {
        if(resCode == LDAPResult::REFERRAL){
            LDAPUrlList urls = res->getReferralUrls();
            delete res;
            delete msg;
            throw LDAPReferralException(urls);
        }else{
            string srvMsg = res->getErrMsg();
            delete res;
            delete msg;
            throw LDAPException(resCode, srvMsg);
        }
    }
    delete res;
    delete msg;   // memcheck
}

void LDAPConnection::saslInteractiveBind( const std::string &mech,
                        int flags,
                        SaslInteractionHandler *sih,
                        const LDAPConstraints *cons)
{
    DEBUG(LDAP_DEBUG_TRACE,"LDAPConnection::bind" << endl);
    LDAPMessageQueue* msg=0;
    LDAPResult* res=0;
    try{
        msg = LDAPAsynConnection::saslInteractiveBind(mech, flags, sih, cons);
        res = (LDAPResult*)msg->getNext();
    }catch(LDAPException &){
        delete msg;
        delete res;
        throw;
    }
    int resCode=res->getResultCode();
    if(resCode != LDAPResult::SUCCESS) {
        if(resCode == LDAPResult::REFERRAL){
            LDAPUrlList urls = res->getReferralUrls();
            delete res;
            delete msg;
            throw LDAPReferralException(urls);
        }else{
            string srvMsg = res->getErrMsg();
            delete res;
            delete msg;
            throw LDAPException(resCode, srvMsg);
        }
    }
    delete res;
    delete msg;
}

void LDAPConnection::unbind(){
    LDAPAsynConnection::unbind();
}

bool LDAPConnection::compare(const string& dn, const LDAPAttribute& attr,
        LDAPConstraints* cons){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPConnection::compare" << endl);
    LDAPMessageQueue* msg=0;
    LDAPResult* res=0;
    try{
        msg = LDAPAsynConnection::compare(dn,attr,cons);
        res = (LDAPResult*)msg->getNext();
    }catch(LDAPException &){
        delete msg;
        delete res;
        throw;
    }
    int resCode=res->getResultCode();
    switch (resCode){
        case LDAPResult::COMPARE_TRUE :
            delete res; 
            delete msg;
            return true;
        break;
        case LDAPResult::COMPARE_FALSE :
            delete res;
            delete msg;
            return false;
        break;
        case LDAPResult::REFERRAL :
        {
            LDAPUrlList urls = res->getReferralUrls();
            delete res;
            delete msg;
            throw LDAPReferralException(urls);
        }
        break;
        default :
            string srvMsg = res->getErrMsg();
            delete res;
            delete msg;
            throw LDAPException(resCode, srvMsg);
    }
}

void LDAPConnection::del(const string& dn, const LDAPConstraints* cons){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPConnection::del" << endl);
    LDAPMessageQueue* msg=0;
    LDAPResult* res=0;
    try{
        msg = LDAPAsynConnection::del(dn,cons);
        res = (LDAPResult*)msg->getNext();
    }catch(LDAPException &){
        delete msg;
        delete res;
        throw;
    }
    int resCode=res->getResultCode();
    switch (resCode){
        case LDAPResult::SUCCESS :
            delete res; 
            delete msg;
        break;
        case LDAPResult::REFERRAL :
        {
            LDAPUrlList urls = res->getReferralUrls();
            delete res;
            delete msg;
            throw LDAPReferralException(urls);
        }
        break;
        default :
            string srvMsg = res->getErrMsg();
            delete res;
            delete msg;
            throw LDAPException(resCode, srvMsg);
    }

}

void LDAPConnection::add(const LDAPEntry* le, const LDAPConstraints* cons){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPConnection::add" << endl);
    LDAPMessageQueue* msg=0;
    LDAPResult* res=0;
    try{
        msg = LDAPAsynConnection::add(le,cons);
        res = (LDAPResult*)msg->getNext();
    }catch(LDAPException &){
        delete msg;
        delete res;
        throw;
    }
    int resCode=res->getResultCode();
    switch (resCode){
        case LDAPResult::SUCCESS :
            delete res; 
            delete msg;
        break;
        case LDAPResult::REFERRAL :
        {
            LDAPUrlList urls = res->getReferralUrls();
            delete res;
            delete msg;
            throw LDAPReferralException(urls);
        }
        break;
        default :
            string srvMsg = res->getErrMsg();
            delete res;
            delete msg;
            throw LDAPException(resCode, srvMsg);
    }
}

void LDAPConnection::modify(const string& dn, const LDAPModList* mods,
        const LDAPConstraints* cons){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPConnection::modify" << endl);
    LDAPMessageQueue* msg=0;
    LDAPResult* res=0;
    try{
        msg = LDAPAsynConnection::modify(dn,mods,cons);
        res = (LDAPResult*)msg->getNext();
    }catch(LDAPException &){
        delete msg;
        delete res;
        throw;
    }
    int resCode=res->getResultCode();
    switch (resCode){
        case LDAPResult::SUCCESS :
            delete res; 
            delete msg;
        break;
        case LDAPResult::REFERRAL :
        {
            LDAPUrlList urls = res->getReferralUrls();
            delete res;
            delete msg;
            throw LDAPReferralException(urls);
        }
        break;
        default :
            string srvMsg = res->getErrMsg();
            delete res;
            delete msg;
            throw LDAPException(resCode, srvMsg);
    }
    
}

void LDAPConnection::rename(const string& dn, const string& newRDN,
        bool delOldRDN, const string& newParentDN, 
        const LDAPConstraints* cons){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPConnection::rename" << endl);
    LDAPMessageQueue* msg=0;
    LDAPResult* res=0;
    try{
        msg = LDAPAsynConnection::rename(dn,newRDN,delOldRDN, newParentDN,
                cons);
        res = (LDAPResult*)msg->getNext();
    }catch(LDAPException &){
        delete msg;
        delete res;
        throw;
    }
    int resCode=res->getResultCode();
    switch (resCode){
        case LDAPResult::SUCCESS :
            delete res; 
            delete msg;
        break;
        case LDAPResult::REFERRAL :
        {
            LDAPUrlList urls = res->getReferralUrls();
            delete res;
            delete msg;
            throw LDAPReferralException(urls);
        }
        break;
        default :
            string srvMsg = res->getErrMsg();
            delete res;
            delete msg;
            throw LDAPException(resCode, srvMsg);
    }
}

LDAPSearchResults* LDAPConnection::search(const string& base, int scope,
        const string& filter, const StringList& attrs, bool attrsOnly, 
        const LDAPConstraints* cons){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPConnection::search" << endl);
    LDAPMessageQueue* msgq=0;
    LDAPResult* res=0;
    LDAPSearchResults* results= 0;
    
    try{
        results = new LDAPSearchResults();
        msgq = LDAPAsynConnection::search(base,scope, filter, attrs, attrsOnly,
                cons);
        res = results->readMessageQueue(msgq);
    }catch(LDAPException &){
        delete results; // memcheck
        delete msgq;
        throw;
    }
    if(res != 0){
        int resCode=res->getResultCode();
        switch (resCode){
            case LDAPResult::SUCCESS :
                delete res; 
                delete msgq;
                return results;
            break;
            case LDAPResult::REFERRAL :
            {
                LDAPUrlList urls = res->getReferralUrls();
                delete results; // memcheck
                delete res;
                delete msgq;
                throw LDAPReferralException(urls);
            }
            break;
            default :
                string srvMsg = res->getErrMsg();
                delete results; // memcheck
                delete res;
                delete msgq;
                throw LDAPException(resCode, srvMsg);
        }
    }        
    return 0;
}

LDAPExtResult* LDAPConnection::extOperation(const string& oid, 
        const string& value, const LDAPConstraints *cons){
    DEBUG(LDAP_DEBUG_TRACE,"LDAPConnection::extOperation" << endl);
    LDAPMessageQueue* msg=0;
    LDAPExtResult* res=0;
    try{
        msg = LDAPAsynConnection::extOperation(oid,value,cons);
        res = (LDAPExtResult*)msg->getNext();
    }catch(LDAPException &){
        delete msg;
        delete res;
        throw;
    }
    int resCode=res->getResultCode();
    switch (resCode){
        case LDAPResult::SUCCESS :
            delete msg;
            return res;
        case LDAPResult::REFERRAL :
        {
            LDAPUrlList urls = res->getReferralUrls();
            delete res;
            delete msg;
            throw LDAPReferralException(urls);
        }
        break;
        default :
            string srvMsg = res->getErrMsg();
            delete res;
            delete msg;
            throw LDAPException(resCode, srvMsg);
    }
}

const string& LDAPConnection::getHost() const{
    return LDAPAsynConnection::getHost();
}

int LDAPConnection::getPort() const{
    return LDAPAsynConnection::getPort();
}

void LDAPConnection::setConstraints(LDAPConstraints* cons){
    LDAPAsynConnection::setConstraints(cons);
}

const LDAPConstraints* LDAPConnection::getConstraints() const{
    return LDAPAsynConnection::getConstraints();
}

TlsOptions LDAPConnection::getTlsOptions() const {
    return LDAPAsynConnection::getTlsOptions();
}

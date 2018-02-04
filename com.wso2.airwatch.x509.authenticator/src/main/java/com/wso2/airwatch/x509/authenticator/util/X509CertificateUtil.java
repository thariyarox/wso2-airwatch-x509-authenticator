package com.wso2.airwatch.x509.authenticator.util;


import com.wso2.airwatch.x509.authenticator.AuthenticatorConstants;
import com.wso2.airwatch.x509.authenticator.DataHolder;
import org.apache.axiom.om.util.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class X509CertificateUtil {

    private static Log log = LogFactory.getLog(X509CertificateUtil.class);

   /**
     * Validate the certificate against with given certificate.
     *
     * @param certificateBytes x509 certificate
     * @return boolean status of the action
     * @throws AuthenticationFailedException
     */
    public static boolean validateCerts(byte[] certificateBytes, boolean allowSelfSignedCerts)
            throws AuthenticationFailedException {

        boolean isCertificateValid = false;

        X509Certificate x509Certificate;
        try {
            x509Certificate = X509Certificate.getInstance(certificateBytes);

            String issuerName = x509Certificate.getIssuerDN().getName();
            log.info("Certificate Issuer Name : " + issuerName);

            //TODO: Validate certificate signature correctly.. this is only for testing purpose
            if("EMAILADDRESS=tharindue@wso2.com, CN=wso2is.com, OU=IS, O=WSO2, L=COLOMBO, ST=WESTERN, C=LK".equals(issuerName)){
                isCertificateValid = true;
                log.info("Certificate validation passed");
            } else {
                log.info("Certificate validation failed");
            }

        } catch (javax.security.cert.CertificateException e) {
            throw new AuthenticationFailedException("Error while retrieving certificate ", e);
        }
        if (log.isDebugEnabled()) {
           // log.debug("X509 certificate validation is completed and the result is " + validateResult);
        }


        return isCertificateValid;
    }

}

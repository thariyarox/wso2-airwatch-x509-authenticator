package com.wso2.airwatch.x509.authenticator;

/**
 * Created by tharindu on 2/1/18.
 */
public class AuthenticatorConstants {

    public static final String SUCCESS = "success";

    public static final String AUTHENTICATOR_NAME = "AirWatchX509";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "AirWatch X509";

    public static final String X_509_CERTIFICATE = "javax.servlet.request.X509Certificate";
    public static final String AUTHENTICATION_ENDPOINT = "https://localhost:8443/x509-certificate-servlet";
    public static final String AUTHENTICATION_ENDPOINT_PARAMETER = "AuthenticationEndpoint";
    public static final String USERNAME = "username";
    public static final String RETRY_PARAM_FOR_CHECKING_CERTIFICATE =
            "&authFailure=true&errorCode=";
    public static final String ERROR_PAGE = "authenticationendpoint/x509CertificateError.jsp";
    public static final String AUTHENTICATORS = "authenticators";
    public static final String X509_CERTIFICATE_ERROR_CODE = "X509CertificateErrorCode";
    public static final String X509_CERTIFICATE_NOT_FOUND_ERROR_CODE = "404";
    public static final String X509_CERTIFICATE_USERNAME = "X509CertificateUsername";

    public static final String X509_AUTHENTICATION_STEP_ATTEMPTED = "x509_authentication_attempted";
    public static final String X509_AUTHENTICATION_STEP_CERTIFICATE_FOUND = "x509_certificate_found";
    public static final String X509_AUTHENTICATION_STEP_CERTIFICATE_VALID = "x509_certificate_valid";

    public static final String X509_AUTHENTICATION_ROOT_CA_ALIAS_PARAMTER = "CAcertAlias";
    public static final String ALLOW_SELF_SIGNED_CERTS_PARAMETER = "allowSelfSignedCerts";

    public static final String DEVICE_TYPE_PARAMTER = "device_type";
    public static final String DEVICE_TYPE_MOBILE = "mobile";
    public static final String DEVICE_TYPE_DESKTOP = "desktop";

}

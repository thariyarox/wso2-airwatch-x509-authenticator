package com.wso2.airwatch.x509.authenticator;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticator;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import com.wso2.airwatch.x509.authenticator.util.X509CertificateUtil;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLEncoder;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.net.HttpURLConnection;

import org.json.*;

public class WSO2AirWatchAuthenticator extends BasicAuthenticator {

    private static Log log = LogFactory.getLog(WSO2AirWatchAuthenticator.class);

    @Override
    public boolean canHandle(HttpServletRequest request) {

        // this should be either basic authentication request or x509 request

        String userName = request.getParameter("username");
        String password = request.getParameter("password");

        if (userName != null && password != null) {
            //Basic authentication flow
            return true;
        } else if (request.getParameter(AuthenticatorConstants.SUCCESS) != null) {
            // X509 authentication flow
            return true;
        }

        return false;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException, LogoutFailedException {

        log.info("-----------------process method called------------------");

        //check if the device type is already identified
        if (context.getParameter(AuthenticatorConstants.DEVICE_TYPE_PARAMTER) == null) {

            String userAgentString = request.getHeader("User-Agent");
            log.info("userAgentString found : " + userAgentString);

            boolean isMobile = isMobileTraffic(userAgentString);

            if (isMobile) {
                context.setProperty(AuthenticatorConstants.DEVICE_TYPE_PARAMTER, AuthenticatorConstants.DEVICE_TYPE_MOBILE);
                log.info("device detected as : Mobile");
            } else {
                context.setProperty(AuthenticatorConstants.DEVICE_TYPE_PARAMTER, AuthenticatorConstants.DEVICE_TYPE_DESKTOP);
                log.info("device detected as : Deskotp");
            }
        } else {
            log.info("device type is already identified");
        }

        return super.process(request, response, context);
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException {

        log.info("-----------------initiateAuthenticationRequest method called------------------");

        boolean terminateAuthenticationFlow = false;

        if (context.isRetrying()) {
            //This is a retry attempt
            if (isEndOfAuthenticationFlow(context)) {
                //if X509 authentication is already attempted previously and if the provided certificate was not valid, show error

                terminateAuthenticationFlow = true;
            }
        }

        Object certAuthenticationAttempted = context.getProperty(AuthenticatorConstants.X509_AUTHENTICATION_STEP_ATTEMPTED);

        if (certAuthenticationAttempted != null) {
            if ("true".equals(certAuthenticationAttempted.toString())) {
                // previously it already has tried to authenticate with x509 and failed
                //change the device type to desktop
                context.setProperty(AuthenticatorConstants.DEVICE_TYPE_PARAMTER, AuthenticatorConstants.DEVICE_TYPE_DESKTOP);

                //Do not treat the next attempt of basic authentication as a retry attempt, to avoid error message displayed in login page
                if(context.getProperty(AuthenticatorConstants.X09_AUTHENTICATION_FALLBACK_TO_BASICAUTH) == null) {
                    //This is the first try of basic auth after failing x509 authentication
                    context.setProperty(AuthenticatorConstants.X09_AUTHENTICATION_FALLBACK_TO_BASICAUTH, "true");
                    context.setRetrying(false);
                }

                log.info("--------------cert authentication value -------: " + certAuthenticationAttempted.toString());
                log.info("falling back to basic authentication");
            }
        }

        if (terminateAuthenticationFlow) {

            try {
                String errorPageUrl = IdentityUtil.getServerURL(AuthenticatorConstants.ERROR_PAGE, false, false);
                String redirectUrl = errorPageUrl + ("?" + FrameworkConstants.SESSION_DATA_KEY + "="
                        + context.getContextIdentifier()) + "&" + AuthenticatorConstants.AUTHENTICATORS
                        + "=" + getName() + AuthenticatorConstants.RETRY_PARAM_FOR_CHECKING_CERTIFICATE
                        + context.getProperty(AuthenticatorConstants.X509_CERTIFICATE_ERROR_CODE);
                context.setProperty(AuthenticatorConstants.X509_CERTIFICATE_ERROR_CODE, "");

                if (log.isDebugEnabled()) {
                    log.debug("Redirect to error page: " + redirectUrl);
                }
                response.sendRedirect(redirectUrl);

            } catch (IOException e) {
                throw new AuthenticationFailedException("Exception while redirecting to the login page", e);
            }

        } else {

            // based on the type of device, initiate the authentication flow

            if (AuthenticatorConstants.DEVICE_TYPE_DESKTOP.equals(context.getProperty(AuthenticatorConstants.DEVICE_TYPE_PARAMTER).toString())) {
                // Continue to basic authentication for non-mobile traffic
                super.initiateAuthenticationRequest(request, response, context);
            } else {
                // Continue with X509 authentication flow
                try {
                    String authEndpoint = getAuthenticatorConfig().getParameterMap().
                            get(AuthenticatorConstants.AUTHENTICATION_ENDPOINT_PARAMETER);
                    if (StringUtils.isEmpty(authEndpoint)) {
                        authEndpoint = AuthenticatorConstants.AUTHENTICATION_ENDPOINT;
                    }
                    String queryParams = FrameworkUtils.getQueryStringWithFrameworkContextId(
                            context.getQueryParams(), context.getCallerSessionKey(),
                            context.getContextIdentifier());
                    if (log.isDebugEnabled()) {
                        log.debug("Request sent to " + authEndpoint);
                    }
                    response.sendRedirect(authEndpoint + ("?" + queryParams));

                } catch (IOException e) {
                    throw new AuthenticationFailedException("Exception while redirecting to the login page", e);
                }
            }

        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response, AuthenticationContext context) throws AuthenticationFailedException {

        log.info("-----------------processAuthenticationResponse method called------------------");

        Object certAuthenticationAttempted = context.getProperty(AuthenticatorConstants.X509_AUTHENTICATION_STEP_ATTEMPTED);
        if (certAuthenticationAttempted != null) {
            if ("true".equals(certAuthenticationAttempted.toString())) {


                // previously it already has tried to authenticate with x509 and failed
                //change the device type to desktop
                context.setProperty(AuthenticatorConstants.DEVICE_TYPE_PARAMTER, AuthenticatorConstants.DEVICE_TYPE_DESKTOP);
                log.info("--------------cert authentication value -------: " + certAuthenticationAttempted.toString());
                log.info("falling back to basic authentication");
            }
        } else {
            log.info("cert authentication is not set to context yet");
        }


        if (AuthenticatorConstants.DEVICE_TYPE_DESKTOP.equals(context.getProperty(AuthenticatorConstants.DEVICE_TYPE_PARAMTER).toString())) {
            // Process the response as basic authentication
            super.processAuthenticationResponse(request, response, context);
        } else {
            // Process the response as X509 authentication

            context.setProperty(AuthenticatorConstants.X509_AUTHENTICATION_STEP_ATTEMPTED, "true");

            Object object = request.getAttribute(AuthenticatorConstants.X_509_CERTIFICATE);
            if (object != null) {
                context.setProperty(AuthenticatorConstants.X509_AUTHENTICATION_STEP_CERTIFICATE_FOUND, "true");


                X509Certificate[] certificates;
                if (object instanceof X509Certificate[]) {
                    certificates = (X509Certificate[]) object;
                } else {
                    throw new AuthenticationFailedException("Exception while casting the X509Certificate");
                }


                if (certificates.length > 0) {
                    if (log.isDebugEnabled()) {
                        log.debug("X509 Certificate Checking in servlet is done! ");
                    }
                    X509Certificate cert = certificates[0];
                    byte[] data;
                    try {
                        data = cert.getEncoded();
                    } catch (CertificateEncodingException e) {
                        throw new AuthenticationFailedException("Encoded certificate in not found", e);
                    }
                    String certAttributes = String.valueOf(cert.getSubjectX500Principal());
                    Map<ClaimMapping, String> claims;

                    claims = getSubjectAttributes(context, certAttributes);

                    //TODO: add the user handling logic here
                    String userName = getUserNameFromCertificate(claims);
                    if (StringUtils.isEmpty(userName)) {
                        throw new AuthenticationFailedException("username can't be empty");
                    }

                    //Get Root CA Alias
                    String rootCAAlias = getAuthenticatorConfig().getParameterMap().
                            get(AuthenticatorConstants.X509_AUTHENTICATION_ROOT_CA_ALIAS_PARAMTER);
                    log.info("root CA alias received: " + rootCAAlias);

                    boolean allowSelfSignedCerts = Boolean.parseBoolean(getAuthenticatorConfig().getParameterMap().
                            get(AuthenticatorConstants.ALLOW_SELF_SIGNED_CERTS_PARAMETER));

                    if (X509CertificateUtil.validateCerts(data, allowSelfSignedCerts)) {
                        if (log.isDebugEnabled()) {
                            log.debug("X509Certificate exits and getting validated");
                        }
                        allowUser(userName, claims, cert, context);
                        context.setProperty(AuthenticatorConstants.X509_AUTHENTICATION_STEP_CERTIFICATE_VALID, "true");
                    } else {
                        context.setProperty(AuthenticatorConstants.X509_AUTHENTICATION_STEP_CERTIFICATE_VALID, "false");
                        throw new AuthenticationFailedException("X509Certificate is not valid");
                    }
                } else {
                    throw new AuthenticationFailedException("X509Certificate object is null");
                }
            } else {
                context.setProperty(AuthenticatorConstants.X509_AUTHENTICATION_STEP_CERTIFICATE_FOUND, "false");

                context.setProperty(AuthenticatorConstants.X509_CERTIFICATE_ERROR_CODE,
                        AuthenticatorConstants.X509_CERTIFICATE_NOT_FOUND_ERROR_CODE);
                throw new AuthenticationFailedException("Unable to find X509 Certificate in browser");
            }

        }


    }

    @Override
    protected boolean retryAuthenticationEnabled() {
        return super.retryAuthenticationEnabled();
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        return super.getContextIdentifier(request);
    }

    @Override
    public String getFriendlyName() {

        //This is the name listed in the dropdown in Local & Outbound Authenticators section of Service Provider configuration
        return AuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {

        //This is the name of the authenticator coming in the 'authenticators' query parameter in authenticationendpoint
        return AuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    private boolean isEndOfAuthenticationFlow(AuthenticationContext context) {

        if (context.getParameter(AuthenticatorConstants.X509_AUTHENTICATION_STEP_ATTEMPTED) != null &&
                Boolean.parseBoolean(context.getParameter(AuthenticatorConstants.X509_AUTHENTICATION_STEP_ATTEMPTED).toString())) {
            //X509 authentication attempted previously

            if (context.getParameter(AuthenticatorConstants.X509_AUTHENTICATION_STEP_CERTIFICATE_FOUND) != null &&
                    Boolean.parseBoolean(context.getParameter(AuthenticatorConstants.X509_AUTHENTICATION_STEP_CERTIFICATE_FOUND).toString())) {
                //certificate was provided previously
                if (context.getParameter(AuthenticatorConstants.X509_AUTHENTICATION_STEP_CERTIFICATE_VALID) != null &&
                        !Boolean.parseBoolean(context.getParameter(AuthenticatorConstants.X509_AUTHENTICATION_STEP_CERTIFICATE_VALID).toString())) {
                    //certificate provided previously was not valid
                    log.info("Previously provided certificate is not valid. This is the end of the authentication flow");
                    return true;
                }
            }
        }
        log.info("this is not the end of the authentication flow");
        return false;
    }


    private boolean isMobileTraffic(String userAgentString) {


        String chrome = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.96 Safari/537.36";
        String firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:53.0) Gecko/20100101 Firefox/53.0";
        String mobile_android_browser = "Mozilla/5.0 (Linux; Android 6.0; HTC_M8x Build/MRA58K) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Mobile Safari/537.36";
        String mobile_chrome_browser = "Mozilla/5.0 (Linux; Android 6.0; HTC_M8x Build/MRA58K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.137 Mobile Safari/537.36";


        boolean isMobile = false;

        String deviceInformation = getDeviceInformation(userAgentString);

        if (deviceInformation != null && !"".equals(deviceInformation)) {

            //Parse the JSON response and decide if this is mobile traffic

            JSONObject obj = new JSONObject(deviceInformation);
            String deviceType = obj.getString("DeviceType");
            if ("SmartPhone".equals(deviceType)) {
                //mobile traffic
                isMobile = true;
            }
        }

        //TODO: Remove following in production
        //override
        if (chrome.equals(userAgentString) || firefox.equals(userAgentString)) {
            isMobile = true;
        }

        return isMobile;
    }

    private String getDeviceInformation(String userAgent) {

        log.info("trying to connect to device information server");

        StringBuffer response = new StringBuffer();

        try {
            String url = "https://la0cmdalw1.execute-api.us-east-1.amazonaws.com/dev/VonageLoginServices/detector?user-agent=" + URLEncoder.encode(userAgent, "UTF-8");
            URL obj = new URL(url);
            HttpURLConnection con = (HttpURLConnection) obj.openConnection();

            // optional default is GET
            con.setRequestMethod("GET");

            //add request header
            con.setRequestProperty("User-Agent", userAgent);
            con.setRequestProperty("Authorization", "foobar"); //hard coded key

            int responseCode = con.getResponseCode();
            log.info("\nSending 'GET' request to URL : " + url);
            log.info("Response Code : " + responseCode);

            BufferedReader in = new BufferedReader(
                    new InputStreamReader(con.getInputStream()));
            String inputLine;

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();
        } catch (IOException e) {
            //error occured while connecting to external endpoint
            log.error("Error occured while detecting device type: ", e);
        }

        //print result
        log.info(response.toString());

        return response.toString();
    }

    private String getUserNameFromCertificate(Map<ClaimMapping, String> claims) {

        String username = "";
        Claim idClaim = new Claim();
        idClaim.setClaimId(0);
        idClaim.setClaimUri("CN");

        ClaimMapping idClaimMapping = new ClaimMapping();
        idClaimMapping.setLocalClaim(idClaim);
        idClaimMapping.setRemoteClaim(idClaim);

        username = claims.get(idClaimMapping);

        return username;

    }

    private void allowUser(String userName, Map claims, X509Certificate cert,
                           AuthenticationContext authenticationContext) {
        AuthenticatedUser authenticatedUserObj;
        authenticatedUserObj = AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(userName);
        authenticatedUserObj.setAuthenticatedSubjectIdentifier(String.valueOf(cert.getSerialNumber()));
        authenticatedUserObj.setUserAttributes(claims);
        authenticationContext.setSubject(authenticatedUserObj);
    }

    protected Map<ClaimMapping, String> getSubjectAttributes(AuthenticationContext authenticationContext, String
            certAttributes)
            throws AuthenticationFailedException {
        Map<ClaimMapping, String> claims = new HashMap<>();
        LdapName ldapDN;
        try {
            ldapDN = new LdapName(certAttributes);
        } catch (InvalidNameException e) {
            throw new AuthenticationFailedException("error occurred while get the certificate claims", e);
        }
        if (log.isDebugEnabled()) {
            log.debug("Getting username attribute");
        }
        String userNameAttribute = getAuthenticatorConfig().getParameterMap().get(AuthenticatorConstants.USERNAME);
        for (Rdn distinguishNames : ldapDN.getRdns()) {
            claims.put(ClaimMapping.build(distinguishNames.getType(), distinguishNames.getType(),
                    null, false), String.valueOf(distinguishNames.getValue()));
            if (StringUtils.isNotEmpty(userNameAttribute)) {
                if (userNameAttribute.equals(distinguishNames.getType())) {
                    if (log.isDebugEnabled()) {
                        log.debug("Setting X509Certificate username attribute: " + userNameAttribute
                                + "and value is " + distinguishNames.getValue());
                    }
                    authenticationContext.setProperty(AuthenticatorConstants.X509_CERTIFICATE_USERNAME, String
                            .valueOf(distinguishNames.getValue()));
                }
            }
        }
        return claims;
    }

}

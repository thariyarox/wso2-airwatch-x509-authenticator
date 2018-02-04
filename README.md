# wso2-airwatch-x509-authenticator


IS_HOEM/repository/conf/identity/application-authentication.xml

        <AuthenticatorConfig name="AirWatchX509" enabled="true">
            <Parameter name="AuthenticationEndpoint">https://SERVER:9443/x509-certificate-servlet</Parameter>
            <Parameter name="CAcertAlias">rootca</Parameter>
            <Parameter name="trustStorePath">/repository/resources/security/cacerts.jks</Parameter>
            <Parameter name="trustStorePassword">cacertspassword</Parameter>
	          <Parameter name="allowSelfSignedCerts">true</Parameter>
        </AuthenticatorConfig>

package com.wso2.airwatch.x509.authenticator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.user.core.service.RealmService;

public class DataHolder {

    private static RealmService realmService;
    private static volatile DataHolder dataHolder;
    private static WSO2AirWatchAuthenticator customBasicAuthenticator;
    private static boolean isRealmServiceSet = false;

    private static Log log = LogFactory.getLog(DataHolder.class);


    private DataHolder() {

        log.info("----------------------------------------- creating data holder instance");

    }

    public static DataHolder getInstance() {

        if (dataHolder == null) {

            synchronized (DataHolder.class) {
                if (dataHolder == null) {
                    dataHolder = new DataHolder();
                    customBasicAuthenticator = new WSO2AirWatchAuthenticator();
                    isRealmServiceSet = false;
                }
            }

        }

        return dataHolder;
    }

    public void setRealmService(RealmService realmService) {

        if(!isRealmServiceSet){
            //realm searvice is not already set
            this.realmService = realmService;
            isRealmServiceSet = true;
        }
    }

    public RealmService getRealmService() {
        return realmService;
    }

    public WSO2AirWatchAuthenticator getCustomBasicAuthenticator() {
        return customBasicAuthenticator;
    }

}

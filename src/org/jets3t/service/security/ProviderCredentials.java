/*
 * jets3t : Java Extra-Tasty S3 Toolkit (for Amazon S3 online storage service)
 * This is a java.net project, see https://jets3t.dev.java.net/
 *
 * Copyright 2010 James Murty
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jets3t.service.security;

import java.io.Serializable;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Abstract class to contain the credentials of a user. 
 *
 * @author James Murty
 * @author Nikolas Coukouma
 * @author Claudio Cherubino
 */
public abstract class ProviderCredentials implements Serializable {
    protected static final Log log = LogFactory.getLog(ProviderCredentials.class);
    
    protected static final String V2_KEYS_DELIMITER = "AWSKEYS";
    protected static final String V3_KEYS_DELIMITER = "\n";

    protected String accessKey = null;
    protected String secretKey = null;
    protected String friendlyName = null;

    /**
     * Construct credentials.
     *
     * @param accessKey
     * Access key for a storage account.
     * @param secretKey
     * Secret key for a storage account.
     */
    public ProviderCredentials(String accessKey, String secretKey) {
        this.accessKey = accessKey;
        this.secretKey = secretKey;
    }

    /**
     * Construct credentials, and associate them with a human-friendly name.
     *
     * @param accessKey
     * Access key for a storage account.
     * @param secretKey
     * Secret key for a storage account.
     * @param friendlyName
     * a name identifying the owner of the credentials, such as 'James'.
     */
    public ProviderCredentials(String accessKey, String secretKey, String friendlyName) {
        this(accessKey, secretKey);
        this.friendlyName = friendlyName;
    }

    /**
     * @return
     * the Access Key.
     */
    public String getAccessKey() {
        return accessKey;
    }

    /**
     * @return
     * the Secret Key.
     */
    public String getSecretKey() {
        return secretKey;
    }

    /**
     * @return
     * the friendly name associated with a storage account, if available.
     */
    public String getFriendlyName() {
        return friendlyName;
    }

    /**
     * @return
     * true if there is a non-null and non-empty friendly name associated
     * with this account.
     */
    public boolean hasFriendlyName() {
        return (friendlyName != null && friendlyName.trim().length() > 0);
    }    

    /**
     * @return
     * a string summarizing these credentials
     */
    public String getLogString() {
        return getAccessKey() + " : " + getSecretKey();
    }
    
    /**
     * @return
     * the string of data that needs to be encrypted (for serialization)
     */
    protected String getDataToEncrypt() {
        return getAccessKey() + V3_KEYS_DELIMITER + getSecretKey();
    }
}

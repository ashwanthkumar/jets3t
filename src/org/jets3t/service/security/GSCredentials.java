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

/**
 * Class to contain the Google Storage (GS) credentials of a user. 
 *
 * @author Google developers
 */
public class GSCredentials extends ProviderCredentials {
    protected static final String GS_TYPE_NAME = "gs";
  
    /**
     * Construct credentials.
     *
     * @param accessKey
     * Access key for a Google Storage account.
     * @param secretKey
     * Secret key for a Google Storage account.
     */
    public GSCredentials(String accessKey, String secretKey) {
        super(accessKey, secretKey);
    }

    /**
     * Construct credentials, and associate them with a human-friendly name.
     *
     * @param accessKey
     * Access key for a Google Storage account.
     * @param secretKey
     * Secret key for a Google Storage account.
     * @param friendlyName
     * a name identifying the owner of the credentials, such as 'James'.
     */
    public GSCredentials(String accessKey, String secretKey, String friendlyName) {
        super(accessKey, secretKey, friendlyName);
    }

    /**
     * @return
     * string representing this credential type's name (for serialization)
     */
    protected String getTypeName() {
        return GS_TYPE_NAME;
    }
}

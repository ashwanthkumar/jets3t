/*
 * JetS3t : Java S3 Toolkit
 * Project hosted at http://bitbucket.org/jmurty/jets3t/
 *
 * Copyright 2011 James Murty
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
 * Class to contain OAuth2 client credentials for authenticating against an
 * OAuth end-point, as opposed to authenticating directly with a storage service.
 *
 * Instead of the typical user access and client keys stored within a {@link ProviderCredentials}
 * class, this class stores an OAuth2 Client ID (as the access key) and Client Secret (as the
 * secret key).
 *
 * @author jmurty
 */
public class OAuth2Credentials extends ProviderCredentials {

    /**
     * Construct credentials.
     *
     * @param clientId
     * Client ID to identify the application to an OAuth2 end-point.
     * @param clientSecret
     * Client Secret for the application to authenticate against an OAuth2 end-point.
     */
    public OAuth2Credentials(String clientId, String clientSecret) {
        super(clientId, clientSecret);
    }

    /**
     * Construct credentials, and associate them with a human-friendly name.
     *
     * @param clientId
     * Client ID to identify the application to an OAuth2 end-point.
     * @param clientSecret
     * Client Secret for the application to authenticate against an OAuth2 end-point.
     * @param friendlyName
     * a name identifying the owner of the credentials, such as 'James'.
     */
    public OAuth2Credentials(String clientId, String clientSecret, String friendlyName) {
        super(clientId, clientSecret, friendlyName);
    }

    /**
     * @return
     * the OAuth2 Client ID (stored as access key)
     */
    public String getClientId() {
        return this.accessKey;
    }

    /**
     * @return
     * the OAuth2 Client Secret (stored as secret key)
     */
    public String getClientSecret() {
        return this.secretKey;
    }

    /**
     * @return
     * string representing this credential type's name (for serialization)
     */
    @Override
    protected String getTypeName() {
        return "OAuth2Client";
    }

    @Override
    public String getVersionPrefix() {
        return "jets3t OAuth2 Client Credentials, version: ";
    }

}

/*
 * JetS3t : Java S3 Toolkit
 * Project hosted at http://bitbucket.org/jmurty/jets3t/
 *
 * Copyright 2006-2010 James Murty
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
package org.jets3t.service.impl.rest.httpclient;

import org.apache.commons.httpclient.HostConfiguration;
import org.apache.commons.httpclient.auth.CredentialsProvider;
import org.jets3t.service.Constants;
import org.jets3t.service.Jets3tProperties;
import org.jets3t.service.S3ServiceException;
import org.jets3t.service.security.ProviderCredentials;

/**
 * REST/HTTP implementation of Google Storage Service based on the
 * <a href="http://jakarta.apache.org/commons/httpclient/">HttpClient</a> library.
 * <p>
 * This class uses properties obtained through {@link org.jets3t.service.Jets3tProperties}. For more information on
 * these properties please refer to
 * <a href="http://jets3t.s3.amazonaws.com/toolkit/configuration.html">JetS3t Configuration</a>
 * </p>
 *
 * @author James Murty
 */
public class GoogleStorageService extends RestStorageService {

    /**
     * Constructs the service and initialises the properties.
     *
     * @param credentials
     * the user credentials to use when communicating with Google Storage, may be null in which case the
     * communication is done as an anonymous user.
     *
     * @throws S3ServiceException
     */
    public GoogleStorageService(ProviderCredentials credentials) throws S3ServiceException {
        this(credentials, null, null);
    }

    /**
     * Constructs the service and initialises the properties.
     *
     * @param credentials
     * the user credentials to use when communicating with Google Storage, may be null in which case the
     * communication is done as an anonymous user.
     * @param invokingApplicationDescription
     * a short description of the application using the service, suitable for inclusion in a
     * user agent string for REST/HTTP requests. Ideally this would include the application's
     * version number, for example: <code>Cockpit/0.7.3</code> or <code>My App Name/1.0</code>
     * @param credentialsProvider
     * an implementation of the HttpClient CredentialsProvider interface, to provide a means for
     * prompting for credentials when necessary.
     *
     * @throws S3ServiceException
     */
    public GoogleStorageService(ProviderCredentials credentials, String invokingApplicationDescription,
        CredentialsProvider credentialsProvider) throws S3ServiceException
    {
        this(credentials, invokingApplicationDescription, credentialsProvider,
            Jets3tProperties.getInstance(Constants.JETS3T_PROPERTIES_FILENAME));
    }

    /**
     * Constructs the service and initialises the properties.
     *
     * @param credentials
     * the user credentials to use when communicating with Google Storage, may be null in which case the
     * communication is done as an anonymous user.
     * @param invokingApplicationDescription
     * a short description of the application using the service, suitable for inclusion in a
     * user agent string for REST/HTTP requests. Ideally this would include the application's
     * version number, for example: <code>Cockpit/0.7.3</code> or <code>My App Name/1.0</code>
     * @param credentialsProvider
     * an implementation of the HttpClient CredentialsProvider interface, to provide a means for
     * prompting for credentials when necessary.
     * @param jets3tProperties
     * JetS3t properties that will be applied within this service.
     *
     * @throws S3ServiceException
     */
    public GoogleStorageService(ProviderCredentials credentials, String invokingApplicationDescription,
        CredentialsProvider credentialsProvider, Jets3tProperties jets3tProperties)
        throws S3ServiceException
    {
        this(credentials, invokingApplicationDescription, credentialsProvider,
            jets3tProperties, new HostConfiguration());
    }

    /**
     * Constructs the service and initialises the properties.
     *
     * @param credentials
     * the user credentials to use when communicating with Google Storage, may be null in which case the
     * communication is done as an anonymous user.
     * @param invokingApplicationDescription
     * a short description of the application using the service, suitable for inclusion in a
     * user agent string for REST/HTTP requests. Ideally this would include the application's
     * version number, for example: <code>Cockpit/0.7.3</code> or <code>My App Name/1.0</code>
     * @param credentialsProvider
     * an implementation of the HttpClient CredentialsProvider interface, to provide a means for
     * prompting for credentials when necessary.
     * @param jets3tProperties
     * JetS3t properties that will be applied within this service.
     * @param hostConfig
     * Custom HTTP host configuration; e.g to register a custom Protocol Socket Factory
     *
     * @throws S3ServiceException
     */
    public GoogleStorageService(ProviderCredentials credentials, String invokingApplicationDescription,
        CredentialsProvider credentialsProvider, Jets3tProperties jets3tProperties,
        HostConfiguration hostConfig) throws S3ServiceException
    {
        super(credentials, invokingApplicationDescription, credentialsProvider, jets3tProperties, hostConfig);
    }

    /**
     * @return
     * the endpoint to be used to connect to Google Storage.
     */
    protected String getEndpoint() {
    	return this.jets3tProperties.getStringProperty(
                "gsservice.gs-endpoint", Constants.GS_DEFAULT_HOSTNAME);
    }

    /**
     * @return
     * the virtual path inside the S3 server.
     */
    protected String getVirtualPath() {
    	return this.jets3tProperties.getStringProperty(
                "gsservice.gs-endpoint-virtual-path", "");
    }

    /**
     * @return
     * the port number to be used for insecure connections over HTTP.
     */
    protected int getHttpPort() {
      return this.jets3tProperties.getIntProperty("gsservice.gs-endpoint-http-port", 80);
    }

    /**
     * @return
     * the port number to be used for secure connections over HTTPS.
     */
    protected int getHttpsPort() {
      return this.jets3tProperties.getIntProperty("gsservice.gs-endpoint-https-port", 443);
    }

    /**
     * @return
     * If true, all communication with GS will be via encrypted HTTPS connections,
     * otherwise communications will be sent unencrypted via HTTP
     */
    protected boolean getHttpsOnly() {
      return this.jets3tProperties.getBoolProperty("gsservice.https-only", true);
    }

    /**
     * @return
     * If true, JetS3t will specify bucket names in the request path of the HTTP message
     * instead of the Host header.
     */
    protected boolean getDisableDnsBuckets() {
      return this.jets3tProperties.getBoolProperty("gsservice.disable-dns-buckets", false);
    }

}

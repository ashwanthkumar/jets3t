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
import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.commons.httpclient.auth.CredentialsProvider;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jets3t.service.Constants;
import org.jets3t.service.Jets3tProperties;
import org.jets3t.service.S3ServiceException;
import org.jets3t.service.security.AWSDevPayCredentials;
import org.jets3t.service.security.ProviderCredentials;

import java.util.Map;

/**
 * REST/HTTP implementation of an S3Service based on the
 * <a href="http://jakarta.apache.org/commons/httpclient/">HttpClient</a> library.
 * <p>
 * This class uses properties obtained through {@link Jets3tProperties}. For more information on
 * these properties please refer to
 * <a href="http://jets3t.s3.amazonaws.com/toolkit/configuration.html">JetS3t Configuration</a>
 * </p>
 *
 * @author James Murty
 */
public class RestS3Service extends RestStorageService {

    private static final Log log = LogFactory.getLog(RestS3Service.class);
    private static final String AWS_SIGNATURE_IDENTIFIER = "AWS";
    private static final String AWS_REST_HEADER_PREFIX = "x-amz-";
    private static final String AWS_REST_METADATA_PREFIX = "x-amz-meta-";

    private String awsDevPayUserToken = null;
    private String awsDevPayProductToken = null;

    private boolean isRequesterPaysEnabled = false;

    /**
     * Constructs the service and initialises the properties.
     *
     * @param credentials
     * the user credentials to use when communicating with S3, may be null in which case the
     * communication is done as an anonymous user.
     *
     * @throws S3ServiceException
     */
    public RestS3Service(ProviderCredentials credentials) throws S3ServiceException {
        this(credentials, null, null);
    }

    /**
     * Constructs the service and initialises the properties.
     *
     * @param credentials
     * the S3 user credentials to use when communicating with S3, may be null in which case the
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
    public RestS3Service(ProviderCredentials credentials, String invokingApplicationDescription,
        CredentialsProvider credentialsProvider) throws S3ServiceException
    {
        this(credentials, invokingApplicationDescription, credentialsProvider,
            Jets3tProperties.getInstance(Constants.JETS3T_PROPERTIES_FILENAME));
    }

    /**
     * Constructs the service and initialises the properties.
     *
     * @param credentials
     * the S3 user credentials to use when communicating with S3, may be null in which case the
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
    public RestS3Service(ProviderCredentials credentials, String invokingApplicationDescription,
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
     * the S3 user credentials to use when communicating with S3, may be null in which case the
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
    public RestS3Service(ProviderCredentials credentials, String invokingApplicationDescription,
        CredentialsProvider credentialsProvider, Jets3tProperties jets3tProperties,
        HostConfiguration hostConfig) throws S3ServiceException
    {
        super(credentials, invokingApplicationDescription, credentialsProvider, jets3tProperties, hostConfig);

        if (credentials instanceof AWSDevPayCredentials) {
            AWSDevPayCredentials awsDevPayCredentials = (AWSDevPayCredentials) credentials;
            this.awsDevPayUserToken = awsDevPayCredentials.getUserToken();
            this.awsDevPayProductToken = awsDevPayCredentials.getProductToken();
        } else {
            this.awsDevPayUserToken = jets3tProperties.getStringProperty("devpay.user-token", null);
            this.awsDevPayProductToken = jets3tProperties.getStringProperty("devpay.product-token", null);
        }

        this.setRequesterPaysEnabled(
            this.jets3tProperties.getBoolProperty("httpclient.requester-pays-buckets-enabled", false));
    }

    /**
     * Set the User Token value to use for requests to a DevPay S3 account.
     * The user token is not required for DevPay web products for which the
     * user token was created after 15th May 2008.
     *
     * @param userToken
     * the user token value provided by the AWS DevPay activation service.
     */
    public void setDevPayUserToken(String userToken) {
        this.awsDevPayUserToken = userToken;
    }

    /**
     * @return
     * the user token value to use in requests to a DevPay S3 account, or null
     * if no such token value has been set.
     */
    public String getDevPayUserToken() {
        return this.awsDevPayUserToken;
    }

    /**
     * Set the Product Token value to use for requests to a DevPay S3 account.
     *
     * @param productToken
     * the token that identifies your DevPay product.
     */
    public void setDevPayProductToken(String productToken) {
        this.awsDevPayProductToken = productToken;
    }

    /**
     * @return
     * the product token value to use in requests to a DevPay S3 account, or
     * null if no such token value has been set.
     */
    public String getDevPayProductToken() {
        return this.awsDevPayProductToken;
    }

    /**
     * Instruct the service whether to generate Requester Pays requests when
     * uploading data to S3, or retrieving data from the service. The default
     * value for the Requester Pays Enabled setting is set according to the
     * jets3t.properties setting
     * <code>httpclient.requester-pays-buckets-enabled</code>.
     *
     * @param isRequesterPays
     * if true, all subsequent S3 service requests will include the Requester
     * Pays flag.
     */
    public void setRequesterPaysEnabled(boolean isRequesterPays) {
        this.isRequesterPaysEnabled = isRequesterPays;
    }

    /**
     * Is this service configured to generate Requester Pays requests when
     * uploading data to S3, or retrieving data from the service. The default
     * value for the Requester Pays Enabled setting is set according to the
     * jets3t.properties setting
     * <code>httpclient.requester-pays-buckets-enabled</code>.
     *
     * @return
     * true if S3 service requests will include the Requester Pays flag, false
     * otherwise.
     */
    public boolean isRequesterPaysEnabled() {
        return this.isRequesterPaysEnabled;
    }

    /**
     * Creates an {@link org.apache.commons.httpclient.HttpMethod} object to handle a particular connection method.
     *
     * @param method
     *        the HTTP method/connection-type to use, must be one of: PUT, HEAD, GET, DELETE
     * @param bucketName
     *        the bucket's name
     * @param objectKey
     *        the object's key name, may be null if the operation is on a bucket only.
     * @return
     *        the HTTP method object used to perform the request
     *
     * @throws org.jets3t.service.S3ServiceException
     */
    @Override
    protected HttpMethodBase setupConnection(String method, String bucketName, String objectKey,
        Map requestParameters) throws S3ServiceException
    {
        HttpMethodBase httpMethod = super.setupConnection(method, bucketName, objectKey, requestParameters);

        // Set DevPay request headers.
        if (getDevPayUserToken() != null || getDevPayProductToken() != null) {
            // DevPay tokens have been provided, include these with the request.
            if (getDevPayProductToken() != null) {
                String securityToken = getDevPayUserToken() + "," + getDevPayProductToken();
                httpMethod.setRequestHeader(Constants.AMZ_SECURITY_TOKEN, securityToken);
                if (log.isDebugEnabled()) {
                    log.debug("Including DevPay user and product tokens in request: "
                        + Constants.AMZ_SECURITY_TOKEN + "=" + securityToken);
                }
            } else {
                httpMethod.setRequestHeader(Constants.AMZ_SECURITY_TOKEN, getDevPayUserToken());
                if (log.isDebugEnabled()) {
                    log.debug("Including DevPay user token in request: "
                        + Constants.AMZ_SECURITY_TOKEN + "=" + getDevPayUserToken());
                }
            }
        }

        // Set Requester Pays header to allow access to these buckets.
        if (this.isRequesterPaysEnabled()) {
            String[] requesterPaysHeaderAndValue = Constants.REQUESTER_PAYS_BUCKET_FLAG.split("=");
            httpMethod.setRequestHeader(requesterPaysHeaderAndValue[0], requesterPaysHeaderAndValue[1]);
            if (log.isDebugEnabled()) {
                log.debug("Including Requester Pays header in request: " +
                    Constants.REQUESTER_PAYS_BUCKET_FLAG);
            }
        }

        return httpMethod;
    }

    /**
     * @return
     * the endpoint to be used to connect to S3.
     */
    @Override
    protected String getEndpoint() {
    	return this.jets3tProperties.getStringProperty(
                "s3service.s3-endpoint", Constants.S3_DEFAULT_HOSTNAME);
    }

    /**
     * @return
     * the virtual path inside the S3 server.
     */
    @Override
    protected String getVirtualPath() {
    	return this.jets3tProperties.getStringProperty(
                "s3service.s3-endpoint-virtual-path", "");
    }

    /**
     * @return
     * the identifier for the signature algorithm.
     */
    @Override
    protected String getSignatureIdentifier() {
    	return AWS_SIGNATURE_IDENTIFIER;
    }

    /**
     * @return
     * header prefix for general Amazon headers: x-amz-.
     */
    @Override
    protected String getRestHeaderPrefix() {
    	return AWS_REST_HEADER_PREFIX;
    }

    /**
     * @return
     * header prefix for Amazon metadata headers: x-amz-meta-.
     */
    @Override
    protected String getRestMetadataPrefix() {
    	return AWS_REST_METADATA_PREFIX;
    }

    /**
     * @return
     * the port number to be used for insecure connections over HTTP.
     */
    @Override
    protected int getHttpPort() {
      return this.jets3tProperties.getIntProperty("s3service.s3-endpoint-http-port", 80);
    }

    /**
     * @return
     * the port number to be used for secure connections over HTTPS.
     */
    @Override
    protected int getHttpsPort() {
      return this.jets3tProperties.getIntProperty("s3service.s3-endpoint-https-port", 443);
    }

    /**
     * @return
     * If true, all communication with S3 will be via encrypted HTTPS connections,
     * otherwise communications will be sent unencrypted via HTTP.
     */
    @Override
    protected boolean getHttpsOnly() {
      return this.jets3tProperties.getBoolProperty("s3service.https-only", true);
    }

    /**
     * @return
     * If true, JetS3t will specify bucket names in the request path of the HTTP message
     * instead of the Host header.
     */
    @Override
    protected boolean getDisableDnsBuckets() {
      return this.jets3tProperties.getBoolProperty("s3service.disable-dns-buckets", false);
    }

}

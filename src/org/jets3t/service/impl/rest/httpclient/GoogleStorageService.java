/*
 * JetS3t : Java S3 Toolkit
 * Project hosted at http://bitbucket.org/jmurty/jets3t/
 *
 * Copyright 2010-2011 James Murty
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

import java.util.Arrays;
import java.util.Calendar;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.protocol.HttpContext;
import org.jets3t.service.Constants;
import org.jets3t.service.Jets3tProperties;
import org.jets3t.service.ServiceException;
import org.jets3t.service.acl.gs.GSAccessControlList;
import org.jets3t.service.impl.rest.XmlResponsesSaxParser;
import org.jets3t.service.model.GSBucket;
import org.jets3t.service.model.GSObject;
import org.jets3t.service.model.StorageBucket;
import org.jets3t.service.model.StorageObject;
import org.jets3t.service.security.OAuth2Credentials;
import org.jets3t.service.security.OAuth2Tokens;
import org.jets3t.service.security.ProviderCredentials;
import org.jets3t.service.utils.oauth.OAuthUtils;

/**
 * REST/HTTP implementation of Google Storage Service based on the
 * <a href="http://jakarta.apache.org/commons/httpclient/">HttpClient</a> library.
 * <p>
 * This class uses properties obtained through {@link org.jets3t.service.Jets3tProperties}. For more information on
 * these properties please refer to
 * <a href="http://www.jets3t.org/toolkit/configuration.html">JetS3t Configuration</a>
 * </p>
 *
 * @author Google Developers
 */
public class GoogleStorageService extends RestStorageService {
    private static final Log log = LogFactory.getLog(GoogleStorageService.class);

    private static final String GOOGLE_SIGNATURE_IDENTIFIER = "GOOG1";
    private static final String GOOGLE_REST_HEADER_PREFIX = "x-goog-";
    private static final String GOOGLE_REST_METADATA_PREFIX = "x-goog-meta-";

    protected OAuth2Tokens oauth2Tokens = null;
    protected OAuthUtils oauthUtils = null;


    /**
     * Constructs the service and initialises the properties.
     *
     * @param credentials
     * the user credentials to use when communicating with Google Storage, may be null in which case the
     * communication is done as an anonymous user.
     *
     * @throws ServiceException
     */
    public GoogleStorageService(ProviderCredentials credentials) throws ServiceException {
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
     * @throws ServiceException
     */
    public GoogleStorageService(ProviderCredentials credentials, String invokingApplicationDescription,
        CredentialsProvider credentialsProvider) throws ServiceException
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
     * @throws ServiceException
     */
    public GoogleStorageService(ProviderCredentials credentials, String invokingApplicationDescription,
        CredentialsProvider credentialsProvider, Jets3tProperties jets3tProperties) throws ServiceException
    {
        super(credentials, invokingApplicationDescription, credentialsProvider, jets3tProperties);

        // If service initialized with OAuth2 credentials, init utility class for handling OAuth
        if (credentials instanceof OAuth2Credentials) {
            OAuth2Credentials oauth2Credentials = (OAuth2Credentials) credentials;
            this.oauthUtils = new OAuthUtils(
                OAuthUtils.OAuthImplementation.GOOGLE_STORAGE_OAUTH2_10,
                oauth2Credentials.getClientId(),
                oauth2Credentials.getClientSecret());
        }
    }

    @Override
    protected boolean isTargettingGoogleStorageService() {
        return true;
    }

    /**
     * @return
     * the endpoint to be used to connect to Google Storage.
     */
    @Override
    public String getEndpoint() {
        return this.jets3tProperties.getStringProperty(
                "gsservice.gs-endpoint", Constants.GS_DEFAULT_HOSTNAME);
    }

    /**
     * @return
     * the virtual path inside the service.
     */
    @Override
    protected String getVirtualPath() {
        return this.jets3tProperties.getStringProperty(
                "gsservice.gs-endpoint-virtual-path", "");
    }

    /**
     * @return
     * the identifier for the signature algorithm.
     */
    @Override
    protected String getSignatureIdentifier() {
        return GOOGLE_SIGNATURE_IDENTIFIER;
    }

    /**
     * @return
     * header prefix for general Google Storage headers: x-goog-.
     */
    @Override
    public String getRestHeaderPrefix() {
        return GOOGLE_REST_HEADER_PREFIX;
    }

    /**
     * @return
     * header prefix for Google Storage metadata headers: x-goog-meta-.
     */
    @Override
    public String getRestMetadataPrefix() {
        return GOOGLE_REST_METADATA_PREFIX;
    }

    @Override
    public List<String> getResourceParameterNames() {
        // Special HTTP parameter names that refer to resources in Google Storage
        return Arrays.asList(new String[] {
            "acl"
        });
    }

    /**
     * @return
     * the port number to be used for insecure connections over HTTP.
     */
    @Override
    protected int getHttpPort() {
      return this.jets3tProperties.getIntProperty("gsservice.gs-endpoint-http-port", 80);
    }

    /**
     * @return
     * the port number to be used for secure connections over HTTPS.
     */
    @Override
    protected int getHttpsPort() {
      return this.jets3tProperties.getIntProperty("gsservice.gs-endpoint-https-port", 443);
    }

    /**
     * @return
     * If true, all communication with GS will be via encrypted HTTPS connections,
     * otherwise communications will be sent unencrypted via HTTP
     */
    @Override
    protected boolean getHttpsOnly() {
      return this.jets3tProperties.getBoolProperty("gsservice.https-only", true);
    }

    /**
     * @return
     * If true, JetS3t will specify bucket names in the request path of the HTTP message
     * instead of the Host header.
     */
    @Override
    protected boolean getDisableDnsBuckets() {
      return this.jets3tProperties.getBoolProperty("gsservice.disable-dns-buckets", false);
    }

    /**
     * @return
     * False, since Google Storage does not support storage classes.
     */
    @Override
    protected boolean getEnableStorageClasses() {
      return false;
    }

    /**
     * @return
     * False, since Google Storage does not support server-side encryption.
     */
    @Override
    protected boolean getEnableServerSideEncryption() {
        return false;
    }


    @Override
    protected XmlResponsesSaxParser getXmlResponseSaxParser() throws ServiceException {
        return new XmlResponsesSaxParser(this.jets3tProperties, true);
    }

    @Override
    protected StorageBucket newBucket() {
        return new GSBucket();
    }

    @Override
    protected StorageObject newObject() {
        return new GSObject();
    }

    ////////////////////////////////////////////////////////////
    // Methods below this point perform actions in GoogleStorage
    ////////////////////////////////////////////////////////////

    @Override
    public GSBucket[] listAllBuckets() throws ServiceException {
        return GSBucket.cast(super.listAllBuckets());
    }

    @Override
    public GSObject[] listObjects(String bucketName) throws ServiceException {
        return GSObject.cast(super.listObjects(bucketName));
    }

    @Override
    public GSObject[] listObjects(String bucketName, String prefix, String delimiter)
        throws ServiceException
    {
        return GSObject.cast(super.listObjects(bucketName, prefix, delimiter));
    }


    @Override
    public GSBucket createBucket(String bucketName) throws ServiceException {
        return (GSBucket) super.createBucket(bucketName);
    }

    @Override
    public GSAccessControlList getBucketAcl(String bucketName) throws ServiceException {
        return (GSAccessControlList) super.getBucketAcl(bucketName);
    }

    /**
     * Applies access control settings to a bucket. The ACL settings must be included
     * inside the bucket.
     *
     * This method can be performed by anonymous services, but can only succeed if the
     * bucket's existing ACL already allows write access by the anonymous user.
     *
     * @param bucketName
     * a name of the bucket with ACL settings to apply.
     * @throws ServiceException
     */
    public void putBucketAcl(String bucketName, GSAccessControlList acl) throws ServiceException {
        if (acl == null) {
            throw new ServiceException("The bucket '" + bucketName +
                "' does not include ACL information");
        }
        putBucketAclImpl(bucketName, acl);
    }

    /**
     * Applies access control settings to a bucket. The ACL settings must be included
     * inside the bucket.
     *
     * This method can be performed by anonymous services, but can only succeed if the
     * bucket's existing ACL already allows write access by the anonymous user.
     *
     * @param bucket
     * a bucket with ACL settings to apply.
     * @throws ServiceException
     */
    public void putBucketAcl(GSBucket bucket) throws ServiceException {
        assertValidBucket(bucket, "Put Bucket Access Control List");
        putBucketAcl(bucket.getName(), bucket.getAcl());
    }

    @Override
    public GSObject getObject(String bucketName, String objectKey) throws ServiceException {
        return (GSObject) super.getObject(bucketName, objectKey);
    }

    public GSObject putObject(String bucketName, GSObject object)
        throws ServiceException
    {
        return (GSObject) super.putObject(bucketName, object);
    }

    @Override
    public GSObject getObject(String bucketName, String objectKey,
        Calendar ifModifiedSince, Calendar ifUnmodifiedSince,
        String[] ifMatchTags, String[] ifNoneMatchTags, Long byteRangeStart,
        Long byteRangeEnd) throws ServiceException
    {
        return (GSObject) super.getObject(bucketName, objectKey, ifModifiedSince,
            ifUnmodifiedSince, ifMatchTags, ifNoneMatchTags, byteRangeStart,
            byteRangeEnd);
    }

    @Override
    public GSObject getObjectDetails(String bucketName, String objectKey)
        throws ServiceException
    {
        return (GSObject) super.getObjectDetails(bucketName, objectKey);
    }

    /**
     * Authorizes an HTTP/S request using the standard HMAC approach or OAuth 2,
     * whichever technique is appropriate.
     *
     * @param httpMethod
     * the request object
     * @throws ServiceException
     */
    @Override
    public void authorizeHttpRequest(HttpUriRequest httpMethod, HttpContext context)
        throws Exception
    {
        if (this.credentials instanceof OAuth2Credentials) {
            if (getOAuth2Tokens() == null) {
                throw new ServiceException(
                    "Cannot authenticate using OAuth2 until initial tokens are provided"
                    + ", i.e. via setOAuth2Tokens()");
            }
            this.authorizeHttpRequestWithOAuth2Tokens(httpMethod, context);
        } else {
            super.authorizeHttpRequest(httpMethod, context);
        }
    }

    public void setOAuth2Tokens(OAuth2Tokens tokens) {
        if (!(this.credentials instanceof OAuth2Credentials)) {
            throw new IllegalStateException(
                "Cannot use OAuth2 tokens with service that does not have OAuth2Credentials");
        }
        this.oauth2Tokens = tokens;
    }

    public OAuth2Tokens getOAuth2Tokens() {
        return this.oauth2Tokens;
    }

    public void authorizeHttpRequestWithOAuth2Tokens(
        HttpUriRequest httpMethod, HttpContext context) throws Exception
    {
        OAuth2Tokens tokens = getOAuth2Tokens();
        if (tokens.isAccessTokenExpired()) {
            this.refreshOAuth2Tokens();
            tokens = getOAuth2Tokens(); // Get updated tokens object
        }

        log.debug("Authorizing service request with OAuth2 access token: "
            + tokens.getAccessToken());
        httpMethod.setHeader("Authorization", "OAuth " + tokens.getAccessToken());
    }

    @Override
    protected boolean isRecoverable403(HttpUriRequest httpRequest, Exception exception) {
        // Only retry if we're using OAuth2 authentication and can refresh the access token
        // TODO Any way to distinguish between expired access token and other 403 reasons?
        OAuth2Tokens tokens = getOAuth2Tokens();
        if (tokens != null) {
            tokens.expireAccessToken();
            return true;
        }
        return super.isRecoverable403(httpRequest, exception);
    }

    protected void refreshOAuth2Tokens() throws Exception {
        OAuth2Tokens oldTokens = getOAuth2Tokens();
        log.debug("Refreshing OAuth2 access token using refresh token: "
            + oldTokens.getRefreshToken());

        OAuth2Tokens newTokens = this.oauthUtils.refreshOAuth2AccessToken(oldTokens);
        setOAuth2Tokens(newTokens);
        log.debug("Refreshed OAuth2 access token to " + newTokens.getAccessToken()
            + " with expiry at " + newTokens.getExpiry());
    }

}

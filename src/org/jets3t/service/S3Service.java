/*
 * JetS3t : Java S3 Toolkit
 * Project hosted at http://bitbucket.org/jmurty/jets3t/
 *
 * Copyright 2008-2010 James Murty, 2008 Zmanda Inc
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
package org.jets3t.service;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.httpclient.HostConfiguration;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.NTCredentials;
import org.apache.commons.httpclient.ProxyHost;
import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.httpclient.auth.AuthScope;
import org.apache.commons.httpclient.contrib.proxy.PluginProxyUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jets3t.service.acl.AccessControlList;
import org.jets3t.service.acl.GrantAndPermission;
import org.jets3t.service.acl.GroupGrantee;
import org.jets3t.service.acl.Permission;
import org.jets3t.service.impl.rest.httpclient.RestS3Service;
import org.jets3t.service.model.BaseVersionOrDeleteMarker;
import org.jets3t.service.model.S3Bucket;
import org.jets3t.service.model.S3BucketLoggingStatus;
import org.jets3t.service.model.S3BucketVersioningStatus;
import org.jets3t.service.model.S3DeleteMarker;
import org.jets3t.service.model.S3Object;
import org.jets3t.service.model.S3Owner;
import org.jets3t.service.model.S3Version;
import org.jets3t.service.mx.MxDelegate;
import org.jets3t.service.security.AWSDevPayCredentials;
import org.jets3t.service.security.ProviderCredentials;
import org.jets3t.service.utils.RestUtils;
import org.jets3t.service.utils.ServiceUtils;

/**
 * A service that handles communication with S3, offering all the operations that can be performed
 * on S3 accounts.
 * <p>
 * This class must be extended by implementation classes that perform the communication with S3 via
 * a particular interface, such as REST or SOAP. The JetS3t suite includes a REST implementation
 * in {@link org.jets3t.service.impl.rest.httpclient.RestS3Service}.
 * </p>
 * <p>
 * Implementations of <code>S3Service</code> must be thread-safe as they will probably be used by
 * the multi-threaded service class {@link org.jets3t.service.multithread.S3ServiceMulti}.
 * </p>
 * <p>
 * This class uses properties obtained through {@link Jets3tProperties}. For more information on
 * these properties please refer to
 * <a href="http://jets3t.s3.amazonaws.com/toolkit/configuration.html">JetS3t Configuration</a>
 * </p>
 *
 * @author James Murty
 * @author Nikolas Coukouma
 */
public abstract class S3Service implements Serializable {

    private static final long serialVersionUID = -4501528341689760431L;

    private static final Log log = LogFactory.getLog(S3Service.class);

    /**
     * The JetS3t suite version number implemented by this service.
     */
    public static final String VERSION_NO__JETS3T_TOOLKIT = "0.7.4-dev";

    public static final int BUCKET_STATUS__MY_BUCKET = 0;
    public static final int BUCKET_STATUS__DOES_NOT_EXIST = 1;
    public static final int BUCKET_STATUS__ALREADY_CLAIMED = 2;

    protected Jets3tProperties jets3tProperties = null;

    private ProviderCredentials credentials = null;

    private String invokingApplicationDescription = null;
    private boolean isHttpsOnly = true;
    private int internalErrorRetryMax = 5;

    private boolean isShutdown = false;

    /**
     * The approximate difference in the current time between your computer and
     * Amazon's S3 server, measured in milliseconds.
     *
     * This value is 0 by default. Use the {@link #getCurrentTimeWithOffset()}
     * to obtain the current time with this offset factor included, and the
     * {@link RestUtils#getAWSTimeAdjustment()} method to calculate an offset value for your
     * computer based on a response from an AWS server.
     */
    protected long timeOffset = 0;

    /**
     * Construct an <code>S3Service</code> identified by the given user credentials.
     *
     * @param credentials
     * the S3 user credentials to use when communicating with S3, may be null in which case the
     * communication is done as an anonymous user.
     * @param invokingApplicationDescription
     * a short description of the application using the service, suitable for inclusion in a
     * user agent string for REST/HTTP requests. Ideally this would include the application's
     * version number, for example: <code>Cockpit/0.7.3</code> or <code>My App Name/1.0</code>
     * @param jets3tProperties
     * JetS3t properties that will be applied within this service.
     * @throws S3ServiceException
     */
    protected S3Service(ProviderCredentials credentials, String invokingApplicationDescription,
        Jets3tProperties jets3tProperties) throws S3ServiceException
    {
        this.credentials = credentials;
        this.invokingApplicationDescription = invokingApplicationDescription;

        this.jets3tProperties = jets3tProperties;
        this.isHttpsOnly = this.getHttpsOnly();
        this.internalErrorRetryMax = jets3tProperties.getIntProperty("s3service.internal-error-retry-max", 5);

        // Configure the InetAddress DNS caching times to work well with S3. The cached DNS will
        // timeout after 5 minutes, while failed DNS lookups will be retried after 1 second.
        System.setProperty("networkaddress.cache.ttl", "300");
        System.setProperty("networkaddress.cache.negative.ttl", "1");

        // (Re)initialize the JetS3t JMX delegate, in case system properties have changed.
        MxDelegate.getInstance().init();

        MxDelegate.getInstance().registerS3ServiceMBean();
        MxDelegate.getInstance().registerS3ServiceExceptionMBean();
    }

    /**
     * Construct an <code>S3Service</code> identified by the given user credentials.
     *
     * @param credentials
     * the S3 user credentials to use when communicating with S3, may be null in which case the
     * communication is done as an anonymous user.
     * @param invokingApplicationDescription
     * a short description of the application using the service, suitable for inclusion in a
     * user agent string for REST/HTTP requests. Ideally this would include the application's
     * version number, for example: <code>Cockpit/0.7.3</code> or <code>My App Name/1.0</code>
     * @throws S3ServiceException
     */
    protected S3Service(ProviderCredentials credentials, String invokingApplicationDescription)
        throws S3ServiceException
    {
        this(credentials, invokingApplicationDescription,
            Jets3tProperties.getInstance(Constants.JETS3T_PROPERTIES_FILENAME));
    }

    /**
     * Construct an <code>S3Service</code> identified by the given user credentials.
     *
     * @param credentials
     * the S3 user credentials to use when communicating with S3, may be null in which case the
     * communication is done as an anonymous user.
     * @throws S3ServiceException
     */
    protected S3Service(ProviderCredentials credentials) throws S3ServiceException {
        this(credentials, null);
    }

    /**
     * Make a best-possible effort to shutdown and clean up any resources used by this
     * service such as HTTP connections, connection pools, threads etc, although there is
     * no guarantee that all such resources will indeed be fully cleaned up.
     *
     * After calling this method the service instance will no longer be usable -- a new
     * instance must be created to do more work.
     */
    public void shutdown() throws S3ServiceException {
        this.isShutdown = true;
        this.shutdownImpl();
    }

    /**
     * @return true if the {@link #shutdown()} method has been used to shut down and
     * clean up this service. If this function returns true this service instance
     * can no longer be used to do work.
     */
    public boolean isShutdown() {
        return this.isShutdown;
    }

    /**
     * @return
     * true if this service has <code>ProviderCredentials</code> identifying an S3 user, false
     * if the service is acting as an anonymous user.
     */
    public boolean isAuthenticatedConnection() {
        return credentials != null;
    }

    /**
     * Whether to use secure HTTPS or insecure HTTP for communicating with S3, as set by the
     * JetS3t property: s3service.https-only
     *
     * @return
     * true if this service should use only secure HTTPS communication channels to S3.
     * If false, the non-secure HTTP protocol will be used.
     */
    public boolean isHttpsOnly() {
        return isHttpsOnly;
    }

    /**
     * @return
     * The maximum number of times to retry when S3 Internal Error (500) errors are encountered,
     * as set by the JetS3t property: s3service.internal-error-retry-max
     */
    public int getInternalErrorRetryMax() {
        return internalErrorRetryMax;
    }

    /**
     * @return
     * the JetS3t properties that will be used by this service.
     */
    public Jets3tProperties getJetS3tProperties() {
        return jets3tProperties;
    }

    /**
     * Sleeps for a period of time based on the number of S3 Internal Server errors a request has
     * encountered, provided the number of errors does not exceed the value set with the
     * property <code>s3service.internal-error-retry-max</code>. If the maximum error count is
     * exceeded, this method will throw an S3ServiceException.
     *
     * The millisecond delay grows rapidly according to the formula
     * <code>50 * (<i>internalErrorCount</i> ^ 2)</code>.
     *
     * <table>
     * <tr><th>Error count</th><th>Delay in milliseconds</th></tr>
     * <tr><td>1</td><td>50</td></tr>
     * <tr><td>2</td><td>200</td></tr>
     * <tr><td>3</td><td>450</td></tr>
     * <tr><td>4</td><td>800</td></tr>
     * <tr><td>5</td><td>1250</td></tr>
     * </table>
     *
     * @param internalErrorCount
     * the number of S3 Internal Server errors encountered by a request.
     *
     * @throws S3ServiceException
     * thrown if the number of internal errors exceeds the value of internalErrorCount.
     * @throws InterruptedException
     * thrown if the thread sleep is interrupted.
     */
    protected void sleepOnInternalError(int internalErrorCount)
        throws S3ServiceException, InterruptedException
    {
        if (internalErrorCount <= internalErrorRetryMax) {
            long delayMs = 50L * (int) Math.pow(internalErrorCount, 2);
            if (log.isWarnEnabled()) {
    	        log.warn("Encountered " + internalErrorCount
    	            + " S3 Internal Server error(s), will retry in " + delayMs + "ms");
            }
            Thread.sleep(delayMs);
        } else {
            throw new S3ServiceException("Encountered too many S3 Internal Server errors ("
                + internalErrorCount + "), aborting request.");
        }
    }

    /**
     * @return the AWS Credentials identifying the S3 user, may be null if the service is acting
     * anonymously.
     */
    public ProviderCredentials getAWSCredentials() {
        return credentials;
    }

    /**
     * @return a description of the application using this service, suitable for inclusion in the
     * user agent string of REST/HTTP requests.
     */
    public String getInvokingApplicationDescription() {
        return invokingApplicationDescription;
    }

    /**
     * Returns the URL representing an object in S3 without a signature. This URL
     * can only be used to download publicly-accessible objects.
     *
     * @param bucketName
     * the name of the bucket that contains the object.
     * @param objectKey
     * the key name of the object.
     * @param isVirtualHost
     * if this parameter is true, the bucket name is treated as a virtual host name. To use
     * this option, the bucket name must be a valid DNS name that is an alias to an S3 bucket.
     * @param isHttps
     * if true, the signed URL will use the HTTPS protocol. If false, the signed URL will
     * use the HTTP protocol.
     * @param isDnsBucketNamingDisabled
     * if true, the signed URL will not use the DNS-name format for buckets eg.
     * <tt>jets3t.s3.amazonaws.com</tt>. Unless you have a specific reason to disable
     * DNS bucket naming, leave this value false.
     *
     * @return
     * the object's URL.
     * 
     * @throws S3ServiceException
     */
    public String createUnsignedObjectUrl(String bucketName, String objectKey,
        boolean isVirtualHost, boolean isHttps, boolean isDnsBucketNamingDisabled)
        throws S3ServiceException
    {
        // Create a signed GET URL then strip away the signature query components.
        String signedGETUrl = createSignedUrl("GET", bucketName, objectKey,
            null, null, 0, isVirtualHost, isHttps, isDnsBucketNamingDisabled);
        return signedGETUrl.split("\\?")[0];
    }

    /**
     * Generates a signed URL string that will grant access to an S3 resource (bucket or object)
     * to whoever uses the URL up until the time specified.
     *
     * @param method
     * the HTTP method to sign, such as GET or PUT (note that S3 does not support POST requests).
     * @param bucketName
     * the name of the bucket to include in the URL, must be a valid bucket name.
     * @param objectKey
     * the name of the object to include in the URL, if null only the bucket name is used.
     * @param specialParamName
     * the name of a request parameter to add to the URL generated by this method. 'Special'
     * parameters may include parameters that specify the kind of S3 resource that the URL
     * will refer to, such as 'acl', 'torrent', 'logging', or 'location'.
     * @param headersMap
     * headers to add to the signed URL, may be null.
     * Headers that <b>must</b> match between the signed URL and the actual request include:
     * content-md5, content-type, and any header starting with 'x-amz-'.
     * @param secondsSinceEpoch
     * the time after which URL's signature will no longer be valid. This time cannot be null.
     *  <b>Note:</b> This time is specified in seconds since the epoch, not milliseconds.
     * @param isVirtualHost
     * if this parameter is true, the bucket name is treated as a virtual host name. To use
     * this option, the bucket name must be a valid DNS name that is an alias to an S3 bucket.
     * @param isHttps
     * if true, the signed URL will use the HTTPS protocol. If false, the signed URL will
     * use the HTTP protocol.
     * @param isDnsBucketNamingDisabled
     * if true, the signed URL will not use the DNS-name format for buckets eg.
     * <tt>jets3t.s3.amazonaws.com</tt>. Unless you have a specific reason to disable
     * DNS bucket naming, leave this value false.
     *
     * @return
     * a URL signed in such a way as to grant access to an S3 resource to whoever uses it.
     *
     * @throws S3ServiceException
     */
    public String createSignedUrl(String method, String bucketName, String objectKey,
        String specialParamName, Map headersMap, long secondsSinceEpoch,
        boolean isVirtualHost, boolean isHttps, boolean isDnsBucketNamingDisabled)
        throws S3ServiceException
    {
        String s3Endpoint = this.getEndpoint();
        System.out.println(s3Endpoint);
        String uriPath = "";

        String hostname = (isVirtualHost
            ? bucketName
            : ServiceUtils.generateS3HostnameForBucket(
                bucketName, isDnsBucketNamingDisabled, s3Endpoint));

        if (headersMap == null) {
            headersMap = new HashMap();
        }

        // If we are using an alternative hostname, include the hostname/bucketname in the resource path.
        String virtualBucketPath = "";
        if (!s3Endpoint.equals(hostname)) {
            int subdomainOffset = hostname.lastIndexOf("." + s3Endpoint);
            if (subdomainOffset > 0) {
                // Hostname represents an S3 sub-domain, so the bucket's name is the CNAME portion
                virtualBucketPath = hostname.substring(0, subdomainOffset) + "/";
            } else {
                // Hostname represents a virtual host, so the bucket's name is identical to hostname
                virtualBucketPath = hostname + "/";
            }
            uriPath = (objectKey != null ? RestUtils.encodeUrlPath(objectKey, "/") : "");
        } else {
            uriPath = bucketName + (objectKey != null ? "/" + RestUtils.encodeUrlPath(objectKey, "/") : "");
        }

        if (specialParamName != null) {
            uriPath += "?" + specialParamName + "&";
        } else {
            uriPath += "?";
        }

        // Include any DevPay tokens in signed request
        if (credentials instanceof AWSDevPayCredentials) {
            AWSDevPayCredentials devPayCredentials = (AWSDevPayCredentials) credentials;
            if (devPayCredentials.getProductToken() != null) {
                String securityToken = devPayCredentials.getUserToken()
                    + "," + devPayCredentials.getProductToken();
                headersMap.put(Constants.AMZ_SECURITY_TOKEN, securityToken);
            } else {
                headersMap.put(Constants.AMZ_SECURITY_TOKEN, devPayCredentials.getUserToken());
            }

            uriPath += Constants.AMZ_SECURITY_TOKEN + "=" +
                RestUtils.encodeUrlString((String) headersMap.get(Constants.AMZ_SECURITY_TOKEN)) + "&";
        }

        uriPath += "AWSAccessKeyId=" + credentials.getAccessKey();
        uriPath += "&Expires=" + secondsSinceEpoch;

        // Include Requester Pays header flag, if the flag is included as a request parameter.
        if (specialParamName != null
            && specialParamName.toLowerCase().indexOf(Constants.REQUESTER_PAYS_BUCKET_FLAG) >= 0)
        {
            String[] requesterPaysHeaderAndValue = Constants.REQUESTER_PAYS_BUCKET_FLAG.split("=");
            headersMap.put(requesterPaysHeaderAndValue[0], requesterPaysHeaderAndValue[1]);
        }

        String serviceEndpointVirtualPath = this.getVirtualPath();

        String canonicalString = RestUtils.makeS3CanonicalString(method,
            serviceEndpointVirtualPath + "/" + virtualBucketPath + uriPath,
            renameMetadataKeys(headersMap), String.valueOf(secondsSinceEpoch), this.getRestHeaderPrefix());
        if (log.isDebugEnabled()) {
            log.debug("Signing canonical string:\n" + canonicalString);
        }

        String signedCanonical = ServiceUtils.signWithHmacSha1(credentials.getSecretKey(),
            canonicalString);
        String encodedCanonical = RestUtils.encodeUrlString(signedCanonical);
        uriPath += "&Signature=" + encodedCanonical;

        if (isHttps) {
            int httpsPort = this.getHttpsPort();
            return "https://" + hostname
                + (httpsPort != 443 ? ":" + httpsPort : "")
                + serviceEndpointVirtualPath
                + "/" + uriPath;
        } else {
            int httpPort = this.getHttpPort();
            return "http://" + hostname
            + (httpPort != 80 ? ":" + httpPort : "")
            + serviceEndpointVirtualPath
            + "/" + uriPath;
        }
    }

    /**
     * Generates a signed URL string that will grant access to an S3 resource (bucket or object)
     * to whoever uses the URL up until the time specified. The URL will use the default
     * JetS3t property settings in the <tt>jets3t.properties</tt> file to determine whether
     * to generate HTTP or HTTPS links (<tt>s3service.https-only</tt>), and whether to disable
     * DNS bucket naming (<tt>s3service.disable-dns-buckets</tt>).
     *
     * @param method
     * the HTTP method to sign, such as GET or PUT (note that S3 does not support POST requests).
     * @param bucketName
     * the name of the bucket to include in the URL, must be a valid bucket name.
     * @param objectKey
     * the name of the object to include in the URL, if null only the bucket name is used.
     * @param specialParamName
     * the name of a request parameter to add to the URL generated by this method. 'Special'
     * parameters may include parameters that specify the kind of S3 resource that the URL
     * will refer to, such as 'acl', 'torrent', 'logging' or 'location'.
     * @param headersMap
     * headers to add to the signed URL, may be null.
     * Headers that <b>must</b> match between the signed URL and the actual request include:
     * content-md5, content-type, and any header starting with 'x-amz-'.
     * @param secondsSinceEpoch
     * the time after which URL's signature will no longer be valid. This time cannot be null.
     *  <b>Note:</b> This time is specified in seconds since the epoch, not milliseconds.
     * @param isVirtualHost
     * if this parameter is true, the bucket name is treated as a virtual host name. To use
     * this option, the bucket name must be a valid DNS name that is an alias to an S3 bucket.
     *
     * @return
     * a URL signed in such a way as to grant access to an S3 resource to whoever uses it.
     *
     * @throws S3ServiceException
     */
    public String createSignedUrl(String method, String bucketName, String objectKey,
        String specialParamName, Map headersMap, long secondsSinceEpoch, boolean isVirtualHost)
        throws S3ServiceException
    {
        boolean isHttps = this.isHttpsOnly();
        boolean disableDnsBuckets = this.getDisableDnsBuckets();

        return createSignedUrl(method, bucketName, objectKey, specialParamName,
            headersMap, secondsSinceEpoch, isVirtualHost, isHttps, disableDnsBuckets);
    }

    /**
     * Generates a signed URL string that will grant access to an S3 resource (bucket or object)
     * to whoever uses the URL up until the time specified.
     *
     * @param method
     * the HTTP method to sign, such as GET or PUT (note that S3 does not support POST requests).
     * @param bucketName
     * the name of the bucket to include in the URL, must be a valid bucket name.
     * @param objectKey
     * the name of the object to include in the URL, if null only the bucket name is used.
     * @param specialParamName
     * the name of a request parameter to add to the URL generated by this method. 'Special'
     * parameters may include parameters that specify the kind of S3 resource that the URL
     * will refer to, such as 'acl', 'torrent', 'logging' or 'location'.
     * @param headersMap
     * headers to add to the signed URL, may be null.
     * Headers that <b>must</b> match between the signed URL and the actual request include:
     * content-md5, content-type, and any header starting with 'x-amz-'.
     * @param secondsSinceEpoch
     * the time after which URL's signature will no longer be valid. This time cannot be null.
     *  <b>Note:</b> This time is specified in seconds since the epoch, not milliseconds.
     *
     * @return
     * a URL signed in such a way as to grant access to an S3 resource to whoever uses it.
     *
     * @throws S3ServiceException
     */
    public String createSignedUrl(String method, String bucketName, String objectKey,
        String specialParamName, Map headersMap, long secondsSinceEpoch)
        throws S3ServiceException
    {
        return createSignedUrl(method, bucketName, objectKey, specialParamName, headersMap,
            secondsSinceEpoch, false);
    }


    /**
     * Generates a signed GET URL.
     *
     * @param bucketName
     * the name of the bucket to include in the URL, must be a valid bucket name.
     * @param objectKey
     * the name of the object to include in the URL, if null only the bucket name is used.
     * @param expiryTime
     * the time after which URL's signature will no longer be valid. This time cannot be null.
     * @param isVirtualHost
     * if this parameter is true, the bucket name is treated as a virtual host name. To use
     * this option, the bucket name must be a valid DNS name that is an alias to an S3 bucket.
     *
     * @return
     * a URL signed in such a way as to grant GET access to an S3 resource to whoever uses it.
     * @throws S3ServiceException
     */
    public String createSignedGetUrl(String bucketName, String objectKey,
        Date expiryTime, boolean isVirtualHost) throws S3ServiceException
    {
        long secondsSinceEpoch = expiryTime.getTime() / 1000;
        return createSignedUrl("GET", bucketName, objectKey, null, null,
            secondsSinceEpoch, isVirtualHost);
    }


    /**
     * Generates a signed GET URL.
     *
     * @param bucketName
     * the name of the bucket to include in the URL, must be a valid bucket name.
     * @param objectKey
     * the name of the object to include in the URL, if null only the bucket name is used.
     * @param expiryTime
     * the time after which URL's signature will no longer be valid. This time cannot be null.
     *
     * @return
     * a URL signed in such a way as to grant GET access to an S3 resource to whoever uses it.
     * @throws S3ServiceException
     */
    public String createSignedGetUrl(String bucketName, String objectKey,
        Date expiryTime) throws S3ServiceException
    {
        return createSignedGetUrl(bucketName, objectKey, expiryTime, false);
    }


    /**
     * Generates a signed PUT URL.
     *
     * @param bucketName
     * the name of the bucket to include in the URL, must be a valid bucket name.
     * @param objectKey
     * the name of the object to include in the URL, if null only the bucket name is used.
     * @param headersMap
     * headers to add to the signed URL, may be null.
     * Headers that <b>must</b> match between the signed URL and the actual request include:
     * content-md5, content-type, and any header starting with 'x-amz-'.
     * @param expiryTime
     * the time after which URL's signature will no longer be valid. This time cannot be null.
     * @param isVirtualHost
     * if this parameter is true, the bucket name is treated as a virtual host name. To use
     * this option, the bucket name must be a valid DNS name that is an alias to an S3 bucket.
     *
     * @return
     * a URL signed in such a way as to allow anyone to PUT an object into S3.
     * @throws S3ServiceException
     */
    public String createSignedPutUrl(String bucketName, String objectKey,
        Map headersMap, Date expiryTime, boolean isVirtualHost) throws S3ServiceException
    {
        long secondsSinceEpoch = expiryTime.getTime() / 1000;
        return createSignedUrl("PUT", bucketName, objectKey, null, headersMap,
            secondsSinceEpoch, isVirtualHost);
    }


    /**
     * Generates a signed PUT URL.
     *
     * @param bucketName
     * the name of the bucket to include in the URL, must be a valid bucket name.
     * @param objectKey
     * the name of the object to include in the URL, if null only the bucket name is used.
     * @param headersMap
     * headers to add to the signed URL, may be null.
     * Headers that <b>must</b> match between the signed URL and the actual request include:
     * content-md5, content-type, and any header starting with 'x-amz-'.
     * @param expiryTime
     * the time after which URL's signature will no longer be valid. This time cannot be null.
     *
     * @return
     * a URL signed in such a way as to allow anyone to PUT an object into S3.
     * @throws S3ServiceException
     */
    public String createSignedPutUrl(String bucketName, String objectKey,
        Map headersMap, Date expiryTime) throws S3ServiceException
    {
        return createSignedPutUrl(bucketName, objectKey, headersMap, expiryTime, false);
    }


    /**
     * Generates a signed DELETE URL.
     *
     * @param bucketName
     * the name of the bucket to include in the URL, must be a valid bucket name.
     * @param objectKey
     * the name of the object to include in the URL, if null only the bucket name is used.
     * @param expiryTime
     * the time after which URL's signature will no longer be valid. This time cannot be null.
     * @param isVirtualHost
     * if this parameter is true, the bucket name is treated as a virtual host name. To use
     * this option, the bucket name must be a valid DNS name that is an alias to an S3 bucket.
     *
     * @return
     * a URL signed in such a way as to allow anyone do DELETE an object in S3.
     * @throws S3ServiceException
     */
    public String createSignedDeleteUrl(String bucketName, String objectKey,
        Date expiryTime, boolean isVirtualHost) throws S3ServiceException
    {
        long secondsSinceEpoch = expiryTime.getTime() / 1000;
        return createSignedUrl("DELETE", bucketName, objectKey, null, null,
            secondsSinceEpoch, isVirtualHost);
    }


    /**
     * Generates a signed DELETE URL.
     *
     * @param bucketName
     * the name of the bucket to include in the URL, must be a valid bucket name.
     * @param objectKey
     * the name of the object to include in the URL, if null only the bucket name is used.
     * @param expiryTime
     * the time after which URL's signature will no longer be valid. This time cannot be null.
     *
     * @return
     * a URL signed in such a way as to allow anyone do DELETE an object in S3.
     * @throws S3ServiceException
     */
    public String createSignedDeleteUrl(String bucketName, String objectKey,
        Date expiryTime) throws S3ServiceException
    {
        return createSignedDeleteUrl(bucketName, objectKey, expiryTime, false);
    }


    /**
     * Generates a signed HEAD URL.
     *
     * @param bucketName
     * the name of the bucket to include in the URL, must be a valid bucket name.
     * @param objectKey
     * the name of the object to include in the URL, if null only the bucket name is used.
     * @param expiryTime
     * the time after which URL's signature will no longer be valid. This time cannot be null.
     * @param isVirtualHost
     * if this parameter is true, the bucket name is treated as a virtual host name. To use
     * this option, the bucket name must be a valid DNS name that is an alias to an S3 bucket.
     *
     * @return
     * a URL signed in such a way as to grant HEAD access to an S3 resource to whoever uses it.
     * @throws S3ServiceException
     */
    public String createSignedHeadUrl(String bucketName, String objectKey,
        Date expiryTime, boolean isVirtualHost) throws S3ServiceException
    {
        long secondsSinceEpoch = expiryTime.getTime() / 1000;
        return createSignedUrl("HEAD", bucketName, objectKey, null, null,
            secondsSinceEpoch, isVirtualHost);
    }


    /**
     * Generates a signed HEAD URL.
     *
     * @param bucketName
     * the name of the bucket to include in the URL, must be a valid bucket name.
     * @param objectKey
     * the name of the object to include in the URL, if null only the bucket name is used.
     * @param expiryTime
     * the time after which URL's signature will no longer be valid. This time cannot be null.
     *
     * @return
     * a URL signed in such a way as to grant HEAD access to an S3 resource to whoever uses it.
     * @throws S3ServiceException
     */
    public String createSignedHeadUrl(String bucketName, String objectKey,
        Date expiryTime) throws S3ServiceException
    {
        return createSignedHeadUrl(bucketName, objectKey, expiryTime, false);
    }

    /**
     * Generates a signed URL string that will grant access to an S3 resource (bucket or object)
     * to whoever uses the URL up until the time specified.
     *
     * @deprecated 0.7.4
     *
     * @param method
     * the HTTP method to sign, such as GET or PUT (note that S3 does not support POST requests).
     * @param bucketName
     * the name of the bucket to include in the URL, must be a valid bucket name.
     * @param objectKey
     * the name of the object to include in the URL, if null only the bucket name is used.
     * @param specialParamName
     * the name of a request parameter to add to the URL generated by this method. 'Special'
     * parameters may include parameters that specify the kind of S3 resource that the URL
     * will refer to, such as 'acl', 'torrent', 'logging', or 'location'.
     * @param headersMap
     * headers to add to the signed URL, may be null.
     * Headers that <b>must</b> match between the signed URL and the actual request include:
     * content-md5, content-type, and any header starting with 'x-amz-'.
     * @param credentials
     * the credentials of someone with sufficient privileges to grant access to the bucket/object
     * @param secondsSinceEpoch
     * the time after which URL's signature will no longer be valid. This time cannot be null.
     *  <b>Note:</b> This time is specified in seconds since the epoch, not milliseconds.
     * @param isVirtualHost
     * if this parameter is true, the bucket name is treated as a virtual host name. To use
     * this option, the bucket name must be a valid DNS name that is an alias to an S3 bucket.
     * @param isHttps
     * if true, the signed URL will use the HTTPS protocol. If false, the signed URL will
     * use the HTTP protocol.
     * @param isDnsBucketNamingDisabled
     * if true, the signed URL will not use the DNS-name format for buckets eg.
     * <tt>jets3t.s3.amazonaws.com</tt>. Unless you have a specific reason to disable
     * DNS bucket naming, leave this value false.
     *
     * @return
     * a URL signed in such a way as to grant access to an S3 resource to whoever uses it.
     *
     * @throws S3ServiceException
     */
    public static String createSignedUrl(String method, String bucketName, String objectKey,
        String specialParamName, Map headersMap, ProviderCredentials credentials,
        long secondsSinceEpoch, boolean isVirtualHost, boolean isHttps,
        boolean isDnsBucketNamingDisabled) throws S3ServiceException
    {
        S3Service s3Service = new RestS3Service(credentials);
        return s3Service.createSignedUrl(method, bucketName, objectKey,
            specialParamName, headersMap, secondsSinceEpoch,
            isVirtualHost, isHttps, isDnsBucketNamingDisabled);
    }

    /**
     * Generates a signed URL string that will grant access to an S3 resource (bucket or object)
     * to whoever uses the URL up until the time specified. The URL will use the default
     * JetS3t property settings in the <tt>jets3t.properties</tt> file to determine whether
     * to generate HTTP or HTTPS links (<tt>s3service.https-only</tt>), and whether to disable
     * DNS bucket naming (<tt>s3service.disable-dns-buckets</tt>).
     *
     * @deprecated 0.7.4
     *
     * @param method
     * the HTTP method to sign, such as GET or PUT (note that S3 does not support POST requests).
     * @param bucketName
     * the name of the bucket to include in the URL, must be a valid bucket name.
     * @param objectKey
     * the name of the object to include in the URL, if null only the bucket name is used.
     * @param specialParamName
     * the name of a request parameter to add to the URL generated by this method. 'Special'
     * parameters may include parameters that specify the kind of S3 resource that the URL
     * will refer to, such as 'acl', 'torrent', 'logging' or 'location'.
     * @param headersMap
     * headers to add to the signed URL, may be null.
     * Headers that <b>must</b> match between the signed URL and the actual request include:
     * content-md5, content-type, and any header starting with 'x-amz-'.
     * @param credentials
     * the credentials of someone with sufficient privileges to grant access to the bucket/object
     * @param secondsSinceEpoch
     * the time after which URL's signature will no longer be valid. This time cannot be null.
     *  <b>Note:</b> This time is specified in seconds since the epoch, not milliseconds.
     * @param isVirtualHost
     * if this parameter is true, the bucket name is treated as a virtual host name. To use
     * this option, the bucket name must be a valid DNS name that is an alias to an S3 bucket.
     *
     * @return
     * a URL signed in such a way as to grant access to an S3 resource to whoever uses it.
     *
     * @throws S3ServiceException
     */
    public String createSignedUrl(String method, String bucketName, String objectKey,
        String specialParamName, Map headersMap, ProviderCredentials credentials,
        long secondsSinceEpoch, boolean isVirtualHost) throws S3ServiceException
    {
        boolean isHttps = this.getHttpsOnly();
        boolean disableDnsBuckets = this.getDisableDnsBuckets();

        return createSignedUrl(method, bucketName, objectKey, specialParamName,
            headersMap, credentials, secondsSinceEpoch, isVirtualHost, isHttps,
            disableDnsBuckets);
    }

    /**
     * Generates a signed URL string that will grant access to an S3 resource (bucket or object)
     * to whoever uses the URL up until the time specified.
     *
     * @deprecated 0.7.4
     *
     * @param method
     * the HTTP method to sign, such as GET or PUT (note that S3 does not support POST requests).
     * @param bucketName
     * the name of the bucket to include in the URL, must be a valid bucket name.
     * @param objectKey
     * the name of the object to include in the URL, if null only the bucket name is used.
     * @param specialParamName
     * the name of a request parameter to add to the URL generated by this method. 'Special'
     * parameters may include parameters that specify the kind of S3 resource that the URL
     * will refer to, such as 'acl', 'torrent', 'logging' or 'location'.
     * @param headersMap
     * headers to add to the signed URL, may be null.
     * Headers that <b>must</b> match between the signed URL and the actual request include:
     * content-md5, content-type, and any header starting with 'x-amz-'.
     * @param credentials
     * the credentials of someone with sufficient privileges to grant access to the bucket/object
     * @param secondsSinceEpoch
     * the time after which URL's signature will no longer be valid. This time cannot be null.
     *  <b>Note:</b> This time is specified in seconds since the epoch, not milliseconds.
     *
     * @return
     * a URL signed in such a way as to grant access to an S3 resource to whoever uses it.
     *
     * @throws S3ServiceException
     */
    public String createSignedUrl(String method, String bucketName, String objectKey,
        String specialParamName, Map headersMap, ProviderCredentials credentials, long secondsSinceEpoch)
        throws S3ServiceException
    {
        return createSignedUrl(method, bucketName, objectKey, specialParamName, headersMap,
            credentials, secondsSinceEpoch, false);
    }


    /**
     * Generates a signed GET URL.
     *
     * @deprecated 0.7.4
     *
     * @param bucketName
     * the name of the bucket to include in the URL, must be a valid bucket name.
     * @param objectKey
     * the name of the object to include in the URL, if null only the bucket name is used.
     * @param credentials
     * the credentials of someone with sufficient privileges to grant access to the bucket/object
     * @param expiryTime
     * the time after which URL's signature will no longer be valid. This time cannot be null.
     * @param isVirtualHost
     * if this parameter is true, the bucket name is treated as a virtual host name. To use
     * this option, the bucket name must be a valid DNS name that is an alias to an S3 bucket.
     *
     * @return
     * a URL signed in such a way as to grant GET access to an S3 resource to whoever uses it.
     * @throws S3ServiceException
     */
    public String createSignedGetUrl(String bucketName, String objectKey,
        ProviderCredentials credentials, Date expiryTime, boolean isVirtualHost)
        throws S3ServiceException
    {
        long secondsSinceEpoch = expiryTime.getTime() / 1000;
        return createSignedUrl("GET", bucketName, objectKey, null, null,
            credentials, secondsSinceEpoch, isVirtualHost);
    }


    /**
     * Generates a signed GET URL.
     *
     * @deprecated 0.7.4
     *
     * @param bucketName
     * the name of the bucket to include in the URL, must be a valid bucket name.
     * @param objectKey
     * the name of the object to include in the URL, if null only the bucket name is used.
     * @param credentials
     * the credentials of someone with sufficient privileges to grant access to the bucket/object
     * @param expiryTime
     * the time after which URL's signature will no longer be valid. This time cannot be null.
     *
     * @return
     * a URL signed in such a way as to grant GET access to an S3 resource to whoever uses it.
     * @throws S3ServiceException
     */
    public String createSignedGetUrl(String bucketName, String objectKey,
        ProviderCredentials credentials, Date expiryTime)
        throws S3ServiceException
    {
        return createSignedGetUrl(bucketName, objectKey, credentials, expiryTime, false);
    }


    /**
     * Generates a signed PUT URL.
     *
     * @deprecated 0.7.4
     *
     * @param bucketName
     * the name of the bucket to include in the URL, must be a valid bucket name.
     * @param objectKey
     * the name of the object to include in the URL, if null only the bucket name is used.
     * @param headersMap
     * headers to add to the signed URL, may be null.
     * Headers that <b>must</b> match between the signed URL and the actual request include:
     * content-md5, content-type, and any header starting with 'x-amz-'.
     * @param credentials
     * the credentials of someone with sufficient privileges to grant access to the bucket/object
     * @param expiryTime
     * the time after which URL's signature will no longer be valid. This time cannot be null.
     * @param isVirtualHost
     * if this parameter is true, the bucket name is treated as a virtual host name. To use
     * this option, the bucket name must be a valid DNS name that is an alias to an S3 bucket.
     *
     * @return
     * a URL signed in such a way as to allow anyone to PUT an object into S3.
     * @throws S3ServiceException
     */
    public String createSignedPutUrl(String bucketName, String objectKey,
        Map headersMap, ProviderCredentials credentials, Date expiryTime, boolean isVirtualHost)
        throws S3ServiceException
    {
        long secondsSinceEpoch = expiryTime.getTime() / 1000;
        return createSignedUrl("PUT", bucketName, objectKey, null, headersMap,
            credentials, secondsSinceEpoch, isVirtualHost);
    }


    /**
     * Generates a signed PUT URL.
     *
     * @deprecated 0.7.4
     *
     * @param bucketName
     * the name of the bucket to include in the URL, must be a valid bucket name.
     * @param objectKey
     * the name of the object to include in the URL, if null only the bucket name is used.
     * @param headersMap
     * headers to add to the signed URL, may be null.
     * Headers that <b>must</b> match between the signed URL and the actual request include:
     * content-md5, content-type, and any header starting with 'x-amz-'.
     * @param credentials
     * the credentials of someone with sufficient privileges to grant access to the bucket/object
     * @param expiryTime
     * the time after which URL's signature will no longer be valid. This time cannot be null.
     *
     * @return
     * a URL signed in such a way as to allow anyone to PUT an object into S3.
     * @throws S3ServiceException
     */
    public String createSignedPutUrl(String bucketName, String objectKey,
        Map headersMap, ProviderCredentials credentials, Date expiryTime)
        throws S3ServiceException
    {
        return createSignedPutUrl(bucketName, objectKey, headersMap, credentials, expiryTime, false);
    }


    /**
     * Generates a signed DELETE URL.
     *
     * @deprecated 0.7.4
     *
     * @param bucketName
     * the name of the bucket to include in the URL, must be a valid bucket name.
     * @param objectKey
     * the name of the object to include in the URL, if null only the bucket name is used.
     * @param credentials
     * the credentials of someone with sufficient privileges to grant access to the bucket/object
     * @param expiryTime
     * the time after which URL's signature will no longer be valid. This time cannot be null.
     * @param isVirtualHost
     * if this parameter is true, the bucket name is treated as a virtual host name. To use
     * this option, the bucket name must be a valid DNS name that is an alias to an S3 bucket.
     *
     * @return
     * a URL signed in such a way as to allow anyone do DELETE an object in S3.
     * @throws S3ServiceException
     */
    public String createSignedDeleteUrl(String bucketName, String objectKey,
        ProviderCredentials credentials, Date expiryTime, boolean isVirtualHost)
        throws S3ServiceException
    {
        long secondsSinceEpoch = expiryTime.getTime() / 1000;
        return createSignedUrl("DELETE", bucketName, objectKey, null, null,
            credentials, secondsSinceEpoch, isVirtualHost);
    }


    /**
     * Generates a signed DELETE URL.
     *
     * @deprecated 0.7.4
     *
     * @param bucketName
     * the name of the bucket to include in the URL, must be a valid bucket name.
     * @param objectKey
     * the name of the object to include in the URL, if null only the bucket name is used.
     * @param credentials
     * the credentials of someone with sufficient privileges to grant access to the bucket/object
     * @param expiryTime
     * the time after which URL's signature will no longer be valid. This time cannot be null.
     *
     * @return
     * a URL signed in such a way as to allow anyone do DELETE an object in S3.
     * @throws S3ServiceException
     */
    public String createSignedDeleteUrl(String bucketName, String objectKey,
        ProviderCredentials credentials, Date expiryTime)
        throws S3ServiceException
    {
        return createSignedDeleteUrl(bucketName, objectKey, credentials, expiryTime, false);
    }


    /**
     * Generates a signed HEAD URL.
     *
     * @deprecated 0.7.4
     *
     * @param bucketName
     * the name of the bucket to include in the URL, must be a valid bucket name.
     * @param objectKey
     * the name of the object to include in the URL, if null only the bucket name is used.
     * @param credentials
     * the credentials of someone with sufficient privileges to grant access to the bucket/object
     * @param expiryTime
     * the time after which URL's signature will no longer be valid. This time cannot be null.
     * @param isVirtualHost
     * if this parameter is true, the bucket name is treated as a virtual host name. To use
     * this option, the bucket name must be a valid DNS name that is an alias to an S3 bucket.
     *
     * @return
     * a URL signed in such a way as to grant HEAD access to an S3 resource to whoever uses it.
     * @throws S3ServiceException
     */
    public String createSignedHeadUrl(String bucketName, String objectKey,
        ProviderCredentials credentials, Date expiryTime, boolean isVirtualHost)
        throws S3ServiceException
    {
        long secondsSinceEpoch = expiryTime.getTime() / 1000;
        return createSignedUrl("HEAD", bucketName, objectKey, null, null,
            credentials, secondsSinceEpoch, isVirtualHost);
    }


    /**
     * Generates a signed HEAD URL.
     *
     * @deprecated 0.7.4
     *
     * @param bucketName
     * the name of the bucket to include in the URL, must be a valid bucket name.
     * @param objectKey
     * the name of the object to include in the URL, if null only the bucket name is used.
     * @param credentials
     * the credentials of someone with sufficient privileges to grant access to the bucket/object
     * @param expiryTime
     * the time after which URL's signature will no longer be valid. This time cannot be null.
     *
     * @return
     * a URL signed in such a way as to grant HEAD access to an S3 resource to whoever uses it.
     * @throws S3ServiceException
     */
    public String createSignedHeadUrl(String bucketName, String objectKey,
        ProviderCredentials credentials, Date expiryTime)
        throws S3ServiceException
    {
        return createSignedHeadUrl(bucketName, objectKey, credentials, expiryTime, false);
    }

    /**
     * Generates a URL string that will return a Torrent file for an object in S3,
     * which file can be downloaded and run in a BitTorrent client.
     *
     * @param bucketName
     * the name of the bucket containing the object.
     * @param objectKey
     * the name of the object.
     * @return
     * a URL to a Torrent file representing the object.
     * @throws S3ServiceException
     */
    public String createTorrentUrl(String bucketName, String objectKey)
    {
        String s3Endpoint = this.getEndpoint();
        String serviceEndpointVirtualPath = this.getVirtualPath();
        int httpPort = this.getHttpPort();
        boolean disableDnsBuckets = this.getDisableDnsBuckets();

        String bucketNameInPath =
            !disableDnsBuckets && ServiceUtils.isBucketNameValidDNSName(bucketName)
            ? ""
            : bucketName + "/";
        return "http://" + ServiceUtils.generateS3HostnameForBucket(
                                        bucketName, disableDnsBuckets, s3Endpoint)
            + (httpPort != 80 ? ":" + httpPort : "")
            + serviceEndpointVirtualPath + "/"
            + bucketNameInPath
            + objectKey + "?torrent";
    }


    /**
     * Generates a policy document condition statement to represent an operation.
     *
     * @param operation
     * the name of the test operation this condition statement will apply.
     * @param name
     * the name of the data item the condition applies to.
     * @param value
     * the test value that will be used by the condition operation.
     * @return
     * a condition statement that can be included in the policy document
     * belonging to an S3 POST form.
     */
    public static String generatePostPolicyCondition(String operation, String name, String value) {
        return "[\"" + operation + "\", \"$" + name + "\", \"" + value + "\"]";
    }

    /**
     * Generates a policy document condition statement that will allow the named
     * data item in a POST request to take on any value.
     *
     * @param name
     * the name of the data item that will be allowed to take on any value.
     * @return
     * a condition statement that can be included in the policy document
     * belonging to an S3 POST form.
     */
    public static String generatePostPolicyCondition_AllowAnyValue(String name) {
        return "[\"starts-with\", \"$" + name + "\", \"\"]";
    }

    /**
     * Generates a policy document condition statement to represent an
     * equality test.
     *
     * @param name
     * the name of the data item that will be tested.
     * @param value
     * the value that the named data item must match.
     * @return
     * a condition statement that can be included in the policy document
     * belonging to an S3 POST form.
     */
    public static String generatePostPolicyCondition_Equality(String name, String value) {
        return "{\"" + name + "\": \"" + value + "\"}";
    }

    /**
     * Generates a policy document condition statement to represent an
     * equality test.
     *
     * @param name
     * the name of the data item that will be tested.
     * @param values
     * a list of values, one of which must match the named data item.
     * @return
     * a condition statement that can be included in the policy document
     * belonging to an S3 POST form.
     */
    public static String generatePostPolicyCondition_Equality(String name, String[] values) {
        return "{\"" + name + "\": \"" + ServiceUtils.join(values, ",") + "\"}";
    }

    /**
     * Generates a policy document condition statement to represent an
     * equality test.
     *
     * @param name
     * the name of the data item that will be tested.
     * @param values
     * a list of values, one of which must match the named data item.
     * @return
     * a condition statement that can be included in the policy document
     * belonging to an S3 POST form.
     */
    public static String generatePostPolicyCondition_Equality(String name, List values) {
        return "{\"" + name + "\": \"" + ServiceUtils.join(values, ",") + "\"}";
    }

    /**
     * Generates a policy document condition statement to represent a test that
     * imposes a limit on the minimum and maximum amount of data the user can
     * upload via a POST form.
     *
     * @param min
     * the minimum number of bytes the user must upload. This value should be
     * greater than or equal to zero.
     * @param max
     * the maximum number of bytes the user can upload. This value must be
     * greater than or equal to the min value.
     * @return
     * a condition statement that can be included in the policy document
     * belonging to an S3 POST form.
     */
    public static String generatePostPolicyCondition_Range(int min, int max) {
        return "[\"content-length-range\", " + min + ", " + max + "]";
    }


    /**
     * Generates an <b>unauthenticated</b> HTML POST form that can be used to
     * upload files or data to S3 from a standard web browser.
     * <p>
     * Because the generated form is unauthenticated, it will not contain a
     * policy document and will only allow uploads to be sent to S3 buckets
     * that are publicly writable.
     *
     * @param bucketName
     * the name of the target bucket to which the data will be uploaded.
     * @param key
     * the key name for the object that will store the data. The key name can
     * include the special variable <tt>${filename}</tt> which expands to the
     * name of the file the user uploaded in the form.
     * @return
     * A form document that can be included in a UTF-8 encoded HTML web page
     * to allow uploads to a publicly-writable S3 bucket via a web browser.
     *
     * @throws S3ServiceException
     * @throws UnsupportedEncodingException
     */
    public static String buildPostForm(String bucketName, String key)
        throws S3ServiceException, UnsupportedEncodingException
    {
        return buildPostForm(bucketName, key, null, null, null, null, null, true);
    }


    /**
     * Generates an HTML POST form that can be used to upload files or data to
     * S3 from a standard web browser.
     * <p>
     * Depending on the parameter values provided, this method will generate an
     * authenticated or unauthenticated form. If the form is unauthenticated, it
     * will not include a policy document and will therefore not have an
     * expiry date or any usage conditions. Unauthenticated forms may only be
     * used to upload data to a publicly writable bucket.
     * <p>
     * If both the expiration and conditions parameters are non-null, the form
     * will include a policy document and will be authenticated. In this case,
     * you must provide your AWS credentials to sign the authenticated form.
     *
     * @param bucketName
     * the name of the target bucket to which the data will be uploaded.
     * @param key
     * the key name for the object that will store the data. The key name can
     * include the special variable <tt>${filename}</tt> which expands to the
     * name of the file the user uploaded in the form.
     * @param credentials
     * your Storage Provideer credentials. Credentials are only required if the form 
     * includes policy document conditions, otherwise this can be null.
     * @param expiration
     * the expiration date beyond which the form will cease to work. If this
     * parameter is null, the generated form will not include a policy document
     * and will not have an expiry date.
     * @param conditions
     * the policy conditions applied to the form, specified as policy document
     * condition statements. These statements can be generated with the
     * convenience method {@link #generatePostPolicyCondition(String, String, String)}
     * and its siblings. If this parameter is null, the generated form will not
     * include a policy document and will not apply any usage conditions.
     * @param inputFields
     * optional input field strings that will be added to the form. Each string
     * must be a valid HTML form input field definition, such as
     * <tt>&lt;input type="hidden" name="acl" value="public-read"></tt>
     * @param textInput
     * an optional input field definition that is used instead of the default
     * file input field <tt>&lt;input name=\"file\" type=\"file\"></tt>. If this
     * parameter is null, the default file input field will be used to allow
     * file uploads. If this parameter is non-null, the provided string must
     * define an input field named "file" that allows the user to provide input,
     * such as <tt>&lt;textarea name="file" cols="60" rows="3">&lt;/textarea></tt>
     * @param isSecureHttp
     * if this parameter is true the form will upload data to S3 using HTTPS,
     * otherwise it will use HTTP.
     * @return
     * A form document that can be included in a UTF-8 encoded HTML web page
     * to allow uploads to S3 via a web browser.
     *
     * @throws S3ServiceException
     * @throws UnsupportedEncodingException
     */
    public static String buildPostForm(String bucketName, String key,
        ProviderCredentials credentials, Date expiration, String[] conditions,
        String[] inputFields, String textInput, boolean isSecureHttp)
        throws S3ServiceException, UnsupportedEncodingException
    {
        return buildPostForm(bucketName, key, credentials, expiration,
        		conditions, inputFields, textInput, isSecureHttp,
        		false, "Upload to Amazon S3");
    }

    /**
     * Generates an HTML POST form that can be used to upload files or data to
     * S3 from a standard web browser.
     * <p>
     * Depending on the parameter values provided, this method will generate an
     * authenticated or unauthenticated form. If the form is unauthenticated, it
     * will not include a policy document and will therefore not have an
     * expiry date or any usage conditions. Unauthenticated forms may only be
     * used to upload data to a publicly writable bucket.
     * <p>
     * If both the expiration and conditions parameters are non-null, the form
     * will include a policy document and will be authenticated. In this case,
     * you must provide your AWS credentials to sign the authenticated form.
     *
     * @param bucketName
     * the name of the target bucket to which the data will be uploaded.
     * @param key
     * the key name for the object that will store the data. The key name can
     * include the special variable <tt>${filename}</tt> which expands to the
     * name of the file the user uploaded in the form.
     * @param credentials
     * your Storage Provider credentials. Credentials are only required if the form 
     * includes policy document conditions, otherwise this can be null.
     * @param expiration
     * the expiration date beyond which the form will cease to work. If this
     * parameter is null, the generated form will not include a policy document
     * and will not have an expiry date.
     * @param conditions
     * the policy conditions applied to the form, specified as policy document
     * condition statements. These statements can be generated with the
     * convenience method {@link #generatePostPolicyCondition(String, String, String)}
     * and its siblings. If this parameter is null, the generated form will not
     * include a policy document and will not apply any usage conditions.
     * @param inputFields
     * optional input field strings that will be added to the form. Each string
     * must be a valid HTML form input field definition, such as
     * <tt>&lt;input type="hidden" name="acl" value="public-read"></tt>
     * @param textInput
     * an optional input field definition that is used instead of the default
     * file input field <tt>&lt;input name=\"file\" type=\"file\"></tt>. If this
     * parameter is null, the default file input field will be used to allow
     * file uploads. If this parameter is non-null, the provided string must
     * define an input field named "file" that allows the user to provide input,
     * such as <tt>&lt;textarea name="file" cols="60" rows="3">&lt;/textarea></tt>
     * @param isSecureHttp
     * if this parameter is true the form will upload data to S3 using HTTPS,
     * otherwise it will use HTTP.
     * @param usePathStyleUrl
     * if true the deprecated path style URL will be used to specify the bucket
     * name, for example: http://s3.amazon.com/BUCKET_NAME. If false, the
     * recommended sub-domain style will be used, for example:
     * http://BUCKET_NAME.s3.amazon.com/.
     * The path style can be useful for accessing US-based buckets with SSL,
     * however non-US buckets are inaccessible with this style URL.
     * @param submitButtonName
     * the name to display on the form's submit button.
     *
     * @return
     * A form document that can be included in a UTF-8 encoded HTML web page
     * to allow uploads to S3 via a web browser.
     *
     * @throws S3ServiceException
     * @throws UnsupportedEncodingException
     */
    public static String buildPostForm(String bucketName, String key,
        ProviderCredentials credentials, Date expiration, String[] conditions,
        String[] inputFields, String textInput, boolean isSecureHttp,
        boolean usePathStyleUrl, String submitButtonName)
        throws S3ServiceException, UnsupportedEncodingException
    {
    	List myInputFields = new ArrayList();

        // Form is only authenticated if a policy is specified.
        if (expiration != null || conditions != null) {
            // Generate policy document
            String policyDocument =
                "{\"expiration\": \"" + ServiceUtils.formatIso8601Date(expiration)
                + "\", \"conditions\": [" + ServiceUtils.join(conditions, ",") + "]}";
            if (log.isDebugEnabled()) {
                log.debug("Policy document for POST form:\n" + policyDocument);
            }

            // Add the base64-encoded policy document as the 'policy' form field
            String policyB64 = ServiceUtils.toBase64(
                policyDocument.getBytes(Constants.DEFAULT_ENCODING));
            myInputFields.add("<input type=\"hidden\" name=\"policy\" value=\""
                + policyB64 + "\">");

            // Add the AWS access key as the 'AWSAccessKeyId' field
            myInputFields.add("<input type=\"hidden\" name=\"AWSAccessKeyId\" " +
                "value=\"" + credentials.getAccessKey() + "\">");

            // Add signature for encoded policy document as the 'AWSAccessKeyId' field
            String signature = ServiceUtils.signWithHmacSha1(
                credentials.getSecretKey(), policyB64);
            myInputFields.add("<input type=\"hidden\" name=\"signature\" " +
                "value=\"" + signature + "\">");
        }

        // Include any additional user-specified form fields
        if (inputFields != null) {
            myInputFields.addAll(Arrays.asList(inputFields));
        }

        // Add the vital 'file' input item, which may be a textarea or file.
        if (textInput != null) {
            // Use a caller-specified string as the input field.
            myInputFields.add(textInput);
        } else {
            myInputFields.add("<input name=\"file\" type=\"file\">");
        }

        // Construct a URL to refer to the target bucket using either the
        // deprecated path style, or the recommended sub-domain style. The
        // HTTPS protocol will be used if the secure HTTP option is enabled.
        String url = null;
        if (usePathStyleUrl) {
            url = "http" + (isSecureHttp? "s" : "") +
                "://s3.amazonaws.com/" +  bucketName;
        } else {
            // Sub-domain URL style
            url = "http" + (isSecureHttp? "s" : "") +
                "://" + bucketName + ".s3.amazonaws.com/";
        }

        // Construct the entire form.
        String form =
          "<form action=\"" + url + "\" method=\"post\" " +
              "enctype=\"multipart/form-data\">\n" +
            "<input type=\"hidden\" name=\"key\" value=\"" + key + "\">\n" +
            ServiceUtils.join(myInputFields, "\n") +
            "\n<br>\n" +
            "<input type=\"submit\" value=\"" + submitButtonName + "\">\n" +
          "</form>";

        if (log.isDebugEnabled()) {
            log.debug("POST Form:\n" + form);
        }
        return form;
    }

    /////////////////////////////////////////////////////////////////////////////
    // Assertion methods used to sanity-check parameters provided to this service
    /////////////////////////////////////////////////////////////////////////////

    /**
     * Throws an exception if this service is anonymous (that is, it was created without
     * an <code>ProviderCredentials</code> object representing an S3 user account.
     * @param action
     * the action being attempted which this assertion is applied, for debugging purposes.
     * @throws S3ServiceException
     */
    protected void assertAuthenticatedConnection(String action) throws S3ServiceException {
        if (!isAuthenticatedConnection()) {
            throw new S3ServiceException(
                "The requested action cannot be performed with a non-authenticated S3 Service: "
                    + action);
        }
    }

    /**
     * Throws an exception if a bucket is null or contains a null/empty name.
     * @param bucket
     * @param action
     * the action being attempted which this assertion is applied, for debugging purposes.
     * @throws S3ServiceException
     */
    protected void assertValidBucket(S3Bucket bucket, String action) throws S3ServiceException {
        if (bucket == null || bucket.getName() == null || bucket.getName().length() == 0) {
            throw new S3ServiceException("The action " + action
                + " cannot be performed with an invalid bucket: " + bucket);
        }
    }

    /**
     * Throws an exception if an object is null or contains a null/empty key.
     * @param object
     * @param action
     * the action being attempted which this assertion is applied, for debugging purposes.
     * @throws S3ServiceException
     */
    protected void assertValidObject(S3Object object, String action) throws S3ServiceException {
        if (object == null || object.getKey() == null || object.getKey().length() == 0) {
            throw new S3ServiceException("The action " + action
                + " cannot be performed with an invalid object: " + object);
        }
    }

    /**
     * Throws an exception if an object's key name is null or empty.
     * @param key
     * An object's key name.
     * @param action
     * the action being attempted which this assertion is applied, for debugging purposes.
     * @throws S3ServiceException
     */
    protected void assertValidObject(String key, String action) throws S3ServiceException {
        if (key == null || key.length() == 0) {
            throw new S3ServiceException("The action " + action
                + " cannot be performed with an invalid object key name: " + key);
        }
    }

    /////////////////////////////////////////////////
    // Methods below this point perform actions in S3
    /////////////////////////////////////////////////

    /**
     * Lists the objects in a bucket.
     * <p>
     * The objects returned by this method contain only minimal information
     * such as the object's size, ETag, and LastModified timestamp. To retrieve
     * the objects' metadata you must perform follow-up <code>getObject</code>
     * or <code>getObjectDetails</code> operations.
     * <p>
     * This method can be performed by anonymous services. Anonymous services
     * can only list the objects in a publicly-readable bucket.
     *
     * @param bucket
     * the bucket whose contents will be listed.
     * This must be a valid S3Bucket object that is non-null and contains a name.
     * @return
     * the set of objects contained in a bucket.
     * @throws S3ServiceException
     */
    public S3Object[] listObjects(S3Bucket bucket) throws S3ServiceException {
        assertValidBucket(bucket, "listObjects");
        return listObjects(bucket, null, null, Constants.DEFAULT_OBJECT_LIST_CHUNK_SIZE);
    }

    /**
     * Lists the objects in a bucket.
     * <p>
     * The objects returned by this method contain only minimal information
     * such as the object's size, ETag, and LastModified timestamp. To retrieve
     * the objects' metadata you must perform follow-up <code>getObject</code>
     * or <code>getObjectDetails</code> operations.
     * <p>
     * This method can be performed by anonymous services. Anonymous services
     * can only list the objects in a publicly-readable bucket.
     *
     * @param bucket
     * the name of the bucket whose contents will be listed.
     * @return
     * the set of objects contained in a bucket.
     * @throws S3ServiceException
     */
    public S3Object[] listObjects(String bucketName) throws S3ServiceException {
        return listObjects(bucketName, null, null, Constants.DEFAULT_OBJECT_LIST_CHUNK_SIZE);
    }

    /**
     * Lists the objects in a bucket matching a prefix and delimiter.
     * <p>
     * The objects returned by this method contain only minimal information
     * such as the object's size, ETag, and LastModified timestamp. To retrieve
     * the objects' metadata you must perform follow-up <code>getObject</code>
     * or <code>getObjectDetails</code> operations.
     * <p>
     * This method can be performed by anonymous services. Anonymous services
     * can only list the objects in a publicly-readable bucket.
     * <p>
     * NOTE: If you supply a delimiter value that could cause CommonPrefixes
     * ("subdirectory paths") to be included in the results from S3, use the
     * {@link #listObjectsChunked(String, String, String, long, String, boolean)}
     * method instead of this one to obtain both object and CommonPrefix values.
     *
     * @param bucket
     * the bucket whose contents will be listed.
     * This must be a valid S3Bucket object that is non-null and contains a name.
     * @param prefix
     * only objects with a key that starts with this prefix will be listed
     * @param delimiter
     * only list objects with key names up to this delimiter, may be null.
     * See note above.
     * <b>Note</b>: If a non-null delimiter is specified, the prefix must include enough text to
     * reach the first occurrence of the delimiter in the bucket's keys, or no results will be returned.
     * @return
     * the set of objects contained in a bucket whose keys start with the given prefix.
     * @throws S3ServiceException
     */
    public S3Object[] listObjects(S3Bucket bucket, String prefix, String delimiter) throws S3ServiceException {
        assertValidBucket(bucket, "listObjects");
        return listObjects(bucket, prefix, delimiter, Constants.DEFAULT_OBJECT_LIST_CHUNK_SIZE);
    }

    /**
     * Creates a bucket in a specific location, without checking whether the bucket already
     * exists. <b>Caution:</b> Performing this operation unnecessarily when a bucket already
     * exists may cause OperationAborted errors with the message "A conflicting conditional
     * operation is currently in progress against this resource.". To avoid this error, use the
     * {@link #getOrCreateBucket(String)} in situations where the bucket may already exist.
     * <p>
     * <b>Warning:</b> Prior to version 0.7.0 this method did check whether a bucket already
     * existed using {@link #isBucketAccessible(String)}. After changes to the way S3 operates,
     * this check started to cause issues so it was removed.
     * <p>
     * This method cannot be performed by anonymous services.
     *
     * @param bucketName
     * the name of the bucket to create.
     * @param location
     * the location of the S3 data centre in which the bucket will be created. Valid values
     * include {@link S3Bucket#LOCATION_EUROPE}, {@link S3Bucket#LOCATION_US_WEST},
     * {@link S3Bucket#LOCATION_ASIA_PACIFIC}, and the default US location that can be
     * expressed in two ways:
     * {@link S3Bucket#LOCATION_US_STANDARD} or {@link S3Bucket#LOCATION_US}.
     * @return
     * the created bucket object. <b>Note:</b> the object returned has minimal information about
     * the bucket that was created, including only the bucket's name.
     * @throws S3ServiceException
     */
    public S3Bucket createBucket(String bucketName, String location) throws S3ServiceException {
        assertAuthenticatedConnection("createBucket");
        S3Bucket bucket = new S3Bucket(bucketName, location);
        return createBucket(bucket);
    }

    /**
     * Creates a bucket. The bucket is created in the default location as
     * specified in the properties setting <tt>s3service.default-bucket-location</tt>.
     * <b>Caution:</b> Performing this operation unnecessarily when a bucket already
     * exists may cause OperationAborted errors with the message "A conflicting conditional
     * operation is currently in progress against this resource.". To avoid this error, use the
     * {@link #getOrCreateBucket(String)} in situations where the bucket may already exist.
     * <p>
     * <b>Warning:</b> Prior to version 0.7.0 this method did check whether a bucket already
     * existed using {@link #isBucketAccessible(String)}. After changes to the way S3 operates,
     * this check started to cause issues so it was removed.
     * <p>
     * This method cannot be performed by anonymous services.
     *
     * @param bucketName
     * the name of the bucket to create.
     * @return
     * the created bucket object. <b>Note:</b> the object returned has minimal information about
     * the bucket that was created, including only the bucket's name.
     * @throws S3ServiceException
     */
    public S3Bucket createBucket(String bucketName) throws S3ServiceException {
        String defaultBucketLocation = jets3tProperties.getStringProperty(
                "s3service.default-bucket-location", S3Bucket.LOCATION_US);
        return createBucket(bucketName, defaultBucketLocation);
    }

    /**
     * Convenience method to check whether an object exists in a bucket.
     *
     * @param bucketName
     * the name of the bucket containing the object.
     * @param objectKey
     * the key identifying the object.
     * @return
     * false if the object is not found in the bucket, true if the object
     * exists (although it may be inaccessible to you).
     */
    public boolean isObjectInBucket(String bucketName, String objectKey)
        throws S3ServiceException
    {
        try {
            getObjectDetails(bucketName, objectKey);
        } catch (S3ServiceException e) {
            if ("NoSuchKey".equals(e.getS3ErrorCode())
                || "NoSuchBucket".equals(e.getS3ErrorCode()))
            {
                return false;
            }
            if ("AccessDenied".equals(e.getS3ErrorCode()))
            {
                // Object is inaccessible to current user, but does exist.
                return true;
            }
            // Something else has gone wrong
            throw e;
        }
        return true;
    }

    /**
     * Returns an object representing the details and data of an item in S3, without applying any
     * preconditions.
     * <p>
     * This method can be performed by anonymous services. Anonymous services
     * can get a publicly-readable object.
     * <p>
     * <b>Important:</b> It is the caller's responsibility to close the object's data input stream.
     * The data stream should be consumed and closed as soon as is practical as network connections
     * may be held open until the streams are closed. Excessive unclosed streams can lead to
     * connection starvation.
     *
     * @param bucket
     * the bucket containing the object.
     * This must be a valid S3Bucket object that is non-null and contains a name.
     * @param objectKey
     * the key identifying the object.
     * @return
     * the object with the given key in S3, including the object's data input stream.
     * @throws S3ServiceException
     */
    public S3Object getObject(S3Bucket bucket, String objectKey) throws S3ServiceException {
        assertValidBucket(bucket, "getObject");
        return getObject(bucket, objectKey, null, null, null, null, null, null);
    }

    /**
     * Returns an object representing the details and data of an item in S3, without applying any
     * preconditions.
     * <p>
     * This method can be performed by anonymous services. Anonymous services
     * can get a publicly-readable object.
     * <p>
     * <b>Important:</b> It is the caller's responsibility to close the object's data input stream.
     * The data stream should be consumed and closed as soon as is practical as network connections
     * may be held open until the streams are closed. Excessive unclosed streams can lead to
     * connection starvation.
     *
     * @param bucketName
     * the name of the bucket containing the object.
     * @param objectKey
     * the key identifying the object.
     * @return
     * the object with the given key in S3, including the object's data input stream.
     * @throws S3ServiceException
     */
    public S3Object getObject(String bucketName, String objectKey) throws S3ServiceException {
        return getObject(new S3Bucket(bucketName), objectKey,
        	null, null, null, null, null, null);
    }

    /**
     * Returns an object representing the details and data of an item in S3 with a specific
     * given version, without applying any preconditions. Versioned objects are only available
     * from buckets with versioning enabled, see {@link #enableBucketVersioning(String)}.
     * <p>
     * This method can be performed by anonymous services. Anonymous services
     * can get a publicly-readable object.
     * <p>
     * <b>Important:</b> It is the caller's responsibility to close the object's data input stream.
     * The data stream should be consumed and closed as soon as is practical as network connections
     * may be held open until the streams are closed. Excessive unclosed streams can lead to
     * connection starvation.
     *
     * @param versionId
     * identifier matching an existing object version that will be retrieved.
     * @param bucketName
     * the name of the versioned bucket containing the object.
     * @param objectKey
     * the key identifying the object.
     * @return
     * the object with the given key in S3, including the object's data input stream.
     * @throws S3ServiceException
     */
    public S3Object getVersionedObject(String versionId, String bucketName, String objectKey)
        throws S3ServiceException
    {
        MxDelegate.getInstance().registerS3ObjectGetEvent(bucketName, objectKey);
        return getObjectImpl(bucketName, objectKey, null, null, null, null, null, null, versionId);
    }

    /**
     * Returns an object representing the details of an item in S3 without the object's data, and
     * without applying any preconditions.
     * <p>
     * This method can be performed by anonymous services. Anonymous services
     * can get a publicly-readable object's details.
     *
     * @param bucket
     * the bucket containing the object.
     * This must be a valid S3Bucket object that is non-null and contains a name.
     * @param objectKey
     * the key identifying the object.
     * @return
     * the object with the given key in S3, including only general details and metadata (not the data
     * input stream)
     * @throws S3ServiceException
     */
    public S3Object getObjectDetails(S3Bucket bucket, String objectKey) throws S3ServiceException {
        assertValidBucket(bucket, "getObjectDetails");
        return getObjectDetails(bucket, objectKey, null, null, null, null);
    }

    /**
     * Returns an object representing the details of an item in S3 without the object's data, and
     * without applying any preconditions.
     * <p>
     * This method can be performed by anonymous services. Anonymous services
     * can get a publicly-readable object's details.
     *
     * @param bucketName
     * the name of the bucket containing the object.
     * @param objectKey
     * the key identifying the object.
     * @return
     * the object with the given key in S3, including only general details and metadata (not the data
     * input stream)
     * @throws S3ServiceException
     */
    public S3Object getObjectDetails(String bucketName, String objectKey) throws S3ServiceException {
        return getObjectDetails(new S3Bucket(bucketName), objectKey, null, null, null, null);
    }

    /**
     * Returns an object representing the details of an item in S3 with a specific given version,
     * without the object's data and without applying any preconditions. Versioned objects are only
     * available from buckets with versioning enabled, see {@link #enableBucketVersioning(String)}.
     * <p>
     * This method can be performed by anonymous services. Anonymous services
     * can get a publicly-readable object's details.
     *
     * @param bucketName
     * the name of the versioned bucket containing the object.
     * @param objectKey
     * the key identifying the object.
     * @return
     * the object with the given key in S3, including only general details and metadata (not the data
     * input stream)
     * @throws S3ServiceException
     */
    public S3Object getVersionedObjectDetails(String versionId, String bucketName,
    	String objectKey) throws S3ServiceException
    {
        MxDelegate.getInstance().registerS3ObjectHeadEvent(bucketName, objectKey);
        return getObjectDetailsImpl(bucketName, objectKey, null, null, null, null, versionId);
    }

    /**
     * Lists the buckets belonging to the service user.
     * <p>
     * This method cannot be performed by anonymous services, and will fail with an exception
     * if the service is not authenticated.
     *
     * @return
     * the list of buckets owned by the service user.
     * @throws S3ServiceException
     */
    public S3Bucket[] listAllBuckets() throws S3ServiceException {
        assertAuthenticatedConnection("List all buckets");
        S3Bucket[] buckets = listAllBucketsImpl();
        MxDelegate.getInstance().registerS3BucketMBeans(buckets);
        return buckets;
    }

    /**
     * Returns the owner of an S3 account, using information available in the
     * ListAllBuckets response.
     * <p>
     * This method cannot be performed by anonymous services, and will fail with an exception
     * if the service is not authenticated.
     *
     * @return
     * the owner of the S3 account.
     * @throws S3ServiceException
     */
    public S3Owner getAccountOwner() throws S3ServiceException {
        assertAuthenticatedConnection("List all buckets to find account owner");
        return getAccountOwnerImpl();

    }

    /**
     * Lists the objects in a bucket matching a prefix, while instructing S3 to
     * send response messages containing no more than a given number of object
     * results.
     *
     * <p>
     * The objects returned by this method contain only minimal information
     * such as the object's size, ETag, and LastModified timestamp. To retrieve
     * the objects' metadata you must perform follow-up <code>getObject</code>
     * or <code>getObjectDetails</code> operations.
     * <p>
     * This method can be performed by anonymous services. Anonymous services
     * can list the contents of a publicly-readable bucket.
     * <p>
     * NOTE: If you supply a delimiter value that could cause CommonPrefixes
     * ("subdirectory paths") to be included in the results from S3, use the
     * {@link #listObjectsChunked(String, String, String, long, String, boolean)}
     * method instead of this one to obtain both object and CommonPrefix values.
     *
     * @param bucket
     * the bucket whose contents will be listed.
     * This must be a valid S3Bucket object that is non-null and contains a name.
     * @param prefix
     * only objects with a key that starts with this prefix will be listed
     * @param delimiter
     * only list objects with key names up to this delimiter, may be null.
     * See note above.
     * @param maxListingLength
     * the maximum number of objects to include in each result message sent by
     * S3. This value has <strong>no effect</strong> on the number of objects
     * that will be returned by this method, because it will always return all
     * the objects in the bucket.
     * @return
     * the set of objects contained in a bucket whose keys start with the given prefix.
     * @throws S3ServiceException
     */
    public S3Object[] listObjects(S3Bucket bucket, String prefix, String delimiter,
        long maxListingLength) throws S3ServiceException
    {
        assertValidBucket(bucket, "List objects in bucket");
        return listObjects(bucket.getName(), prefix, delimiter, maxListingLength);
    }

    /**
     * Lists the objects in a bucket matching a prefix, while instructing S3 to
     * send response messages containing no more than a given number of object
     * results.
     * <p>
     * The objects returned by this method contain only minimal information
     * such as the object's size, ETag, and LastModified timestamp. To retrieve
     * the objects' metadata you must perform follow-up <code>getObject</code>
     * or <code>getObjectDetails</code> operations.
     * <p>
     * This method can be performed by anonymous services. Anonymous services
     * can list the contents of a publicly-readable bucket.
     * <p>
     * NOTE: If you supply a delimiter value that could cause CommonPrefixes
     * ("subdirectory paths") to be included in the results from S3, use the
     * {@link #listObjectsChunked(String, String, String, long, String, boolean)}
     * method instead of this one to obtain both object and CommonPrefix values.
     *
     * @param bucketName
     * the name of the the bucket whose contents will be listed.
     * @param prefix
     * only objects with a key that starts with this prefix will be listed
     * @param delimiter
     * only list objects with key names up to this delimiter, may be null.
     * See note above.
     * @param maxListingLength
     * the maximum number of objects to include in each result message sent by
     * S3. This value has <strong>no effect</strong> on the number of objects
     * that will be returned by this method, because it will always return all
     * the objects in the bucket.
     * @return
     * the set of objects contained in a bucket whose keys start with the given prefix.
     * @throws S3ServiceException
     */
    public S3Object[] listObjects(String bucketName, String prefix, String delimiter,
        long maxListingLength) throws S3ServiceException
    {
        MxDelegate.getInstance().registerS3BucketListEvent(bucketName);
        S3Object[] objects = listObjectsImpl(bucketName, prefix, delimiter, maxListingLength);
        MxDelegate.getInstance().registerS3ObjectMBean(bucketName, objects);
        return objects;
    }

    /**
     * Lists versioning information in a versioned bucket where the objects
     * match a given constraints. The S3 service will also be instructed to send
     * response messages containing no more than a given number of object results.
     * <p>
     * This operation can only be performed by the bucket owner.
     *
     * @param bucketName
     * the name of the the versioned bucket whose contents will be listed.
     * @param prefix
     * only objects with a key that starts with this prefix will be listed
     * @param delimiter
     * only list objects with key names up to this delimiter, may be null.
     * See note above.
     * @return
     * the set of objects contained in a bucket whose keys start with the given prefix.
     * @throws S3ServiceException
     */
    public BaseVersionOrDeleteMarker[] listVersionedObjects(String bucketName, String prefix,
    	String delimiter)
        throws S3ServiceException
    {
        return listVersionedObjectsImpl(bucketName, prefix, delimiter, null, null, 1000);
    }

    /**
     * Return version information for a specific object.
     * <p>
     * This is a convenience function that applies logic in addition to the LISTVERSIONS
     * S3 operation to simplify retrieval of an object's version history. This method
     * is *not* the most efficient way of retrieving version history in bulk, so if you
     * need version history for multiple objects you should use the
     * {@link #listVersionedObjects(String, String, String)} or
     * {@link #listVersionedObjectsChunked(String, String, String, long, String, String, boolean)}
     * methods instead.
     *
     * @param bucketName
     * the name of the versioned bucket containing the object.
     * @param objectKey
     * the key identifying the object.
     * @return
     * an array of {@link S3Version} and {@link S3DeleteMarker} objects that describe
     * the version history of the given object.
     *
     * @throws S3ServiceException
     */
    public BaseVersionOrDeleteMarker[] getObjectVersions(String bucketName, String objectKey)
        throws S3ServiceException
    {
        BaseVersionOrDeleteMarker[] matchesForNamePrefix =
        	listVersionedObjectsImpl(bucketName, objectKey, null, null, null, 1000);
        // Limit results to only matches for the exact object key name
        int exactMatchCount = 0;
        for (int i = 0; i < matchesForNamePrefix.length && i <= exactMatchCount; i++) {
        	if (matchesForNamePrefix[i].getKey().equals(objectKey)) {
        		exactMatchCount++;
        	}
        }
        BaseVersionOrDeleteMarker[] exactMatches = new BaseVersionOrDeleteMarker[exactMatchCount];
        System.arraycopy(matchesForNamePrefix, 0, exactMatches, 0, exactMatchCount);
        return exactMatches;
    }

    /**
     * Lists the objects in a bucket matching a prefix, chunking the results into batches of
     * a given size, and returning each chunk separately. It is the responsibility of the caller
     * to building a complete bucket object listing by performing follow-up requests if necessary.
     * <p>
     * The objects returned by this method contain only minimal information
     * such as the object's size, ETag, and LastModified timestamp. To retrieve
     * the objects' metadata you must perform follow-up <code>getObject</code>
     * or <code>getObjectDetails</code> operations.
     * <p>
     * This method can be performed by anonymous services. Anonymous services
     * can list the contents of a publicly-readable bucket.
     *
     * @param bucketName
     * the name of the the bucket whose contents will be listed.
     * @param prefix
     * only objects with a key that starts with this prefix will be listed
     * @param maxListingLength
     * the maximum number of objects to include in each result chunk
     * @param priorLastKey
     * the last object key received in a prior call to this method. The next chunk of objects
     * listed will start with the next object in the bucket <b>after</b> this key name.
     * This parameter may be null, in which case the listing will start at the beginning of the
     * bucket's object contents.
     * @return
     * the set of objects contained in a bucket whose keys start with the given prefix.
     * @throws S3ServiceException
     */
    public S3ObjectsChunk listObjectsChunked(String bucketName, String prefix, String delimiter,
        long maxListingLength, String priorLastKey) throws S3ServiceException
    {
        MxDelegate.getInstance().registerS3BucketListEvent(bucketName);
        S3ObjectsChunk chunk = listObjectsChunkedImpl(bucketName, prefix, delimiter, maxListingLength,
            priorLastKey, false);
        MxDelegate.getInstance().registerS3ObjectMBean(bucketName, chunk.getObjects());
        return chunk;
    }

    /**
     * Lists the objects in a bucket matching a prefix and also returns the
     * common prefixes returned by S3. Depending on the value of the completeListing
     * variable, this method can be set to automatically perform follow-up requests
     * to build a complete object listing, or to return only a partial listing.
     * <p>
     * The objects returned by this method contain only minimal information
     * such as the object's size, ETag, and LastModified timestamp. To retrieve
     * the objects' metadata you must perform follow-up <code>getObject</code>
     * or <code>getObjectDetails</code> operations.
     * <p>
     * This method can be performed by anonymous services. Anonymous services
     * can list the contents of a publicly-readable bucket.
     *
     * @param bucketName
     * the name of the the bucket whose contents will be listed.
     * @param prefix
     * only objects with a key that starts with this prefix will be listed
     * @param maxListingLength
     * the maximum number of objects to include in each result chunk
     * @param priorLastKey
     * the last object key received in a prior call to this method. The next chunk of objects
     * listed will start with the next object in the bucket <b>after</b> this key name.
     * This parameter may be null, in which case the listing will start at the beginning of the
     * bucket's object contents.
     * @param completeListing
     * if true, the service class will automatically perform follow-up requests to
     * build a complete bucket object listing.
     * @return
     * the set of objects contained in a bucket whose keys start with the given prefix.
     * @throws S3ServiceException
     */
    public S3ObjectsChunk listObjectsChunked(String bucketName, String prefix, String delimiter,
        long maxListingLength, String priorLastKey, boolean completeListing) throws S3ServiceException
    {
        MxDelegate.getInstance().registerS3BucketListEvent(bucketName);
        S3ObjectsChunk chunk = listObjectsChunkedImpl(bucketName, prefix, delimiter,
            maxListingLength, priorLastKey, completeListing);
        MxDelegate.getInstance().registerS3ObjectMBean(bucketName, chunk.getObjects());
        return chunk;
    }

    /**
     * Lists information for a versioned bucket where the items match given constarints.
     * Depending on the value of the completeListing variable, this method can be set to
     * automatically perform follow-up requests to build a complete object listing, or to
     * return only a partial listing.
     * <p>
     * The objects returned by this method contain only minimal information
     * such as the object's size, ETag, and LastModified timestamp. To retrieve
     * the objects' metadata you must perform follow-up <code>getObject</code>
     * or <code>getObjectDetails</code> operations.
     * <p>
     * This method can be performed by anonymous services. Anonymous services
     * can list the contents of a publicly-readable bucket.
     *
     * @param bucketName
     * the name of the versioned bucket whose contents will be listed.
     * @param prefix
     * only objects with a key that starts with this prefix will be listed
     * @param maxListingLength
     * the maximum number of objects to include in each result chunk
     * @param priorLastKey
     * the last object key received in a prior call to this method. The next chunk of items
     * listed will start with the next object in the bucket <b>after</b> this key name.
     * This parameter may be null, in which case the listing will start at the beginning of the
     * bucket's object contents.
     * @param priorLastVersionId
     * the last version ID received in a prior call to this method. The next chunk of items
     * listed will start with the next object version <b>after</b> this version.
     * This parameter can only be used with a non-null priorLastKey.
     * @param completeListing
     * if true, the service class will automatically perform follow-up requests to
     * build a complete bucket object listing.
     * @return
     * the set of objects contained in a bucket whose keys start with the given prefix.
     * @throws S3ServiceException
     */
    public VersionOrDeleteMarkersChunk listVersionedObjectsChunked(String bucketName,
    	String prefix, String delimiter, long maxListingLength, String priorLastKey,
    	String priorLastVersionId, boolean completeListing) throws S3ServiceException
    {
        return listVersionedObjectsChunkedImpl(bucketName, prefix, delimiter,
            maxListingLength, priorLastKey, priorLastVersionId, completeListing);
    }

    /**
     * Creates a bucket in S3 based on the provided bucket object.
     * <b>Caution:</b> Performing this operation unnecessarily when a bucket already
     * exists may cause OperationAborted errors with the message "A conflicting conditional
     * operation is currently in progress against this resource.". To avoid this error, use the
     * {@link #getOrCreateBucket(String)} in situations where the bucket may already exist.
     * <p>
     * <b>Warning:</b> Prior to version 0.7.0 this method did check whether a bucket already
     * existed using {@link #isBucketAccessible(String)}. After changes to the way S3 operates,
     * this check started to cause issues so it was removed.
     * <p>
     * This method cannot be performed by anonymous services.
     *
     * @param bucket
     * an object representing the bucket to create which must be valid, and may contain ACL settings.
     * @return
     * the created bucket object, populated with all metadata made available by the creation operation.
     * @throws S3ServiceException
     */
    public S3Bucket createBucket(S3Bucket bucket) throws S3ServiceException {
        assertAuthenticatedConnection("Create Bucket");
        assertValidBucket(bucket, "Create Bucket");
        return createBucketImpl(bucket.getName(), bucket.getLocation(), bucket.getAcl());
    }

    /**
     * Returns a bucket in your S3 account by listing all your buckets
     * (using {@link #listAllBuckets()}), and looking for the named bucket in
     * this list.
     * <p>
     * This method cannot be performed by anonymous services.
     *
     * @param bucketName
     * @return
     * the bucket in your account, or null if you do not own the named bucket.
     *
     * @throws S3ServiceException
     */
    public S3Bucket getBucket(String bucketName) throws S3ServiceException {
        assertAuthenticatedConnection("Get Bucket");

        // List existing buckets and return the named bucket if it exists.
        S3Bucket[] existingBuckets = listAllBuckets();
        for (int i = 0; i < existingBuckets.length; i++) {
            if (existingBuckets[i].getName().equals(bucketName)) {
                return existingBuckets[i];
            }
        }
        return null;
    }

    /**
     * Returns a bucket in your S3 account, and creates the bucket in the given S3 location
     * if it does not yet exist.
     * <p>
     * Note: This method will not change the location of an existing bucket if you specify
     * a different location from a bucket's current location. To move a bucket between
     * locations you must first delete it in the original location, then re-create it
     * in the new location.
     *
     * @param bucketName
     * the name of the bucket to retrieve or create.
     * @param location
     * the location of the S3 data centre in which the bucket will be created. Valid values
     * include {@link S3Bucket#LOCATION_EUROPE}, {@link S3Bucket#LOCATION_US_WEST},
     * {@link S3Bucket#LOCATION_ASIA_PACIFIC}, and the default US location that can be
     * expressed in two ways:
     * {@link S3Bucket#LOCATION_US_STANDARD} or {@link S3Bucket#LOCATION_US}.
     * @return
     * the bucket in your account.
     *
     * @throws S3ServiceException
     */
    public S3Bucket getOrCreateBucket(String bucketName, String location)
        throws S3ServiceException
    {
        assertAuthenticatedConnection("Get or Create Bucket with location");

        S3Bucket bucket = getBucket(bucketName);
        if (bucket == null) {
            // Bucket does not exist in this user's account, create it.
            bucket = createBucket(new S3Bucket(bucketName, location));
        }
        return bucket;
    }

    /**
     * Returns a bucket in your S3 account, and creates the bucket in the default
     * location specified by the property "s3service.default-bucket-location" if
     * it does not yet exist.
     *
     * @param bucketName
     * the name of the bucket to retrieve or create.
     * @return
     * the bucket in your account.
     *
     * @throws S3ServiceException
     */
    public S3Bucket getOrCreateBucket(String bucketName) throws S3ServiceException {
        String defaultBucketLocation = jets3tProperties.getStringProperty(
                "s3service.default-bucket-location", S3Bucket.LOCATION_US);
        return getOrCreateBucket(bucketName, defaultBucketLocation);
    }

    /**
     * Deletes an S3 bucket. Only the owner of a bucket may delete it.
     * <p>
     * This method cannot be performed by anonymous services.
     *
     *
     * @param bucket
     * the bucket to delete.
     * @throws S3ServiceException
     */
    public void deleteBucket(S3Bucket bucket) throws S3ServiceException {
        assertValidBucket(bucket, "Delete bucket");
        deleteBucketImpl(bucket.getName());
    }

    /**
     * Deletes an S3 bucket. Only the owner of a bucket may delete it.
     * <p>
     * This method cannot be performed by anonymous services.
     *
     * @param bucketName
     * the name of the bucket to delete.
     * @throws S3ServiceException
     */
    public void deleteBucket(String bucketName) throws S3ServiceException {
        deleteBucketImpl(bucketName);
    }

    /**
     * Enable the S3 object versioning feature for a bucket.
     * Multi-factor authentication will not be required to delete versions.
     *
     * @param bucketName
     * the name of the bucket that will have versioning enabled.
     * @throws S3ServiceException
     */
    public void enableBucketVersioning(String bucketName) throws S3ServiceException
    {
        updateBucketVersioningStatusImpl(bucketName, true, false, null, null);
    }

    /**
     * Enable the S3 object versioning feature and also enable the
     * multi-factor authentication (MFA) feature for a bucket which
     * does not yet have MFA enabled.
     *
     * @param bucketName
     * the name of the bucket that will have versioning enabled.
     * @throws S3ServiceException
     */
    public void enableBucketVersioningAndMFA(String bucketName)
        throws S3ServiceException
    {
        updateBucketVersioningStatusImpl(bucketName, true, true, null, null);
    }

    /**
     * Enable the S3 object versioning feature for a bucket that
     * already has multi-factor authentication (MFA) enabled.
     *
     * @param bucketName
     * the name of the bucket that will have versioning enabled.
     * @param multiFactorSerialNumber
     * the serial number for a multi-factor authentication device.
     * @param multiFactorAuthCode
     * a multi-factor authentication code generated by a device.
     * @throws S3ServiceException
     */
    public void enableBucketVersioningWithMFA(String bucketName,
        String multiFactorSerialNumber, String multiFactorAuthCode)
        throws S3ServiceException
    {
        updateBucketVersioningStatusImpl(bucketName, true, true,
            multiFactorSerialNumber, multiFactorAuthCode);
    }

    /**
     * Disable the multi-factor authentication (MFA) feature for a
     * bucket that already has S3 object versioning and MFA enabled.
     *
     * @param bucketName
     * the name of the bucket that will have versioning enabled.
     * versioning status of the bucket.
     * @param multiFactorSerialNumber
     * the serial number for a multi-factor authentication device.
     * @param multiFactorAuthCode
     * a multi-factor authentication code generated by a device.
     * @throws S3ServiceException
     */
    public void disableMFAForVersionedBucket(String bucketName,
    	String multiFactorSerialNumber, String multiFactorAuthCode)
        throws S3ServiceException
    {
        updateBucketVersioningStatusImpl(bucketName, true, false,
    		multiFactorSerialNumber, multiFactorAuthCode);
    }

    /**
     * Suspend (disable) the S3 object versioning feature for a bucket.
     * The bucket must not have the multi-factor authentication (MFA)
     * feature enabled.
     *
     * @param bucketName
     * the name of the versioned bucket that will have versioning suspended.
     * @throws S3ServiceException
     */
    public void suspendBucketVersioning(String bucketName)
    	throws S3ServiceException
    {
        updateBucketVersioningStatusImpl(bucketName, false, false, null, null);
    }

    /**
     * Suspend (disable) the S3 object versioning feature for a bucket that
     * requires multi-factor authentication.
     *
     * @param bucketName
     * the name of the versioned bucket that will have versioning suspended.
     * @param multiFactorSerialNumber
     * the serial number for a multi-factor authentication device.
     * @param multiFactorAuthCode
     * a multi-factor authentication code generated by a device.
     * @throws S3ServiceException
     */
    public void suspendBucketVersioningWithMFA(String bucketName,
    	String multiFactorSerialNumber, String multiFactorAuthCode)
        throws S3ServiceException
    {
        updateBucketVersioningStatusImpl(bucketName, false,
    		false, multiFactorSerialNumber, multiFactorAuthCode);
    }

    /**
     * Return versioning status of bucket, which reports on whether the given bucket
     * has S3 object versioning enabled and whether multi-factor authentication is
     * required to delete versions.
     *
     * @param bucketName
     * the name of the bucket.
     * @throws S3ServiceException
     */
    public S3BucketVersioningStatus getBucketVersioningStatus(String bucketName)
        throws S3ServiceException
    {
        return getBucketVersioningStatusImpl(bucketName);
    }

    /**
     * Puts an object inside an existing bucket in S3, creating a new object or overwriting
     * an existing one with the same key.
     * <p>
     * This method can be performed by anonymous services. Anonymous services
     * can put objects into a publicly-writable bucket.
     *
     * @param bucketName
     * the name of the bucket inside which the object will be put.
     * @param object
     * the object containing all information that will be written to S3. At very least this object must
     * be valid. Beyond that it may contain: an input stream with the object's data content, metadata,
     * and access control settings.<p>
     * <b>Note:</b> It is very important to set the object's Content-Length to match the size of the
     * data input stream when possible, as this can remove the need to read data into memory to
     * determine its size.
     *
     * @return
     * the object populated with any metadata information made available by S3.
     * @throws S3ServiceException
     */
    public S3Object putObject(String bucketName, S3Object object) throws S3ServiceException {
        assertValidObject(object, "Create Object in bucket " + bucketName);
        MxDelegate.getInstance().registerS3ObjectPutEvent(bucketName, object.getKey());
        return putObjectImpl(bucketName, object);
    }

    /**
     * Copy an object within your S3 account. You can copy an object within a
     * single bucket or between buckets, and can optionally update the object's
     * metadata at the same time.
     * <p>
     * This method cannot be performed by anonymous services. You must have read
     * access to the source object and write access to the destination bucket.
     * <p>
     * An object can be copied over itself, in which case you can update its
     * metadata without making any other changes.
     *
     * @param sourceBucketName
     * the name of the bucket that contains the original object.
     * @param sourceObjectKey
     * the key name of the original object.
     * @param destinationBucketName
     * the name of the destination bucket to which the object will be copied.
     * @param destinationObject
     * the object that will be created by the copy operation. If this item
     * includes an AccessControlList setting the copied object will be assigned
     * that ACL, otherwise the copied object will be assigned the default private
     * ACL setting.
     * @param replaceMetadata
     * If this parameter is true, the copied object will be assigned the metadata
     * values present in the destinationObject. Otherwise, the copied object will
     * have the same metadata as the original object.
     * @param ifModifiedSince
     * a precondition specifying a date after which the object must have been
     * modified, ignored if null.
     * @param ifUnmodifiedSince
     * a precondition specifying a date after which the object must not have
     * been modified, ignored if null.
     * @param ifMatchTags
     * a precondition specifying an MD5 hash the object must match, ignored if
     * null.
     * @param ifNoneMatchTags
     * a precondition specifying an MD5 hash the object must not match, ignored
     * if null.
     *
     * @return
     * a map of the header and result information returned by S3 after the object
     * copy. The map includes the object's MD5 hash value (ETag), its size
     * (Content-Length), and update timestamp (Last-Modified).
     *
     * @throws S3ServiceException
     */
    public Map copyObject(String sourceBucketName, String sourceObjectKey,
        String destinationBucketName, S3Object destinationObject, boolean replaceMetadata,
        Calendar ifModifiedSince, Calendar ifUnmodifiedSince, String[] ifMatchTags,
        String[] ifNoneMatchTags) throws S3ServiceException
    {
        assertAuthenticatedConnection("copyObject");
        Map destinationMetadata =
            replaceMetadata ? destinationObject.getModifiableMetadata() : null;

        MxDelegate.getInstance().registerS3ObjectCopyEvent(sourceBucketName, sourceObjectKey);
        return copyObjectImpl(sourceBucketName, sourceObjectKey,
            destinationBucketName, destinationObject.getKey(),
            destinationObject.getAcl(), destinationMetadata,
            ifModifiedSince, ifUnmodifiedSince, ifMatchTags, ifNoneMatchTags, null,
            destinationObject.getStorageClass());
    }

    /**
     * Copy an object with a specific version within your S3 account. You can copy an object
     * within a single bucket or between buckets, and can optionally update the object's
     * metadata at the same time.
     * <p>
     * This method cannot be performed by anonymous services. You must have read
     * access to the source object and write access to the destination bucket.
     * <p>
     * An object can be copied over itself, in which case you can update its
     * metadata without making any other changes.
     *
     * @param versionId
     * identifier matching an existing object version that will be copied.
     * @param sourceBucketName
     * the name of the versioned bucket that contains the original object.
     * @param sourceObjectKey
     * the key name of the original object.
     * @param destinationBucketName
     * the name of the destination bucket to which the object will be copied.
     * @param destinationObject
     * the object that will be created by the copy operation. If this item
     * includes an AccessControlList setting the copied object will be assigned
     * that ACL, otherwise the copied object will be assigned the default private
     * ACL setting.
     * @param replaceMetadata
     * If this parameter is true, the copied object will be assigned the metadata
     * values present in the destinationObject. Otherwise, the copied object will
     * have the same metadata as the original object.
     * @param ifModifiedSince
     * a precondition specifying a date after which the object must have been
     * modified, ignored if null.
     * @param ifUnmodifiedSince
     * a precondition specifying a date after which the object must not have
     * been modified, ignored if null.
     * @param ifMatchTags
     * a precondition specifying an MD5 hash the object must match, ignored if
     * null.
     * @param ifNoneMatchTags
     * a precondition specifying an MD5 hash the object must not match, ignored
     * if null.
     *
     * @return
     * a map of the header and result information returned by S3 after the object
     * copy. The map includes the object's MD5 hash value (ETag), its size
     * (Content-Length), and update timestamp (Last-Modified).
     *
     * @throws S3ServiceException
     */
    public Map copyVersionedObject(String versionId, String sourceBucketName,
    	String sourceObjectKey, String destinationBucketName, S3Object destinationObject,
    	boolean replaceMetadata, Calendar ifModifiedSince,
    	Calendar ifUnmodifiedSince, String[] ifMatchTags,
        String[] ifNoneMatchTags) throws S3ServiceException
    {
        assertAuthenticatedConnection("copyVersionedObject");
        Map destinationMetadata =
            replaceMetadata ? destinationObject.getModifiableMetadata() : null;

        MxDelegate.getInstance().registerS3ObjectCopyEvent(sourceBucketName, sourceObjectKey);
        return copyObjectImpl(sourceBucketName, sourceObjectKey,
            destinationBucketName, destinationObject.getKey(),
            destinationObject.getAcl(), destinationMetadata,
            ifModifiedSince, ifUnmodifiedSince, ifMatchTags, ifNoneMatchTags, versionId,
            destinationObject.getStorageClass());
    }


    /**
     * Copy an object within your S3 account. You can copy an object within a
     * single bucket or between buckets, and can optionally update the object's
     * metadata at the same time.
     * <p>
     * This method cannot be performed by anonymous services. You must have read
     * access to the source object and write access to the destination bucket.
     * <p>
     * An object can be copied over itself, in which case you can update its
     * metadata without making any other changes.
     *
     * @param sourceBucketName
     * the name of the bucket that contains the original object.
     * @param sourceObjectKey
     * the key name of the original object.
     * @param destinationBucketName
     * the name of the destination bucket to which the object will be copied.
     * @param destinationObject
     * the object that will be created by the copy operation. If this item
     * includes an AccessControlList setting the copied object will be assigned
     * that ACL, otherwise the copied object will be assigned the default private
     * ACL setting.
     * @param replaceMetadata
     * If this parameter is true, the copied object will be assigned the metadata
     * values present in the destinationObject. Otherwise, the copied object will
     * have the same metadata as the original object.
     *
     * @return
     * a map of the header and result information returned by S3 after the object
     * copy. The map includes the object's MD5 hash value (ETag), its size
     * (Content-Length), and update timestamp (Last-Modified).
     *
     * @throws S3ServiceException
     */
    public Map copyObject(String sourceBucketName, String sourceObjectKey,
        String destinationBucketName, S3Object destinationObject,
        boolean replaceMetadata) throws S3ServiceException
    {
        return copyObject(sourceBucketName, sourceObjectKey, destinationBucketName,
            destinationObject, replaceMetadata, null, null, null, null);
    }

    /**
     * Copy an object with a specific version within your S3 account. You can copy an object
     * within a single bucket or between buckets, and can optionally update the object's
     * metadata at the same time.
     * <p>
     * This method cannot be performed by anonymous services. You must have read
     * access to the source object and write access to the destination bucket.
     * <p>
     * An object can be copied over itself, in which case you can update its
     * metadata without making any other changes.
     *
     * @param versionId
     * identifier matching an existing object version that will be copied.
     * @param sourceBucketName
     * the name of the versioned bucket that contains the original object.
     * @param sourceObjectKey
     * the key name of the original object.
     * @param destinationBucketName
     * the name of the destination bucket to which the object will be copied.
     * @param destinationObject
     * the object that will be created by the copy operation. If this item
     * includes an AccessControlList setting the copied object will be assigned
     * that ACL, otherwise the copied object will be assigned the default private
     * ACL setting.
     * @param replaceMetadata
     * If this parameter is true, the copied object will be assigned the metadata
     * values present in the destinationObject. Otherwise, the copied object will
     * have the same metadata as the original object.
     *
     * @return
     * a map of the header and result information returned by S3 after the object
     * copy. The map includes the object's MD5 hash value (ETag), its size
     * (Content-Length), and update timestamp (Last-Modified).
     *
     * @throws S3ServiceException
     */
    public Map copyVersionedObject(String versionId, String sourceBucketName, String sourceObjectKey,
        String destinationBucketName, S3Object destinationObject,
        boolean replaceMetadata) throws S3ServiceException
    {
        return copyVersionedObject(versionId, sourceBucketName, sourceObjectKey,
        	destinationBucketName, destinationObject, replaceMetadata, null, null, null, null);
    }

    /**
     * Move an object from your S3 account. This method works by invoking the
     * {@link #copyObject(String, String, String, S3Object, boolean)} method to
     * copy the original object, then deletes the original object once the
     * copy has succeeded.
     * <p>
     * This method cannot be performed by anonymous services. You must have read
     * access to the source object, write access to the destination bucket, and
     * write access to the source bucket.
     * <p>
     * If the copy operation succeeds but the delete operation fails, this
     * method will not throw an exception but the result map object will contain
     * an item named "DeleteException" with the exception thrown by the delete
     * operation.
     *
     * @param sourceBucketName
     * the name of the bucket that contains the original object.
     * @param sourceObjectKey
     * the key name of the original object.
     * @param destinationBucketName
     * the name of the destination bucket to which the object will be copied.
     * @param destinationObject
     * the object that will be created by the move operation. If this item
     * includes an AccessControlList setting the copied object will be assigned
     * that ACL, otherwise the copied object will be assigned the default private
     * ACL setting.
     * @param replaceMetadata
     * If this parameter is true, the copied object will be assigned the metadata
     * values present in the destinationObject. Otherwise, the copied object will
     * have the same metadata as the original object.
     *
     * @return
     * a map of the header and result information returned by S3 after the object
     * copy. The map includes the object's MD5 hash value (ETag), its size
     * (Content-Length), and update timestamp (Last-Modified). If the object was
     * successfully copied but the original could not be deleted, the map will
     * also include an item named "DeleteException" with the exception thrown by
     * the delete operation.
     *
     * @throws S3ServiceException
     */
    public Map moveObject(String sourceBucketName, String sourceObjectKey,
        String destinationBucketName, S3Object destinationObject,
        boolean replaceMetadata) throws S3ServiceException
    {
        Map copyResult = copyObject(sourceBucketName, sourceObjectKey,
            destinationBucketName, destinationObject, replaceMetadata);

        try {
            deleteObject(sourceBucketName, sourceObjectKey);
        } catch (Exception e) {
            copyResult.put("DeleteException", e);
        }
        return copyResult;
    }

    /**
     * Rename an object in your S3 account. This method works by invoking the
     * {@link #moveObject(String, String, String, S3Object, boolean)} method to
     * move the original object to a new key name.
     * <p>
     * The original object's metadata is retained, but to apply an access
     * control setting other than private you must specify an ACL in the
     * destination object.
     * <p>
     * This method cannot be performed by anonymous services. You must have
     * write access to the source object and write access to the bucket.
     *
     * @param bucketName
     * the name of the bucket containing the original object that will be copied.
     * @param sourceObjectKey
     * the key name of the original object.
     * @param destinationObject
     * the object that will be created by the rename operation. If this item
     * includes an AccessControlList setting the copied object will be assigned
     * that ACL, otherwise the copied object will be assigned the default private
     * ACL setting.
     *
     * @return
     * a map of the header and result information returned by S3 after the object
     * copy. The map includes the object's MD5 hash value (ETag), its size
     * (Content-Length), and update timestamp (Last-Modified). If the object was
     * successfully copied but the original could not be deleted, the map will
     * also include an item named "DeleteException" with the exception thrown by
     * the delete operation.
     *
     * @throws S3ServiceException
     */
    public Map renameObject(String bucketName, String sourceObjectKey,
        S3Object destinationObject) throws S3ServiceException
    {
        return moveObject(bucketName, sourceObjectKey,
            bucketName, destinationObject, false);
    }

    /**
     * Update an object's metadata. This method works by invoking the
     * {@link #copyObject(String, String, String, S3Object, boolean)} method to
     * copy the original object over itself, applying the new metadata in the
     * process.
     *
     * @param bucketName
     * the name of the bucket containing the object that will be updated.
     * @param object
     * the object that will be updated. If this item includes an
     * AccessControlList setting the copied object will be assigned
     * that ACL, otherwise the copied object will be assigned the default private
     * ACL setting.
     *
     * @return
     * a map of the header and result information returned by S3 after the object
     * copy. The map includes the object's MD5 hash value (ETag), its size
     * (Content-Length), and update timestamp (Last-Modified).
     *
     * @throws S3ServiceException
     */
    public Map updateObjectMetadata(String bucketName, S3Object object)
        throws S3ServiceException
    {
        return copyObject(bucketName, object.getKey(),
            bucketName, object, true);
    }

    /**
     * Puts an object inside an existing bucket in S3, creating a new object or overwriting
     * an existing one with the same key.
     * <p>
     * This method can be performed by anonymous services. Anonymous services
     * can put objects into a publicly-writable bucket.
     *
     * @param bucket
     * the bucket inside which the object will be put, which must be valid.
     * @param object
     * the object containing all information that will be written to S3. At very least this object must
     * be valid. Beyond that it may contain: an input stream with the object's data content, metadata,
     * and access control settings.<p>
     * <b>Note:</b> It is very important to set the object's Content-Length to match the size of the
     * data input stream when possible, as this can remove the need to read data into memory to
     * determine its size.
     *
     * @return
     * the object populated with any metadata information made available by S3.
     * @throws S3ServiceException
     */
    public S3Object putObject(S3Bucket bucket, S3Object object) throws S3ServiceException {
        assertValidBucket(bucket, "Create Object in bucket");
        return putObject(bucket.getName(), object);
    }

    /**
     * Deletes an object from a bucket in S3.
     * <p>
     * This method can be performed by anonymous services. Anonymous services
     * can delete objects from publicly-writable buckets.
     *
     * @param bucket
     * the bucket containing the object to be deleted.
     * @param objectKey
     * the key representing the object in S3.
     * @throws S3ServiceException
     */
    public void deleteObject(S3Bucket bucket, String objectKey) throws S3ServiceException {
        assertValidBucket(bucket, "deleteObject");
        assertValidObject(objectKey, "deleteObject");
        deleteObject(bucket.getName(), objectKey);
    }

    /**
     * Deletes an object from a bucket in S3.
     * <p>
     * This method can be performed by anonymous services. Anonymous services
     * can delete objects from publicly-writable buckets.
     *
     * @param bucketName
     * the name of the bucket containing the object to be deleted.
     * @param objectKey
     * the key representing the object in S3.
     * @throws S3ServiceException
     */
    public void deleteObject(String bucketName, String objectKey) throws S3ServiceException {
        assertValidObject(objectKey, "deleteObject");
        MxDelegate.getInstance().registerS3ObjectDeleteEvent(bucketName, objectKey);
        deleteObjectImpl(bucketName, objectKey, null, null, null);
    }

    /**
     * Deletes a object version from a bucket in S3. This will delete only the specific
     * version identified and will not affect any other Version or DeleteMarkers related
     * to the object.
     * <p>
     * This operation can only be performed by the owner of the S3 bucket.
     *
     * @param versionId
     * the identifier of an object version that will be deleted.
     * @param multiFactorSerialNumber
     * the serial number for a multi-factor authentication device.
     * @param multiFactorAuthCode
     * a multi-factor authentication code generated by a device.
     * @param bucketName
     * the name of the versioned bucket containing the object to be deleted.
     * @param objectKey
     * the key representing the object in S3.
     * @throws S3ServiceException
     */
    public void deleteVersionedObjectWithMFA(String versionId,
        String multiFactorSerialNumber, String multiFactorAuthCode,
    	String bucketName, String objectKey) throws S3ServiceException
    {
        assertValidObject(objectKey, "deleteVersionedObjectWithMFA");
        MxDelegate.getInstance().registerS3ObjectDeleteEvent(bucketName, objectKey);
        deleteObjectImpl(bucketName, objectKey, versionId,
        	multiFactorSerialNumber, multiFactorAuthCode);
    }

    /**
     * Deletes a object version from a bucket in S3. This will delete only the specific
     * version identified and will not affect any other Version or DeleteMarkers related
     * to the object.
     * <p>
     * This operation can only be performed by the owner of the S3 bucket.
     *
     * @param versionId
     * the identifier of an object version that will be deleted.
     * @param bucketName
     * the name of the versioned bucket containing the object to be deleted.
     * @param objectKey
     * the key representing the object in S3.
     * @throws S3ServiceException
     */
    public void deleteVersionedObject(String versionId, String bucketName, String objectKey)
        throws S3ServiceException
    {
        assertValidObject(objectKey, "deleteVersionedObject");
        MxDelegate.getInstance().registerS3ObjectDeleteEvent(bucketName, objectKey);
        deleteObjectImpl(bucketName, objectKey, versionId, null, null);
    }

    /**
     * Returns an object representing the details of an item in S3 that meets any given preconditions.
     * The object is returned without the object's data.
     * <p>
     * An exception is thrown if any of the preconditions fail.
     * Preconditions are only applied if they are non-null.
     * <p>
     * This method can be performed by anonymous services. Anonymous services
     * can get details of publicly-readable objects.
     *
     * @param bucket
     * the bucket containing the object.
     * This must be a valid S3Bucket object that is non-null and contains a name.
     * @param objectKey
     * the key identifying the object.
     * @param ifModifiedSince
     * a precondition specifying a date after which the object must have been modified, ignored if null.
     * @param ifUnmodifiedSince
     * a precondition specifying a date after which the object must not have been modified, ignored if null.
     * @param ifMatchTags
     * a precondition specifying an MD5 hash the object must match, ignored if null.
     * @param ifNoneMatchTags
     * a precondition specifying an MD5 hash the object must not match, ignored if null.
     * @return
     * the object with the given key in S3, including only general details and metadata (not the data
     * input stream)
     * @throws S3ServiceException
     */
    public S3Object getObjectDetails(S3Bucket bucket, String objectKey,
        Calendar ifModifiedSince, Calendar ifUnmodifiedSince, String[] ifMatchTags,
        String[] ifNoneMatchTags) throws S3ServiceException
    {
        assertValidBucket(bucket, "Get Object Details");
        MxDelegate.getInstance().registerS3ObjectHeadEvent(bucket.getName(), objectKey);
        return getObjectDetailsImpl(bucket.getName(), objectKey, ifModifiedSince, ifUnmodifiedSince,
            ifMatchTags, ifNoneMatchTags, null);
    }

    /**
     * Returns an object representing the details of a versioned object in S3 that also
     * meets any given preconditions. The object is returned without the object's data.
     * <p>
     * An exception is thrown if any of the preconditions fail.
     * Preconditions are only applied if they are non-null.
     * <p>
     * This method can be performed by anonymous services. Anonymous services
     * can get details of publicly-readable objects.
     *
     * @param versionId
     * the identifier of the object version to return.
     * @param bucket
     * the versioned bucket containing the object.
     * This must be a valid S3Bucket object that is non-null and contains a name.
     * @param objectKey
     * the key identifying the object.
     * @param ifModifiedSince
     * a precondition specifying a date after which the object must have been modified, ignored if null.
     * @param ifUnmodifiedSince
     * a precondition specifying a date after which the object must not have been modified, ignored if null.
     * @param ifMatchTags
     * a precondition specifying an MD5 hash the object must match, ignored if null.
     * @param ifNoneMatchTags
     * a precondition specifying an MD5 hash the object must not match, ignored if null.
     * @return
     * the object with the given key in S3, including only general details and metadata (not the data
     * input stream)
     * @throws S3ServiceException
     */
    public S3Object getVersionedObjectDetails(String versionId, S3Bucket bucket, String objectKey,
        Calendar ifModifiedSince, Calendar ifUnmodifiedSince, String[] ifMatchTags,
        String[] ifNoneMatchTags) throws S3ServiceException
    {
        assertValidBucket(bucket, "Get Versioned Object Details");
        MxDelegate.getInstance().registerS3ObjectHeadEvent(bucket.getName(), objectKey);
        return getObjectDetailsImpl(bucket.getName(), objectKey, ifModifiedSince, ifUnmodifiedSince,
            ifMatchTags, ifNoneMatchTags, versionId);
    }

    /**
     * Returns an object representing the details of an item in S3 that meets any given preconditions.
     * The object is returned without the object's data.
     * <p>
     * An exception is thrown if any of the preconditions fail.
     * Preconditions are only applied if they are non-null.
     * <p>
     * This method can be performed by anonymous services. Anonymous services
     * can get details of publicly-readable objects.
     *
     * @param bucketName
     * the name of the bucket containing the object.
     * @param objectKey
     * the key identifying the object.
     * @param ifModifiedSince
     * a precondition specifying a date after which the object must have been modified, ignored if null.
     * @param ifUnmodifiedSince
     * a precondition specifying a date after which the object must not have been modified, ignored if null.
     * @param ifMatchTags
     * a precondition specifying an MD5 hash the object must match, ignored if null.
     * @param ifNoneMatchTags
     * a precondition specifying an MD5 hash the object must not match, ignored if null.
     * @return
     * the object with the given key in S3, including only general details and metadata (not the data
     * input stream)
     * @throws S3ServiceException
     */
    public S3Object getObjectDetails(String bucketName, String objectKey,
        Calendar ifModifiedSince, Calendar ifUnmodifiedSince, String[] ifMatchTags,
        String[] ifNoneMatchTags) throws S3ServiceException
    {
        MxDelegate.getInstance().registerS3ObjectHeadEvent(bucketName, objectKey);
        return getObjectDetailsImpl(bucketName, objectKey, ifModifiedSince, ifUnmodifiedSince,
            ifMatchTags, ifNoneMatchTags, null);
    }

    /**
     * Returns an object representing the details of a versioned object in S3 that also meets
     * any given preconditions. The object is returned without the object's data.
     * <p>
     * An exception is thrown if any of the preconditions fail.
     * Preconditions are only applied if they are non-null.
     * <p>
     * This method can be performed by anonymous services. Anonymous services
     * can get details of publicly-readable objects.
     *
     * @param versionId
     * the identifier of the object version to return.
     * @param bucketName
     * the name of the versioned bucket containing the object.
     * @param objectKey
     * the key identifying the object.
     * @param ifModifiedSince
     * a precondition specifying a date after which the object must have been modified, ignored if null.
     * @param ifUnmodifiedSince
     * a precondition specifying a date after which the object must not have been modified, ignored if null.
     * @param ifMatchTags
     * a precondition specifying an MD5 hash the object must match, ignored if null.
     * @param ifNoneMatchTags
     * a precondition specifying an MD5 hash the object must not match, ignored if null.
     * @return
     * the object with the given key in S3, including only general details and metadata (not the data
     * input stream)
     * @throws S3ServiceException
     */
    public S3Object getVersionedObjectDetails(String versionId, String bucketName, String objectKey,
        Calendar ifModifiedSince, Calendar ifUnmodifiedSince, String[] ifMatchTags,
        String[] ifNoneMatchTags) throws S3ServiceException
    {
        MxDelegate.getInstance().registerS3ObjectHeadEvent(bucketName, objectKey);
        return getObjectDetailsImpl(bucketName, objectKey, ifModifiedSince, ifUnmodifiedSince,
            ifMatchTags, ifNoneMatchTags, versionId);
    }

    /**
     * Returns an object representing the details and data of an item in S3 that meets any given preconditions.
     * <p>
     * <b>Important:</b> It is the caller's responsibility to close the object's data input stream.
     * The data stream should be consumed and closed as soon as is practical as network connections
     * may be held open until the streams are closed. Excessive unclosed streams can lead to
     * connection starvation.
     * <p>
     * An exception is thrown if any of the preconditions fail.
     * Preconditions are only applied if they are non-null.
     * <p>
     * This method can be performed by anonymous services. Anonymous services
     * can get publicly-readable objects.
     * <p>
     * <b>Implementation notes</b><p>
     * Implementations should use {@link #assertValidBucket} assertion.
     *
     * @param bucket
     * the bucket containing the object.
     * This must be a valid S3Bucket object that is non-null and contains a name.
     * @param objectKey
     * the key identifying the object.
     * @param ifModifiedSince
     * a precondition specifying a date after which the object must have been modified, ignored if null.
     * @param ifUnmodifiedSince
     * a precondition specifying a date after which the object must not have been modified, ignored if null.
     * @param ifMatchTags
     * a precondition specifying an MD5 hash the object must match, ignored if null.
     * @param ifNoneMatchTags
     * a precondition specifying an MD5 hash the object must not match, ignored if null.
     * @param byteRangeStart
     * include only a portion of the object's data - starting at this point, ignored if null.
     * @param byteRangeEnd
     * include only a portion of the object's data - ending at this point, ignored if null.
     * @return
     * the object with the given key in S3, including only general details and metadata (not the data
     * input stream)
     * @throws S3ServiceException
     */
    public S3Object getObject(S3Bucket bucket, String objectKey, Calendar ifModifiedSince,
        Calendar ifUnmodifiedSince, String[] ifMatchTags, String[] ifNoneMatchTags,
        Long byteRangeStart, Long byteRangeEnd) throws S3ServiceException
    {
        assertValidBucket(bucket, "Get Object");
        MxDelegate.getInstance().registerS3ObjectGetEvent(bucket.getName(), objectKey);
        return getObjectImpl(bucket.getName(), objectKey, ifModifiedSince, ifUnmodifiedSince,
            ifMatchTags, ifNoneMatchTags, byteRangeStart, byteRangeEnd, null);
    }

    /**
     * Returns an object representing the details and data of a versioned object in S3 that
     * also meets any given preconditions.
     * <p>
     * <b>Important:</b> It is the caller's responsibility to close the object's data input stream.
     * The data stream should be consumed and closed as soon as is practical as network connections
     * may be held open until the streams are closed. Excessive unclosed streams can lead to
     * connection starvation.
     * <p>
     * An exception is thrown if any of the preconditions fail.
     * Preconditions are only applied if they are non-null.
     * <p>
     * This method can be performed by anonymous services. Anonymous services
     * can get publicly-readable objects.
     * <p>
     * <b>Implementation notes</b><p>
     * Implementations should use {@link #assertValidBucket} assertion.
     *
     * @param versionId
     * the identifier of the object version to return.
     * @param bucket
     * the versioned bucket containing the object.
     * This must be a valid S3Bucket object that is non-null and contains a name.
     * @param objectKey
     * the key identifying the object.
     * @param ifModifiedSince
     * a precondition specifying a date after which the object must have been modified, ignored if null.
     * @param ifUnmodifiedSince
     * a precondition specifying a date after which the object must not have been modified, ignored if null.
     * @param ifMatchTags
     * a precondition specifying an MD5 hash the object must match, ignored if null.
     * @param ifNoneMatchTags
     * a precondition specifying an MD5 hash the object must not match, ignored if null.
     * @param byteRangeStart
     * include only a portion of the object's data - starting at this point, ignored if null.
     * @param byteRangeEnd
     * include only a portion of the object's data - ending at this point, ignored if null.
     * @return
     * the object with the given key in S3, including only general details and metadata (not the data
     * input stream)
     * @throws S3ServiceException
     */
    public S3Object getVersionedObject(String versionId, S3Bucket bucket, String objectKey,
    	Calendar ifModifiedSince, Calendar ifUnmodifiedSince,
    	String[] ifMatchTags, String[] ifNoneMatchTags,
        Long byteRangeStart, Long byteRangeEnd) throws S3ServiceException
    {
        assertValidBucket(bucket, "Get Versioned Object");
        MxDelegate.getInstance().registerS3ObjectGetEvent(bucket.getName(), objectKey);
        return getObjectImpl(bucket.getName(), objectKey, ifModifiedSince, ifUnmodifiedSince,
            ifMatchTags, ifNoneMatchTags, byteRangeStart, byteRangeEnd, versionId);
    }

    /**
     * Returns an object representing the details and data of an item in S3 that meets any given preconditions.
     * <p>
     * <b>Important:</b> It is the caller's responsibility to close the object's data input stream.
     * The data stream should be consumed and closed as soon as is practical as network connections
     * may be held open until the streams are closed. Excessive unclosed streams can lead to
     * connection starvation.
     * <p>
     * An exception is thrown if any of the preconditions fail.
     * Preconditions are only applied if they are non-null.
     * <p>
     * This method can be performed by anonymous services. Anonymous services
     * can get a publicly-readable object.
     * <p>
     * <b>Implementation notes</b><p>
     * Implementations should use {@link #assertValidBucket} assertion.
     *
     * @param bucketName
     * the name of the bucket containing the object.
     * @param objectKey
     * the key identifying the object.
     * @param ifModifiedSince
     * a precondition specifying a date after which the object must have been modified, ignored if null.
     * @param ifUnmodifiedSince
     * a precondition specifying a date after which the object must not have been modified, ignored if null.
     * @param ifMatchTags
     * a precondition specifying an MD5 hash the object must match, ignored if null.
     * @param ifNoneMatchTags
     * a precondition specifying an MD5 hash the object must not match, ignored if null.
     * @param byteRangeStart
     * include only a portion of the object's data - starting at this point, ignored if null.
     * @param byteRangeEnd
     * include only a portion of the object's data - ending at this point, ignored if null.
     * @return
     * the object with the given key in S3, including only general details and metadata (not the data
     * input stream)
     * @throws S3ServiceException
     */
    public S3Object getObject(String bucketName, String objectKey, Calendar ifModifiedSince,
        Calendar ifUnmodifiedSince, String[] ifMatchTags, String[] ifNoneMatchTags,
        Long byteRangeStart, Long byteRangeEnd) throws S3ServiceException
    {
        MxDelegate.getInstance().registerS3ObjectGetEvent(bucketName, objectKey);
        return getObjectImpl(bucketName, objectKey, ifModifiedSince, ifUnmodifiedSince,
            ifMatchTags, ifNoneMatchTags, byteRangeStart, byteRangeEnd, null);
    }

    /**
     * Returns an object representing the details and data of a versioned object in S3 that
     * also meets any given preconditions.
     * <p>
     * <b>Important:</b> It is the caller's responsibility to close the object's data input stream.
     * The data stream should be consumed and closed as soon as is practical as network connections
     * may be held open until the streams are closed. Excessive unclosed streams can lead to
     * connection starvation.
     * <p>
     * An exception is thrown if any of the preconditions fail.
     * Preconditions are only applied if they are non-null.
     * <p>
     * This method can be performed by anonymous services. Anonymous services
     * can get a publicly-readable object.
     * <p>
     * <b>Implementation notes</b><p>
     * Implementations should use {@link #assertValidBucket} assertion.
     *
     * @param versionId
     * the identifier of the object version to return.
     * @param bucketName
     * the name of the versioned bucket containing the object.
     * @param objectKey
     * the key identifying the object.
     * @param ifModifiedSince
     * a precondition specifying a date after which the object must have been modified, ignored if null.
     * @param ifUnmodifiedSince
     * a precondition specifying a date after which the object must not have been modified, ignored if null.
     * @param ifMatchTags
     * a precondition specifying an MD5 hash the object must match, ignored if null.
     * @param ifNoneMatchTags
     * a precondition specifying an MD5 hash the object must not match, ignored if null.
     * @param byteRangeStart
     * include only a portion of the object's data - starting at this point, ignored if null.
     * @param byteRangeEnd
     * include only a portion of the object's data - ending at this point, ignored if null.
     * @return
     * the object with the given key in S3, including only general details and metadata (not the data
     * input stream)
     * @throws S3ServiceException
     */
    public S3Object getVersionedObject(String versionId, String bucketName, String objectKey,
    	Calendar ifModifiedSince, Calendar ifUnmodifiedSince,
    	String[] ifMatchTags, String[] ifNoneMatchTags,
        Long byteRangeStart, Long byteRangeEnd) throws S3ServiceException
    {
        MxDelegate.getInstance().registerS3ObjectGetEvent(bucketName, objectKey);
        return getObjectImpl(bucketName, objectKey, ifModifiedSince, ifUnmodifiedSince,
            ifMatchTags, ifNoneMatchTags, byteRangeStart, byteRangeEnd, versionId);
    }

    /**
     * Applies access control settings to an object. The ACL settings must be included
     * with the object.
     *
     * This method can be performed by anonymous services, but can only succeed if the
     * object's existing ACL already allows write access by the anonymous user.
     * In general, you can only access the ACL of an object if the ACL already in place
     * for that object (in S3) allows you to do so. See
     * <a href="http://docs.amazonwebservices.com/AmazonS3/2006-03-01/index.html?S3_ACLs.html">
     * the S3 documentation on ACLs</a> for more details on access to ACLs.
     *
     * @param bucket
     * the bucket containing the object to modify.
     * @param object
     * the object with ACL settings that will be applied.
     * @throws S3ServiceException
     */
    public void putObjectAcl(S3Bucket bucket, S3Object object) throws S3ServiceException {
        assertValidBucket(bucket, "Put Object Access Control List");
        assertValidObject(object, "Put Object Access Control List");
        putObjectAcl(bucket.getName(), object.getKey(), object.getAcl());
    }

    /**
     * Applies access control settings to an object. The ACL settings must be included
     * with the object.
     *
     * This method can be performed by anonymous services, but can only succeed if the
     * object's existing ACL already allows write access by the anonymous user.
     * In general, you can only access the ACL of an object if the ACL already in place
     * for that object (in S3) allows you to do so. See
     * <a href="http://docs.amazonwebservices.com/AmazonS3/2006-03-01/index.html?S3_ACLs.html">
     * the S3 documentation on ACLs</a> for more details on access to ACLs.
     *
     * @param bucketName
     * the name of the bucket containing the object to modify.
     * @param objectKey
     * the key name of the object with ACL settings that will be applied.
     * @throws S3ServiceException
     */
    public void putObjectAcl(String bucketName, String objectKey, AccessControlList acl)
        throws S3ServiceException
    {
        if (acl == null) {
            throw new S3ServiceException("The object '" + objectKey +
                "' does not include ACL information");
        }
        putObjectAclImpl(bucketName, objectKey, acl, null);
    }

    /**
     * Applies access control settings to a versioned object.
     *
     * This method can be performed by anonymous services, but can only succeed if the
     * object's existing ACL already allows write access by the anonymous user.
     * In general, you can only access the ACL of an object if the ACL already in place
     * for that object (in S3) allows you to do so. See
     * <a href="http://docs.amazonwebservices.com/AmazonS3/2006-03-01/index.html?S3_ACLs.html">
     * the S3 documentation on ACLs</a> for more details on access to ACLs.
     *
     * @param versionId
     * the identifier of the object version whose ACL will be updated.
     * @param bucketName
     * the name of the versioned bucket containing the object to modify.
     * @param objectKey
     * the key name of the object with ACL settings that will be applied.
     * @throws S3ServiceException
     */
    public void putVersionedObjectAcl(String versionId, String bucketName,
    	String objectKey, AccessControlList acl) throws S3ServiceException
    {
        putObjectAclImpl(bucketName, objectKey, acl, versionId);
    }

    /**
     * Applies access control settings to a versioned object.
     * The ACL settings must be included with the object.
     *
     * This method can be performed by anonymous services, but can only succeed if the
     * object's existing ACL already allows write access by the anonymous user.
     * In general, you can only access the ACL of an object if the ACL already in place
     * for that object (in S3) allows you to do so. See
     * <a href="http://docs.amazonwebservices.com/AmazonS3/2006-03-01/index.html?S3_ACLs.html">
     * the S3 documentation on ACLs</a> for more details on access to ACLs.
     *
     * @param versionId
     * the identifier of the object version whose ACL will be updated.
     * @param bucket
     * the bucket containing the object to modify.
     * @param object
     * the object with ACL settings that will be applied.
     *
     * @throws S3ServiceException
     */
    public void putVersionedObjectAcl(String versionId, S3Bucket bucket, S3Object object)
        throws S3ServiceException
    {
        assertValidBucket(bucket, "Put Versioned Object Access Control List");
        assertValidObject(object, "Put Versioned Object Access Control List");
        String objectKey = object.getKey();
        AccessControlList acl = object.getAcl();
        if (acl == null) {
            throw new S3ServiceException("The object '" + objectKey +
                "' does not include ACL information");
        }
        putObjectAclImpl(bucket.getName(), objectKey, acl, versionId);
    }

    /**
     * Applies access control settings to a bucket. The ACL settings must be included
     * inside the bucket.
     *
     * This method can be performed by anonymous services, but can only succeed if the
     * bucket's existing ACL already allows write access by the anonymous user.
     * In general, you can only access the ACL of a bucket if the ACL already in place
     * for that bucket (in S3) allows you to do so. See
     * <a href="http://docs.amazonwebservices.com/AmazonS3/2006-03-01/index.html?S3_ACLs.html">
     * the S3 documentation on ACLs</a> for more details on access to ACLs.
     *
     * @param bucket
     * a bucket with ACL settings to apply.
     * @throws S3ServiceException
     */
    public void putBucketAcl(S3Bucket bucket) throws S3ServiceException {
        assertValidBucket(bucket, "Put Bucket Access Control List");
        putBucketAcl(bucket.getName(), bucket.getAcl());
    }

    /**
     * Applies access control settings to a bucket. The ACL settings must be included
     * inside the bucket.
     *
     * This method can be performed by anonymous services, but can only succeed if the
     * bucket's existing ACL already allows write access by the anonymous user.
     * In general, you can only access the ACL of a bucket if the ACL already in place
     * for that bucket (in S3) allows you to do so. See
     * <a href="http://docs.amazonwebservices.com/AmazonS3/2006-03-01/index.html?S3_ACLs.html">
     * the S3 documentation on ACLs</a> for more details on access to ACLs.
     *
     * @param bucketName
     * a name of the bucket with ACL settings to apply.
     * @throws S3ServiceException
     */
    public void putBucketAcl(String bucketName, AccessControlList acl) throws S3ServiceException {
        if (acl == null) {
            throw new S3ServiceException("The bucket '" + bucketName +
                "' does not include ACL information");
        }
        putBucketAclImpl(bucketName, acl);
    }

    /**
     * Retrieves the access control settings of an object.
     *
     * This method can be performed by anonymous services, but can only succeed if the
     * object's existing ACL already allows read access by the anonymous user.
     * In general, you can only access the ACL of an object if the ACL already in place
     * for that object (in S3) allows you to do so. See
     * <a href="http://docs.amazonwebservices.com/AmazonS3/2006-03-01/index.html?S3_ACLs.html">
     * the S3 documentation on ACLs</a> for more details on access to ACLs.
     *
     * @param bucket
     * the bucket whose ACL settings will be retrieved (if objectKey is null) or the bucket containing the
     * object whose ACL settings will be retrieved (if objectKey is non-null).
     * @param objectKey
     * if non-null, the key of the object whose ACL settings will be retrieved. Ignored if null.
     * @return
     * the ACL settings of the bucket or object.
     * @throws S3ServiceException
     */
    public AccessControlList getObjectAcl(S3Bucket bucket, String objectKey)
        throws S3ServiceException
    {
        assertValidBucket(bucket, "Get Object Access Control List");
        return getObjectAclImpl(bucket.getName(), objectKey, null);
    }

    /**
     * Retrieves the access control settings of a versioned object.
     *
     * This method can be performed by anonymous services, but can only succeed if the
     * object's existing ACL already allows read access by the anonymous user.
     * In general, you can only access the ACL of an object if the ACL already in place
     * for that object (in S3) allows you to do so. See
     * <a href="http://docs.amazonwebservices.com/AmazonS3/2006-03-01/index.html?S3_ACLs.html">
     * the S3 documentation on ACLs</a> for more details on access to ACLs.
     *
     * @param versionId
     * the identifier of the object version whose ACL will be returned.
     * @param bucket
     * the versioned bucket whose ACL settings will be retrieved (if objectKey is null) or the bucket
     * containing the object whose ACL settings will be retrieved (if objectKey is non-null).
     * @param objectKey
     * if non-null, the key of the object whose ACL settings will be retrieved. Ignored if null.
     * @return
     * the ACL settings of the bucket or object.
     * @throws S3ServiceException
     */
    public AccessControlList getVersionedObjectAcl(String versionId, S3Bucket bucket,
    	String objectKey) throws S3ServiceException
    {
        assertValidBucket(bucket, "Get versioned Object Access Control List");
        return getObjectAclImpl(bucket.getName(), objectKey, versionId);
    }

    /**
     * Retrieves the access control settings of an object.
     *
     * This method can be performed by anonymous services, but can only succeed if the
     * object's existing ACL already allows write access by the anonymous user.
     * In general, you can only access the ACL of an object if the ACL already in place
     * for that object (in S3) allows you to do so. See
     * <a href="http://docs.amazonwebservices.com/AmazonS3/2006-03-01/index.html?S3_ACLs.html">
     * the S3 documentation on ACLs</a> for more details on access to ACLs.
     *
     * @param bucketName
     * the name of the bucket whose ACL settings will be retrieved (if objectKey is null) or the
     * name of the bucket containing the object whose ACL settings will be retrieved (if objectKey is non-null).
     * @param objectKey
     * if non-null, the key of the object whose ACL settings will be retrieved. Ignored if null.
     * @return
     * the ACL settings of the bucket or object.
     * @throws S3ServiceException
     */
    public AccessControlList getObjectAcl(String bucketName, String objectKey)
        throws S3ServiceException
    {
        return getObjectAclImpl(bucketName, objectKey, null);
    }

    /**
     * Retrieves the access control settings of a versioned object.
     *
     * This method can be performed by anonymous services, but can only succeed if the
     * object's existing ACL already allows write access by the anonymous user.
     * In general, you can only access the ACL of an object if the ACL already in place
     * for that object (in S3) allows you to do so. See
     * <a href="http://docs.amazonwebservices.com/AmazonS3/2006-03-01/index.html?S3_ACLs.html">
     * the S3 documentation on ACLs</a> for more details on access to ACLs.
     *
     * @param versionId
     * the identifier of the object version whose ACL will be returned.
     * @param bucketName
     * the name of the versioned bucket containing the object whose ACL settings will be retrieved.
     * @param objectKey
     * if non-null, the key of the object whose ACL settings will be retrieved. Ignored if null.
     * @return
     * the ACL settings of the bucket or object.
     * @throws S3ServiceException
     */
    public AccessControlList getVersionedObjectAcl(String versionId, String bucketName,
    	String objectKey) throws S3ServiceException
    {
        return getObjectAclImpl(bucketName, objectKey, versionId);
    }

    /**
     * Retrieves the access control settings of a bucket.
     *
     * This method can be performed by anonymous services, but can only succeed if the
     * bucket's existing ACL already allows write access by the anonymous user.
     * In general, you can only access the ACL of a bucket if the ACL already in place
     * for that bucket (in S3) allows you to do so. See
     * <a href="http://docs.amazonwebservices.com/AmazonS3/2006-03-01/index.html?S3_ACLs.html">
     * the S3 documentation on ACLs</a> for more details on access to ACLs.
     *
     * @param bucket
     * the bucket whose access control settings will be returned.
     * This must be a valid S3Bucket object that is non-null and contains a name.
     * @return
     * the ACL settings of the bucket.
     * @throws S3ServiceException
     */
    public AccessControlList getBucketAcl(S3Bucket bucket) throws S3ServiceException {
        assertValidBucket(bucket, "Get Bucket Access Control List");
        return getBucketAclImpl(bucket.getName());
    }

    /**
     * Retrieves the access control settings of a bucket.
     *
     * This method can be performed by anonymous services, but can only succeed if the
     * bucket's existing ACL already allows write access by the anonymous user.
     * In general, you can only access the ACL of a bucket if the ACL already in place
     * for that bucket (in S3) allows you to do so. See
     * <a href="http://docs.amazonwebservices.com/AmazonS3/2006-03-01/index.html?S3_ACLs.html">
     * the S3 documentation on ACLs</a> for more details on access to ACLs.
     *
     * @param bucketName
     * the name of the bucket whose access control settings will be returned.
     * @return
     * the ACL settings of the bucket.
     * @throws S3ServiceException
     */
    public AccessControlList getBucketAcl(String bucketName) throws S3ServiceException {
        return getBucketAclImpl(bucketName);
    }

    /**
     * Retrieves the location of a bucket. Only the owner of a bucket may retrieve its location.
     *
     * @param bucketName
     * the name of the bucket whose location will be returned.
     * @return
     * a string representing the location of the bucket, such as "EU" for a bucket
     * located in Europe or null for a bucket in the default US location.
     * @throws S3ServiceException
     */
    public String getBucketLocation(String bucketName) throws S3ServiceException {
        return getBucketLocationImpl(bucketName);
    }

    /**
     * Retrieves the logging status settings of a bucket. Only the owner of a bucket may retrieve
     * its logging status.
     *
     * @param bucketName
     * the name of the bucket whose logging status settings will be returned.
     * @return
     * the Logging Status settings of the bucket.
     * @throws S3ServiceException
     */
    public S3BucketLoggingStatus getBucketLoggingStatus(String bucketName) throws S3ServiceException {
        return getBucketLoggingStatusImpl(bucketName);
    }

    /**
     * Applies logging settings to a bucket, optionally modifying the ACL permissions for the
     * logging target bucket to ensure log files can be written to it. Only the owner of
     * a bucket may change its logging status.
     *
     * @param bucketName
     * the name of the bucket the logging settings will apply to.
     * @param status
     * the logging status settings to apply to the bucket.
     * @param updateTargetACLifRequired
     * if true, when logging is enabled the method will check the target bucket to ensure it has the
     * necessary ACL permissions set to allow logging (that is, WRITE and READ_ACP for the group
     * <tt>http://acs.amazonaws.com/groups/s3/LogDelivery</tt>). If the target bucket does not
     * have the correct permissions the bucket's ACL will be updated to have the correct
     * permissions. If this parameter is false, no ACL checks or updates will occur.
     *
     * @throws S3ServiceException
     */
    public void setBucketLoggingStatus(String bucketName, S3BucketLoggingStatus status,
        boolean updateTargetACLifRequired)
        throws S3ServiceException
    {
        if (status.isLoggingEnabled() && updateTargetACLifRequired) {
            // Check whether the target bucket has the ACL permissions necessary for logging.
            if (log.isDebugEnabled()) {
            	log.debug("Checking whether the target logging bucket '" +
            		status.getTargetBucketName() + "' has the appropriate ACL settings");
            }
            boolean isSetLoggingGroupWrite = false;
            boolean isSetLoggingGroupReadACP = false;
            String groupIdentifier = GroupGrantee.LOG_DELIVERY.getIdentifier();

            AccessControlList logBucketACL = getBucketAcl(status.getTargetBucketName());

            Iterator grantIter = logBucketACL.getGrants().iterator();
            while (grantIter.hasNext()) {
                GrantAndPermission gap = (GrantAndPermission) grantIter.next();

                if (groupIdentifier.equals(gap.getGrantee().getIdentifier())) {
                    // Found a Group Grantee.
                    if (gap.getPermission().equals(Permission.PERMISSION_WRITE)) {
                        isSetLoggingGroupWrite = true;
                        if (log.isDebugEnabled()) {
                            log.debug("Target bucket '" + status.getTargetBucketName() + "' has ACL "
                            		+ "permission " + Permission.PERMISSION_WRITE + " for group " +
                            		groupIdentifier);
                        }
                    } else if (gap.getPermission().equals(Permission.PERMISSION_READ_ACP)) {
                        isSetLoggingGroupReadACP = true;
                        if (log.isDebugEnabled()) {
                            log.debug("Target bucket '" + status.getTargetBucketName() + "' has ACL "
                                + "permission " + Permission.PERMISSION_READ_ACP + " for group " +
                                groupIdentifier);
                        }
                    }
                }
            }

            // Update target bucket's ACL if necessary.
            if (!isSetLoggingGroupWrite || !isSetLoggingGroupReadACP) {
                if (log.isWarnEnabled()) {
                    log.warn("Target logging bucket '" + status.getTargetBucketName()
                        + "' does not have the necessary ACL settings, updating ACL now");
                }

                logBucketACL.grantPermission(GroupGrantee.LOG_DELIVERY, Permission.PERMISSION_WRITE);
                logBucketACL.grantPermission(GroupGrantee.LOG_DELIVERY, Permission.PERMISSION_READ_ACP);
                putBucketAcl(status.getTargetBucketName(), logBucketACL);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Target logging bucket '" + status.getTargetBucketName()
                        + "' has the necessary ACL settings");
                }
            }
        }

        setBucketLoggingStatusImpl(bucketName, status);
    }

    /**
     * Return true if the given bucket is configured as a
     * <a href="http://docs.amazonwebservices.com/AmazonS3/latest/RequesterPaysBuckets.html">
     * Requester Pays</a> bucket, in which case the requester must supply their own AWS
     * credentials when accessing objects in the bucket, and will be responsible for request
     * and data transfer fees.
     *
     * @param bucketName
     * the name of the bucket whose request payment configuration setting will be returned.
     *
     * @return
     * true if the given bucket is configured to be Requester Pays, false if it is has the
     * default Owner pays configuration.
     *
     * @throws S3ServiceException
     */
    public boolean isRequesterPaysBucket(String bucketName) throws S3ServiceException
    {
        return isRequesterPaysBucketImpl(bucketName);
    }

    /**
     * Applies <a href="http://docs.amazonwebservices.com/AmazonS3/latest/RequesterPaysBuckets.html">
     * request payment configuration</a> settings to a bucket, setting the bucket to
     * be either Requester Pays or Bucket Owner pays. Only the owner of a bucket may change
     * its request payment status.
     *
     * @param bucketName
     * the name of the bucket to which the request payment configuration settings will be applied.
     * @param requesterPays
     * if true, the bucket will be configured to be Requester Pays. If false, the bucket will
     * be configured to be Owner pays (the default configuration setting).
     *
     * @throws S3ServiceException
     */
    public void setRequesterPaysBucket(String bucketName, boolean requesterPays)
        throws S3ServiceException
    {
        setRequesterPaysBucketImpl(bucketName, requesterPays);
    }


    /**
     * Returns the current date and time, adjusted according to the time
     * offset between your computer and an AWS server (as set by the
     * {@link RestUtils#getAWSTimeAdjustment()} method).
     *
     * @return
     * the current time, or the current time adjusted to match the AWS time
     * if the {@link RestUtils#getAWSTimeAdjustment()} method has been invoked.
     */
    public Date getCurrentTimeWithOffset() {
        return new Date(System.currentTimeMillis() + timeOffset);
    }

    /**
     * Renames metadata property names to be suitable for use as HTTP Headers. This is done
     * by renaming any non-HTTP headers to have the prefix <code>x-amz-meta-</code> and leaving the
     * HTTP header names unchanged. The HTTP header names left unchanged are those found in
     * {@link #HTTP_HEADER_METADATA_NAMES}
     *
     * @param metadata
     * @return
     * a map of metadata property name/value pairs renamed to be suitable for use as HTTP headers.
     */
    public Map renameMetadataKeys(Map metadata) {
        Map convertedMetadata = new HashMap();
        // Add all meta-data headers.
        if (metadata != null) {
            Iterator metaDataIter = metadata.entrySet().iterator();
            while (metaDataIter.hasNext()) {
                Map.Entry entry = (Map.Entry) metaDataIter.next();
                String key = (String) entry.getKey();
                Object value = entry.getValue();

                if (!RestUtils.HTTP_HEADER_METADATA_NAMES.contains(key.toLowerCase(Locale.getDefault()))
                    && !key.startsWith(this.getRestHeaderPrefix()))
                {
                    key = this.getRestMetadataPrefix() + key;
                }
                convertedMetadata.put(key, value);
            }
        }
        return convertedMetadata;
    }

    // /////////////////////////////////////////////////////////////////////////////////
    // Abstract methods that must be implemented by interface-specific S3Service classes
    // /////////////////////////////////////////////////////////////////////////////////

    /**
     * Indicates whether a bucket exists and is accessible to a service user.
     * <b>Caution:</b> After changes to the way S3 operates, this check started to
     * cause issues in situations where you need to immediately create a bucket
     * when it does not exist. To conditionally create a bucket, use the
     * {@link #getOrCreateBucket(String)} method instead.
     * <p>
     * This method can be performed by anonymous services.
     * <p>
     * <b>Implementation notes</b><p>
     * This method can be implemented by attempting to list the objects in a bucket. If the listing
     * is successful return true, if the listing failed for any reason return false.
     *
     * @return
     * true if the bucket exists and is accessible to the service user, false otherwise.
     * @throws S3ServiceException
     */
    public abstract boolean isBucketAccessible(String bucketName) throws S3ServiceException;

    /**
     * Find out the status of an S3 bucket with the given name. This method is only implemented
     * in the {@link org.jets3t.service.impl.rest.httpclient.RestS3Service} client.
     * <p>
     * <b>Warning!</b> S3 can act strangely when you use this method in some circumstances.
     * If you check the status of a bucket and find that it does not exist, then create
     * the bucket, S3 will continue to tell you the bucket does not exists for up to 30
     * seconds. This problem has something to do with connection caching (I think).
     * <p>
     * This S3 quirk makes it a bad idea to use this method to check for a bucket's
     * existence before creating that bucket. Use the {@link #getOrCreateBucket(String)}
     * method for this purpose instead.
     *
     * @param bucketName
     * @return
     * {@link #BUCKET_STATUS__MY_BUCKET} if you already own the bucket,
     * {@link #BUCKET_STATUS__DOES_NOT_EXIST} if the bucket does not yet exist
     * in S3, or {@link #BUCKET_STATUS__ALREADY_CLAIMED} if someone else has
     * already created a bucket with the given name.
     *
     * @throws S3ServiceException
     */
    public abstract int checkBucketStatus(String bucketName) throws S3ServiceException;

    protected abstract String getBucketLocationImpl(String bucketName)
        throws S3ServiceException;

    protected abstract S3BucketLoggingStatus getBucketLoggingStatusImpl(String bucketName)
        throws S3ServiceException;

    protected abstract void setBucketLoggingStatusImpl(String bucketName, S3BucketLoggingStatus status)
        throws S3ServiceException;

    protected abstract void setRequesterPaysBucketImpl(String bucketName, boolean requesterPays)
        throws S3ServiceException;

    protected abstract boolean isRequesterPaysBucketImpl(String bucketName)
        throws S3ServiceException;

    /**
     * @return
     * the buckets in an S3 account.
     *
     * @throws S3ServiceException
     */
    protected abstract S3Bucket[] listAllBucketsImpl() throws S3ServiceException;

    /**
     * @return
     * the owner of an S3 account.
     * @throws S3ServiceException
     */
    protected abstract S3Owner getAccountOwnerImpl() throws S3ServiceException;

    /**
     * Lists objects in a bucket.
     *
     * <b>Implementation notes</b><p>
     * The implementation of this method is expected to return <b>all</b> the objects
     * in a bucket, not a subset. This may require repeating the S3 list operation if the
     * first one doesn't include all the available objects, such as when the number of objects
     * is greater than <code>maxListingLength</code>.
     * <p>
     *
     * @param bucketName
     * @param prefix
     * @param delimiter
     * @param maxListingLength
     * @return
     * the objects in a bucket.
     *
     * @throws S3ServiceException
     */
    protected abstract S3Object[] listObjectsImpl(String bucketName, String prefix,
        String delimiter, long maxListingLength) throws S3ServiceException;

    protected abstract BaseVersionOrDeleteMarker[] listVersionedObjectsImpl(String bucketName,
    	String prefix, String delimiter, String keyMarker, String versionMarker,
    	long maxListingLength) throws S3ServiceException;

    /**
     * Lists objects in a bucket up to the maximum listing length specified.
     *
     * <p>
     * <b>Implementation notes</b>
     * The implementation of this method returns only as many objects as requested in the chunk
     * size. It is the responsibility of the caller to build a complete object listing from
     * multiple chunks, should this be necessary.
     * </p>
     *
     * @param bucketName
     * @param prefix
     * @param delimiter
     * @param maxListingLength
     * @param priorLastKey
     * @param completeListing
     * @throws S3ServiceException
     */
    protected abstract S3ObjectsChunk listObjectsChunkedImpl(String bucketName, String prefix,
        String delimiter, long maxListingLength, String priorLastKey, boolean completeListing)
        throws S3ServiceException;

    /**
     * Lists version or delete markers in a versioned bucket, up to the maximum listing
     * length specified.
     *
     * <p>
     * <b>Implementation notes</b>
     * The implementation of this method returns only as many items as requested in the chunk
     * size. It is the responsibility of the caller to build a complete object listing from
     * multiple chunks, should this be necessary.
     * </p>
     *
     * @param bucketName
     * @param prefix
     * @param delimiter
     * @param maxListingLength
     * @param priorLastKey
     * @param completeListing
     * @throws S3ServiceException
     */
    protected abstract VersionOrDeleteMarkersChunk listVersionedObjectsChunkedImpl(
    	String bucketName, String prefix, String delimiter, long maxListingLength,
    	String priorLastKey, String priorLastVersion, boolean completeListing)
        throws S3ServiceException;

    /**
     * Creates a bucket.
     *
     * <b>Implementation notes</b><p>
     * The implementing method must populate the bucket object's metadata with the results of the
     * operation before returning the object. It must also apply any <code>AccessControlList</code>
     * settings included with the bucket.
     *
     * @param bucketName
     * the name of the bucket to create.
     * @param location
     * the geographical location where the bucket will be stored (see {@link S3Bucket#getLocation()}.
     * A null string value will cause the bucket to be stored in the default S3 location: US.
     * @param acl
     * an access control object representing the initial acl values for the bucket.
     * May be null, in which case the default permissions are applied.
     * @return
     * the created bucket object, populated with all metadata made available by the creation operation.
     * @throws S3ServiceException
     */
    protected abstract S3Bucket createBucketImpl(String bucketName, String location,
        AccessControlList acl) throws S3ServiceException;

    protected abstract void deleteBucketImpl(String bucketName) throws S3ServiceException;

    protected abstract void updateBucketVersioningStatusImpl(String bucketName,
    	boolean enabled, boolean multiFactorAuthDeleteEnabled,
    	String multiFactorSerialNumber, String multiFactorAuthCode)
        throws S3ServiceException;

    protected abstract S3BucketVersioningStatus getBucketVersioningStatusImpl(
    	String bucketName) throws S3ServiceException;

    protected abstract S3Object putObjectImpl(String bucketName, S3Object object) throws S3ServiceException;

    /**
     * Copy an object within your S3 account. Copies within a single bucket or between
     * buckets, and optionally updates the object's metadata at the same time. An
     * object can be copied over itself, allowing you to update the metadata without
     * making any other changes.
     *
     * @param sourceBucketName
     * the name of the bucket that contains the original object.
     * @param sourceObjectKey
     * the key name of the original object.
     * @param destinationBucketName
     * the name of the destination bucket to which the object will be copied.
     * @param destinationObjectKey
     * the key name for the copied object.
     * @param acl
     * the access control settings that will be applied to the copied object.
     * If this parameter is null, the default (private) ACL setting will be
     * applied to the copied object.
     * @param destinationMetadata
     * metadata items to apply to the copied object. If this parameter is null,
     * the metadata will be copied unchanged from the original object. If this
     * parameter is not null, the copied object will have only the supplied
     * metadata.
     *
     * @return
     * a map of the header and result information returned by S3 after the object
     * copy. The map includes the object's MD5 hash value (ETag), its size
     * (Content-Length), and update timestamp (Last-Modified).
     *
     * @throws S3ServiceException
     */
    protected abstract Map copyObjectImpl(String sourceBucketName, String sourceObjectKey,
        String destinationBucketName, String destinationObjectKey,
        AccessControlList acl, Map destinationMetadata,
        Calendar ifModifiedSince, Calendar ifUnmodifiedSince,
        String[] ifMatchTags, String[] ifNoneMatchTags, String versionId,
        String destinationObjectStorageClass)
        throws S3ServiceException;

    protected abstract void deleteObjectImpl(String bucketName, String objectKey,
    	String versionId, String multiFactorSerialNumber, String multiFactorAuthCode)
        throws S3ServiceException;

    protected abstract S3Object getObjectDetailsImpl(String bucketName, String objectKey,
        Calendar ifModifiedSince, Calendar ifUnmodifiedSince, String[] ifMatchTags,
        String[] ifNoneMatchTags, String versionId) throws S3ServiceException;

    protected abstract S3Object getObjectImpl(String bucketName, String objectKey, Calendar ifModifiedSince,
        Calendar ifUnmodifiedSince, String[] ifMatchTags, String[] ifNoneMatchTags,
        Long byteRangeStart, Long byteRangeEnd, String versionId) throws S3ServiceException;

    protected abstract void putBucketAclImpl(String bucketName, AccessControlList acl)
        throws S3ServiceException;

    protected abstract void putObjectAclImpl(String bucketName, String objectKey,
    	AccessControlList acl, String versionId) throws S3ServiceException;

    protected abstract AccessControlList getObjectAclImpl(String bucketName, String objectKey,
    	String versionId) throws S3ServiceException;

    protected abstract AccessControlList getBucketAclImpl(String bucketName) throws S3ServiceException;

    protected abstract void shutdownImpl() throws S3ServiceException;

    protected abstract String getEndpoint();
    protected abstract String getVirtualPath();
    protected abstract String getSignatureIdentifier();
    protected abstract String getRestHeaderPrefix();
    protected abstract String getRestMetadataPrefix();
    protected abstract int getHttpPort();
    protected abstract int getHttpsPort();
    protected abstract boolean getHttpsOnly();
    protected abstract boolean getDisableDnsBuckets();

}

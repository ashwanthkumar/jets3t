/*
 * jets3t : Java Extra-Tasty S3 Toolkit (for Amazon S3 online storage service)
 * This is a java.net project, see https://jets3t.dev.java.net/
 *
 * Copyright 2008 - 2009 James Murty
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

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.xml.parsers.FactoryConfigurationError;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.apache.commons.httpclient.HostConfiguration;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.auth.CredentialsProvider;
import org.apache.commons.httpclient.methods.DeleteMethod;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.PutMethod;
import org.apache.commons.httpclient.methods.StringRequestEntity;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jets3t.service.impl.rest.CloudFrontXmlResponsesSaxParser;
import org.jets3t.service.impl.rest.CloudFrontXmlResponsesSaxParser.DistributionConfigHandler;
import org.jets3t.service.impl.rest.CloudFrontXmlResponsesSaxParser.DistributionHandler;
import org.jets3t.service.impl.rest.CloudFrontXmlResponsesSaxParser.ErrorHandler;
import org.jets3t.service.impl.rest.CloudFrontXmlResponsesSaxParser.ListDistributionListHandler;
import org.jets3t.service.impl.rest.CloudFrontXmlResponsesSaxParser.OriginAccessIdentityConfigHandler;
import org.jets3t.service.impl.rest.CloudFrontXmlResponsesSaxParser.OriginAccessIdentityHandler;
import org.jets3t.service.impl.rest.CloudFrontXmlResponsesSaxParser.OriginAccessIdentityListHandler;
import org.jets3t.service.impl.rest.httpclient.AWSRequestAuthorizer;
import org.jets3t.service.impl.rest.httpclient.HttpClientAndConnectionManager;
import org.jets3t.service.model.cloudfront.Distribution;
import org.jets3t.service.model.cloudfront.DistributionConfig;
import org.jets3t.service.model.cloudfront.LoggingStatus;
import org.jets3t.service.model.cloudfront.OriginAccessIdentity;
import org.jets3t.service.model.cloudfront.OriginAccessIdentityConfig;
import org.jets3t.service.model.cloudfront.StreamingDistribution;
import org.jets3t.service.model.cloudfront.StreamingDistributionConfig;
import org.jets3t.service.security.AWSCredentials;
import org.jets3t.service.security.EncryptionUtil;
import org.jets3t.service.utils.RestUtils;
import org.jets3t.service.utils.ServiceUtils;

import com.jamesmurty.utils.XMLBuilder;

/**
 * A service that handles communication with the Amazon CloudFront REST API, offering
 * all the operations that can be performed on CloudFront distributions.
 * <p>
 * This class uses properties obtained through {@link Jets3tProperties}. For more information on
 * these properties please refer to
 * <a href="http://jets3t.s3.amazonaws.com/toolkit/configuration.html">JetS3t Configuration</a>
 * </p>
 *
 * @author James Murty
 */
public class CloudFrontService implements AWSRequestAuthorizer {
    private static final Log log = LogFactory.getLog(CloudFrontService.class);

    public static final String ENDPOINT = "https://cloudfront.amazonaws.com/";
    public static final String VERSION = "2009-12-01";
    public static final String XML_NAMESPACE = "http://cloudfront.amazonaws.com/doc/" + VERSION + "/";
    public static final String DEFAULT_BUCKET_SUFFIX = ".s3.amazonaws.com";
    public static final String ORIGIN_ACCESS_IDENTITY_URI_PATH = "/origin-access-identity/cloudfront";
    public static final String ORIGIN_ACCESS_IDENTITY_PREFIX = "origin-access-identity/cloudfront/";

    private HttpClient httpClient = null;
    private CredentialsProvider credentialsProvider = null;

    private AWSCredentials awsCredentials = null;
    protected Jets3tProperties jets3tProperties = null;
    private String invokingApplicationDescription = null;
    protected int internalErrorRetryMax = 5;


    /**
     * The approximate difference in the current time between your computer and
     * Amazon's servers, measured in milliseconds.
     *
     * This value is 0 by default. Use the {@link #getCurrentTimeWithOffset()}
     * to obtain the current time with this offset factor included, and the
     * {@link RestUtils#getAWSTimeAdjustment()} method to calculate an offset value for your
     * computer based on a response from an AWS server.
     */
    protected long timeOffset = 0;

    /**
     * Constructs the service and initialises its properties.
     *
     * @param awsCredentials
     * the AWS user credentials to use when communicating with CloudFront
     * @param invokingApplicationDescription
     * a short description of the application using the service, suitable for inclusion in a
     * user agent string for REST/HTTP requests. Ideally this would include the application's
     * version number, for example: <code>Cockpit/0.7.3</code> or <code>My App Name/1.0</code>.
     * May be null.
     * @param credentialsProvider
     * an implementation of the HttpClient CredentialsProvider interface, to provide a means for
     * prompting for credentials when necessary. May be null.
     * @param jets3tProperties
     * JetS3t properties that will be applied within this service. May be null.
     * @param hostConfig
     * Custom HTTP host configuration; e.g to register a custom Protocol Socket Factory.
     * May be null.
     *
     * @throws CloudFrontServiceException
     */
    public CloudFrontService(AWSCredentials awsCredentials, String invokingApplicationDescription,
        CredentialsProvider credentialsProvider, Jets3tProperties jets3tProperties,
        HostConfiguration hostConfig) throws CloudFrontServiceException
    {
        this.awsCredentials = awsCredentials;
        this.invokingApplicationDescription = invokingApplicationDescription;
        this.credentialsProvider = credentialsProvider;
        if (jets3tProperties == null) {
            jets3tProperties = Jets3tProperties.getInstance(Constants.JETS3T_PROPERTIES_FILENAME);
        }
        this.jets3tProperties = jets3tProperties;

        // Configure the InetAddress DNS caching times to work well with CloudFront. The cached DNS will
        // timeout after 5 minutes, while failed DNS lookups will be retried after 1 second.
        System.setProperty("networkaddress.cache.ttl", "300");
        System.setProperty("networkaddress.cache.negative.ttl", "1");

        this.internalErrorRetryMax = jets3tProperties.getIntProperty("cloudfront-service.internal-error-retry-max", 5);

        if (hostConfig == null) {
            hostConfig = new HostConfiguration();
        }

        HttpClientAndConnectionManager initHttpResult = RestUtils.initHttpConnection(
            this, hostConfig, jets3tProperties,
            this.invokingApplicationDescription, this.credentialsProvider);
        this.httpClient = initHttpResult.getHttpClient();

        // Retrieve Proxy settings.
        if (this.jets3tProperties.getBoolProperty("httpclient.proxy-autodetect", true)) {
            RestUtils.initHttpProxy(this.httpClient);
        } else {
            String proxyHostAddress = this.jets3tProperties.getStringProperty("httpclient.proxy-host", null);
            int proxyPort = this.jets3tProperties.getIntProperty("httpclient.proxy-port", -1);
            String proxyUser = this.jets3tProperties.getStringProperty("httpclient.proxy-user", null);
            String proxyPassword = this.jets3tProperties.getStringProperty("httpclient.proxy-password", null);
            String proxyDomain = this.jets3tProperties.getStringProperty("httpclient.proxy-domain", null);
            RestUtils.initHttpProxy(this.httpClient, proxyHostAddress, proxyPort, proxyUser, proxyPassword, proxyDomain);
        }

        /* TODO: CloudFront service does not seem to support 100-continue protocol for 2009-04-02
         * DistributionConfig updates, causing unnecessary timeouts when updating these settings.
         * This will probably be fixed, remove the following line when full support returns.
         */
        this.httpClient.getParams().setBooleanParameter("http.protocol.expect-continue", false);
    }

    /**
     * Constructs the service with default properties.
     *
     * @param awsCredentials
     * the AWS user credentials to use when communicating with CloudFront
     *
     * @throws CloudFrontServiceException
     */
    public CloudFrontService(AWSCredentials awsCredentials) throws CloudFrontServiceException
    {
        this(awsCredentials, null, null, null, null);
    }

    /**
     * @return the AWS Credentials identifying the AWS user.
     */
    public AWSCredentials getAWSCredentials() {
        return awsCredentials;
    }

    /**
     * Returns the current date and time, adjusted according to the time
     * offset between your computer and an AWS server (as set by the
     * {@link RestUtils#getAWSTimeAdjustment()} method).
     *
     * @return
     * the current time, or the current time adjusted to match the AWS time
     * if the service has experienced a RequestExpired error.
     */
    protected Date getCurrentTimeWithOffset() {
        return new Date(System.currentTimeMillis() + timeOffset);
    }

    /**
     * Sign the given HTTP method object using the AWS credentials provided
     * by {@link #getAWSCredentials()}.
     *
     * @param httpMethod
     * the request object
     * @throws Exception
     */
    public void authorizeHttpRequest(HttpMethod httpMethod) throws Exception {
        String date = ServiceUtils.formatRfc822Date(getCurrentTimeWithOffset());

        // Set/update the date timestamp to the current time
        // Note that this will be over-ridden if an "x-amz-date" header is present.
        httpMethod.setRequestHeader("Date", date);

        // Sign the date to authenticate the request.
        // Sign the canonical string.
        String signature = ServiceUtils.signWithHmacSha1(
            getAWSCredentials().getSecretKey(), date);

        // Add encoded authorization to connection as HTTP Authorization header.
        String authorizationString = "AWS " + getAWSCredentials().getAccessKey() + ":" + signature;
        httpMethod.setRequestHeader("Authorization", authorizationString);
    }

    /**
     * Performs an HTTP/S request by invoking the provided HttpMethod object. If the HTTP
     * response code doesn't match the expected value, an exception is thrown.
     *
     * @param httpMethod
     * the object containing a request target and all other information necessary to
     * perform the request
     * @param expectedResponseCode
     * the HTTP response code that indicates a successful request. If the response code received
     * does not match this value an error must have occurred, so an exception is thrown.
     * @throws CloudFrontServiceException
     * all exceptions are wrapped in a CloudFrontServiceException. Depending on the kind of error that
     * occurred, this exception may contain additional error information available from an XML
     * error response document.
     */
    protected void performRestRequest(HttpMethod httpMethod, int expectedResponseCode)
        throws CloudFrontServiceException
    {
        // Set mandatory Request headers.
        if (httpMethod.getRequestHeader("Date") == null) {
            httpMethod.setRequestHeader("Date", ServiceUtils.formatRfc822Date(
                getCurrentTimeWithOffset()));
        }

        boolean completedWithoutRecoverableError = true;
        int internalErrorCount = 0;

        try {
            do {
                completedWithoutRecoverableError = true;
                authorizeHttpRequest(httpMethod);
                int responseCode = httpClient.executeMethod(httpMethod);

                if (responseCode != expectedResponseCode) {
                    if (responseCode == 500) {
                        // Retry on Internal Server errors, up to the defined limit.
                        long delayMs = 1000;
                        if (++internalErrorCount < this.internalErrorRetryMax) {
                            log.warn("Encountered " + internalErrorCount +
                                " CloudFront Internal Server error(s), will retry in " + delayMs + "ms");
                            Thread.sleep(delayMs);
                            completedWithoutRecoverableError = false;
                        } else {
                            throw new CloudFrontServiceException("Encountered too many CloudFront Internal Server errors ("
                                + internalErrorCount + "), aborting request.");
                        }
                    } else {
                        // Parse XML error message.
                        ErrorHandler handler = (new CloudFrontXmlResponsesSaxParser(this.jets3tProperties))
                            .parseErrorResponse(httpMethod.getResponseBodyAsStream());

                        CloudFrontServiceException exception = new CloudFrontServiceException(
                            "Request failed with CloudFront Service error",
                            responseCode, handler.getType(), handler.getCode(),
                            handler.getMessage(), handler.getDetail(),
                            handler.getRequestId());

                        if ("RequestExpired".equals(exception.getErrorCode())) {
                            // Retry on time skew errors.
                            this.timeOffset = RestUtils.getAWSTimeAdjustment();
                            if (log.isWarnEnabled()) {
                                log.warn("Adjusted time offset in response to RequestExpired error. "
                                    + "Local machine and CloudFront server disagree on the time by approximately "
                                    + (this.timeOffset / 1000) + " seconds. Retrying connection.");
                            }
                            completedWithoutRecoverableError = false;
                        } else {
                            throw exception;
                        }
                    }
                } // End responseCode check
            } while (!completedWithoutRecoverableError);
        } catch (CloudFrontServiceException e) {
            httpMethod.releaseConnection();
            throw e;
        } catch (Throwable t) {
            httpMethod.releaseConnection();
            throw new CloudFrontServiceException("CloudFront Request failed", t);
        }
    }

    /**
     * List streaming or non-streaming Distributions in a CloudFront account.
     * @param isStreaming
     * @param pagingSize
     * @return
     * A list of {@link Distribution}s.
     * @throws CloudFrontServiceException
     */
    protected List listDistributionsImpl(boolean isStreaming, int pagingSize)
        throws CloudFrontServiceException
    {
        if (log.isDebugEnabled()) {
            log.debug("Listing "
            	+ (isStreaming ? "streaming" : "")
            	+ " distributions for AWS user: " + getAWSCredentials().getAccessKey());
        }
        try {
            List distributions = new ArrayList();
            String nextMarker = null;
            boolean incompleteListing = true;
            do {
                String uri = ENDPOINT + VERSION
                	+ (isStreaming ? "/streaming-distribution" : "/distribution")
        			+ "?MaxItems=" + pagingSize;
                if (nextMarker != null) {
                	uri += "&Marker=" + nextMarker;
                }
                HttpMethod httpMethod = new GetMethod(uri);
                performRestRequest(httpMethod, 200);

                ListDistributionListHandler handler =
                    (new CloudFrontXmlResponsesSaxParser(this.jets3tProperties))
                        .parseDistributionListResponse(httpMethod.getResponseBodyAsStream());
                distributions.addAll(handler.getDistributions());

                incompleteListing = handler.isTruncated();
                nextMarker = handler.getNextMarker();

                // Sanity check for valid pagination values.
                if (incompleteListing && nextMarker == null) {
                    throw new CloudFrontServiceException("Unable to retrieve paginated "
                    		+ "DistributionList results without a valid NextMarker value.");
                }
            } while (incompleteListing);

            return distributions;
        } catch (CloudFrontServiceException e) {
            throw e;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new CloudFrontServiceException(e);
        }
    }

    /**
     * List all your standard CloudFront distributions, with a given maximum
     * number of Distribution items in each "page" of results.
     *
     * @param pagingSize
     * the maximum number of distributions the CloudFront service will
     * return in each response message.
     * @return
     * a list of your distributions.
     *
     * @throws CloudFrontServiceException
     */
    public Distribution[] listDistributions(int pagingSize) throws CloudFrontServiceException {
        List distributions = listDistributionsImpl(false, pagingSize);
        return (Distribution[]) distributions.toArray(new Distribution[distributions.size()]);
    }

    /**
     * List all your streaming CloudFront distributions, with a given maximum
     * number of Distribution items in each "page" of results.
     *
     * @param pagingSize
     * the maximum number of distributions the CloudFront service will
     * return in each response message.
     * @return
     * a list of your distributions.
     *
     * @throws CloudFrontServiceException
     */
    public StreamingDistribution[] listStreamingDistributions(int pagingSize)
        throws CloudFrontServiceException
    {
        List distributions = listDistributionsImpl(true, pagingSize);
        return (StreamingDistribution[]) distributions.toArray(
        	new StreamingDistribution[distributions.size()]);
    }

    /**
     * List all your standard CloudFront distributions.
     *
     * @return
     * a list of your distributions.
     *
     * @throws CloudFrontServiceException
     */
    public Distribution[] listDistributions() throws CloudFrontServiceException {
        return listDistributions(100);
    }

    /**
     * List all your standard CloudFront distributions.
     *
     * @return
     * a list of your streaming distributions.
     *
     * @throws CloudFrontServiceException
     */
    public StreamingDistribution[] listStreamingDistributions() throws CloudFrontServiceException {
        return listStreamingDistributions(100);
    }

    /**
     * List streaming or non-stream distributions whose origin is the given S3 bucket name.
     *
     * @param bucketName
     * the name of the S3 bucket whose distributions will be returned.
     * @return
     * a list of distributions applied to the given S3 bucket, or an empty list
     * if there are no such distributions.
     *
     * @throws CloudFrontServiceException
     */
    public List listDistributionsByBucketName(boolean isStreaming, String bucketName)
        throws CloudFrontServiceException
    {
        if (log.isDebugEnabled()) {
            log.debug("Listing "
            	+ (isStreaming ? "streaming" : "")
                + " distributions for the S3 bucket '" + bucketName
                + "' for AWS user: " + getAWSCredentials().getAccessKey());
        }
        ArrayList bucketDistributions = new ArrayList();
        Distribution[] allDistributions =
            (isStreaming ? listStreamingDistributions() : listDistributions());
        for (int i = 0; i < allDistributions.length; i++) {
            String distributionOrigin = allDistributions[i].getOrigin();
            if (distributionOrigin.equals(bucketName)
                || bucketName.equals(ServiceUtils.findBucketNameInHostname(distributionOrigin)))
            {
                bucketDistributions.add(allDistributions[i]);
            }
        }
        return bucketDistributions;
    }

    /**
     * List the distributions whose origin is the given S3 bucket name.
     *
     * @param bucketName
     * the name of the S3 bucket whose distributions will be returned.
     * @return
     * a list of distributions applied to the given S3 bucket, or an empty list
     * if there are no such distributions.
     *
     * @throws CloudFrontServiceException
     */
    public Distribution[] listDistributions(String bucketName) throws CloudFrontServiceException {
        List bucketDistributions = listDistributionsByBucketName(false, bucketName);
        return (Distribution[]) bucketDistributions.toArray(
            new Distribution[bucketDistributions.size()]);
    }

    /**
     * List the streaming distributions whose origin is the given S3 bucket name.
     *
     * @param bucketName
     * the name of the S3 bucket whose distributions will be returned.
     * @return
     * a list of distributions applied to the given S3 bucket, or an empty list
     * if there are no such distributions.
     *
     * @throws CloudFrontServiceException
     */
    public StreamingDistribution[] listStreamingDistributions(String bucketName)
        throws CloudFrontServiceException
    {
        List streamingDistributions = listDistributionsByBucketName(true, bucketName);
        return (StreamingDistribution[]) streamingDistributions.toArray(
            new StreamingDistribution[streamingDistributions.size()]);
    }

    /**
     * Generate a DistributionConfig or StreamingDistributionConfig XML document.
     *
     * @param isStreamingDistribution
     * @param origin
     * @param callerReference
     * @param cnames
     * @param comment
     * @param enabled
     * @param loggingStatus
     * @param originAccessIdentityId
     * @param trustedSignerSelf
     * @param trustedSignerAwsAccountNumbers
     * @return
     * XML document representing a Distribution Configuration
     * @throws TransformerException
     * @throws ParserConfigurationException
     * @throws FactoryConfigurationError
     */
    protected String buildDistributionConfigXmlDocument(boolean isStreamingDistribution,
    	String origin, String callerReference, String[] cnames, String comment, boolean enabled,
    	LoggingStatus loggingStatus, String originAccessIdentityId, boolean trustedSignerSelf,
        String[] trustedSignerAwsAccountNumbers)
    	throws TransformerException, ParserConfigurationException, FactoryConfigurationError
    {
        XMLBuilder builder = XMLBuilder.create(
        	isStreamingDistribution ? "StreamingDistributionConfig" : "DistributionConfig")
            .a("xmlns", XML_NAMESPACE)
            .e("Origin").t(origin).up()
            .e("CallerReference").t(callerReference).up();
        for (int i = 0; i < cnames.length; i++) {
            builder.e("CNAME").t(cnames[i]).up();
        }
        builder
            .e("Comment").t(comment).up()
            .e("Enabled").t("" + enabled);
        if (originAccessIdentityId != null) {
        	builder.e("OriginAccessIdentity")
        		.t(ORIGIN_ACCESS_IDENTITY_PREFIX + originAccessIdentityId)
    		.up();
        }
        if (trustedSignerSelf
    		|| (trustedSignerAwsAccountNumbers != null
    			&& trustedSignerAwsAccountNumbers.length > 0))
        {
        	XMLBuilder trustedSigners = builder.e("TrustedSigners");
        	if (trustedSignerSelf) {
        		trustedSigners.e("Self");
        	}
        	for (int i = 0;
        		trustedSignerAwsAccountNumbers != null
        			&& i < trustedSignerAwsAccountNumbers.length;
        		i++)
        	{
        		trustedSigners.e("AWSAccountNumber")
        			.t(trustedSignerAwsAccountNumbers[i]);
        	}
        	builder.up();
        }
        if (loggingStatus != null) {
        	builder.e("Logging")
        		.e("Bucket").t(loggingStatus.getBucket()).up()
        		.e("Prefix").t(loggingStatus.getPrefix()).up()
        	.up();
        }
        return builder.asString(null);
    }

    /**
     * Create a streaming or non-streaming distribution.
     * @param isStreaming
     * @param origin
     * @param callerReference
     * @param cnames
     * @param comment
     * @param enabled
     * @param loggingStatus
     * @param originAccessIdentityId
     * @param trustedSignerSelf
     * @param trustedSignerAwsAccountNumbers
     * @return
     * Information about the newly-created distribution.
     * @throws CloudFrontServiceException
     */
    protected Distribution createDistributionImpl(
    	boolean isStreaming, String origin, String callerReference,
        String[] cnames, String comment, boolean enabled, LoggingStatus loggingStatus,
        String originAccessIdentityId, boolean trustedSignerSelf,
        String[] trustedSignerAwsAccountNumbers) throws CloudFrontServiceException
    {
        if (log.isDebugEnabled()) {
            log.debug("Creating "
            	+ (isStreaming ? "streaming" : "")
                + " distribution for origin: " + origin);
        }

        // Sanitize parameters.
        origin = sanitizeS3BucketName(origin);
        if (callerReference == null) {
            callerReference = "" + System.currentTimeMillis();
        }
        if (cnames == null) {
            cnames = new String[] {};
        }
        if (comment == null) {
            comment = "";
        }

        PostMethod httpMethod = new PostMethod(ENDPOINT + VERSION
        	+ (isStreaming ? "/streaming-distribution" : "/distribution"));

        try {
            String distributionConfigXml = buildDistributionConfigXmlDocument(isStreaming,
        		origin, callerReference, cnames, comment, enabled, loggingStatus,
        		originAccessIdentityId, trustedSignerSelf, trustedSignerAwsAccountNumbers);

            httpMethod.setRequestEntity(
                new StringRequestEntity(distributionConfigXml, "text/xml", Constants.DEFAULT_ENCODING));

            performRestRequest(httpMethod, 201);

            DistributionHandler handler =
                (new CloudFrontXmlResponsesSaxParser(this.jets3tProperties))
                    .parseDistributionResponse(httpMethod.getResponseBodyAsStream());

            return handler.getDistribution();
        } catch (CloudFrontServiceException e) {
            throw e;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new CloudFrontServiceException(e);
        }
    }

    /**
     * Create a public or private CloudFront distribution for an S3 bucket.
     *
     * @param origin
     * the Amazon S3 bucket to associate with the distribution, specified as a full
     * S3 sub-domain path (e.g. 'jets3t.s3.amazonaws.com' for the 'jets3t' bucket)
     * @param callerReference
     * A user-set unique reference value that ensures the request can't be replayed
     * (max UTF-8 encoding size 128 bytes). This parameter may be null, in which
     * case your computer's local epoch time in milliseconds will be used.
     * @param cnames
     * A list of up to 10 CNAME aliases to associate with the distribution. This
     * parameter may be a null or empty array.
     * @param comment
     * An optional comment to describe the distribution in your own terms
     * (max 128 characters). May be null.
     * @param enabled
     * Should the distribution should be enabled and publicly accessible upon creation?
     * @param loggingStatus
     * Logging status settings (bucket, prefix) for the distribution. If this value
     * is null, logging will be disabled for the distribution.
     * @param originAccessIdentityId
     * Identifier of the origin access identity that can authorize access to
     * S3 objects via a private distribution. If provided the distribution will be
     * private, if null the distribution will be be public.
     * @param trustedSignerSelf
     * If true the owner of the distribution (you) will be be allowed to generate
     * signed URLs for a private distribution. Note: If either trustedSignerSelf or
     * trustedSignerAwsAccountNumbers parameters are provided the private distribution
     * will require signed URLs to access content.
     * @param trustedSignerAwsAccountNumbers
     * Account Number identifiers for AWS account holders other than the
     * distribution's owner who will be allowed to generate signed URLs for a private
     * distribution. If null or empty, no additional AWS account holders may generate
     * signed URLs. Note: If either trustedSignerSelf or
     * trustedSignerAwsAccountNumbers parameters are provided the private distribution
     * will require signed URLs to access content.
     *
     * @return
     * an object that describes the newly-created distribution, in particular the
     * distribution's identifier and domain name values.
     *
     * @throws CloudFrontServiceException
     */
    public Distribution createDistribution(String origin, String callerReference,
        String[] cnames, String comment, boolean enabled, LoggingStatus loggingStatus,
        String originAccessIdentityId, boolean trustedSignerSelf,
        String[] trustedSignerAwsAccountNumbers) throws CloudFrontServiceException
    {
        return createDistributionImpl(false, origin, callerReference, cnames, comment,
    		enabled, loggingStatus, originAccessIdentityId, trustedSignerSelf,
    		trustedSignerAwsAccountNumbers);
    }

    /**
     * Create a minimally-configured CloudFront distribution for an S3 bucket that will
     * be publicly available once created.
     *
     * @param origin
     * the Amazon S3 bucket to associate with the distribution, specified as a full
     * S3 sub-domain path (e.g. 'jets3t.s3.amazonaws.com' for the 'jets3t' bucket)
     *
     * @return
     * an object that describes the newly-created distribution, in particular the
     * distribution's identifier and domain name values.
     *
     * @throws CloudFrontServiceException
     */
    public Distribution createDistribution(String origin) throws CloudFrontServiceException
    {
        return this.createDistribution(origin, null, null, null, true, null);
    }

    /**
     * Create a public CloudFront distribution for an S3 bucket.
     *
     * @param origin
     * the Amazon S3 bucket to associate with the distribution, specified as a full
     * S3 sub-domain path (e.g. 'jets3t.s3.amazonaws.com' for the 'jets3t' bucket)
     * @param callerReference
     * A user-set unique reference value that ensures the request can't be replayed
     * (max UTF-8 encoding size 128 bytes). This parameter may be null, in which
     * case your computer's local epoch time in milliseconds will be used.
     * @param cnames
     * A list of up to 10 CNAME aliases to associate with the distribution. This
     * parameter may be a null or empty array.
     * @param comment
     * An optional comment to describe the distribution in your own terms
     * (max 128 characters). May be null.
     * @param enabled
     * Should the distribution should be enabled and publicly accessible upon creation?
     * @param loggingStatus
     * Logging status settings (bucket, prefix) for the distribution. If this value
     * is null, logging will be disabled for the distribution.
     *
     * @return
     * an object that describes the newly-created distribution, in particular the
     * distribution's identifier and domain name values.
     *
     * @throws CloudFrontServiceException
     */
    public Distribution createDistribution(String origin, String callerReference,
        String[] cnames, String comment, boolean enabled, LoggingStatus loggingStatus)
        throws CloudFrontServiceException
    {
        return createDistribution(origin, callerReference, cnames, comment, enabled,
        		loggingStatus, null, false, null);
    }

     /**
      * Create a public or private CloudFront distribution for an S3 bucket based
      * on a pre-configured {@link DistributionConfig}.
      *
      * @param config
      * Configuration settings to apply to the distribution.
      *
      * @return
      * an object that describes the newly-created distribution, in particular the
      * distribution's identifier and domain name values.
      *
      * @throws CloudFrontServiceException
      */
    public Distribution createDistribution(DistributionConfig config)
        throws CloudFrontServiceException
    {
        return createDistribution(config.getOrigin(), config.getCallerReference(),
    		config.getCNAMEs(), config.getComment(), config.isEnabled(),
    		config.getLoggingStatus(), config.getOrigin(),
    		config.isTrustedSignerSelf(), config.getTrustedSignerAwsAccountNumbers());
    }

    /**
     * Create a streaming CloudFront distribution for an S3 bucket.
     *
     * @param origin
     * the Amazon S3 bucket to associate with the distribution, specified as a full
     * S3 sub-domain path (e.g. 'jets3t.s3.amazonaws.com' for the 'jets3t' bucket)
     * @param callerReference
     * A user-set unique reference value that ensures the request can't be replayed
     * (max UTF-8 encoding size 128 bytes). This parameter may be null, in which
     * case your computer's local epoch time in milliseconds will be used.
     * @param cnames
     * A list of up to 10 CNAME aliases to associate with the distribution. This
     * parameter may be a null or empty array.
     * @param comment
     * An optional comment to describe the distribution in your own terms
     * (max 128 characters). May be null.
     * @param enabled
     * Should the distribution should be enabled and publicly accessible upon creation?
     *
     * @return
     * an object that describes the newly-created distribution, in particular the
     * distribution's identifier and domain name values.
     *
     * @throws CloudFrontServiceException
     */
    public StreamingDistribution createStreamingDistribution(String origin, String callerReference,
            String[] cnames, String comment, boolean enabled) throws CloudFrontServiceException
    {
        return (StreamingDistribution) createDistributionImpl(true, origin, callerReference,
    		cnames, comment, enabled, null, null, false, null);
    }

    /**
     * @param isStreaming
     * @param id
     * @return
     * Information about a streaming or non-streaming distribution.
     * @throws CloudFrontServiceException
     */
    protected Distribution getDistributionInfoImpl(boolean isStreaming, String id)
        throws CloudFrontServiceException
    {
        if (log.isDebugEnabled()) {
            log.debug("Getting information for "
            	+ (isStreaming ? "streaming" : "")
            	+ " distribution with id: " + id);
        }
        GetMethod httpMethod = new GetMethod(ENDPOINT + VERSION
        	+ (isStreaming ? "/streaming-distribution/" : "/distribution/")
        	+ id);

        try {
            performRestRequest(httpMethod, 200);

            DistributionHandler handler =
                (new CloudFrontXmlResponsesSaxParser(this.jets3tProperties))
                    .parseDistributionResponse(httpMethod.getResponseBodyAsStream());

            return handler.getDistribution();
        } catch (CloudFrontServiceException e) {
            throw e;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new CloudFrontServiceException(e);
        }
    }

    /**
     * Lookup information for a standard distribution.
     *
     * @param id
     * the distribution's unique identifier.
     *
     * @return
     * an object that describes the distribution, including its identifier and domain
     * name values as well as its configuration details.
     *
     * @throws CloudFrontServiceException
     */
    public Distribution getDistributionInfo(String id) throws CloudFrontServiceException {
        return getDistributionInfoImpl(false, id);
    }

    /**
     * Lookup information for a streaming distribution.
     *
     * @param id
     * the distribution's unique identifier.
     *
     * @return
     * an object that describes the distribution, including its identifier and domain
     * name values as well as its configuration details.
     *
     * @throws CloudFrontServiceException
     */
    public StreamingDistribution getStreamingDistributionInfo(String id)
        throws CloudFrontServiceException
    {
        return (StreamingDistribution) getDistributionInfoImpl(true, id);
    }

    /**
     * @param isStreaming
     * @param id
     * @return
     * Information about a streaming or non-streaming distribution configuration.
     * @throws CloudFrontServiceException
     */
    protected DistributionConfig getDistributionConfigImpl(boolean isStreaming, String id)
        throws CloudFrontServiceException
    {
        if (log.isDebugEnabled()) {
            log.debug("Getting configuration for "
            	+ (isStreaming ? "streaming" : "")
            	+ " distribution with id: " + id);
        }
        GetMethod httpMethod = new GetMethod(ENDPOINT + VERSION
        	+ (isStreaming ? "/streaming-distribution/" : "/distribution/")
        	+ id + "/config");

        try {
            performRestRequest(httpMethod, 200);

            DistributionConfigHandler handler =
                (new CloudFrontXmlResponsesSaxParser(this.jets3tProperties))
                    .parseDistributionConfigResponse(httpMethod.getResponseBodyAsStream());

            DistributionConfig config = handler.getDistributionConfig();
            config.setEtag(httpMethod.getResponseHeader("ETag").getValue());
            return config;
        } catch (CloudFrontServiceException e) {
            throw e;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new CloudFrontServiceException(e);
        }
    }

    /**
     * Lookup configuration information for a standard distribution. The configuration
     * information is a subset of the information available from the
     * {@link #getDistributionInfo(String)} method.
     *
     * @param id
     * the distribution's unique identifier.
     *
     * @return
     * an object that describes the distribution's configuration, including its origin bucket
     * and CNAME aliases.
     *
     * @throws CloudFrontServiceException
     */
    public DistributionConfig getDistributionConfig(String id)
        throws CloudFrontServiceException
    {
        return getDistributionConfigImpl(false, id);
    }

    /**
     * Lookup configuration information for a streaming distribution. The configuration
     * information is a subset of the information available from the
     * {@link #getDistributionInfo(String)} method.
     *
     * @param id
     * the distribution's unique identifier.
     *
     * @return
     * an object that describes the distribution's configuration, including its origin bucket
     * and CNAME aliases.
     *
     * @throws CloudFrontServiceException
     */
    public StreamingDistributionConfig getStreamingDistributionConfig(String id)
        throws CloudFrontServiceException
    {
        return (StreamingDistributionConfig) getDistributionConfigImpl(true, id);
    }

    /**
     * Update a streaming or non-streaming distribution.
     * @param isStreaming
     * @param id
     * @param cnames
     * @param comment
     * @param enabled
     * @param loggingStatus
     * @param originAccessIdentityId
     * @param trustedSignerSelf
     * @param trustedSignerAwsAccountNumbers
     * @return
     * Information about the updated distribution configuration.
     * @throws CloudFrontServiceException
     */
    protected DistributionConfig updateDistributionConfigImpl(
    	boolean isStreaming, String id, String[] cnames,
        String comment, boolean enabled, LoggingStatus loggingStatus,
        String originAccessIdentityId, boolean trustedSignerSelf,
        String[] trustedSignerAwsAccountNumbers)
        throws CloudFrontServiceException
    {
        if (log.isDebugEnabled()) {
            log.debug("Updating configuration of "
            	+ (isStreaming ? "streaming" : "")
            	+ "distribution with id: " + id);
        }

        // Retrieve the old configuration.
        DistributionConfig oldConfig =
            (isStreaming ? getStreamingDistributionConfig(id) : getDistributionConfig(id));

        // Sanitize parameters.
        if (cnames == null) {
            cnames = oldConfig.getCNAMEs();
        }
        if (comment == null) {
            comment = oldConfig.getComment();
        }

        PutMethod httpMethod = new PutMethod(ENDPOINT + VERSION
        	+ (isStreaming ? "/streaming-distribution/" : "/distribution/")
        	+ id + "/config");

        try {
            String distributionConfigXml = buildDistributionConfigXmlDocument(isStreaming,
            		oldConfig.getOrigin(), oldConfig.getCallerReference(), cnames, comment, enabled,
            		loggingStatus, originAccessIdentityId, trustedSignerSelf,
            		trustedSignerAwsAccountNumbers);

            httpMethod.setRequestEntity(
                new StringRequestEntity(distributionConfigXml, "text/xml", Constants.DEFAULT_ENCODING));
            httpMethod.setRequestHeader("If-Match", oldConfig.getEtag());

            performRestRequest(httpMethod, 200);

            DistributionConfigHandler handler =
                (new CloudFrontXmlResponsesSaxParser(this.jets3tProperties))
                    .parseDistributionConfigResponse(httpMethod.getResponseBodyAsStream());

            DistributionConfig config = handler.getDistributionConfig();
            config.setEtag(httpMethod.getResponseHeader("ETag").getValue());
            return config;
        } catch (CloudFrontServiceException e) {
            throw e;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new CloudFrontServiceException(e);
        }
    }

    /**
     * Update the configuration of an existing distribution to change its properties
     * or public/private status. The new configuration properties provided
     * <strong>replace</strong> any existing configuration, and may take some time
     * to be fully applied.
     * <p>
     * This method performs all the steps necessary to update the configuration. It
     * first performs lookup on the distribution  using
     * {@link #getDistributionConfig(String)} to find its origin and caller reference
     * values, then uses this information to apply your configuration changes.
     *
     * @param id
     * the distribution's unique identifier.
     * @param cnames
     * A list of up to 10 CNAME aliases to associate with the distribution. This
     * parameter may be null, in which case the original CNAME aliases are retained.
     * @param comment
     * An optional comment to describe the distribution in your own terms
     * (max 128 characters). May be null, in which case the original comment is retained.
     * @param enabled
     * Should the distribution should be enabled and publicly accessible after the
     * configuration update?
     * @param loggingStatus
     * Logging status settings (bucket, prefix) for the distribution. If this value
     * is null, logging will be disabled for the distribution.
     * @param originAccessIdentityId
     * Identifier of the origin access identity that can authorize access to
     * S3 objects via a private distribution. If provided the distribution will be
     * private, if null the distribution will be be public.
     * @param trustedSignerSelf
     * If true the owner of the distribution (you) will be be allowed to generate
     * signed URLs for a private distribution. Note: If either trustedSignerSelf or
     * trustedSignerAwsAccountNumbers parameters are provided the private distribution
     * will require signed URLs to access content.
     * @param trustedSignerAwsAccountNumbers
     * Account Number identifiers for AWS account holders other than the
     * distribution's owner who will be allowed to generate signed URLs for a private
     * distribution. If null or empty, no additional AWS account holders may generate
     * signed URLs. Note: If either trustedSignerSelf or
     * trustedSignerAwsAccountNumbers parameters are provided the private distribution
     * will require signed URLs to access content.
     *
     * @return
     * an object that describes the distribution's updated configuration, including its
     * origin bucket and CNAME aliases.
     *
     * @throws CloudFrontServiceException
     */
    public DistributionConfig updateDistributionConfig(String id, String[] cnames,
        String comment, boolean enabled, LoggingStatus loggingStatus,
        String originAccessIdentityId, boolean trustedSignerSelf,
        String[] trustedSignerAwsAccountNumbers)
        throws CloudFrontServiceException
    {
        return updateDistributionConfigImpl(false, id, cnames, comment, enabled, loggingStatus,
    		originAccessIdentityId, trustedSignerSelf, trustedSignerAwsAccountNumbers);
    }

    /**
     * Update the configuration of an existing streaming distribution to change its
     * properties. The new configuration properties provided <strong>replace</strong>
     * any existing configuration, and may take some time to be fully applied.
     * <p>
     * This method performs all the steps necessary to update the configuration. It
     * first performs lookup on the distribution  using
     * {@link #getDistributionConfig(String)} to find its origin and caller reference
     * values, then uses this information to apply your configuration changes.
     *
     * @param id
     * the distribution's unique identifier.
     * @param cnames
     * A list of up to 10 CNAME aliases to associate with the distribution. This
     * parameter may be null, in which case the original CNAME aliases are retained.
     * @param comment
     * An optional comment to describe the distribution in your own terms
     * (max 128 characters). May be null, in which case the original comment is retained.
     * @param enabled
     * Should the distribution should be enabled and publicly accessible after the
     * configuration update?
     *
     * @return
     * an object that describes the distribution's updated configuration, including its
     * origin bucket and CNAME aliases.
     *
     * @throws CloudFrontServiceException
     */
    public StreamingDistributionConfig updateStreamingDistributionConfig(
    	String id, String[] cnames, String comment, boolean enabled)
        throws CloudFrontServiceException
    {
        return (StreamingDistributionConfig) updateDistributionConfigImpl(
    		true, id, cnames, comment, enabled, null, null, false, null);
    }

    /**
     * Update the configuration of an existing distribution to change its properties.
     * If the original distribution is private this method will make it public instead.
     * The new configuration properties provided <strong>replace</strong> any existing
     * configuration, and may take some time to be fully applied.
     * <p>
     * This method performs all the steps necessary to update the configuration. It
     * first performs lookup on the distribution  using
     * {@link #getDistributionConfig(String)} to find its origin and caller reference
     * values, then uses this information to apply your configuration changes.
     *
     * @param id
     * the distribution's unique identifier.
     * @param cnames
     * A list of up to 10 CNAME aliases to associate with the distribution. This
     * parameter may be null, in which case the original CNAME aliases are retained.
     * @param comment
     * An optional comment to describe the distribution in your own terms
     * (max 128 characters). May be null, in which case the original comment is retained.
     * @param enabled
     * Should the distribution should be enabled and publicly accessible after the
     * configuration update?
     * @param loggingStatus
     * Logging status settings (bucket, prefix) for the distribution. If this value
     * is null, logging will be disabled for the distribution.
     *
     * @return
     * an object that describes the distribution's updated configuration, including its
     * origin bucket and CNAME aliases.
     *
     * @throws CloudFrontServiceException
     */    public DistributionConfig updateDistributionConfig(String id, String[] cnames,
        String comment, boolean enabled, LoggingStatus loggingStatus)
        throws CloudFrontServiceException
    {
        return updateDistributionConfig(id, cnames, comment, enabled, loggingStatus,
    		null, false, null);
    }

     /**
      * Update the configuration of an existing distribution to change its properties
      * or public/private status. The new configuration properties provided
      * <strong>replace</strong> any existing configuration, and may take some time
      * to be fully applied.
      * <p>
      * This method performs all the steps necessary to update the configuration. It
      * first performs lookup on the distribution  using
      * {@link #getDistributionConfig(String)} to find its origin and caller reference
      * values, then uses this information to apply your configuration changes.
      *
      * @param id
      * the distribution's unique identifier.
      * @param config
      * Configuration properties to apply to the distribution.
      *
      * @return
      * an object that describes the distribution's updated configuration, including its
      * origin bucket and CNAME aliases.
      *
      * @throws CloudFrontServiceException
      */
    public DistributionConfig updateDistributionConfig(String id,
    	DistributionConfig config) throws CloudFrontServiceException
    {
        return updateDistributionConfig(id, config.getCNAMEs(), config.getComment(),
    		config.isEnabled(), config.getLoggingStatus(), config.getOriginAccessIdentity(),
    		config.isTrustedSignerSelf(), config.getTrustedSignerAwsAccountNumbers());
    }

    /**
     * Convenience method to disable a distribution that you intend to delete.
     * This method merely calls the
     * {@link #updateDistributionConfig(String, String[], String, boolean, LoggingStatus)}
     * method with default values for most of the distribution's configuration
     * settings.
     * <p>
     * <strong>Warning</strong>: Do not use this method on distributions you
     * intend to keep, because it will reset most of the distribution's
     * configuration settings such as CNAMEs and logging status.
     *
     * @param id
     * the distribution's unique identifier.
     *
     * @throws CloudFrontServiceException
     */
    public void disableDistributionForDeletion(String id)
        throws CloudFrontServiceException
    {
        updateDistributionConfig(id, new String[] {}, "Disabled prior to deletion", false, null);
    }

    /**
     * Convenience method to disable a streaming distribution that you intend to delete.
     * This method merely calls the
     * {@link #updateStreamingDistributionConfig(String, String[], String, boolean)}
     * method with default values for most of the distribution's configuration
     * settings.
     * <p>
     * <strong>Warning</strong>: Do not use this method on distributions you
     * intend to keep, because it will reset most of the distribution's
     * configuration settings such as CNAMEs and logging status.
     *
     * @param id
     * the distribution's unique identifier.
     *
     * @throws CloudFrontServiceException
     */
    public void disableStreamingDistributionForDeletion(String id)
    	throws CloudFrontServiceException
    {
    	updateStreamingDistributionConfig(id, new String[] {}, "Disabled prior to deletion", false);
    }

    /**
     * Delete a streaming or non-streaming distribution.
     * @param isStreaming
     * @param id
     * @throws CloudFrontServiceException
     */
    protected void deleteDistributionImpl(boolean isStreaming, String id)
        throws CloudFrontServiceException
    {
        if (log.isDebugEnabled()) {
            log.debug("Deleting "
            	+ (isStreaming ? "streaming" : "")
            	+ "distribution with id: " + id);
        }

        // Get the distribution's current config.
        DistributionConfig currentConfig =
            (isStreaming ? getStreamingDistributionConfig(id) : getDistributionConfig(id));

        DeleteMethod httpMethod = new DeleteMethod(ENDPOINT + VERSION
        	+ (isStreaming ? "/streaming-distribution/" : "/distribution/")
        	+ id);

        try {
            httpMethod.setRequestHeader("If-Match", currentConfig.getEtag());
            performRestRequest(httpMethod, 204);
        } catch (CloudFrontServiceException e) {
            throw e;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new CloudFrontServiceException(e);
        }
    }

    /**
     * Delete a disabled distribution. You can only delete a distribution that is
     * already disabled, if you delete an enabled distribution this operation will
     * fail with a <tt>DistributionNotDisabled</tt> error.
     * <p>
     * This method performs many of the steps necessary to delete a disabled
     * distribution. It first performs lookup on the distribution using
     * {@link #getDistributionConfig(String)} to find its ETag value, then uses
     * this information to delete the distribution.
     * <p>
     * Because it can take a long time (minutes) to disable a distribution, this
     * task is not performed automatically by this method. In your own code, you
     * need to verify that a distribution is disabled with a status of
     * <tt>Deployed</tt> before you invoke this method.
     *
     * @param id
     * the distribution's unique identifier.
     *
     * @throws CloudFrontServiceException
     */
    public void deleteDistribution(String id) throws CloudFrontServiceException {
        deleteDistributionImpl(false, id);
    }

    /**
     * Delete a disabled streaming distribution. You can only delete a distribution
     * that is already disabled, if you delete an enabled distribution this operation
     * will fail with a <tt>DistributionNotDisabled</tt> error.
     * <p>
     * This method performs many of the steps necessary to delete a disabled
     * distribution. It first performs lookup on the distribution using
     * {@link #getDistributionConfig(String)} to find its ETag value, then uses
     * this information to delete the distribution.
     * <p>
     * Because it can take a long time (minutes) to disable a distribution, this
     * task is not performed automatically by this method. In your own code, you
     * need to verify that a distribution is disabled with a status of
     * <tt>Deployed</tt> before you invoke this method.
     *
     * @param id
     * the distribution's unique identifier.
     *
     * @throws CloudFrontServiceException
     */
    public void deleteStreamingDistribution(String id) throws CloudFrontServiceException {
        deleteDistributionImpl(true, id);
    }

    /**
     * Create a new Origin Access Identity
     *
     * @param callerReference
     * A user-set unique reference value that ensures the request can't be replayed
     * (max UTF-8 encoding size 128 bytes). This parameter may be null, in which
     * case your computer's local epoch time in milliseconds will be used.
     * @param comment
     * An optional comment to describe the identity (max 128 characters). May be null.
     *
     * @return
     * The origin access identity's properties.
     *
     * @throws CloudFrontServiceException
     */
    public OriginAccessIdentity createOriginAccessIdentity(
        	String callerReference, String comment)
        	throws CloudFrontServiceException
    {
        if (log.isDebugEnabled()) {
            log.debug("Creating origin access identity");
        }

        PostMethod httpMethod = new PostMethod(ENDPOINT + VERSION +
            	ORIGIN_ACCESS_IDENTITY_URI_PATH);

        if (callerReference == null) {
            callerReference = "" + System.currentTimeMillis();
        }

        try {
            XMLBuilder builder = XMLBuilder.create(
            	"CloudFrontOriginAccessIdentityConfig")
                .a("xmlns", XML_NAMESPACE)
                .e("CallerReference").t(callerReference).up()
                .e("Comment").t(comment);

            httpMethod.setRequestEntity(new StringRequestEntity(
                	builder.asString(null), "text/xml", Constants.DEFAULT_ENCODING));

            performRestRequest(httpMethod, 201);

            OriginAccessIdentityHandler handler =
                (new CloudFrontXmlResponsesSaxParser(this.jets3tProperties))
                    .parseOriginAccessIdentity(httpMethod.getResponseBodyAsStream());

            return handler.getOriginAccessIdentity();
        } catch (CloudFrontServiceException e) {
            throw e;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new CloudFrontServiceException(e);
        }
    }

    /**
     * List the Origin Access Identities in a CloudFront account.
     *
     * @return
     * List of {@link OriginAccessIdentity} objects describing the identities.
     *
     * @throws CloudFrontServiceException
     */
    public List getOriginAccessIdentityList() throws CloudFrontServiceException {
        if (log.isDebugEnabled()) {
            log.debug("Getting list of origin access identities");
        }
        GetMethod httpMethod = new GetMethod(ENDPOINT + VERSION + ORIGIN_ACCESS_IDENTITY_URI_PATH);

        try {
            performRestRequest(httpMethod, 200);

            OriginAccessIdentityListHandler handler =
                (new CloudFrontXmlResponsesSaxParser(this.jets3tProperties))
                    .parseOriginAccessIdentityListResponse(httpMethod.getResponseBodyAsStream());
            return handler.getOriginAccessIdentityList();
        } catch (CloudFrontServiceException e) {
            throw e;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new CloudFrontServiceException(e);
        }
    }

    /**
     * Obtain the complete properties of an Origin Access Identity.
     *
     * @param id
     * The identifier of the Origin Access Identity.
     *
     * @return
     * The origin access identity's properties.
     *
     * @throws CloudFrontServiceException
     */
    public OriginAccessIdentity getOriginAccessIdentity(String id)
        	throws CloudFrontServiceException
    {
        if (log.isDebugEnabled()) {
            log.debug("Getting information for origin access identity with id: " + id);
        }
        GetMethod httpMethod = new GetMethod(ENDPOINT + VERSION +
            	ORIGIN_ACCESS_IDENTITY_URI_PATH + "/" + id);

        try {
            performRestRequest(httpMethod, 200);

            OriginAccessIdentityHandler handler =
                (new CloudFrontXmlResponsesSaxParser(this.jets3tProperties))
                    .parseOriginAccessIdentity(httpMethod.getResponseBodyAsStream());
            return handler.getOriginAccessIdentity();
        } catch (CloudFrontServiceException e) {
            throw e;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new CloudFrontServiceException(e);
        }
    }

    /**
     * Obtain the configuration properties of an Origin Access Identity.
     *
     * @param id
     * The identifier of the Origin Access Identity.
     *
     * @return
     * The origin access identity's configuration properties.
     *
     * @throws CloudFrontServiceException
     */
    public OriginAccessIdentityConfig getOriginAccessIdentityConfig(String id)
    	throws CloudFrontServiceException
    {
    	if (log.isDebugEnabled()) {
    	    log.debug("Getting config for origin access identity with id: " + id);
    	}
    	GetMethod httpMethod = new GetMethod(ENDPOINT + VERSION +
    			ORIGIN_ACCESS_IDENTITY_URI_PATH + "/" + id + "/config");

    	try {
    	    performRestRequest(httpMethod, 200);

    	    OriginAccessIdentityConfigHandler handler =
    	        (new CloudFrontXmlResponsesSaxParser(this.jets3tProperties))
    	            .parseOriginAccessIdentityConfig(httpMethod.getResponseBodyAsStream());

    	    OriginAccessIdentityConfig config = handler.getOriginAccessIdentityConfig();
    	    config.setEtag(httpMethod.getResponseHeader("ETag").getValue());
    		return config;
    	} catch (CloudFrontServiceException e) {
    	    throw e;
    	} catch (RuntimeException e) {
    		throw e;
    	} catch (Exception e) {
    	    throw new CloudFrontServiceException(e);
    	}
    }

    /**
     * Update the properties of an Origin Access Identity.
     *
     * @param id
     * The identifier of the Origin Access Identity.
     * @param comment
     * A new comment to apply to the identity.
     *
     * @return
     * The origin access identity's configuration properties.
     *
     * @throws CloudFrontServiceException
     */
    public OriginAccessIdentityConfig updateOriginAccessIdentityConfig(
        	String id, String comment) throws CloudFrontServiceException
    {
        if (log.isDebugEnabled()) {
            log.debug("Updating configuration of origin access identity with id: " + id);
        }

        // Retrieve the old configuration.
        OriginAccessIdentityConfig oldConfig = getOriginAccessIdentityConfig(id);

        // Sanitize parameters.
        if (comment == null) {
            comment = oldConfig.getComment();
        }

        PutMethod httpMethod = new PutMethod(ENDPOINT + VERSION +
            	ORIGIN_ACCESS_IDENTITY_URI_PATH + "/" + id + "/config");

        try {
            XMLBuilder builder = XMLBuilder.create(
            	"CloudFrontOriginAccessIdentityConfig")
                .a("xmlns", XML_NAMESPACE)
                .e("CallerReference").t(oldConfig.getCallerReference()).up()
                .e("Comment").t(comment);

            httpMethod.setRequestEntity(new StringRequestEntity(
            	builder.asString(null), "text/xml", Constants.DEFAULT_ENCODING));
            httpMethod.setRequestHeader("If-Match", oldConfig.getEtag());

            performRestRequest(httpMethod, 200);

            OriginAccessIdentityConfigHandler handler =
                (new CloudFrontXmlResponsesSaxParser(this.jets3tProperties))
                    .parseOriginAccessIdentityConfig(httpMethod.getResponseBodyAsStream());

            OriginAccessIdentityConfig config = handler.getOriginAccessIdentityConfig();
            config.setEtag(httpMethod.getResponseHeader("ETag").getValue());
            return config;
        } catch (CloudFrontServiceException e) {
            throw e;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new CloudFrontServiceException(e);
        }
    }

    /**
     * Delete an Origin Access Identity.
     *
     * @param id
     * The identifier of the Origin Access Identity.
     *
     * @throws CloudFrontServiceException
     */
    public void deleteOriginAccessIdentity(String id) throws CloudFrontServiceException
    {
        if (log.isDebugEnabled()) {
            log.debug("Deleting origin access identity with id: " + id);
        }

        // Get the identity's current config.
        OriginAccessIdentityConfig currentConfig = getOriginAccessIdentityConfig(id);

        DeleteMethod httpMethod = new DeleteMethod(ENDPOINT + VERSION +
            	ORIGIN_ACCESS_IDENTITY_URI_PATH + "/" + id);

        try {
            httpMethod.setRequestHeader("If-Match", currentConfig.getEtag());
            performRestRequest(httpMethod, 204);
        } catch (CloudFrontServiceException e) {
            throw e;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new CloudFrontServiceException(e);
        }
    }

    /**
     * Sanitizes a proposed bucket name to ensure it is fully-specified rather than
     * merely the bucket's short name. A fully specified bucket name looks like
     * "jets3t.s3.amazonaws.com".
     *
     * @param proposedBucketName
     * the proposed S3 bucket name that will be sanitized.
     *
     * @return
     * the bucket name with the {@link #DEFAULT_BUCKET_SUFFIX} added, if necessary.
     */
    public static String sanitizeS3BucketName(String proposedBucketName) {
        if (!proposedBucketName.endsWith(DEFAULT_BUCKET_SUFFIX)) {
            log.warn("Bucket names used within the CloudFront service should be specified as " +
            		"full S3 subdomain paths like 'jets3t.s3.amazonaws.com'. Repairing " +
            		"faulty bucket name value \"" + proposedBucketName + "\" by adding suffix " +
            		"'" + DEFAULT_BUCKET_SUFFIX + "'.");
            return proposedBucketName + DEFAULT_BUCKET_SUFFIX;
        } else {
            return proposedBucketName;
        }
    }

    /**
     * Convert the given string to be safe for use in signed URLs for a private distribution.
     * @param str
     * @return
     * a URL-safe Base64 encoded version of the data.
     * @throws UnsupportedEncodingException
     */
    protected static String makeStringUrlSafe(String str) throws UnsupportedEncodingException {
        return ServiceUtils.toBase64(str.getBytes("UTF-8"))
        	.replace('+', '-')
        	.replace('=', '_')
        	.replace('/', '~');
    }

    /**
     * Convert the given data to be safe for use in signed URLs for a private distribution by
     * using specialized Base64 encoding.
     * @param bytes
     * @return
     * a URL-safe Base64 encoded version of the data.
     * @throws UnsupportedEncodingException
     */
    protected static String makeBytesUrlSafe(byte[] bytes) throws UnsupportedEncodingException {
        return ServiceUtils.toBase64(bytes)
        	.replace('+', '-')
        	.replace('=', '_')
        	.replace('/', '~');
    }

    /**
     * Generate a policy document that describes custom access permissions to apply
     * via a private distribution's signed URL.
     *
     * @param resourcePath
     * An optional resource path that restricts which distribution and S3 objects will be
     * accessible in a signed URL. The '*' and '?' characters can be used as a wildcards
     * to allow multi-character or single-character matches respectively:
     * <ul>
     * <li><tt>*</tt> : All distributions/objects will be accessible</li>
     * <li><tt>a1b2c3d4e5f6g7.cloudfront.net/*</tt> : All objects within the distribution
     *     a1b2c3d4e5f6g7 will be accessible</li>
     * <li><tt>a1b2c3d4e5f6g7.cloudfront.net/path/to/object.txt</tt> : Only the S3 object
     *     named <tt>path/to/object.txt</tt> in the distribution a1b2c3d4e5f6g7 will be
     *     accessible.</li>
     * </ul>
     * If this parameter is null the policy will permit access to all distributions and S3
     * objects associated with the certificate keypair used to generate the signed URL.
     * @param epochDateLessThan
     * The time and date when the signed URL will expire. REQUIRED.
     * @param limitToIpAddressCIDR
     * An optional range of client IP addresses that will be allowed to access the distribution,
     * specified as a CIDR range. If null, the CIDR will be <tt>0.0.0.0/0</tt> and any
     * client will be permitted.
     * @param epochDateGreaterThan
     * An optional time and date when the signed URL will become active. If null, the signed
     * URL will be active as soon as it is created.
     *
     * @return
     * A policy document describing the access permission to apply when generating a signed URL.
     *
     * @throws CloudFrontServiceException
     */
    public static String buildPolicyForSignedUrl(
    	String resourcePath, Date epochDateLessThan,
    	String limitToIpAddressCIDR, Date epochDateGreaterThan)
        throws CloudFrontServiceException
    {
        if (epochDateLessThan == null) {
        	throw new CloudFrontServiceException(
    			"epochDateLessThan must be provided to sign CloudFront URLs");
        }
        if (resourcePath == null) {
        	resourcePath = "*";
        }
        try {
        	String resource = "http://" + resourcePath;
        	String ipAddress = (limitToIpAddressCIDR == null
    			? "0.0.0.0/0"
    			: limitToIpAddressCIDR);
        	String policy =
        		"{\n" +
        		"   \"Statement\": [{\n" +
        		"      \"Resource\":\"" + resource + "\",\n" +
        		"      \"Condition\":{\n" +
    			"         \"DateLessThan\":{\"AWS:EpochTime\":"
        					+ epochDateLessThan.getTime() / 1000 + "}" +
        				(ipAddress == null ? "" : ",\n" +
    			"         \"IpAddress\":{\"AWS:SourceIp\":\"" + ipAddress + "\"}") +
        				(epochDateGreaterThan == null ? "" : ",\n" +
    			"         \"DateGreaterThan\":{\"AWS:EpochTime\":"
        					+ epochDateGreaterThan.getTime() / 1000 + "}") +
    			"\n      }\n" +
    			"   }]\n" +
    			"}";
        	return policy;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new CloudFrontServiceException(e);
        }
    }

    /**
     * Generate a signed URL that allows access to distribution and S3 objects by
     * applying access restrictions specified in a custom policy document.
     *
     * @param domainName
     * The distribution's domain name, e.g.
     * <tt>a1b2c3d4e5f6g7.cloudfront.net/path/to/object.txt</tt>
     * @param s3ObjectKey
     * Key name of the S3 object that will be made accessible through the signed URL.
     * @param keyPairId
     * Identifier of a public/private certificate keypair already configured in your
     * Amazon Web Services account.
     * @param derPrivateKey
     * The RSA private key data that corresponding to the certificate keypair identified by
     * keyPairId, in DER format. To convert a standard PEM private key file into this format
     * use the utility method {@link EncryptionUtil#convertRsaPemToDer(java.io.InputStream)}
     * @param policy
     * A policy document that describes the access permissions that will be applied by the
     * signed URL. To generate a custom policy use
     * {@link #buildPolicyForSignedUrl(String, Date, String, Date)}.
     *
     * @return
     * A signed URL that will permit access to distribution and S3 objects as specified
     * in the policy document.
     *
     * @throws CloudFrontServiceException
     */
    public static String signUrl(String domainName, String s3ObjectKey,
    	String keyPairId, byte[] derPrivateKey, String policy)
        throws CloudFrontServiceException
    {
        try {
    		String url = "http://" + domainName + "/" + s3ObjectKey;
        	byte[] signatureBytes = EncryptionUtil.signWithRsaSha1(derPrivateKey,
        		policy.getBytes("UTF-8"));

        	String urlSafePolicy = makeStringUrlSafe(policy);
        	String urlSafeSignature = makeBytesUrlSafe(signatureBytes);

        	String signedUrl = url
        		+ (url.indexOf('?') >= 0 ? "&" : "?")
        		+ "Policy=" + urlSafePolicy
        		+ "&Signature=" + urlSafeSignature
        		+ "&Key-Pair-Id=" + keyPairId;
        	return signedUrl;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new CloudFrontServiceException(e);
        }
    }

    /**
     * Generate a signed URL that allows access to a specific distribution and
     * S3 object by applying a access restrictions from a "canned" (simplified)
     * policy document.
     *
     * @param domainName
     * The distribution's domain name, e.g.
     * <tt>a1b2c3d4e5f6g7.cloudfront.net/path/to/object.txt</tt>
     * @param s3ObjectKey
     * Key name of the S3 object that will be made accessible through the signed URL.
     * @param keyPairId
     * Identifier of a public/private certificate keypair already configured in your
     * Amazon Web Services account.
     * @param derPrivateKey
     * The RSA private key data that corresponding to the certificate keypair identified by
     * keyPairId, in DER format. To convert a standard PEM private key file into this format
     * use the utility method {@link EncryptionUtil#convertRsaPemToDer(java.io.InputStream)}
     * @param epochDateLessThan
     * The time and date when the signed URL will expire. REQUIRED.
     *
     * @return
     * A signed URL that will permit access to a specific distribution and S3 object.
     *
     * @throws CloudFrontServiceException
     */
    public static String signUrlCanned(String domainName, String s3ObjectKey,
        	String keyPairId, byte[] derPrivateKey, Date epochDateLessThan)
            throws CloudFrontServiceException
    {
        try {
    		String url = "http://" + domainName + "/" + s3ObjectKey;
    		String resourcePath = url;

            String cannedPolicy =
            	"{\"Statement\":[{\"Resource\":\"" + resourcePath
        		+ "\",\"Condition\":{\"DateLessThan\":{\"AWS:EpochTime\":"
        		+ epochDateLessThan.getTime() / 1000 + "}}}]}";

        	byte[] signatureBytes = EncryptionUtil.signWithRsaSha1(derPrivateKey,
        		cannedPolicy.getBytes("UTF-8"));

        	String urlSafeSignature = makeBytesUrlSafe(signatureBytes);

        	String signedUrl = url
        		+ (url.indexOf('?') >= 0 ? "&" : "?")
        		+ "Expires=" + epochDateLessThan.getTime() / 1000
        		+ "&Signature=" + urlSafeSignature
        		+ "&Key-Pair-Id=" + keyPairId;
        	return signedUrl;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new CloudFrontServiceException(e);
        }
    }

}

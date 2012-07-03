/*
 * JetS3t : Java S3 Toolkit
 * Project hosted at http://bitbucket.org/jmurty/jets3t/
 *
 * Copyright 2008 - 2011 James Murty
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
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import javax.xml.parsers.FactoryConfigurationError;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.params.HttpProtocolParams;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;
import org.jets3t.service.impl.rest.CloudFrontXmlResponsesSaxParser;
import org.jets3t.service.impl.rest.CloudFrontXmlResponsesSaxParser.DistributionConfigHandler;
import org.jets3t.service.impl.rest.CloudFrontXmlResponsesSaxParser.DistributionHandler;
import org.jets3t.service.impl.rest.CloudFrontXmlResponsesSaxParser.DistributionListHandler;
import org.jets3t.service.impl.rest.CloudFrontXmlResponsesSaxParser.ErrorHandler;
import org.jets3t.service.impl.rest.CloudFrontXmlResponsesSaxParser.InvalidationHandler;
import org.jets3t.service.impl.rest.CloudFrontXmlResponsesSaxParser.InvalidationListHandler;
import org.jets3t.service.impl.rest.CloudFrontXmlResponsesSaxParser.OriginAccessIdentityConfigHandler;
import org.jets3t.service.impl.rest.CloudFrontXmlResponsesSaxParser.OriginAccessIdentityHandler;
import org.jets3t.service.impl.rest.CloudFrontXmlResponsesSaxParser.OriginAccessIdentityListHandler;
import org.jets3t.service.impl.rest.httpclient.JetS3tRequestAuthorizer;
import org.jets3t.service.model.S3Object;
import org.jets3t.service.model.cloudfront.CacheBehavior;
import org.jets3t.service.model.cloudfront.CustomOrigin;
import org.jets3t.service.model.cloudfront.Distribution;
import org.jets3t.service.model.cloudfront.DistributionConfig;
import org.jets3t.service.model.cloudfront.Invalidation;
import org.jets3t.service.model.cloudfront.InvalidationList;
import org.jets3t.service.model.cloudfront.InvalidationSummary;
import org.jets3t.service.model.cloudfront.LoggingStatus;
import org.jets3t.service.model.cloudfront.Origin;
import org.jets3t.service.model.cloudfront.OriginAccessIdentity;
import org.jets3t.service.model.cloudfront.OriginAccessIdentityConfig;
import org.jets3t.service.model.cloudfront.S3Origin;
import org.jets3t.service.model.cloudfront.StreamingDistribution;
import org.jets3t.service.model.cloudfront.StreamingDistributionConfig;
import org.jets3t.service.security.EncryptionUtil;
import org.jets3t.service.security.ProviderCredentials;
import org.jets3t.service.utils.RestUtils;
import org.jets3t.service.utils.ServiceUtils;

import com.jamesmurty.utils.XMLBuilder;

/**
 * A service that handles communication with the Amazon CloudFront REST API, offering
 * all the operations that can be performed on CloudFront distributions.
 * <p>
 * This class uses properties obtained through {@link Jets3tProperties}. For more information on
 * these properties please refer to
 * <a href="http://www.jets3t.org/toolkit/configuration.html">JetS3t Configuration</a>
 * </p>
 *
 * @author James Murty
 */
public class CloudFrontService implements JetS3tRequestAuthorizer {
    private static final Log log = LogFactory.getLog(CloudFrontService.class);

    public static final String ENDPOINT = "https://cloudfront.amazonaws.com/";
    public static final String VERSION = "2012-05-05";
    public static final String XML_NAMESPACE = "http://cloudfront.amazonaws.com/doc/" + VERSION + "/";
    public static final String DEFAULT_BUCKET_SUFFIX = ".s3.amazonaws.com";
    public static final String ORIGIN_ACCESS_IDENTITY_URI_PATH = "/origin-access-identity/cloudfront";
    public static final String ORIGIN_ACCESS_IDENTITY_PREFIX = "origin-access-identity/cloudfront/";

    protected HttpClient httpClient;
    private CredentialsProvider credentialsProvider;

    private ProviderCredentials credentials;
    protected Jets3tProperties jets3tProperties;
    private String invokingApplicationDescription;
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
     * @param credentials
     * the Storage Provider user credentials to use when communicating with CloudFront
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
     *
     * @throws CloudFrontServiceException
     */
    public CloudFrontService(ProviderCredentials credentials, String invokingApplicationDescription,
        CredentialsProvider credentialsProvider, Jets3tProperties jets3tProperties)
    throws CloudFrontServiceException
    {
        this.credentials = credentials;
        this.invokingApplicationDescription = invokingApplicationDescription;
        this.credentialsProvider = credentialsProvider;
        if (jets3tProperties == null) {
            jets3tProperties = Jets3tProperties.getInstance(Constants.JETS3T_PROPERTIES_FILENAME);
        }
        this.jets3tProperties = jets3tProperties;
        this.internalErrorRetryMax = jets3tProperties.getIntProperty("cloudfront-service.internal-error-retry-max", 5);
        this.initializeDefaults();
    }

    protected void initializeDefaults(){
        // Configure the InetAddress DNS caching times to work well with CloudFront. The cached DNS will
        // timeout after 5 minutes, while failed DNS lookups will be retried after 1 second.
        System.setProperty("networkaddress.cache.ttl", "300");
        System.setProperty("networkaddress.cache.negative.ttl", "1");

        this.httpClient = initHttpConnection();
        /* TODO: CloudFront service does not seem to support 100-continue protocol for 2009-04-02
         * DistributionConfig updates, causing unnecessary timeouts when updating these settings.
         * This will probably be fixed, remove the following line when full support returns.
         */
        HttpProtocolParams.setUseExpectContinue(this.httpClient.getParams(), false);
        initializeProxy();
    }

    protected HttpClient initHttpConnection() {
        return RestUtils.initHttpConnection(
                this,
                this.jets3tProperties,
                this.invokingApplicationDescription,
                this.credentialsProvider);
    }

    protected void initializeProxy() {
        // Retrieve Proxy settings.
        if (this.jets3tProperties.getBoolProperty("httpclient.proxy-autodetect", true)) {
            RestUtils.initHttpProxy(this.httpClient, this.jets3tProperties);
        } else {
            String proxyHostAddress = this.jets3tProperties.getStringProperty("httpclient.proxy-host", null);
            int proxyPort = this.jets3tProperties.getIntProperty("httpclient.proxy-port", -1);
            String proxyUser = this.jets3tProperties.getStringProperty("httpclient.proxy-user", null);
            String proxyPassword = this.jets3tProperties.getStringProperty("httpclient.proxy-password", null);
            String proxyDomain = this.jets3tProperties.getStringProperty("httpclient.proxy-domain", null);
            RestUtils.initHttpProxy(this.httpClient, this.jets3tProperties,
                proxyHostAddress, proxyPort, proxyUser, proxyPassword, proxyDomain);
        }
    }

    /**
     * Constructs the service with default properties.
     *
     * @param credentials
     * the Storage Provider user credentials to use when communicating with CloudFront
     *
     * @throws CloudFrontServiceException
     */
    public CloudFrontService(ProviderCredentials credentials) throws CloudFrontServiceException
    {
        this(credentials, null, null, null);
    }

    /**
     * @return the Storage Provider Credentials identifying the AWS user.
     */
    public ProviderCredentials getAWSCredentials() {
        return credentials;
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
     * @param context
     * @throws ServiceException
     */
    public void authorizeHttpRequest(HttpUriRequest httpMethod, HttpContext context) throws ServiceException {
        String date = ServiceUtils.formatRfc822Date(getCurrentTimeWithOffset());

        // Set/update the date timestamp to the current time
        // Note that this will be over-ridden if an "x-amz-date" header is present.
        httpMethod.setHeader("Date", date);

        // Sign the date to authenticate the request.
        // Sign the canonical string.
        String signature = ServiceUtils.signWithHmacSha1(
            getAWSCredentials().getSecretKey(), date);

        // Add encoded authorization to connection as HTTP Authorization header.
        String authorizationString = "AWS " + getAWSCredentials().getAccessKey() + ":" + signature;
        httpMethod.setHeader("Authorization", authorizationString);
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
    protected HttpResponse performRestRequest(HttpRequestBase httpMethod, int expectedResponseCode)
        throws CloudFrontServiceException
    {
        // Set mandatory Request headers.
        if (httpMethod.getFirstHeader("Date") == null) {
            httpMethod.setHeader("Date", ServiceUtils.formatRfc822Date(
                getCurrentTimeWithOffset()));
        }

        HttpResponse response = null;
        boolean completedWithoutRecoverableError;
        int internalErrorCount = 0;

        try {
            do {
                completedWithoutRecoverableError = true;
                authorizeHttpRequest(httpMethod, null);
                response = httpClient.execute(httpMethod);
                int responseCode = response.getStatusLine().getStatusCode();

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
                        ErrorHandler handler = new CloudFrontXmlResponsesSaxParser(
                                this.jets3tProperties).parseErrorResponse(
                                        response.getEntity().getContent());

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
            releaseConnection(response);
            throw e;
        } catch (Throwable t) {
            releaseConnection(response);
            throw new CloudFrontServiceException("CloudFront Request failed", t);
        }
        return response;
    }

    private void releaseConnection(HttpResponse pResponse){
        if (pResponse == null){
            return;
        }
        try {
            EntityUtils.consume(pResponse.getEntity());
        } catch (Exception e){
            //ignore
        }
    }

    /**
     * List streaming or non-streaming Distributions in a CloudFront account.
     * @param isStreaming
     * Only return streaming distributions
     * @param pagingSize
     * the maximum number of distributions the CloudFront service will
     * return in each response message.
     * @return
     * A list of {@link Distribution}s.
     * @throws CloudFrontServiceException
     */
    protected List<Distribution> listDistributionsImpl(boolean isStreaming, int pagingSize)
        throws CloudFrontServiceException
    {
        if (log.isDebugEnabled()) {
            log.debug("Listing "
                + (isStreaming ? "streaming" : "")
                + " distributions for AWS user: " + getAWSCredentials().getAccessKey());
        }
        try {
            List<Distribution> distributions = new ArrayList<Distribution>();
            String nextMarker = null;
            boolean incompleteListing;
            do {
                String uri = ENDPOINT + VERSION
                    + (isStreaming ? "/streaming-distribution" : "/distribution")
                    + "?MaxItems=" + pagingSize;
                if (nextMarker != null) {
                    uri += "&Marker=" + nextMarker;
                }
                HttpRequestBase httpMethod = new HttpGet(uri);
                HttpResponse response = performRestRequest(httpMethod, 200);

                DistributionListHandler handler =
                    (new CloudFrontXmlResponsesSaxParser(this.jets3tProperties))
                        .parseDistributionListResponse(response.getEntity().getContent());
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
        List<Distribution> distributions = listDistributionsImpl(false, pagingSize);
        return distributions.toArray(new Distribution[distributions.size()]);
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
        List<Distribution> distributions = listDistributionsImpl(true, pagingSize);
        return distributions.toArray(
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
     * List all your streaming CloudFront distributions.
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
     * @param isStreaming List streaming distributions
     * @param bucketName
     * the name of the S3 bucket whose distributions will be returned.
     * @return
     * a list of distributions applied to the given S3 bucket, or an empty list
     * if there are no such distributions.
     *
     * @throws CloudFrontServiceException
     */
    public List<Distribution> listDistributionsByBucketName(boolean isStreaming, String bucketName)
        throws CloudFrontServiceException
    {
        String s3Endpoint = this.jets3tProperties.getStringProperty(
            "s3service.s3-endpoint", Constants.S3_DEFAULT_HOSTNAME);
        if (log.isDebugEnabled()) {
            log.debug("Listing "
                + (isStreaming ? "streaming" : "")
                + " distributions for the S3 bucket '" + bucketName
                + "' for AWS user: " + getAWSCredentials().getAccessKey());
        }
        ArrayList<Distribution> bucketDistributions = new ArrayList<Distribution>();
        Distribution[] allDistributions =
            (isStreaming ? listStreamingDistributions() : listDistributions());
        for(Distribution distribution : allDistributions) {
            Origin origin = distribution.getOrigin();
            if(!(origin instanceof S3Origin)) {
                continue;
            }
            S3Origin s3Origin = (S3Origin) origin;
            if(s3Origin.getDomainName().equals(bucketName)
                    || bucketName.equals(ServiceUtils.findBucketNameInHostname(s3Origin.getDomainName(), s3Endpoint))) {
                bucketDistributions.add(distribution);
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
        List<Distribution> bucketDistributions = listDistributionsByBucketName(false, bucketName);
        return bucketDistributions.toArray(
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
        List<Distribution> streamingDistributions = listDistributionsByBucketName(true, bucketName);
        return streamingDistributions.toArray(
            new StreamingDistribution[streamingDistributions.size()]);
    }

    /**
     * Generate XML representing an S3 or non-S3 (custom) origin.
     *
     * @param origin S3 or non-S3 (custom) origin.
     * @return
     * XML document representing an origin
     *
     * @throws TransformerException
     * @throws ParserConfigurationException
     * @throws FactoryConfigurationError
     */
    protected XMLBuilder buildOrigin(Origin origin) throws TransformerException,
        ParserConfigurationException, FactoryConfigurationError
    {
        XMLBuilder builder = XMLBuilder.create("Origin");
        if (origin.getId() != null) {
            builder.e("Id").t(origin.getId());
        } else {
            builder.e("Id").t("default-origin-id");
        }
        if (origin instanceof S3Origin) {
            builder.e("DomainName").t(sanitizeS3BucketName(origin.getDomainName()));
            S3Origin o = (S3Origin) origin;
            XMLBuilder oaiBuilder = builder
                .e("S3OriginConfig")
                    .e("OriginAccessIdentity");
            if (o.getOriginAccessIdentity() != null) {
                oaiBuilder.t(o.getOriginAccessIdentity());
            }
        } else {
            CustomOrigin o = (CustomOrigin) origin;
            builder.e("DomainName").t(origin.getDomainName());
            builder.e("CustomOriginConfig")
                .e("HTTPPort").t(String.valueOf(o.getHttpPort())).up()
                .e("HTTPSPort").t(String.valueOf(o.getHttpsPort())).up()
                .e("OriginProtocolPolicy").t(o.getOriginProtocolPolicy().toText());
        }
        return builder;
    }

    protected XMLBuilder buildDefaultCacheBehavior(CacheBehavior cb)
        throws TransformerException, ParserConfigurationException, FactoryConfigurationError
    {
        return this.buildCacheBehaviorsElement(true, new CacheBehavior[] {cb});
    }

    protected XMLBuilder buildCacheBehaviors(CacheBehavior[] cbs)
        throws TransformerException, ParserConfigurationException, FactoryConfigurationError
    {
        return this.buildCacheBehaviorsElement(false, cbs);
    }

    protected XMLBuilder buildCacheBehaviorsElement(boolean isDefault, CacheBehavior[] cbs)
        throws TransformerException, ParserConfigurationException, FactoryConfigurationError
    {
        XMLBuilder builder;
        if (isDefault) {
            builder = XMLBuilder.create("DefaultCacheBehavior");
        } else {
            builder = XMLBuilder.create("CacheBehaviors")
                .e("Quantity").t(String.valueOf(cbs.length)).up();
        }
        if (!isDefault && cbs.length > 0) {
            builder = builder.e("Items");
        }
        for (CacheBehavior cb: cbs) {
            XMLBuilder itemBuilder;
            if (isDefault) {
                itemBuilder = builder;
            } else {
                itemBuilder = builder.e("CacheBehavior");
                itemBuilder.e("PathPattern").t(cb.getPathPattern());
            }

            if (cb.getTargetOriginId() != null) {
                itemBuilder.e("TargetOriginId").t(cb.getTargetOriginId());
            } else {
                itemBuilder.e("TargetOriginId").t("default-origin-id");
            }
            itemBuilder.e("ForwardedValues").e("QueryString").t(String.valueOf(cb.isForwardQueryString()));

            XMLBuilder trustedSignersBuilder = itemBuilder.e("TrustedSigners");
            if (cb.getTrustedSignerAwsAccountNumbers() == null
                || cb.getTrustedSignerAwsAccountNumbers().length == 0)
            {
                trustedSignersBuilder
                    .e("Enabled").t(String.valueOf(false)).up()
                    .e("Quantity").t(String.valueOf(0));
            } else {
                XMLBuilder itemsBuilder = trustedSignersBuilder
                    .e("Enabled").t(String.valueOf(true)).up()
                    .e("Quantity").t(String.valueOf(cb.getTrustedSignerAwsAccountNumbers().length)).up()
                    .e("Items");
                for (String awsAccountNumber: cb.getTrustedSignerAwsAccountNumbers()) {
                    itemsBuilder.e("AwsAccountNumber").t(awsAccountNumber);
                }
            }

            itemBuilder.e("ViewerProtocolPolicy").t(cb.getViewerProtocolPolicy().toText());
            if (cb.getMinTTL() != null) {
                itemBuilder.e("MinTTL").t(String.valueOf(cb.getMinTTL()));
            } else {
                itemBuilder.e("MinTTL").t(String.valueOf(0));
            }
        }

        return builder;
    }


    /**
     * Generate a DistributionConfig or StreamingDistributionConfig XML document.
     * @return
     * XML document representing a Distribution Configuration
     * @throws TransformerException
     * @throws ParserConfigurationException
     * @throws FactoryConfigurationError
     */
    protected String buildDistributionConfigXmlDocument(DistributionConfig config)
        throws TransformerException, ParserConfigurationException, FactoryConfigurationError
    {
        XMLBuilder builder = XMLBuilder.create(config.isStreamingDistributionConfig()
            ? "StreamingDistributionConfig"
            : "DistributionConfig")
            .a("xmlns", XML_NAMESPACE);

        builder.e("CallerReference").t(config.getCallerReference() == null ? String.valueOf(System.currentTimeMillis()) : config.getCallerReference());

        XMLBuilder aliasesBuilder = builder.e("Aliases");
        if (config.getCNAMEs() != null && config.getCNAMEs().length > 0) {
            aliasesBuilder.e("Quantity").t(String.valueOf(config.getCNAMEs().length));
            XMLBuilder items = aliasesBuilder.e("Items");
            for (String cname: config.getCNAMEs()) {
                items.e("CNAME").t(cname);
            }
        } else {
            aliasesBuilder.e("Quantity").t(String.valueOf("0"));
        }

        if (config.getDefaultRootObject() != null) {
            builder.e("DefaultRootObject").t(config.getDefaultRootObject());
        } else {
            builder.e("DefaultRootObject");
        }

        XMLBuilder originsBuilder = builder
            .e("Origins")
                .e("Quantity").t(String.valueOf(config.getOrigins().length)).up()
                .e("Items");
        for (Origin origin: config.getOrigins()) {
            originsBuilder.importXMLBuilder(buildOrigin(origin));
        }

        builder.importXMLBuilder(buildDefaultCacheBehavior(config.getDefaultCacheBehavior()));

        builder.importXMLBuilder(buildCacheBehaviors(config.getCacheBehaviors()));

        builder.e("Comment").t(null == config.getComment() ? "" : config.getComment());

        if (config.getLoggingStatus() != null) {
            builder.e("Logging")
                .e("Enabled").t(String.valueOf(true)).up()
                .e("Bucket").t(config.getLoggingStatus().getBucket()).up()
                .e("Prefix").t(config.getLoggingStatus().getPrefix());
        } else {
            builder.e("Logging")
                .e("Enabled").t(String.valueOf(false)).up()
                .e("Bucket").up()
                .e("Prefix");
        }

        builder.e("Enabled").t(String.valueOf(config.isEnabled()));

        return builder.asString(null);
    }

    /**
     * Create a streaming or non-streaming distribution.
     * @param config Configuration document
     * @return
     * Information about the newly-created distribution.
     * @throws CloudFrontServiceException
     */
    protected Distribution createDistributionImpl(DistributionConfig config)
        throws CloudFrontServiceException
    {
        if (log.isDebugEnabled()) {
            log.debug("Creating "
                + (config.isStreamingDistributionConfig() ? "streaming" : "")
                + " distribution for origins: " + Arrays.asList(config.getOrigins()));
        }

        HttpPost httpMethod = new HttpPost(ENDPOINT + VERSION
            + (config.isStreamingDistributionConfig()
                ? "/streaming-distribution"
                : "/distribution"));

        try {
            String distributionConfigXml = buildDistributionConfigXmlDocument(config);

            httpMethod.setEntity(new StringEntity(
                    distributionConfigXml,
                    ContentType.create("text/xml", Constants.DEFAULT_ENCODING)));

            HttpResponse response = performRestRequest(httpMethod, 201);

            DistributionHandler handler =
                (new CloudFrontXmlResponsesSaxParser(this.jets3tProperties))
                    .parseDistributionResponse(response.getEntity().getContent());

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
     * the origin to associate with the distribution, either an Amazon S3 bucket or
     * a custom HTTP/S-accessible location.
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
     * @param requiredProtocols
     * List of protocols that must be used by clients to retrieve content from the
     * distribution. If this value is null or is an empty array, all protocols will be
     * supported.
     * @param defaultRootObject
     * The name of an object that will be served when someone visits the root of a
     * distribution.
     *
     * @return
     * an object that describes the newly-created distribution, in particular the
     * distribution's identifier and domain name values.
     *
     * @throws CloudFrontServiceException
     */
    public Distribution createDistribution(Origin origin, String callerReference,
        String[] cnames, String comment, boolean enabled, LoggingStatus loggingStatus,
        boolean trustedSignerSelf, String[] trustedSignerAwsAccountNumbers,
        String[] requiredProtocols, String defaultRootObject)
        throws CloudFrontServiceException
    {
        return this.createDistribution(
            origin, callerReference, cnames, comment, enabled, loggingStatus,
            trustedSignerSelf, trustedSignerAwsAccountNumbers, requiredProtocols, defaultRootObject,
            null // minTTL
            );
    }

    /**
     * Create a public or private CloudFront distribution for an S3 bucket.
     *
     * @deprecated as of 2012-05-05 API version, use {@link #createDistribution(DistributionConfig)}.
     *
     * @param origin
     * the origin to associate with the distribution, either an Amazon S3 bucket or
     * a custom HTTP/S-accessible location.
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
     * @param requiredProtocols
     * List of protocols that must be used by clients to retrieve content from the
     * distribution. If this value is null or is an empty array, all protocols will be
     * supported.
     * @param defaultRootObject
     * The name of an object that will be served when someone visits the root of a
     * distribution.
     * @param minTTL
     * The time to live (TTL) to apply to objects served by this distribution.
     *
     * @return
     * an object that describes the newly-created distribution, in particular the
     * distribution's identifier and domain name values.
     *
     * @throws CloudFrontServiceException
     */
    @Deprecated
    public Distribution createDistribution(Origin origin, String callerReference,
        String[] cnames, String comment, boolean enabled, LoggingStatus loggingStatus,
        boolean trustedSignerSelf, String[] trustedSignerAwsAccountNumbers,
        String[] requiredProtocols, String defaultRootObject, Long minTTL)
        throws CloudFrontServiceException
    {
        DistributionConfig config = new DistributionConfig(
            origin, callerReference, cnames, comment, enabled, loggingStatus,
            trustedSignerSelf, trustedSignerAwsAccountNumbers, requiredProtocols,
            defaultRootObject, minTTL);
        return createDistributionImpl(config);
    }

    /**
     * Create a minimally-configured CloudFront distribution for an S3 bucket that will
     * be publicly available once created.
     *
     * @param origin
     * the origin to associate with the distribution, either an Amazon S3 bucket or
     * a custom HTTP/S-accessible location.
     *
     * @return
     * an object that describes the newly-created distribution, in particular the
     * distribution's identifier and domain name values.
     *
     * @throws CloudFrontServiceException
     */
    public Distribution createDistribution(Origin origin) throws CloudFrontServiceException
    {
        return this.createDistribution(origin, null, null, null, true, null);
    }

    /**
     * Create a public CloudFront distribution for an S3 bucket.
     *
     * @param origin
     * the origin to associate with the distribution, either an Amazon S3 bucket or
     * a custom HTTP/S-accessible location.
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
    public Distribution createDistribution(Origin origin, String callerReference,
        String[] cnames, String comment, boolean enabled, LoggingStatus loggingStatus)
        throws CloudFrontServiceException
    {
        return createDistribution(origin, callerReference, cnames, comment, enabled,
                loggingStatus, false, null, null, null);
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
        return createDistributionImpl(config);
    }

    /**
     * Create a public or private streaming CloudFront distribution for an S3 bucket.
     *
     * @deprecated as of 2012-05-05 API version, use {@link #createDistribution(DistributionConfig)}.
     *
     * @param origin
     * the origin to associate with the distribution, either an Amazon S3 bucket or
     * a custom HTTP/S-accessible location.
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
    @Deprecated
    public StreamingDistribution createStreamingDistribution(Origin origin, String callerReference,
            String[] cnames, String comment, boolean enabled, LoggingStatus loggingStatus,
            boolean trustedSignerSelf, String[] trustedSignerAwsAccountNumbers)
        throws CloudFrontServiceException
    {
        StreamingDistributionConfig config = new StreamingDistributionConfig(
            origin, callerReference, cnames, comment, enabled, loggingStatus,
            trustedSignerSelf, trustedSignerAwsAccountNumbers, null);
        return (StreamingDistribution) createDistributionImpl(config);
    }

    /**
     * Create a public streaming CloudFront distribution for an S3 bucket.
     *
     * @deprecated as of 2012-05-05 API version, use {@link #createDistribution(DistributionConfig)}.
     *
     * @param origin
     * the origin to associate with the distribution, either an Amazon S3 bucket or
     * a custom HTTP/S-accessible location.
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
    @Deprecated
    public StreamingDistribution createStreamingDistribution(Origin origin, String callerReference,
            String[] cnames, String comment, boolean enabled, LoggingStatus loggingStatus)
        throws CloudFrontServiceException
    {
        StreamingDistributionConfig config = new StreamingDistributionConfig(
            origin, callerReference, cnames, comment, enabled, loggingStatus);
        return (StreamingDistribution) createDistributionImpl(config);
    }

    /**
     * @param isStreaming
     * Only return streaming distributions
     * @param distributionId
     * The distribution's unique identifier.
     * @return
     * Information about a streaming or non-streaming distribution.
     * @throws CloudFrontServiceException
     */
    protected Distribution getDistributionInfoImpl(boolean isStreaming, String distributionId)
        throws CloudFrontServiceException
    {
        if (log.isDebugEnabled()) {
            log.debug("Getting information for "
                + (isStreaming ? "streaming" : "")
                + " distribution with id: " + distributionId);
        }
        HttpGet httpMethod = new HttpGet(ENDPOINT + VERSION
                + (isStreaming ? "/streaming-distribution/" : "/distribution/")
                + distributionId);

        try {
            HttpResponse response = performRestRequest(httpMethod, 200);
            DistributionHandler handler =
                (new CloudFrontXmlResponsesSaxParser(this.jets3tProperties))
                    .parseDistributionResponse(response.getEntity().getContent());

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
     * @param distributionId
     * the distribution's unique identifier.
     *
     * @return
     * an object that describes the distribution, including its identifier and domain
     * name values as well as its configuration details.
     *
     * @throws CloudFrontServiceException
     */
    public StreamingDistribution getStreamingDistributionInfo(String distributionId)
        throws CloudFrontServiceException
    {
        return (StreamingDistribution) getDistributionInfoImpl(true, distributionId);
    }

    /**
     * @param isStreaming
     * Only return streaming distributions
     * @param distributionId
     * The distribution's unique identifier.
     * @return
     * Information about a streaming or non-streaming distribution configuration.
     * @throws CloudFrontServiceException
     */
    protected DistributionConfig getDistributionConfigImpl(boolean isStreaming, String distributionId)
        throws CloudFrontServiceException
    {
        if (log.isDebugEnabled()) {
            log.debug("Getting configuration for "
                + (isStreaming ? "streaming" : "")
                + " distribution with id: " + distributionId);
        }
        HttpGet httpMethod = new HttpGet(ENDPOINT + VERSION
                + (isStreaming ? "/streaming-distribution/" : "/distribution/")
                + distributionId + "/config");

        try {
            HttpResponse response = performRestRequest(httpMethod, 200);
            DistributionConfigHandler handler =
                (new CloudFrontXmlResponsesSaxParser(this.jets3tProperties))
                    .parseDistributionConfigResponse(response.getEntity().getContent());

            DistributionConfig config = handler.getDistributionConfig();
            config.setEtag(response.getFirstHeader("ETag").getValue());
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
     * @param distributionId
     * the distribution's unique identifier.
     *
     * @return
     * an object that describes the distribution's configuration, including its origin bucket
     * and CNAME aliases.
     *
     * @throws CloudFrontServiceException
     */
    public DistributionConfig getDistributionConfig(String distributionId)
        throws CloudFrontServiceException
    {
        return getDistributionConfigImpl(false, distributionId);
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
     *
     * @param config
     * Configuration properties to apply to the distribution.
     * @return
     * Information about the updated distribution configuration.
     * @throws CloudFrontServiceException
     */
    protected DistributionConfig updateDistributionConfigImpl(String id, DistributionConfig config)
        throws CloudFrontServiceException
    {
        if (log.isDebugEnabled()) {
            log.debug("Updating configuration of "
                + (config.isStreamingDistributionConfig() ? "streaming" : "")
                + "distribution with id: " + id);
        }

        // Retrieve the old configuration.
        DistributionConfig oldConfig = (config.isStreamingDistributionConfig()
            ? getStreamingDistributionConfig(id)
            : getDistributionConfig(id));

        HttpPut httpMethod = new HttpPut(ENDPOINT + VERSION
                + (config.isStreamingDistributionConfig()
                    ? "/streaming-distribution/"
                    : "/distribution/")
                + id + "/config");

        try {
            String distributionConfigXml = buildDistributionConfigXmlDocument(config);

            httpMethod.setEntity(new StringEntity(
                    distributionConfigXml,
                    ContentType.create("text/xml", Constants.DEFAULT_ENCODING)));
            httpMethod.setHeader("If-Match", oldConfig.getEtag());
            HttpResponse response = performRestRequest(httpMethod, 200);

            DistributionConfigHandler handler =
                (new CloudFrontXmlResponsesSaxParser(this.jets3tProperties))
                    .parseDistributionConfigResponse(response.getEntity().getContent());

            DistributionConfig resultConfig = handler.getDistributionConfig();
            resultConfig.setEtag(response.getFirstHeader("ETag").getValue());
            return resultConfig;
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
     * @deprecated as of 2012-05-05 API version, use {@link #updateDistributionConfig(String, DistributionConfig)}.
     *
     * @param id
     * the distribution's unique identifier.
     * @param origin
     * the origin to associate with the distribution, either an Amazon S3 bucket or
     * a custom HTTP/S-accessible location.
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
     * @param requiredProtocols
     * List of protocols that must be used by clients to retrieve content from the
     * distribution. If this value is null or is an empty array all protocols will be
     * permitted.
     * @param defaultRootObject
     * The name of an object that will be served when someone visits the root of a
     * distribution.
     * @param minTTL
     * The time to live (TTL) to apply to objects served by this distribution.
     *
     * @return
     * an object that describes the distribution's updated configuration, including its
     * origin bucket and CNAME aliases.
     *
     * @throws CloudFrontServiceException
     */
    @Deprecated
    public DistributionConfig updateDistributionConfig(String id, Origin origin,
        String[] cnames, String comment, boolean enabled, LoggingStatus loggingStatus,
        boolean trustedSignerSelf, String[] trustedSignerAwsAccountNumbers,
        String[] requiredProtocols, String defaultRootObject, Long minTTL)
        throws CloudFrontServiceException
    {
        DistributionConfig config = new DistributionConfig(
            origin, null, cnames, comment, enabled, loggingStatus,
            trustedSignerSelf, trustedSignerAwsAccountNumbers, requiredProtocols,
            defaultRootObject, minTTL);
        return updateDistributionConfigImpl(id, config);
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
     * @param origin
     * the origin to associate with the distribution, either an Amazon S3 bucket or
     * a custom HTTP/S-accessible location.
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
     * @param requiredProtocols
     * List of protocols that must be used by clients to retrieve content from the
     * distribution. If this value is null or is an empty array all protocols will be
     * permitted.
     * @param defaultRootObject
     * The name of an object that will be served when someone visits the root of a
     * distribution.
     *
     * @return
     * an object that describes the distribution's updated configuration, including its
     * origin bucket and CNAME aliases.
     *
     * @throws CloudFrontServiceException
     */
    public DistributionConfig updateDistributionConfig(String id, Origin origin,
        String[] cnames, String comment, boolean enabled, LoggingStatus loggingStatus,
        boolean trustedSignerSelf, String[] trustedSignerAwsAccountNumbers,
        String[] requiredProtocols, String defaultRootObject)
        throws CloudFrontServiceException
    {
        DistributionConfig config = new DistributionConfig(
            origin, null, cnames, comment, enabled, loggingStatus,
            trustedSignerSelf, trustedSignerAwsAccountNumbers, requiredProtocols,
            defaultRootObject, null);
        return this.updateDistributionConfigImpl(id, config);
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
     * @deprecated as of 2012-05-05 API version, use {@link #updateDistributionConfig(String, DistributionConfig)}.
     *
     * @param id
     * the distribution's unique identifier.
     * @param origin
     * the origin to associate with the distribution, either an Amazon S3 bucket or
     * a custom HTTP/S-accessible location.
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
     */
    @Deprecated
    public StreamingDistributionConfig updateStreamingDistributionConfig(
        String id, Origin origin, String[] cnames, String comment, boolean enabled,
        LoggingStatus loggingStatus)
        throws CloudFrontServiceException
    {
        StreamingDistributionConfig config = new StreamingDistributionConfig(
            origin, null, cnames, comment, enabled, loggingStatus,
            false, null, null);
        return (StreamingDistributionConfig) updateDistributionConfigImpl(id, config);
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
     * @deprecated as of 2012-05-05 API version, use {@link #updateDistributionConfig(String, DistributionConfig)}.
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
     * @param origin
     * the origin to associate with the distribution, either an Amazon S3 bucket or
     * a custom HTTP/S-accessible location.
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
    @Deprecated
    public StreamingDistributionConfig updateStreamingDistributionConfig(
        String id, Origin origin, String[] cnames, String comment, boolean enabled,
        LoggingStatus loggingStatus, boolean trustedSignerSelf,
        String[] trustedSignerAwsAccountNumbers)
        throws CloudFrontServiceException
    {
        StreamingDistributionConfig config = new StreamingDistributionConfig(
            origin, null, cnames, comment, enabled, loggingStatus,
            trustedSignerSelf, trustedSignerAwsAccountNumbers, null);
        return (StreamingDistributionConfig) updateDistributionConfigImpl(id, config);
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
     * @param origin
     * the origin to associate with the distribution, either an Amazon S3 bucket or
     * a custom HTTP/S-accessible location.
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
     */
    public DistributionConfig updateDistributionConfig(String id, Origin origin,
        String[] cnames, String comment, boolean enabled, LoggingStatus loggingStatus)
        throws CloudFrontServiceException
    {
        return updateDistributionConfig(id, origin, cnames, comment, enabled, loggingStatus,
            false, null, null, null);
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
        return updateDistributionConfigImpl(id, config);
    }

    /**
     * Convenience method to disable a distribution that you intend to delete.
     * This method merely calls the
     * {@link #updateDistributionConfig(String, Origin, String[], String, boolean, LoggingStatus)}
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
        updateDistributionConfig(id, null, new String[] {}, "Disabled prior to deletion", false, null);
    }

    /**
     * Convenience method to disable a streaming distribution that you intend to delete.
     * This method merely calls the
     * {@link #updateStreamingDistributionConfig(String, Origin, String[], String, boolean, LoggingStatus)}
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
        updateStreamingDistributionConfig(id, null, new String[] {}, "Disabled prior to deletion",
            false, // enabled?
            null // LoggingStatus
            );
    }

    /**
     * Delete a streaming or non-streaming distribution.
     * @param isStreaming
     * Only return streaming distributions
     * @param distributionId
     * The distribution's unique identifier.
     * @throws CloudFrontServiceException
     */
    protected void deleteDistributionImpl(boolean isStreaming, String distributionId)
        throws CloudFrontServiceException
    {
        if (log.isDebugEnabled()) {
            log.debug("Deleting "
                + (isStreaming ? "streaming" : "")
                + "distribution with id: " + distributionId);
        }

        // Get the distribution's current config.
        DistributionConfig currentConfig =
            (isStreaming ? getStreamingDistributionConfig(distributionId) : getDistributionConfig(distributionId));
        HttpDelete httpMethod = new HttpDelete(ENDPOINT + VERSION
                + (isStreaming ? "/streaming-distribution/" : "/distribution/")
                + distributionId);

        try {
            httpMethod.setHeader("If-Match", currentConfig.getEtag());
            HttpResponse response = performRestRequest(httpMethod, 204);
            releaseConnection(response);
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

        HttpPost httpMethod = new HttpPost(ENDPOINT + VERSION +
                ORIGIN_ACCESS_IDENTITY_URI_PATH);

        if (callerReference == null) {
            callerReference = String.valueOf(System.currentTimeMillis());
        }

        try {
            XMLBuilder builder = XMLBuilder.create(
                "CloudFrontOriginAccessIdentityConfig")
                .a("xmlns", XML_NAMESPACE)
                .e("CallerReference").t(callerReference).up()
                .e("Comment").t(comment);

            httpMethod.setEntity(new StringEntity(
                    builder.asString(null),
                    ContentType.create("text/xml", Constants.DEFAULT_ENCODING)));
            HttpResponse response = performRestRequest(httpMethod, 201);

            OriginAccessIdentityHandler handler =
                (new CloudFrontXmlResponsesSaxParser(this.jets3tProperties))
                    .parseOriginAccessIdentity(response.getEntity().getContent());

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
    public List<OriginAccessIdentity> getOriginAccessIdentityList()
        throws CloudFrontServiceException
    {
        if (log.isDebugEnabled()) {
            log.debug("Getting list of origin access identities");
        }
        HttpGet httpMethod = new HttpGet(ENDPOINT + VERSION + ORIGIN_ACCESS_IDENTITY_URI_PATH);

        try {
            HttpResponse response = performRestRequest(httpMethod, 200);

            OriginAccessIdentityListHandler handler =
                (new CloudFrontXmlResponsesSaxParser(this.jets3tProperties))
                    .parseOriginAccessIdentityListResponse(response.getEntity().getContent());
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
        HttpGet httpMethod = new HttpGet(ENDPOINT + VERSION +
                ORIGIN_ACCESS_IDENTITY_URI_PATH + "/" + id);

        try {
            HttpResponse response = performRestRequest(httpMethod, 200);

            OriginAccessIdentityHandler handler =
                (new CloudFrontXmlResponsesSaxParser(this.jets3tProperties))
                    .parseOriginAccessIdentity(response.getEntity().getContent());
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
        HttpGet httpMethod = new HttpGet(ENDPOINT + VERSION +
                ORIGIN_ACCESS_IDENTITY_URI_PATH + "/" + id + "/config");

        try {
            HttpResponse response = performRestRequest(httpMethod, 200);

            OriginAccessIdentityConfigHandler handler =
                (new CloudFrontXmlResponsesSaxParser(this.jets3tProperties))
                    .parseOriginAccessIdentityConfig(response.getEntity().getContent());

            OriginAccessIdentityConfig config = handler.getOriginAccessIdentityConfig();
            config.setEtag(response.getFirstHeader("ETag").getValue());
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

        HttpPut httpMethod = new HttpPut(ENDPOINT + VERSION +
                ORIGIN_ACCESS_IDENTITY_URI_PATH + "/" + id + "/config");

        try {
            XMLBuilder builder = XMLBuilder.create(
                "CloudFrontOriginAccessIdentityConfig")
                .a("xmlns", XML_NAMESPACE)
                .e("CallerReference").t(oldConfig.getCallerReference()).up()
                .e("Comment").t(comment);
            httpMethod.setEntity(new StringEntity(
                    builder.asString(null),
                    ContentType.create("text/xml", Constants.DEFAULT_ENCODING)));
            httpMethod.setHeader("If-Match", oldConfig.getEtag());
            HttpResponse response = performRestRequest(httpMethod, 200);

            OriginAccessIdentityConfigHandler handler =
                (new CloudFrontXmlResponsesSaxParser(this.jets3tProperties))
                    .parseOriginAccessIdentityConfig(response.getEntity().getContent());

            OriginAccessIdentityConfig config = handler.getOriginAccessIdentityConfig();
            config.setEtag(response.getFirstHeader("ETag").getValue());
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

        HttpDelete httpMethod = new HttpDelete(ENDPOINT + VERSION +
                ORIGIN_ACCESS_IDENTITY_URI_PATH + "/" + id);

        try {
            httpMethod.setHeader("If-Match", currentConfig.getEtag());
            HttpResponse response = performRestRequest(httpMethod, 204);
            releaseConnection(response);
        } catch (CloudFrontServiceException e) {
            throw e;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new CloudFrontServiceException(e);
        }
    }

    /**
     * Remove distribution objects from a CloudFront edge server cache to force
     * a refresh of the object data from the S3 origin.
     *
     * @param distributionId
     * The distribution's unique identifier.
     * @param objectKeys
     * S3 object key names of object(s) to invalidate.
     * @param callerReference
     * Unique description for this distribution config
     * @return
     * invalidation object
     * @throws CloudFrontServiceException
     */
    public Invalidation invalidateObjects(String distributionId, String[] objectKeys,
        String callerReference) throws CloudFrontServiceException
    {
        HttpPost httpMethod = new HttpPost(ENDPOINT + VERSION +
            "/distribution/" + distributionId + "/invalidation");
        try {
            XMLBuilder builder = XMLBuilder.create("InvalidationBatch");
            for (String objectPath: objectKeys) {
                String encodedPath = RestUtils.encodeUrlPath(objectPath, "/");
                if (!encodedPath.startsWith("/")) {
                    encodedPath = "/" + encodedPath;
                }
                builder.e("Path").t(encodedPath);
            }
            builder.e("CallerReference").t(callerReference);

            httpMethod.setEntity(new StringEntity(
                    builder.asString(null),
                    ContentType.create("text/xml", Constants.DEFAULT_ENCODING)));
            HttpResponse response = performRestRequest(httpMethod, 201);

            InvalidationHandler handler =
                (new CloudFrontXmlResponsesSaxParser(this.jets3tProperties))
                    .parseInvalidationResponse(response.getEntity().getContent());
            return handler.getInvalidation();
        } catch (CloudFrontServiceException e) {
            throw e;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new CloudFrontServiceException(e);
        }
    }

    /**
     * Remove distribution objects from a CloudFront edge server cache to force
     * a refresh of the object data from the S3 origin.
     *
     * @param distributionId
     * The distribution's unique identifier.
     * @param objects
     * S3 object(s) to invalidate.
     * @param callerReference
     * Unique description for this distribution config
     * @return
     * invalidation object
     *
     * @throws CloudFrontServiceException
     */
    public Invalidation invalidateObjects(String distributionId, S3Object[] objects,
        String callerReference) throws CloudFrontServiceException
    {
        String[] objectKeys = new String[objects.length];
        for (int i = 0; i < objects.length; i++) {
            objectKeys[i] = objects[i].getKey();
        }
        return invalidateObjects(distributionId, objectKeys, callerReference);
    }

    /**
     * @param distributionId
     * The distribution's unique identifier.
     * @param invalidationId
     * The identifier for the invalidation request
     * @return
     * Details of a prior invalidation operation.
     * @throws CloudFrontServiceException
     */
    public Invalidation getInvalidation(String distributionId, String invalidationId)
        throws CloudFrontServiceException
    {
        HttpGet httpMethod = new HttpGet(ENDPOINT + VERSION +
            "/distribution/" + distributionId + "/invalidation/" + invalidationId);
        try {
            HttpResponse response = performRestRequest(httpMethod, 200);

            InvalidationHandler handler =
                (new CloudFrontXmlResponsesSaxParser(this.jets3tProperties))
                    .parseInvalidationResponse(response.getEntity().getContent());
            return handler.getInvalidation();
        } catch (CloudFrontServiceException e) {
            throw e;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new CloudFrontServiceException(e);
        }
    }

    /**
     * List a single page of up to pagingSize past invalidation summaries, ordered from
     * most recent to oldest. If there are more prior invalidations than will fit on the
     * page you must perform follow-up calls to this method to obtain a complete listing.
     *
     * @param distributionId
     * The distribution's unique identifier.
     * @param nextMarker
     * a marker string indicating where to begin the next page of listing results.
     * Start with null for an initial listing page, then set to the NextMarker value
     * of each subsequent page returned.
     * @param pagingSize
     * maximum number of invalidation summaries to include in each result page, up to 100.
     * @return
     * invalidation listing
     * @throws CloudFrontServiceException
     */
    public InvalidationList listInvalidations(String distributionId, String nextMarker, int pagingSize)
        throws CloudFrontServiceException
    {
        try {
            String uri = ENDPOINT + VERSION +
            "/distribution/" + distributionId + "/invalidation"
            + "?MaxItems=" + pagingSize;
            if (nextMarker != null) {
                uri += "&Marker=" + nextMarker;
            }
            HttpGet httpMethod = new HttpGet(uri);
            HttpResponse response = performRestRequest(httpMethod, 200);

            InvalidationListHandler handler =
                (new CloudFrontXmlResponsesSaxParser(this.jets3tProperties))
                    .parseInvalidationListResponse(response.getEntity().getContent());
            return handler.getInvalidationList();
        } catch (CloudFrontServiceException e) {
            throw e;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new CloudFrontServiceException(e);
        }
    }

    /**
     * List all past invalidation summaries, ordered from most recent to oldest.
     *
     * @param distributionId
     * The distribution's unique identifier.
     * @return
     * list of invalidation objects
     * @throws CloudFrontServiceException
     */
    public List<InvalidationSummary> listInvalidations(String distributionId)
        throws CloudFrontServiceException
    {
        try {
            List<InvalidationSummary> invalidationSummaries =
                new ArrayList<InvalidationSummary>();

            String nextMarker = null;
            boolean incompleteListing;
            do {
                InvalidationList invalidationList = listInvalidations(
                    distributionId, nextMarker, 100);
                invalidationSummaries.addAll(invalidationList.getInvalidationSummaries());

                incompleteListing = invalidationList.isTruncated();
                nextMarker = invalidationList.getNextMarker();

                // Sanity check for valid pagination values.
                if (incompleteListing && nextMarker == null) {
                    throw new CloudFrontServiceException("Unable to retrieve paginated "
                            + "InvalidationList results without a valid NextMarker value.");
                }
            } while (incompleteListing);

            return invalidationSummaries;
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
     * An optional HTTP/S or RTMP resource path that restricts which distribution and S3 objects
     * will be accessible in a signed URL. For standard distributions the resource URL will be
     * <tt>"http://" + distributionName + "/" + objectKey</tt> (may also include URL
     * parameters. For distributions with the HTTPS required protocol, the resource URL
     * must start with <tt>"https://"</tt>. RTMP resources do not take the form of a URL,
     * and instead the resource path is nothing but the stream's name.
     *
     * The '*' and '?' characters can be used as a wildcards to allow multi-character or
     * single-character matches respectively:
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
        String ipAddress = (limitToIpAddressCIDR == null
            ? "0.0.0.0/0"  // No IP restriction
            : limitToIpAddressCIDR);
        return "{\"Statement\": [{" +
         "\"Resource\":\"" + resourcePath + "\"" +
         ",\"Condition\":{" +
         "\"DateLessThan\":{\"AWS:EpochTime\":"
            + epochDateLessThan.getTime() / 1000 + "}" +
         ",\"IpAddress\":{\"AWS:SourceIp\":\"" + ipAddress + "\"}" +
         (epochDateGreaterThan == null ? ""
             : ",\"DateGreaterThan\":{\"AWS:EpochTime\":"
                 + epochDateGreaterThan.getTime() / 1000 + "}") +
        "}}]}";
    }

    /**
     * Generate a signed URL that allows access to distribution and S3 objects by
     * applying access restrictions specified in a custom policy document.
     *
     * @param resourceUrlOrPath
     * The URL or path that uniquely identifies a resource within a distribution.
     * For standard distributions the resource URL will be
     * <tt>"http://" + distributionName + "/" + objectKey</tt> (may also include URL
     * parameters. For distributions with the HTTPS required protocol, the resource URL
     * must start with <tt>"https://"</tt>. RTMP resources do not take the form of a URL,
     * and instead the resource path is nothing but the stream's name.
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
    public static String signUrl(String resourceUrlOrPath,
        String keyPairId, byte[] derPrivateKey, String policy)
        throws CloudFrontServiceException
    {
        try {
            byte[] signatureBytes = EncryptionUtil.signWithRsaSha1(derPrivateKey,
                policy.getBytes("UTF-8"));

            String urlSafePolicy = makeStringUrlSafe(policy);
            String urlSafeSignature = makeBytesUrlSafe(signatureBytes);

            return resourceUrlOrPath
                + (resourceUrlOrPath.indexOf('?') >= 0 ? "&" : "?")
                + "Policy=" + urlSafePolicy
                + "&Signature=" + urlSafeSignature
                + "&Key-Pair-Id=" + keyPairId;
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
     * @param resourceUrlOrPath
     * The URL or path that uniquely identifies a resource within a distribution.
     * For standard distributions the resource URL will be
     * <tt>"http://" + distributionName + "/" + objectKey</tt> (may also include URL
     * parameters. For distributions with the HTTPS required protocol, the resource URL
     * must start with <tt>"https://"</tt>. RTMP resources do not take the form of a URL,
     * and instead the resource path is nothing but the stream's name.
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
    public static String signUrlCanned(String resourceUrlOrPath,
            String keyPairId, byte[] derPrivateKey, Date epochDateLessThan)
            throws CloudFrontServiceException
    {
        try {
            String cannedPolicy =
                "{\"Statement\":[{\"Resource\":\"" + resourceUrlOrPath
                + "\",\"Condition\":{\"DateLessThan\":{\"AWS:EpochTime\":"
                + epochDateLessThan.getTime() / 1000 + "}}}]}";

            byte[] signatureBytes = EncryptionUtil.signWithRsaSha1(derPrivateKey,
                cannedPolicy.getBytes("UTF-8"));

            String urlSafeSignature = makeBytesUrlSafe(signatureBytes);

            return resourceUrlOrPath
                + (resourceUrlOrPath.indexOf('?') >= 0 ? "&" : "?")
                + "Expires=" + epochDateLessThan.getTime() / 1000
                + "&Signature=" + urlSafeSignature
                + "&Key-Pair-Id=" + keyPairId;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new CloudFrontServiceException(e);
        }
    }
}

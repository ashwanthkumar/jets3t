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
package org.jets3t.service.utils;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;

import org.apache.commons.httpclient.contrib.proxy.PluginProxyUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Header;
import org.apache.http.HttpConnection;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.HttpResponse;
import org.apache.http.HttpVersion;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.AuthState;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.NTCredentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.params.ClientPNames;
import org.apache.http.client.protocol.ClientContext;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.ClientConnectionManagerFactory;
import org.apache.http.conn.params.ConnManagerParams;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.AbstractHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.impl.client.RequestWrapper;
import org.apache.http.impl.conn.tsccm.AbstractConnPool;
import org.apache.http.impl.conn.tsccm.ConnPoolByRoute;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;
import org.apache.http.params.HttpProtocolParams;
import org.apache.http.params.SyncBasicHttpParams;
import org.apache.http.protocol.ExecutionContext;
import org.apache.http.protocol.HTTP;
import org.apache.http.protocol.HttpContext;
import org.jets3t.service.Constants;
import org.jets3t.service.Jets3tProperties;
import org.jets3t.service.impl.rest.httpclient.JetS3tRequestAuthorizer;
import org.jets3t.service.io.UnrecoverableIOException;
import org.jets3t.service.security.ProviderCredentials;

/**
 * Utilities useful for REST/HTTP S3Service implementations.
 *
 * @author James Murty
 */
public class RestUtils {

    private static final Log log = LogFactory.getLog(RestUtils.class);

    /**
     * A list of HTTP-specific header names, that may be present in S3Objects as metadata but
     * which should be treated as plain HTTP headers during transmission (ie not converted into
     * S3 Object metadata items). All items in this list are in lower case.
     * <p>
     * This list includes the items:
     * <table summary="Headers names treated as plain HTTP headers">
     * <tr><th>Unchanged metadata names</th></tr>
     * <tr><td>content-type</td></tr>
     * <tr><td>content-md5</td></tr>
     * <tr><td>content-length</td></tr>
     * <tr><td>content-language</td></tr>
     * <tr><td>expires</td></tr>
     * <tr><td>cache-control</td></tr>
     * <tr><td>content-disposition</td></tr>
     * <tr><td>content-encoding</td></tr>
     * </table>
     */
    public static final List<String> HTTP_HEADER_METADATA_NAMES = Arrays.asList(
            "content-type",
            "content-md5",
            "content-length",
            "content-language",
            "expires",
            "cache-control",
            "content-disposition",
            "content-encoding");

    public static final SimpleDateFormat awsFlavouredISO8601DateParser =
        new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");


    /**
     * Encodes a URL string, and ensures that spaces are encoded as "%20" instead of "+" to keep
     * fussy web browsers happier.
     *
     * @param path
     * @return
     * encoded URL.
     */
    public static String encodeUrlString(String path) {
        String encodedPath = null;
        try {
            encodedPath = URLEncoder.encode(path, Constants.DEFAULT_ENCODING);
        }
        catch(UnsupportedEncodingException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
        // Web browsers do not always handle '+' characters well, use the well-supported '%20' instead.
        encodedPath = encodedPath.replaceAll("\\+", "%20");
        // '@' character need not be URL encoded and Google Chrome balks on signed URLs if it is.
        encodedPath = encodedPath.replaceAll("%40", "@");
        return encodedPath;
    }

    /**
     * Encodes a URL string but leaves a delimiter string unencoded.
     * Spaces are encoded as "%20" instead of "+".
     *
     * @param path
     * @param delimiter
     * @return
     * encoded URL string.
     */
    public static String encodeUrlPath(String path, String delimiter) {
        StringBuilder result = new StringBuilder();
        String tokens[] = path.split(delimiter);
        for (int i = 0; i < tokens.length; i++) {
            result.append(encodeUrlString(tokens[i]));
            if (i < tokens.length - 1) {
                result.append(delimiter);
            }
        }
        return result.toString();
    }

    /**
     * Calculate the canonical string for a REST/HTTP request to a storage service.
     *
     * When expires is non-null, it will be used instead of the Date header.
     */
    public static String makeServiceCanonicalString(String method, String resource,
        Map<String, Object> headersMap, String expires, String headerPrefix,
        List<String> serviceResourceParameterNames)
    {
        StringBuilder canonicalStringBuf = new StringBuilder();
        canonicalStringBuf.append(method).append("\n");

        // Add all interesting headers to a list, then sort them.  "Interesting"
        // is defined as Content-MD5, Content-Type, Date, and x-amz-
        SortedMap<String, Object> interestingHeaders = new TreeMap<String, Object>();
        if (headersMap != null && headersMap.size() > 0) {
            for (Map.Entry<String, Object> entry: headersMap.entrySet()) {
                Object key = entry.getKey();
                Object value = entry.getValue();

                if (key == null) {
                    continue;
                }
                String lk = key.toString().toLowerCase(Locale.ENGLISH);

                // Ignore any headers that are not particularly interesting.
                if (lk.equals("content-type") || lk.equals("content-md5") || lk.equals("date") ||
                    lk.startsWith(headerPrefix))
                {
                    interestingHeaders.put(lk, value);
                }
            }
        }

        // Remove default date timestamp if "x-amz-date" or "x-goog-date" is set.
        if (interestingHeaders.containsKey(Constants.REST_METADATA_ALTERNATE_DATE_AMZ)
            || interestingHeaders.containsKey(Constants.REST_METADATA_ALTERNATE_DATE_GOOG)) {
          interestingHeaders.put("date", "");
        }

        // Use the expires value as the timestamp if it is available. This trumps both the default
        // "date" timestamp, and the "x-amz-date" header.
        if (expires != null) {
            interestingHeaders.put("date", expires);
        }

        // these headers require that we still put a new line in after them,
        // even if they don't exist.
        if (! interestingHeaders.containsKey("content-type")) {
            interestingHeaders.put("content-type", "");
        }
        if (! interestingHeaders.containsKey("content-md5")) {
            interestingHeaders.put("content-md5", "");
        }

        // Finally, add all the interesting headers (i.e.: all that start with x-amz- ;-))
        for (Map.Entry<String, Object> entry: interestingHeaders.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();

            if (key.startsWith(headerPrefix)) {
                canonicalStringBuf.append(key).append(':').append(value);
            } else {
                canonicalStringBuf.append(value);
            }
            canonicalStringBuf.append("\n");
        }

        // don't include the query parameters...
        int queryIndex = resource.indexOf('?');
        if (queryIndex == -1) {
            canonicalStringBuf.append(resource);
        } else {
            canonicalStringBuf.append(resource.substring(0, queryIndex));
        }

        // ...unless the parameter(s) are in the set of special params
        // that actually identify a service resource.
        if (queryIndex >= 0) {
            SortedMap<String, String> sortedResourceParams = new TreeMap<String, String>();

            // Parse parameters from resource string
            String query = resource.substring(queryIndex + 1);
            for (String paramPair: query.split("&")) {
                String[] paramNameValue = paramPair.split("=");
                try {
                    String name = URLDecoder.decode(paramNameValue[0], "UTF-8");
                    String value = null;
                    if (paramNameValue.length > 1) {
                        value = URLDecoder.decode(paramNameValue[1], "UTF-8");
                    }
                    // Only include parameter (and its value if present) in canonical
                    // string if it is a resource-identifying parameter
                    if (serviceResourceParameterNames.contains(name)) {
                        sortedResourceParams.put(name, value);
                    }
                }
                catch(UnsupportedEncodingException e) {
                    throw new RuntimeException(e.getMessage(), e);
                }
            }

            // Add resource parameters
            if (sortedResourceParams.size() > 0) {
                canonicalStringBuf.append("?");
            }
            boolean addedParam = false;
            for (Map.Entry<String, String> entry: sortedResourceParams.entrySet()) {
                if (addedParam) {
                    canonicalStringBuf.append("&");
                }
                canonicalStringBuf.append(entry.getKey());
                if (entry.getValue() != null) {
                    canonicalStringBuf.append("=").append(entry.getValue());
                }
                addedParam = true;
            }
        }

        return canonicalStringBuf.toString();
    }

    /**
     * Calculate AWS Version 4 signature for a HTTP request and apply the
     * appropriate "Authorization" header value to authorize it.
     *
     * @param httpMethod
     * the request's HTTP method just prior to sending
     * @param requestSignatureVersion
     * request signature version string, e.g. "AWS4-HMAC-SHA256"
     * @param providerCredentials
     * account holder's access and secret key credentials
     * @param requestPayloadHexSha256Hash
     * hex-encoded SHA256 hash of request's payload. May be null or "" in
     * which case the default SHA256 hash of an empty string is used.
     * @param region
     * region to which the request will be sent
     * {@link "http://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region"}
     */
    public static void signRequestAuthorizationHeaderForAWSVersion4(
        String requestSignatureVersion, HttpUriRequest httpMethod,
        ProviderCredentials providerCredentials,
        String requestPayloadHexSha256Hash, String region)
    {
        // Ensure the required Host header is set prior to signing.
        if (httpMethod.getFirstHeader("Host") == null) {
            httpMethod.setHeader("Host", httpMethod.getURI().getHost());
        }

        // Generate AWS-flavoured ISO8601 timestamp string
        String timestampISO8601 = RestUtils.parseAndFormatDateForAWSVersion4(
            httpMethod);

        // Apply AWS-flavoured ISO8601 timestamp string to "x-aws-date"
        // metadata, otherwise if only the Date header is present and it is
        // RFC 822 formatted S3 expects that date to be part of the string
        // to sign, not the AWS-flavoured ISO8601 timestamp as claimed by the
        // documentation.
        if (httpMethod.getFirstHeader("x-amz-date") == null) {
            httpMethod.setHeader("x-amz-date", timestampISO8601);
        }

        // Canonical request string
        String canonicalRequestString =
            RestUtils.buildCanonicalRequestStringAWSVersion4(
                httpMethod, requestPayloadHexSha256Hash);

        // String to sign
        String stringToSign = RestUtils.buildStringToSignAWSVersion4(
            requestSignatureVersion, canonicalRequestString,
            timestampISO8601, region);

        // Signing key
        byte[] signingKey = RestUtils.buildSigningKeyAWSVersion4(
            providerCredentials.getSecretKey(), timestampISO8601,
            region);

        // Request signature
        String signature = ServiceUtils.toHex(ServiceUtils.hmacSHA256(
            signingKey, ServiceUtils.stringToBytes(stringToSign)));

        // Authorization header value
        String authorizationHeaderValue =
            RestUtils.buildAuthorizationHeaderValueAWSVersion4(
                providerCredentials.getAccessKey(), signature,
                requestSignatureVersion, canonicalRequestString,
                timestampISO8601, region);

        httpMethod.setHeader("Authorization", authorizationHeaderValue);
    }

    /**
     * Extract the request timestamp from the given HTTP request, from either
     * the "x-amz-date" metadata header or the Date header, and convert it
     * into an AWS-flavoured ISO8601 string format suitable for us in
     * request authorization for AWS version 4 signatures.
     *
     * @param httpMethod
     * request containing at least one of the "x-amz-date" or Date headers with
     * a timestamp value in one of the supported formats: RFC 822, ISO 8601,
     * AWS-flavoured ISO 8601.
     * @return timestamp formatted as AWS-flavoured ISO8601: "YYYYMMDDTHHmmssZ"
     */
    public static String parseAndFormatDateForAWSVersion4(
        HttpUriRequest httpMethod)
    {
        // Retrieve request's date header, from locations in order of
        // preference: explicit metadata date, request Date header
        Header dateHeader = httpMethod.getFirstHeader("x-amz-date");
        if (dateHeader == null) {
            dateHeader = httpMethod.getFirstHeader("Date");
        }
        if (dateHeader == null) {
            throw new RuntimeException(
                "Request must have a date timestamp applied before it can be"
                + " signed with AWS Version 4, but no date value found in"
                + " \"x-amz-date\" or \"Date\" headers");
        }

        // Parse provided Date object or string into ISO8601 format timestamp
        String dateValue = dateHeader.getValue();
        if (dateValue.indexOf("Z") >= 0) {
            // ISO8601-like date, does it need to be converted to AWS flavour?
            try {
                awsFlavouredISO8601DateParser.parse(dateValue);
                // Parse succeeded, no more work necessary
                return dateValue;
            } catch (ParseException e) {
                // Parse failed, try parsing normal ISO8601 format
                try {
                    return awsFlavouredISO8601DateParser.format(
                        ServiceUtils.parseIso8601Date(dateValue));
                } catch (ParseException e2) {
                    throw new RuntimeException(
                        "Invalid date value in request: " + dateValue, e2);
                }
            }
        } else {
            try {
                return awsFlavouredISO8601DateParser.format(
                    ServiceUtils.parseRfc822Date(dateValue));
            } catch (ParseException e) {
                throw new RuntimeException(
                    "Invalid date value in request: " + dateValue, e);
            }
        }
    }

    /**
     * Build the canonical request string for a REST/HTTP request to a storage
     * service for the AWS Request Signature version 4.
     *
     * {@link "http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html"}
     *
     * @param httpMethod
     * the request's HTTP method just prior to sending
     * @param requestPayloadHexSha256Hash
     * hex-encoded SHA256 hash of request's payload. May be null or "" in
     * which case the default SHA256 hash of an empty string is used.
     * @return canonical request string according to AWS Request Signature version 4
     */
    public static String buildCanonicalRequestStringAWSVersion4(
        HttpUriRequest httpMethod, String requestPayloadHexSha256Hash)
    {
        StringBuilder canonicalStringBuf = new StringBuilder();
        URI uri = httpMethod.getURI();

        // HTTP Request method: GET, POST etc
        canonicalStringBuf
            .append(httpMethod.getMethod())
            .append("\n");

        // Canonical URI: URI-encoded version of the absolute path
        String absolutePath = uri.getPath();
        if (absolutePath.length() == 0) {
            canonicalStringBuf.append("/");
        } else {
            canonicalStringBuf.append(
                RestUtils.awsURIEncode(absolutePath, false));
        }
        canonicalStringBuf.append("\n");

        // Canonical query string
        String query = uri.getQuery();
        if (query == null || query.length() == 0) {
            canonicalStringBuf.append("\n");
        } else {
            // Parse and sort query parameters and values from query string
            SortedMap<String, String> sortedQueryParameters =
                new TreeMap<String, String>();
            for (String paramPair: query.split("&")) {
                String[] paramNameValue = paramPair.split("=");
                String name = paramNameValue[0];
                String value = "";
                if (paramNameValue.length > 1) {
                    value = paramNameValue[1];
                }
                // Add parameters to sorting map, URI-encoded appropriately
                sortedQueryParameters.put(
                    RestUtils.awsURIEncode(name, true),
                    RestUtils.awsURIEncode(value, true));
            }
            // Add query parameters to canonical string
            boolean isPriorParam = false;
            for (Map.Entry<String, String> entry: sortedQueryParameters.entrySet()) {
                if (isPriorParam) {
                    canonicalStringBuf.append("&");
                }
                canonicalStringBuf
                    .append(entry.getKey())
                    .append("=")
                    .append(entry.getValue());
                isPriorParam = true;
            }
            canonicalStringBuf.append("\n");
        }

        // Canonical Headers
        SortedMap<String, String> sortedHeaders = new TreeMap<String, String>();
        Header[] headers = httpMethod.getAllHeaders();
        for (Header header: headers) {
            // Trim whitespace and make lower-case for header names
            String name = header.getName().trim().toLowerCase();
            // Trim whitespace for header values
            String value = header.getValue().trim();
            sortedHeaders.put(name, value);
        }
        for (Map.Entry<String, String> entry: sortedHeaders.entrySet()) {
            canonicalStringBuf
                .append(entry.getKey())
                .append(":")
                .append(entry.getValue())
                .append("\n");
        }
        canonicalStringBuf.append("\n");

        // Signed headers
        boolean isPriorSignedHeader = false;
        for (Map.Entry<String, String> entry: sortedHeaders.entrySet()) {
            if (isPriorSignedHeader) {
                canonicalStringBuf.append(";");
            }
            canonicalStringBuf.append(entry.getKey());
            isPriorSignedHeader = true;
        }
        canonicalStringBuf.append("\n");

        // Hashed Payload.
        canonicalStringBuf
            .append(requestPayloadHexSha256Hash);

        return canonicalStringBuf.toString();
    }

    /**
     * Build the string to sign for a REST/HTTP request to a storage
     * service for the AWS Request Signature version 4.
     *
     * {@link "http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html"}
     *
     * @param requestSignatureVersion
     * request signature version string, e.g. "AWS4-HMAC-SHA256"
     * @param canonicalRequestString
     * canonical request string as generated by {@link #buildCanonicalRequestStringAWSVersion4(HttpUriRequest, String)}
     * @param timestampISO8601
     * timestamp of request creation in ISO8601 format
     * @param region
     * region to which the request will be sent
     * {@link "http://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region"}
     * @return string to sign according to AWS Request Signature version 4
     */
    public static String buildStringToSignAWSVersion4(
            String requestSignatureVersion, String canonicalRequestString,
            String timestampISO8601, String region)
    {
        String service = "s3";
        String datestampISO8601 = timestampISO8601.substring(0, 8); // TODO
        String credentialScope =
            datestampISO8601 + "/" + region + "/" + service + "/aws4_request";
        String hashedCanonicalString = ServiceUtils.toHex(
            ServiceUtils.hash(canonicalRequestString, "SHA-256"));

        String stringToSign =
            requestSignatureVersion + "\n"
            + timestampISO8601 + "\n"
            + credentialScope + "\n"
            + hashedCanonicalString;
        return stringToSign;
    }

    /**
     * Build the signing key for a REST/HTTP request to a storage
     * service for the AWS Request Signature version 4.
     *
     * @param secretAccessKey
     * account holder's secret access key
     * @param timestampISO8601
     * timestamp of request creation in ISO8601 format
     * @param region
     * region to which the request will be sent
     * {@link "http://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region"}
     * @return signing key according to AWS Request Signature version 4
     */
    public static byte[] buildSigningKeyAWSVersion4(
            String secretAccessKey, String timestampISO8601, String region)
    {
        String service = "s3";
        String datestampISO8601 = timestampISO8601.substring(0, 8);
        byte[] kDate = ServiceUtils.hmacSHA256(
            "AWS4" + secretAccessKey, datestampISO8601);
        byte[] kRegion = ServiceUtils.hmacSHA256(
            kDate, ServiceUtils.stringToBytes(region));
        byte[] kService = ServiceUtils.hmacSHA256(
            kRegion, ServiceUtils.stringToBytes(service));
        byte[] kSigning = ServiceUtils.hmacSHA256(
            kService, ServiceUtils.stringToBytes("aws4_request"));
        return kSigning;
    }

    /**
     * Build the Authorization header value for a REST/HTTP request to a storage
     * service for the AWS Request Signature version 4.
     *
     * {@link "http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html"}
     *
     * @param accessKey
     * account holder's access key
     * @param requestSignature
     * request signature as generated signing the string to sign from
     * {@link #buildStringToSignAWSVersion4(String, String, String, String)}
     * with the key from
     * {@link #buildSigningKeyAWSVersion4(String, String, String)}
     * @param requestSignatureVersion
     * request signature version string, e.g. "AWS4-HMAC-SHA256"
     * @param canonicalRequestString
     * canonical request string as generated by
     * {@link #buildCanonicalRequestStringAWSVersion4(HttpUriRequest, String)}
     * @param timestampISO8601
     * timestamp of request creation in ISO8601 format
     * @param region
     * region to which request will be sent, see
     * {@link "http://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region"}
     * @return string to sign according to AWS Request Signature version 4
     */
    public static String buildAuthorizationHeaderValueAWSVersion4(
            String accessKey, String requestSignature,
            String requestSignatureVersion, String canonicalRequestString,
            String timestampISO8601, String region)
    {
        String service = "s3";
        String datestampISO8601 = timestampISO8601.substring(0, 8); // TODO
        // Parse signed headers back out of canonical request string
        String[] canonicalStringComponents = canonicalRequestString.split("\n");
        String signedHeaders = canonicalStringComponents[canonicalStringComponents.length - 2];

        String credentialScope =
            datestampISO8601 + "/" + region + "/" + service + "/aws4_request";

        String authorizationHeaderValue =
            requestSignatureVersion + " "
            + "Credential=" + accessKey
            + "/" + credentialScope
            + ",SignedHeaders=" + signedHeaders
            + ",Signature=" + requestSignature;
        return authorizationHeaderValue;
    }

    /**
     * Slightly modified version of "uri-encode" from:
     * {@link "http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html"}
     */
    public static String awsURIEncode(CharSequence input, boolean encodeSlash) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char ch = input.charAt(i);
            if ((ch >= 'A' && ch <= 'Z')
                || (ch >= 'a' && ch <= 'z')
                || (ch >= '0' && ch <= '9')
                || ch == '_'
                || ch == '-'
                || ch == '~'
                || ch == '.')
            {
                result.append(ch);
            } else if (ch == '/') {
                result.append(encodeSlash ? "%2F" : ch);
            } else {
                String hex = encodeUrlString(String.valueOf(ch));
                result.append(hex);
            }
        }
        return result.toString();
    }

    /**
     * Initialises, or re-initialises, the underlying HttpConnectionManager and
     * HttpClient objects a service will use to communicate with an AWS service.
     * If proxy settings are specified in this service's {@link Jets3tProperties} object,
     * these settings will also be passed on to the underlying objects.
     */
    public static HttpClient initHttpConnection(
            final JetS3tRequestAuthorizer requestAuthorizer,
            Jets3tProperties jets3tProperties,
            String userAgentDescription,
            CredentialsProvider credentialsProvider) {
        // Configure HttpClient properties based on Jets3t Properties.
        HttpParams params = createDefaultHttpParams();
        params.setParameter(Jets3tProperties.JETS3T_PROPERTIES_ID, jets3tProperties);

        params.setParameter(
            ClientPNames.CONNECTION_MANAGER_FACTORY_CLASS_NAME,
            jets3tProperties.getStringProperty(
                ClientPNames.CONNECTION_MANAGER_FACTORY_CLASS_NAME,
                ConnManagerFactory.class.getName()));

        HttpConnectionParams.setConnectionTimeout(params,
            jets3tProperties.getIntProperty("httpclient.connection-timeout-ms", 60000));
        HttpConnectionParams.setSoTimeout(params,
            jets3tProperties.getIntProperty("httpclient.socket-timeout-ms", 60000));
        HttpConnectionParams.setStaleCheckingEnabled(params,
            jets3tProperties.getBoolProperty("httpclient.stale-checking-enabled", true));

        // Connection properties to take advantage of S3 window scaling.
        if (jets3tProperties.containsKey("httpclient.socket-receive-buffer")) {
            HttpConnectionParams.setSocketBufferSize(params,
                jets3tProperties.getIntProperty("httpclient.socket-receive-buffer", 0));
        }

        HttpConnectionParams.setTcpNoDelay(params, true);

        // Set user agent string.
        String userAgent = jets3tProperties.getStringProperty("httpclient.useragent", null);
        if (userAgent == null) {
            userAgent = ServiceUtils.getUserAgentDescription(userAgentDescription);
        }
        if (log.isDebugEnabled()) {
            log.debug("Setting user agent string: " + userAgent);
        }
        HttpProtocolParams.setUserAgent(params, userAgent);

        boolean expectContinue
                = jets3tProperties.getBoolProperty("http.protocol.expect-continue", true);
        HttpProtocolParams.setUseExpectContinue(params, expectContinue);

        long connectionManagerTimeout
                = jets3tProperties.getLongProperty("httpclient.connection-manager-timeout", 0);
        ConnManagerParams.setTimeout(params, connectionManagerTimeout);

        DefaultHttpClient httpClient = new DefaultHttpClient(params);
        httpClient.setHttpRequestRetryHandler(
            new JetS3tRetryHandler(
                jets3tProperties.getIntProperty("httpclient.retry-max", 5), requestAuthorizer));

        if (credentialsProvider != null) {
            if (log.isDebugEnabled()) {
                log.debug("Using credentials provider class: "
                        + credentialsProvider.getClass().getName());
            }
            httpClient.setCredentialsProvider(credentialsProvider);
            if (jets3tProperties.getBoolProperty(
                    "httpclient.authentication-preemptive",
                    false)) {
                // Add as the very first interceptor in the protocol chain
                httpClient.addRequestInterceptor(new PreemptiveInterceptor(), 0);
            }
        }

        return httpClient;
    }

    /**
     * Initialises this service's HTTP proxy by auto-detecting the proxy settings.
     */
    public static void initHttpProxy(HttpClient httpClient, Jets3tProperties jets3tProperties) {
        initHttpProxy(httpClient, jets3tProperties, true, null, -1, null, null, null);
    }

    /**
     * Initialises this service's HTTP proxy by auto-detecting the proxy settings using the given endpoint.
     */
    public static void initHttpProxy(HttpClient httpClient, Jets3tProperties jets3tProperties,
        String endpoint) {
        initHttpProxy(httpClient, jets3tProperties, true, null, -1, null, null, null, endpoint);
    }

    /**
     * Initialises this service's HTTP proxy with the given proxy settings.
     *
     * @param proxyHostAddress
     * @param proxyPort
     */
    public static void initHttpProxy(HttpClient httpClient, String proxyHostAddress,
        int proxyPort, Jets3tProperties jets3tProperties) {
        initHttpProxy(httpClient, jets3tProperties, false,
            proxyHostAddress, proxyPort, null, null, null);
    }

    /**
     * Initialises this service's HTTP proxy for authentication using the given
     * proxy settings.
     *
     * @param proxyHostAddress
     * @param proxyPort
     * @param proxyUser
     * @param proxyPassword
     * @param proxyDomain
     * if a proxy domain is provided, an {@link NTCredentials} credential provider
     * will be used. If the proxy domain is null, a
     * {@link UsernamePasswordCredentials} credentials provider will be used.
     */
    public static void initHttpProxy(HttpClient httpClient, Jets3tProperties jets3tProperties,
        String proxyHostAddress, int proxyPort, String proxyUser,
        String proxyPassword, String proxyDomain)
    {
        initHttpProxy(httpClient, jets3tProperties, false,
            proxyHostAddress, proxyPort, proxyUser, proxyPassword, proxyDomain);
    }

    /**
     * @param httpClient
     * @param proxyAutodetect
     * @param proxyHostAddress
     * @param proxyPort
     * @param proxyUser
     * @param proxyPassword
     * @param proxyDomain
     */
    public static void initHttpProxy(HttpClient httpClient,
        Jets3tProperties jets3tProperties, boolean proxyAutodetect,
        String proxyHostAddress, int proxyPort, String proxyUser,
        String proxyPassword, String proxyDomain)
    {
        String s3Endpoint = jets3tProperties.getStringProperty(
                "s3service.s3-endpoint", Constants.S3_DEFAULT_HOSTNAME);
        initHttpProxy(httpClient, jets3tProperties, proxyAutodetect, proxyHostAddress, proxyPort,
            proxyUser, proxyPassword, proxyDomain, s3Endpoint);
    }

    /**
     * @param httpClient
     * @param proxyAutodetect
     * @param proxyHostAddress
     * @param proxyPort
     * @param proxyUser
     * @param proxyPassword
     * @param proxyDomain
     * @param endpoint
     */
    public static void initHttpProxy(
            HttpClient httpClient,
            Jets3tProperties jets3tProperties,
            boolean proxyAutodetect,
            String proxyHostAddress,
            int proxyPort,
            String proxyUser,
            String proxyPassword,
            String proxyDomain,
            String endpoint) {

        // Use explicit proxy settings, if available.
        if (proxyHostAddress != null && proxyPort != -1) {
            if (log.isInfoEnabled()) {
                log.info("Using Proxy: " + proxyHostAddress + ":" + proxyPort);
            }

            HttpHost proxy = new HttpHost(proxyHostAddress, proxyPort);
            httpClient.getParams().setParameter(ConnRoutePNames.DEFAULT_PROXY,
                    proxy);
            /*
             * TODO: Use alternative method?
             * Alternate method based on JRE standard
             *
            ProxySelectorRoutePlanner routePlanner = new ProxySelectorRoutePlanner(
                    httpClient.getConnectionManager().getSchemeRegistry(),
                    ProxySelector.getDefault());
            ((DefaultHttpClient)httpClient).setRoutePlanner(routePlanner);
            */

            if (proxyUser != null && !proxyUser.trim().equals("")
                    && httpClient instanceof AbstractHttpClient) {
                if (proxyDomain != null) {
                    ((AbstractHttpClient) httpClient).getCredentialsProvider()
                            .setCredentials(new AuthScope(
                                    proxyHostAddress,
                                    proxyPort),
                                    new NTCredentials(
                                            proxyUser,
                                            proxyPassword,
                                            proxyHostAddress,
                                            proxyDomain));
                } else {
                    ((AbstractHttpClient) httpClient).getCredentialsProvider()
                            .setCredentials(new AuthScope(
                                    proxyHostAddress,
                                    proxyPort),
                                    new UsernamePasswordCredentials(proxyUser,
                                            proxyPassword));
                }
            }
        }
        // If no explicit settings are available, try autodetecting proxies (unless autodetect is disabled)
        else if (proxyAutodetect) {
            // Try to detect any proxy settings from applet.
            HttpHost proxyHost = null;
            try {
                proxyHost = PluginProxyUtil.detectProxy(
                        new URL("http://" + endpoint));
                if (proxyHost != null) {
                    if (log.isInfoEnabled()) {
                        log.info("Using Proxy: " + proxyHost.getHostName()
                                + ":" + proxyHost.getPort());
                    }
                    httpClient.getParams()
                            .setParameter(ConnRoutePNames.DEFAULT_PROXY,
                                    proxyHost);
                }
            } catch (Throwable t) {
                if (log.isDebugEnabled()) {
                    log.debug("Unable to set proxy configuration", t);
                }
            }
        }
    }

    /**
     * Calculates and returns a time offset value to reflect the time difference
     * between your computer's clock and the current time according to the 'Date'
     * header in the given HTTP response, likely provided by a service endpoint
     * whose time you wish to treat as authoritative.
     *
     * Ideally you should not rely on this method to overcome clock-related
     * disagreements between your computer and a service endpoint.
     * If you computer is set to update its clock periodically and has the
     * correct timezone setting you should never have to resort to this work-around.
     *
     * @throws ParseException
     */
    public static long calculateTimeAdjustmentOffset(HttpResponse response)
        throws ParseException
    {
        Header[] dateHeaders = response.getHeaders("Date");
        if (dateHeaders.length > 0) {
            // Retrieve the service time according to response Date header
            String dateHeader = dateHeaders[0].getValue();
            Date awsTime = ServiceUtils.parseRfc822Date(dateHeader);
            // Calculate the difference between the current time according to AWS,
            // and the current time according to your computer's clock.
            Date localTime = new Date();
            long timeOffset = awsTime.getTime() - localTime.getTime();

            if (log.isDebugEnabled()) {
                log.debug("Calculated time offset value of " + timeOffset
                    + " milliseconds between the local machine and the response: "
                    + response);
            }
            return timeOffset;
        } else {
            if (log.isWarnEnabled()) {
                log.warn("Unable to calculate value of time offset between the "
                    + "local machine and the response: " + response);
            }
            return 0l;
        }
    }

    public static Map<String, String> convertHeadersToMap(Header[] headers) {
        Map<String, String> s3Headers = new HashMap<String, String>();
        for (Header header: headers) {
            s3Headers.put(header.getName(), header.getValue());
        }
        return s3Headers;
    }

    /**
     * Default Http parameters got from the DefaultHttpClient implementation.
     *
     * @return
     * Default HTTP connection parameters
     */
    public static HttpParams createDefaultHttpParams() {
        HttpParams params = new SyncBasicHttpParams();
        HttpProtocolParams.setVersion(params, HttpVersion.HTTP_1_1);
        HttpProtocolParams.setContentCharset(params,
                HTTP.DEFAULT_CONTENT_CHARSET);
        HttpConnectionParams.setTcpNoDelay(params, true);
        HttpConnectionParams.setSocketBufferSize(params, 8192);
        return params;
    }

    /**
     * A ClientConnectionManagerFactory that creates ThreadSafeClientConnManager
     */
    public static class ConnManagerFactory implements
            ClientConnectionManagerFactory {
        /*
         * @see ClientConnectionManagerFactory#newInstance(HttpParams, SchemeRegistry)
         */
        public ClientConnectionManager newInstance(HttpParams params,
                SchemeRegistry schemeRegistry) {
            return new ThreadSafeConnManager(params, schemeRegistry);
        }

    } //ConnManagerFactory

    /**
     * ThreadSafeConnManager is a ThreadSafeClientConnManager configured via
     * jets3tProperties.
     *
     * @see Jets3tProperties#JETS3T_PROPERTIES_ID
     */
    public static class ThreadSafeConnManager extends
            ThreadSafeClientConnManager {
        public ThreadSafeConnManager(final HttpParams params,
                final SchemeRegistry schreg) {
            super(params, schreg);
        }

        @Override
        protected AbstractConnPool createConnectionPool(final HttpParams params) {
            // Set the maximum connections per host for the HTTP connection manager,
            // *and* also set the maximum number of total connections (new in 0.7.1).
            // The max connections per host setting is made the same value as the max
            // global connections if there is no per-host property.
            Jets3tProperties props = (Jets3tProperties) params.getParameter(
                    Jets3tProperties.JETS3T_PROPERTIES_ID);
            int maxConn = 20;
            int maxConnectionsPerHost = 0;
            if (props != null) {
                maxConn = props.getIntProperty("httpclient.max-connections", 20);
                maxConnectionsPerHost = props.getIntProperty(
                        "httpclient.max-connections-per-host",
                        0);
            }
            if (maxConnectionsPerHost == 0) {
                maxConnectionsPerHost = maxConn;
            }
            connPerRoute.setDefaultMaxPerRoute(maxConnectionsPerHost);
            return new ConnPoolByRoute(connOperator, connPerRoute, maxConn,props.getLongProperty("httpclient.connection.ttl", -1L), TimeUnit.MILLISECONDS);
        }
    } //ThreadSafeConnManager

    public static class JetS3tRetryHandler extends DefaultHttpRequestRetryHandler {
        private final JetS3tRequestAuthorizer requestAuthorizer;

        public JetS3tRetryHandler(int pRetryMaxCount, JetS3tRequestAuthorizer requestAuthorizer) {
            super(pRetryMaxCount, false);
            this.requestAuthorizer = requestAuthorizer;
        }

        @Override
        public boolean retryRequest(IOException exception,
                int executionCount,
                HttpContext context) {
            if (super.retryRequest(exception, executionCount, context)){

                if (exception instanceof UnrecoverableIOException) {
                    if (log.isDebugEnabled()) {
                        log.debug("Deliberate interruption, will not retry");
                    }
                    return false;
                }
                HttpRequest request = (HttpRequest) context.getAttribute(
                        ExecutionContext.HTTP_REQUEST);

                // Convert RequestWrapper to original HttpBaseRequest (issue #127)
                if (request instanceof RequestWrapper) {
                    request = ((RequestWrapper)request).getOriginal();
                }

                if (!(request instanceof HttpRequestBase)) {
                    return false;
                }
                HttpRequestBase method = (HttpRequestBase) request;

                // Release underlying connection so we will get a new one (hopefully) when we retry.
                HttpConnection conn = (HttpConnection) context.getAttribute(
                        ExecutionContext.HTTP_CONNECTION);
                try {
                    conn.close();
                } catch (Exception e) {
                    //ignore
                }

                if (log.isDebugEnabled()) {
                    log.debug("Retrying " + method.getMethod()
                            + " request with path '" + method.getURI()
                            + "' - attempt " + executionCount + " of "
                            + getRetryCount());
                }

                // Build the authorization string for the method.
                try {
                    if (requestAuthorizer != null){
                        requestAuthorizer.authorizeHttpRequest(method, context);
                    }
                    return true; // request OK'd for retry by base handler and myself
                } catch (Exception e) {
                    if (log.isWarnEnabled()) {
                        log.warn("Unable to generate updated authorization string for retried request",
                                e);
                    }
                }
            }

            return false;
        }
    } //AWSRetryHandler

    /**
     * PreemptiveInterceptor
     */
    // A preemptive interceptor (copied from doc).
    private static class PreemptiveInterceptor implements
            HttpRequestInterceptor {

        public void process(final HttpRequest request, final HttpContext context) {
            AuthState authState = (AuthState) context.getAttribute(
                    ClientContext.TARGET_AUTH_STATE);
            CredentialsProvider credsProvider = (CredentialsProvider) context.getAttribute(
                    ClientContext.CREDS_PROVIDER);
            HttpHost targetHost = (HttpHost) context.getAttribute(
                    ExecutionContext.HTTP_TARGET_HOST);
            // If not auth scheme has been initialized yet
            if (authState.getAuthScheme() == null) {
                AuthScope authScope = new AuthScope(targetHost.getHostName(),
                        targetHost.getPort());
                // Obtain credentials matching the target host
                Credentials creds = credsProvider.getCredentials(authScope);
                // If found, generate BasicScheme preemptively
                if (creds != null) {
                    authState.setAuthScheme(new BasicScheme());
                    authState.setCredentials(creds);
                }
            }
        }
    } //PreemptiveInterceptor
}

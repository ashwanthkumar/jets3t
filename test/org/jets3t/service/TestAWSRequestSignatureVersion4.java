package org.jets3t.service;

import java.io.InputStream;
import java.util.Properties;

import junit.framework.TestCase;

import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.jets3t.service.utils.RestUtils;
import org.jets3t.service.utils.ServiceUtils;
import org.jets3t.service.model.StorageBucket;
import org.jets3t.service.security.AWSCredentials;
import org.jets3t.service.security.ProviderCredentials;
import org.junit.Test;
import org.jets3t.service.impl.rest.httpclient.RestS3Service;



/**
 * {@link "http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html"}
 */
public class TestAWSRequestSignatureVersion4 extends TestCase {
    protected String TEST_PROPERTIES_FILENAME = "test.properties";
    protected Properties testProperties = null;

    String awsAccessKey = "AKIAIOSFODNN7EXAMPLE";
    String awsSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    String timestampISO8601 = "20130524T000000Z";
    String bucketName = "examplebucket";
    String region = "us-east-1";
    String service = "s3";
    String requestSignatureVersion = "AWS4-HMAC-SHA256";

    public TestAWSRequestSignatureVersion4() throws Exception {
        // Load test properties
        InputStream propertiesIS =
            ClassLoader.getSystemResourceAsStream(TEST_PROPERTIES_FILENAME);
        if (propertiesIS == null) {
            throw new Exception(
                "Unable to load test properties file from classpath: "
                + TEST_PROPERTIES_FILENAME);
        }
        this.testProperties = new Properties();
        this.testProperties.load(propertiesIS);
    }

    @Test
    public void testS3ApiReferenceExampleGetObject() {
        HttpGet httpGet = new HttpGet("http://examplebucket.s3.amazonaws.com/test.txt");
        httpGet.setHeader("Host", "examplebucket.s3.amazonaws.com");
        // NOTE: Date header missed in example test case
        httpGet.setHeader("Range", "bytes=0-9");
        httpGet.setHeader("x-amz-content-sha256",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        httpGet.setHeader("x-amz-date", this.timestampISO8601);

        String requestPayloadHexSHA256Hash = null; // empty payload

        // Canonical request string
        String expected =
            "GET\n" +
            "/test.txt\n" +
            "\n" +
            "host:examplebucket.s3.amazonaws.com\n" +
            "range:bytes=0-9\n" +
            "x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n" +
            "x-amz-date:20130524T000000Z\n" +
            "\n" +
            "host;range;x-amz-content-sha256;x-amz-date\n"+
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        String canonicalRequestString = RestUtils.buildCanonicalRequestStringAWSVersion4(
            httpGet, requestPayloadHexSHA256Hash);
        assertEquals(expected, canonicalRequestString);

        // String to sign
        expected =
            "AWS4-HMAC-SHA256\n" +
            "20130524T000000Z\n" +
            "20130524/us-east-1/s3/aws4_request\n" +
            "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972";
        String stringToSign = RestUtils.buildStringToSignAWSVersion4(
            requestSignatureVersion, canonicalRequestString,
            this.timestampISO8601, this.region);
        assertEquals(expected, stringToSign);

        // Signature
        byte[] signingKey = RestUtils.buildSigningKeyAWSVersion4(
            this.awsSecretAccessKey, this.timestampISO8601,
            this.region);
        String signature = ServiceUtils.toHex(
            ServiceUtils.hmacSHA256(
                signingKey, ServiceUtils.stringToBytes(stringToSign)));
        expected = "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41";
        assertEquals(expected, signature);

        // Authorization header
        String authorizationHeaderValue =
            RestUtils.buildAuthorizationHeaderValueAWSVersion4(
                this.awsAccessKey, signature, this.requestSignatureVersion,
                canonicalRequestString, this.timestampISO8601, this.region);
        expected = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41";
        assertEquals(expected, authorizationHeaderValue);

        // The whole request
        RestUtils.signRequestAuthorizationHeaderForAWSVersion4(
            this.requestSignatureVersion, httpGet,
            new AWSCredentials(this.awsAccessKey, this.awsSecretAccessKey),
            requestPayloadHexSHA256Hash, this.region);
        assertEquals(expected, httpGet.getFirstHeader("Authorization").getValue());
    }

    @Test
    public void testS3ApiReferenceExamplePutObject() {
        HttpPut httpPut = new HttpPut("http://examplebucket.s3.amazonaws.com/test$file.text");
        httpPut.setHeader("Host", "examplebucket.s3.amazonaws.com");
        httpPut.setHeader("Date", "Fri, 24 May 2013 00:00:00 GMT");
        httpPut.setHeader("x-amz-date", this.timestampISO8601);
        httpPut.setHeader("x-amz-storage-class", "REDUCED_REDUNDANCY");

        String payload = "Welcome to Amazon S3.";
        httpPut.setEntity(new StringEntity(
            payload, ContentType.create("text/plain", Constants.DEFAULT_ENCODING)));

        String requestPayloadHexSHA256Hash = ServiceUtils.toHex(
            ServiceUtils.hash(payload, "SHA-256"));
        httpPut.setHeader("x-amz-content-sha256", requestPayloadHexSHA256Hash);

        // Canonical request string
        String expected =
            "PUT\n" +
            "/test%24file.text\n" +
            "\n" +
            "date:Fri, 24 May 2013 00:00:00 GMT\n" +
            "host:examplebucket.s3.amazonaws.com\n" +
            "x-amz-content-sha256:44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072\n" +
            "x-amz-date:20130524T000000Z\n" +
            "x-amz-storage-class:REDUCED_REDUNDANCY\n" +
            "\n" +
            "date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class\n" +
            "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072";
        String canonicalRequestString = RestUtils.buildCanonicalRequestStringAWSVersion4(
            httpPut, requestPayloadHexSHA256Hash);
        assertEquals(expected, canonicalRequestString);

        // String to sign
        expected =
            "AWS4-HMAC-SHA256\n" +
            "20130524T000000Z\n" +
            "20130524/us-east-1/s3/aws4_request\n" +
            "9e0e90d9c76de8fa5b200d8c849cd5b8dc7a3be3951ddb7f6a76b4158342019d";
        String stringToSign = RestUtils.buildStringToSignAWSVersion4(
            requestSignatureVersion, canonicalRequestString,
            this.timestampISO8601, this.region);
        assertEquals(expected, stringToSign);

        // Signature
        byte[] signingKey = RestUtils.buildSigningKeyAWSVersion4(
            this.awsSecretAccessKey, this.timestampISO8601,
            this.region);
        String signature = ServiceUtils.toHex(
            ServiceUtils.hmacSHA256(
                signingKey, ServiceUtils.stringToBytes(stringToSign)));
        expected = "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd";
        assertEquals(expected, signature);

        // Authorization header
        String authorizationHeaderValue =
            RestUtils.buildAuthorizationHeaderValueAWSVersion4(
                this.awsAccessKey, signature, this.requestSignatureVersion,
                canonicalRequestString, this.timestampISO8601, this.region);
        expected = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class,Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd";
        assertEquals(expected, authorizationHeaderValue);

        // The whole request
        RestUtils.signRequestAuthorizationHeaderForAWSVersion4(
            this.requestSignatureVersion, httpPut,
            new AWSCredentials(this.awsAccessKey, this.awsSecretAccessKey),
            requestPayloadHexSHA256Hash, this.region);
        assertEquals(expected, httpPut.getFirstHeader("Authorization").getValue());
    }

    @Test
    public void testS3ApiReferenceExampleGetBucketLifecycle() {
        HttpGet httpGet = new HttpGet("http://examplebucket.s3.amazonaws.com?lifecycle");
        httpGet.setHeader("Host", "examplebucket.s3.amazonaws.com");
        // NOTE: Date header missed in example test case
        httpGet.setHeader("x-amz-date", this.timestampISO8601);

        // Empty payload
        String payload = "";
        String requestPayloadHexSHA256Hash = ServiceUtils.toHex(
            ServiceUtils.hash(payload, "SHA-256"));
        httpGet.setHeader("x-amz-content-sha256", requestPayloadHexSHA256Hash);

        // Canonical request string
        String expected =
            "GET\n" +
            "/\n" +
            "lifecycle=\n" +
            "host:examplebucket.s3.amazonaws.com\n" +
            "x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n" +
            "x-amz-date:20130524T000000Z\n" +
            "\n" +
            "host;x-amz-content-sha256;x-amz-date\n" +
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        String canonicalRequestString = RestUtils.buildCanonicalRequestStringAWSVersion4(
            httpGet, requestPayloadHexSHA256Hash);
        assertEquals(expected, canonicalRequestString);

        // String to sign
        expected =
            "AWS4-HMAC-SHA256\n" +
            "20130524T000000Z\n" +
            "20130524/us-east-1/s3/aws4_request\n" +
            "9766c798316ff2757b517bc739a67f6213b4ab36dd5da2f94eaebf79c77395ca";
        String stringToSign = RestUtils.buildStringToSignAWSVersion4(
            requestSignatureVersion, canonicalRequestString,
            this.timestampISO8601, this.region);
        assertEquals(expected, stringToSign);

        // Signature
        byte[] signingKey = RestUtils.buildSigningKeyAWSVersion4(
            this.awsSecretAccessKey, this.timestampISO8601,
            this.region);
        String signature = ServiceUtils.toHex(
            ServiceUtils.hmacSHA256(
                signingKey, ServiceUtils.stringToBytes(stringToSign)));
        expected = "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543";
        assertEquals(expected, signature);

        // Authorization header
        String authorizationHeaderValue =
            RestUtils.buildAuthorizationHeaderValueAWSVersion4(
                this.awsAccessKey, signature, this.requestSignatureVersion,
                canonicalRequestString, this.timestampISO8601, this.region);
        expected = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543";
        assertEquals(expected, authorizationHeaderValue);

        // The whole request
        RestUtils.signRequestAuthorizationHeaderForAWSVersion4(
            this.requestSignatureVersion, httpGet,
            new AWSCredentials(this.awsAccessKey, this.awsSecretAccessKey),
            requestPayloadHexSHA256Hash, this.region);
        assertEquals(expected, httpGet.getFirstHeader("Authorization").getValue());
    }

    @Test
    public void testS3ApiReferenceExampleGetBucketListObjects() {
        HttpGet httpGet = new HttpGet("http://examplebucket.s3.amazonaws.com?max-keys=2&prefix=J");
        httpGet.setHeader("Host", "examplebucket.s3.amazonaws.com");
        // NOTE: Date header missed in example test case
        httpGet.setHeader("x-amz-date", this.timestampISO8601);

        // Empty payload
        String payload = "";
        String requestPayloadHexSHA256Hash = ServiceUtils.toHex(
            ServiceUtils.hash(payload, "SHA-256"));
        httpGet.setHeader("x-amz-content-sha256", requestPayloadHexSHA256Hash);

        // Canonical request string
        String expected =
            "GET\n" +
            "/\n" +
            "max-keys=2&prefix=J\n" +
            "host:examplebucket.s3.amazonaws.com\n" +
            "x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n" +
            "x-amz-date:20130524T000000Z\n" +
            "\n" +
            "host;x-amz-content-sha256;x-amz-date\n" +
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        String canonicalRequestString = RestUtils.buildCanonicalRequestStringAWSVersion4(
            httpGet, requestPayloadHexSHA256Hash);
        assertEquals(expected, canonicalRequestString);

        // String to sign
        expected =
            "AWS4-HMAC-SHA256\n" +
            "20130524T000000Z\n" +
            "20130524/us-east-1/s3/aws4_request\n" +
            "df57d21db20da04d7fa30298dd4488ba3a2b47ca3a489c74750e0f1e7df1b9b7";
        String stringToSign = RestUtils.buildStringToSignAWSVersion4(
            requestSignatureVersion, canonicalRequestString,
            this.timestampISO8601, this.region);
        assertEquals(expected, stringToSign);

        // Signature
        byte[] signingKey = RestUtils.buildSigningKeyAWSVersion4(
            this.awsSecretAccessKey, this.timestampISO8601,
            this.region);
        String signature = ServiceUtils.toHex(
            ServiceUtils.hmacSHA256(
                signingKey, ServiceUtils.stringToBytes(stringToSign)));
        expected = "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7";
        assertEquals(expected, signature);

        // Authorization header
        String authorizationHeaderValue =
            RestUtils.buildAuthorizationHeaderValueAWSVersion4(
                this.awsAccessKey, signature, this.requestSignatureVersion,
                canonicalRequestString, this.timestampISO8601, this.region);
        expected = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7";
        assertEquals(expected, authorizationHeaderValue);

        // The whole request
        RestUtils.signRequestAuthorizationHeaderForAWSVersion4(
            this.requestSignatureVersion, httpGet,
            new AWSCredentials(this.awsAccessKey, this.awsSecretAccessKey),
            requestPayloadHexSHA256Hash, this.region);
        assertEquals(expected, httpGet.getFirstHeader("Authorization").getValue());
    }

    // Very basic test of signed GET request with no payload.
    @Test
    public void testWithServiceListAllBuckets() throws Exception {
        ProviderCredentials credentials = new AWSCredentials(
            testProperties.getProperty("aws.accesskey"),
            testProperties.getProperty("aws.secretkey"));

        Jets3tProperties properties = new Jets3tProperties();
        properties.setProperty(
            "storage-service.request-signature-version",
            this.requestSignatureVersion);

        RestS3Service service = new RestS3Service(
            credentials, null, null, properties);

        service.listAllBuckets();
    }

}

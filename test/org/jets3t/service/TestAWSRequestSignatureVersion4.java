package org.jets3t.service;

import junit.framework.TestCase;

import org.apache.http.client.methods.HttpGet;
import org.jets3t.service.utils.RestUtils;
import org.jets3t.service.utils.ServiceUtils;
import org.junit.Test;

/**
 * {@link "http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html"}
 */
public class TestAWSRequestSignatureVersion4 extends TestCase {
    String awsAccessKey = "AKIAIOSFODNN7EXAMPLE";
    String awsSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    String timestampISO8601 = "20130524T000000Z";
    String bucketName = "examplebucket";
    String region = "us-east-1";
    String service = "s3";
    String requestSignatureVersion = "AWS4-HMAC-SHA256";

    @Test
    public void testGetObject() {
        HttpGet httpGet = new HttpGet("http://examplebucket.s3.amazonaws.com/test.txt");
        httpGet.setHeader("Host", "examplebucket.s3.amazonaws.com");
        httpGet.setHeader("Range", "bytes=0-9");
        httpGet.setHeader("x-amz-content-sha256",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        httpGet.setHeader("x-amz-date", "20130524T000000Z");

        String requestPayloadBase64SHA256 = null; // empty payload

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
            httpGet, requestPayloadBase64SHA256);
        assertEquals(expected, canonicalRequestString);

        // String to sign
        expected =
            "AWS4-HMAC-SHA256\n" +
            "20130524T000000Z\n" +
            "20130524/us-east-1/s3/aws4_request\n" +
            "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972";
        String stringToSign = RestUtils.buildStringToSignAWSVersion4(
            requestSignatureVersion, canonicalRequestString, this.timestampISO8601, "us-east-1");
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
    }

    // TODO Test PUT object

    // TODO Test GET Bucket Lifecycle

    // TODO Test Get Bucket (List Objects)
}

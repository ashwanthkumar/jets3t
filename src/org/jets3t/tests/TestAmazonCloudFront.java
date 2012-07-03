/*
 * JetS3t : Java S3 Toolkit
 * Project hosted at http://bitbucket.org/jmurty/jets3t/
 *
 * Copyright 2012 James Murty
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
package org.jets3t.tests;

import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import junit.framework.TestCase;

import org.jets3t.samples.SamplesUtils;
import org.jets3t.service.CloudFrontService;
import org.jets3t.service.CloudFrontServiceException;
import org.jets3t.service.Constants;
import org.jets3t.service.Jets3tProperties;
import org.jets3t.service.ServiceException;
import org.jets3t.service.impl.rest.httpclient.RestS3Service;
import org.jets3t.service.impl.rest.httpclient.RestStorageService;
import org.jets3t.service.model.cloudfront.CacheBehavior;
import org.jets3t.service.model.cloudfront.CustomOrigin;
import org.jets3t.service.model.cloudfront.Invalidation;
import org.jets3t.service.model.cloudfront.InvalidationSummary;
import org.jets3t.service.model.cloudfront.Origin;
import org.jets3t.service.model.cloudfront.OriginAccessIdentity;
import org.jets3t.service.model.cloudfront.Distribution;
import org.jets3t.service.model.cloudfront.DistributionConfig;
import org.jets3t.service.model.cloudfront.LoggingStatus;
import org.jets3t.service.model.cloudfront.OriginAccessIdentityConfig;
import org.jets3t.service.model.cloudfront.S3Origin;
import org.jets3t.service.model.cloudfront.StreamingDistribution;
import org.jets3t.service.model.cloudfront.StreamingDistributionConfig;
import org.jets3t.service.model.cloudfront.CacheBehavior.ViewerProtocolPolicy;
import org.jets3t.service.security.AWSCredentials;
import org.jets3t.service.security.EncryptionUtil;
import org.jets3t.service.security.ProviderCredentials;
import org.jets3t.service.utils.ServiceUtils;

public class TestAmazonCloudFront extends TestCase {

    protected String originBucket = "jets3t.s3.amazonaws.com";

    protected String TEST_PROPERTIES_FILENAME = "test.properties";
    protected Properties testProperties = null;

    public TestAmazonCloudFront() throws Exception {
        // Load test properties
        InputStream propertiesIS =
            ClassLoader.getSystemResourceAsStream(TEST_PROPERTIES_FILENAME);
        if (propertiesIS == null) {
            throw new Exception("Unable to load test properties file from classpath: "
                + TEST_PROPERTIES_FILENAME);
        }
        this.testProperties = new Properties();
        this.testProperties.load(propertiesIS);
        this.originBucket = this.testProperties.getProperty(
            "cloudfront-origin-bucket", this.originBucket);
    }

    protected CloudFrontService getService() throws CloudFrontServiceException
    {
        AWSCredentials credentials = new AWSCredentials(
            testProperties.getProperty("aws.accesskey"),
            testProperties.getProperty("aws.secretkey"));
        return new CloudFrontService(credentials);
    }

    public void testCreateUpdatePublicDistribution() throws Exception {
        // Create a new public distribution
        String callerId = "test-" + System.currentTimeMillis(); // Caller reference - a unique string value
        String comment = "Testing";
        String[] cnames = new String[] {callerId + this.originBucket}; // CNAME aliases for distribution
        Distribution distribution = getService().createDistribution(
            new S3Origin(this.originBucket),
            callerId,
            cnames,
            comment,
            false,  // Distribution is enabled?
            null  // Logging status of distribution (null means disabled)
            );

        // Check distribution info
        this.assertNotNull(distribution.getId());
        this.assertNotNull(distribution.getDomainName());
        this.assertNotNull(distribution.getLastModifiedTime());
        this.assertEquals("InProgress", distribution.getStatus());
        this.assertEquals(0, distribution.getActiveTrustedSigners().size());
        // Check distribution config info
        DistributionConfig config = distribution.getConfig();
        this.assertEquals(callerId, config.getCallerReference());
        this.assertEquals(comment, config.getComment());
        this.assertEquals(false, config.isEnabled());
        this.assertEquals(Arrays.asList(cnames), Arrays.asList(config.getCNAMEs()));
        this.assertEquals(1, config.getOrigins().length);
        this.assertEquals(S3Origin.class, config.getOrigins()[0].getClass());
        S3Origin origin = (S3Origin) config.getOrigins()[0];
        this.assertEquals("default-origin-id", origin.getId());
        this.assertEquals(this.originBucket, origin.getDomainName());
        this.assertNull(origin.getOriginAccessIdentity());
        this.assertEquals(this.originBucket.split("\\.")[0], origin.getOriginAsBucketName());
        // Check cache behaviors
        CacheBehavior defaultCacheBehavior = config.getDefaultCacheBehavior();
        this.assertNull(defaultCacheBehavior.getPathPattern());
        this.assertEquals(origin.getId(), defaultCacheBehavior.getTargetOriginId());
        this.assertEquals(false, defaultCacheBehavior.isForwardQueryString());
        this.assertEquals(Long.valueOf(0), defaultCacheBehavior.getMinTTL());
        this.assertEquals(0, defaultCacheBehavior.getTrustedSignerAwsAccountNumbers().length);
        this.assertEquals(ViewerProtocolPolicy.ALLOW_ALL, defaultCacheBehavior.getViewerProtocolPolicy());
        // Check legacy distribution info (pre 2012-05-05 API version)
        this.assertEquals(comment, distribution.getComment());
        this.assertEquals(Arrays.asList(cnames), Arrays.asList(distribution.getCNAMEs()));
        this.assertEquals(false, distribution.isEnabled());
        this.assertTrue(distribution.getOrigin() instanceof S3Origin);
        origin = (S3Origin) distribution.getOrigin();

        // Update distribution to enable it, add a CNAME, update comment, enable logging,
        // set default root object, set default cache behavior, add additional cache behavior
        cnames = new String[] {callerId + this.originBucket, callerId + "2" + this.originBucket};
        comment = "Updated comment";
        LoggingStatus logging = new LoggingStatus("log-bucket.s3.amazonaws.com", "log-prefix/");
        DistributionConfig testDistributionConfig = new DistributionConfig(
            distribution.getConfig().getOrigins(),
            distribution.getConfig().getCallerReference(),
            cnames,
            comment,
            true, // Enabled
            logging,
            "index.html", // defaultRootObject
            // defaultCacheBehavior
            new CacheBehavior(
                distribution.getConfig().getOrigins()[0].getId(),
                false, // isForwardQueryString
                new String[] {"self"}, // trustedSignerAwsAccountNumbers
                ViewerProtocolPolicy.HTTPS_ONLY,
                3600l // minTTL
                ),
            // Additional cache behavior
            new CacheBehavior[] {
                new CacheBehavior(
                    "/https-only-path",  // pathPattern
                    distribution.getConfig().getOrigins()[0].getId(),
                    true, // isForwardQueryString
                    null, // trustedSignerAwsAccountNumbers
                    ViewerProtocolPolicy.ALLOW_ALL,
                    1800l // minTTL
                    )}
            );
        config = getService().updateDistributionConfig(
            distribution.getId(), testDistributionConfig);

        // Check distribution config info
        this.assertEquals(testDistributionConfig.getCallerReference(), config.getCallerReference());
        this.assertEquals(testDistributionConfig.getComment(), config.getComment());
        this.assertEquals(testDistributionConfig.isEnabled(), config.isEnabled());
        this.assertEquals(Arrays.asList(testDistributionConfig.getCNAMEs()), Arrays.asList(config.getCNAMEs()));
        this.assertEquals(1, config.getOrigins().length);
        this.assertEquals(S3Origin.class, config.getOrigins()[0].getClass());
        origin = (S3Origin) config.getOrigins()[0];
        this.assertEquals("default-origin-id", origin.getId());
        this.assertEquals(this.originBucket, origin.getDomainName());
        this.assertNull(origin.getOriginAccessIdentity());
        this.assertEquals(this.originBucket.split("\\.")[0], origin.getOriginAsBucketName());
        // Check cache behaviors
        defaultCacheBehavior = config.getDefaultCacheBehavior();
        this.assertNull(defaultCacheBehavior.getPathPattern());
        this.assertEquals(origin.getId(), defaultCacheBehavior.getTargetOriginId());
        this.assertEquals(false, defaultCacheBehavior.isForwardQueryString());
        this.assertEquals(Long.valueOf(3600), defaultCacheBehavior.getMinTTL());
        this.assertEquals(1, defaultCacheBehavior.getTrustedSignerAwsAccountNumbers().length);
        this.assertEquals("self", defaultCacheBehavior.getTrustedSignerAwsAccountNumbers()[0]);
        this.assertEquals(ViewerProtocolPolicy.HTTPS_ONLY, defaultCacheBehavior.getViewerProtocolPolicy());
        this.assertEquals(1, config.getCacheBehaviors().length);
        CacheBehavior cacheBehavior = config.getCacheBehaviors()[0];
        this.assertEquals("/https-only-path", cacheBehavior.getPathPattern());
        this.assertEquals(origin.getId(), cacheBehavior.getTargetOriginId());
        this.assertTrue(cacheBehavior.isForwardQueryString());
        this.assertEquals(Long.valueOf(1800), cacheBehavior.getMinTTL());
        this.assertEquals(0, cacheBehavior.getTrustedSignerAwsAccountNumbers().length);
        this.assertEquals(ViewerProtocolPolicy.ALLOW_ALL, cacheBehavior.getViewerProtocolPolicy());

        // TODO Get distribution details

        // TODO Disable distribution in preparation for deletion

        // TODO Delete distribution
    }

}

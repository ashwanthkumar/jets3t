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
package org.jets3t.tests;

import org.jets3t.service.S3Service;
import org.jets3t.service.S3ServiceException;
import org.jets3t.service.acl.GrantAndPermission;
import org.jets3t.service.acl.GroupGrantee;
import org.jets3t.service.acl.Permission;
import org.jets3t.service.impl.rest.httpclient.RestS3Service;
import org.jets3t.service.model.S3Bucket;
import org.jets3t.service.model.S3BucketLoggingStatus;
import org.jets3t.service.security.AWSCredentials;
import org.jets3t.service.security.ProviderCredentials;

/**
 * Test the RestS3Service against the S3 endpoint, and apply tests specific to S3.
 *
 * @author James Murty
 */
public class TestRestS3Service extends BaseStorageServiceTests {

    public TestRestS3Service() throws Exception {
        super();
    }

    @Override
    protected ProviderCredentials getCredentials() {
        return new AWSCredentials(
            testProperties.getProperty("aws.accesskey"),
            testProperties.getProperty("aws.secretkey"));
    }

    @Override
    protected S3Service getStorageService(ProviderCredentials credentials) throws S3ServiceException {
        return new RestS3Service(credentials);
    }

    public void testBucketLogging() throws Exception {
        S3Service s3Service = getStorageService(getCredentials());
        S3Bucket bucket = createBucketForTest("testBucketLogging");
        String bucketName = bucket.getName();

        try {
            // Check logging status is false
            S3BucketLoggingStatus loggingStatus = s3Service.getBucketLoggingStatus(bucket.getName());
            assertFalse("Expected logging to be disabled for bucket " + bucketName,
                loggingStatus.isLoggingEnabled());

            // Enable logging (non-existent target bucket)
            try {
                S3BucketLoggingStatus newLoggingStatus = new S3BucketLoggingStatus(
                    getCredentials().getAccessKey() + ".NonExistentBucketName", "access-log-");
                s3Service.setBucketLoggingStatus(bucket.getName(), newLoggingStatus, true);
                fail("Using non-existent target bucket should have caused an exception");
            } catch (Exception e) {
            }

            // Enable logging (in same bucket)
            S3BucketLoggingStatus newLoggingStatus = new S3BucketLoggingStatus(bucketName, "access-log-");
            s3Service.setBucketLoggingStatus(bucket.getName(), newLoggingStatus, true);
            loggingStatus = s3Service.getBucketLoggingStatus(bucket.getName());
            assertTrue("Expected logging to be enabled for bucket " + bucketName,
                loggingStatus.isLoggingEnabled());
            assertEquals("Target bucket", bucketName, loggingStatus.getTargetBucketName());
            assertEquals("Log file prefix", "access-log-", loggingStatus.getLogfilePrefix());

            // Add TargetGrants ACLs for log files
            newLoggingStatus.addTargetGrant(new GrantAndPermission(
                GroupGrantee.ALL_USERS, Permission.PERMISSION_READ));
            newLoggingStatus.addTargetGrant(new GrantAndPermission(
                GroupGrantee.AUTHENTICATED_USERS, Permission.PERMISSION_READ_ACP));
            s3Service.setBucketLoggingStatus(bucket.getName(), newLoggingStatus, false);
            // Retrieve and verify TargetGrants
            loggingStatus = s3Service.getBucketLoggingStatus(bucket.getName());
            assertEquals(2, loggingStatus.getTargetGrants().length);
            GrantAndPermission gap = loggingStatus.getTargetGrants()[0];
            assertEquals(gap.getGrantee().getIdentifier(), GroupGrantee.ALL_USERS.getIdentifier());
            assertEquals(gap.getPermission(), Permission.PERMISSION_READ);
            gap = loggingStatus.getTargetGrants()[1];
            assertEquals(gap.getGrantee().getIdentifier(), GroupGrantee.AUTHENTICATED_USERS.getIdentifier());
            assertEquals(gap.getPermission(), Permission.PERMISSION_READ_ACP);

            // Disable logging
            newLoggingStatus = new S3BucketLoggingStatus();
            s3Service.setBucketLoggingStatus(bucket.getName(), newLoggingStatus, true);
            loggingStatus = s3Service.getBucketLoggingStatus(bucket.getName());
            assertFalse("Expected logging to be disabled for bucket " + bucketName,
                loggingStatus.isLoggingEnabled());
        } finally {
            cleanupBucketForTest("testBucketLogging");
        }
    }
}

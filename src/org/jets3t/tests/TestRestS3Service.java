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

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.jets3t.service.Constants;
import org.jets3t.service.Jets3tProperties;
import org.jets3t.service.S3Service;
import org.jets3t.service.S3ServiceException;
import org.jets3t.service.ServiceException;
import org.jets3t.service.StorageService;
import org.jets3t.service.acl.AccessControlList;
import org.jets3t.service.impl.rest.httpclient.RestS3Service;
import org.jets3t.service.impl.rest.httpclient.RestStorageService;
import org.jets3t.service.model.MultipartCompleted;
import org.jets3t.service.model.MultipartPart;
import org.jets3t.service.model.MultipartUpload;
import org.jets3t.service.model.NotificationConfig;
import org.jets3t.service.model.S3Bucket;
import org.jets3t.service.model.S3BucketLoggingStatus;
import org.jets3t.service.model.S3Object;
import org.jets3t.service.model.StorageBucket;
import org.jets3t.service.model.StorageBucketLoggingStatus;
import org.jets3t.service.model.StorageObject;
import org.jets3t.service.model.WebsiteConfig;
import org.jets3t.service.model.NotificationConfig.TopicConfig;
import org.jets3t.service.multi.s3.MultipartUploadAndParts;
import org.jets3t.service.multi.s3.S3ServiceEventAdaptor;
import org.jets3t.service.multi.s3.ThreadedS3Service;
import org.jets3t.service.security.AWSCredentials;
import org.jets3t.service.security.ProviderCredentials;
import org.jets3t.service.utils.MultipartUtils;
import org.jets3t.service.utils.ObjectUtils;
import org.jets3t.service.utils.RestUtils;
import org.jets3t.service.utils.ServiceUtils;

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
    protected AccessControlList buildAccessControlList() {
        return new AccessControlList();
    }

    @Override
    protected String getTargetService() {
        return TARGET_SERVICE_S3;
    }

    @Override
    protected ProviderCredentials getCredentials() {
        return new AWSCredentials(
            testProperties.getProperty("aws.accesskey"),
            testProperties.getProperty("aws.secretkey"));
    }

    @Override
    protected RestStorageService getStorageService(ProviderCredentials credentials)
        throws ServiceException
    {
        return getStorageService(credentials, Constants.S3_DEFAULT_HOSTNAME);
    }

    @Override
    protected StorageBucketLoggingStatus getBucketLoggingStatus(
        String targetBucketName, String logfilePrefix) throws Exception
    {
        return new S3BucketLoggingStatus(targetBucketName, logfilePrefix);
    }


    protected RestStorageService getStorageService(ProviderCredentials credentials,
        String endpointHostname) throws ServiceException
    {
        Jets3tProperties properties = new Jets3tProperties();
        properties.setProperty("s3service.s3-endpoint", endpointHostname);
        return getStorageService(credentials, properties);
    }

    protected RestStorageService getStorageService(ProviderCredentials credentials,
        Jets3tProperties properties) throws ServiceException
    {
        return new RestS3Service(credentials, null, null, properties);
    }

    protected StorageBucket createBucketForTest(String testName, String location) throws Exception {
        String bucketName = getBucketNameForTest(testName);
        StorageService service = getStorageService(getCredentials());
        return ((S3Service)service).getOrCreateBucket(bucketName, location);
    }

    public void testUrlSigning() throws Exception {
        RestS3Service service = (RestS3Service) getStorageService(getCredentials());
        StorageBucket bucket = createBucketForTest("testUrlSigning");
        String bucketName = bucket.getName();

        try {
            // Create test object, with private ACL
            String dataString = "Text for the URL Signing test object...";
            S3Object object = new S3Object("Testing URL Signing", dataString);
            object.setContentType("text/html");
            object.addMetadata(service.getRestMetadataPrefix() + "example-header", "example-value");
            object.setAcl(AccessControlList.REST_CANNED_PRIVATE);

            // Determine what the time will be in 5 minutes.
            Calendar cal = Calendar.getInstance();
            cal.add(Calendar.MINUTE, 5);
            Date expiryDate = cal.getTime();

            // Create a signed HTTP PUT URL.
            String signedPutUrl = service.createSignedPutUrl(bucket.getName(), object.getKey(),
                object.getMetadataMap(), expiryDate, false);

            // Put the object in S3 using the signed URL (no AWS credentials required)
            RestS3Service restS3Service = new RestS3Service(null);
            restS3Service.putObjectWithSignedUrl(signedPutUrl, object);

            // Ensure the object was created.
            StorageObject objects[] = service.listObjects(bucketName, object.getKey(), null);
            assertEquals("Signed PUT URL failed to put/create object", objects.length, 1);

            // Change the object's content-type and ensure the signed PUT URL disallows the put.
            object.setContentType("application/octet-stream");
            try {
                restS3Service.putObjectWithSignedUrl(signedPutUrl, object);
                fail("Should not be able to use a signed URL for an object with a changed content-type");
            } catch (ServiceException e) {
                object.setContentType("text/html");
            }

            // Add an object header and ensure the signed PUT URL disallows the put.
            object.addMetadata(service.getRestMetadataPrefix() + "example-header-2", "example-value");
            try {
                restS3Service.putObjectWithSignedUrl(signedPutUrl, object);
                fail("Should not be able to use a signed URL for an object with changed metadata");
            } catch (ServiceException e) {
                object.removeMetadata(service.getRestMetadataPrefix() + "example-header-2");
            }

            // Change the object's name and ensure the signed PUT URL uses the signed name, not the object name.
            String originalName = object.getKey();
            object.setKey("Testing URL Signing 2");
            object.setDataInputStream(new ByteArrayInputStream(dataString.getBytes()));
            object = restS3Service.putObjectWithSignedUrl(signedPutUrl, object);
            assertEquals("Ensure returned object key is renamed based on signed PUT URL",
                originalName, object.getKey());

            // Test last-resort MD5 sanity-check for uploaded object when ETag is missing.
            S3Object objectWithoutETag = new S3Object("Object Without ETag");
            objectWithoutETag.setContentType("text/html");
            String objectWithoutETagSignedPutURL = service.createSignedPutUrl(
                bucket.getName(), objectWithoutETag.getKey(), objectWithoutETag.getMetadataMap(),
                expiryDate, false);
            objectWithoutETag.setDataInputStream(new ByteArrayInputStream(dataString.getBytes()));
            objectWithoutETag.setContentLength(dataString.getBytes().length);
            restS3Service.putObjectWithSignedUrl(objectWithoutETagSignedPutURL, objectWithoutETag);
            service.deleteObject(bucketName, objectWithoutETag.getKey());

            // Ensure we can't get the object with a normal URL.
            String s3Url = "https://s3.amazonaws.com";
            URL url = new URL(s3Url + "/" + bucket.getName() + "/" + RestUtils.encodeUrlString(object.getKey()));
            assertEquals("Expected denied access (403) error", 403, ((HttpURLConnection) url
                .openConnection()).getResponseCode());

            // Create a signed HTTP GET URL.
            String signedGetUrl = service.createSignedGetUrl(bucket.getName(), object.getKey(),
                expiryDate, false);

            // Ensure the signed URL can retrieve the object.
            url = new URL(signedGetUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            assertEquals("Expected signed GET URL ("+ signedGetUrl +") to retrieve object with response code 200",
                200, conn.getResponseCode());

            // Sanity check the data in the S3 object.
            String objectData = (new BufferedReader(
                new InputStreamReader(conn.getInputStream())))
                .readLine();
            assertEquals("Unexpected data content in S3 object", dataString, objectData);

            // Confirm we got the expected Content-Type
            assertEquals("text/html", conn.getHeaderField("content-type"));

            // Modify response data via special "response-*" request parameters
            signedGetUrl = service.createSignedUrl("GET", bucket.getName(), object.getKey(),
                "response-content-type=text/plain&response-content-encoding=latin1",
                null, // No headers
                (expiryDate.getTime() / 1000) // Expiry time after epoch in seconds
                );
            url = new URL(signedGetUrl);
            conn = (HttpURLConnection) url.openConnection();
            assertEquals("text/plain", conn.getHeaderField("content-type"));
            assertEquals("latin1", conn.getHeaderField("content-encoding"));

            // Clean up.
            service.deleteObject(bucketName, object.getKey());
        } finally {
            cleanupBucketForTest("testUrlSigning");
        }
    }

    public void testMultipartUtils() throws Exception {
        RestS3Service service = (RestS3Service) getStorageService(getCredentials());
        StorageBucket bucket = createBucketForTest("testMultipartUtils");
        String bucketName = bucket.getName();

        try {
            // Ensure constructor enforces sanity constraints
            try {
                new MultipartUtils(MultipartUtils.MIN_PART_SIZE - 1);
                fail("Expected failure creating MultipartUtils with illegally small part size");
            } catch (IllegalArgumentException e) {}

            try {
                new MultipartUtils(MultipartUtils.MAX_OBJECT_SIZE + 1);
                fail("Expected failure creating MultipartUtils with illegally large part size");
            } catch (IllegalArgumentException e) {}

            // Default part size is maximum possible
            MultipartUtils multipartUtils = new MultipartUtils();
            assertEquals("Unexpected default part size",
                MultipartUtils.MAX_OBJECT_SIZE, multipartUtils.getMaxPartSize());

            // Create a util with the minimum part size, for quicker testing
            multipartUtils = new MultipartUtils(MultipartUtils.MIN_PART_SIZE);
            assertEquals("Unexpected default part size",
                MultipartUtils.MIN_PART_SIZE, multipartUtils.getMaxPartSize());

            // Create a large (11 MB) file
            File largeFile = File.createTempFile("JetS3t-testMultipartUtils-large", ".txt");
            BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(largeFile));
            int offset = 0;
            while (offset < 11 * 1024 * 1024) {
                bos.write((offset++ % 256));
            }
            bos.close();

            // Create a medium (6 MB) file
            File mediumFile = File.createTempFile("JetS3t-testMultipartUtils-medium", ".txt");
            bos = new BufferedOutputStream(new FileOutputStream(mediumFile));
            offset = 0;
            while (offset < 6 * 1024 * 1024) {
                bos.write((offset++ % 256));
            }
            bos.close();

            // Create a small (5 MB) file
            File smallFile = File.createTempFile("JetS3t-testMultipartUtils-small", ".txt");
            bos = new BufferedOutputStream(new FileOutputStream(smallFile));
            offset = 0;
            while (offset < 5 * 1024 * 1024) {
                bos.write((offset++ % 256));
            }
            bos.close();

            assertFalse("Expected small file to be <= 5MB",
                multipartUtils.isFileLargerThanMaxPartSize(smallFile));
            assertTrue("Expected medium file to be > 5MB",
                multipartUtils.isFileLargerThanMaxPartSize(mediumFile));
            assertTrue("Expected large file to be > 5MB",
                multipartUtils.isFileLargerThanMaxPartSize(largeFile));

            // Split small file into 5MB object parts
            List<S3Object> parts = multipartUtils.splitFileIntoObjectsByMaxPartSize(
                smallFile.getName(), smallFile);
            assertEquals(1, parts.size());

            // Split medium file into 5MB object parts
            parts = multipartUtils.splitFileIntoObjectsByMaxPartSize(
                mediumFile.getName(), mediumFile);
            assertEquals(2, parts.size());

            // Split large file into 5MB object parts
            parts = multipartUtils.splitFileIntoObjectsByMaxPartSize(
                largeFile.getName(), largeFile);
            assertEquals(3, parts.size());

            /*
             * Upload medium-sized file as object in multiple parts
             */
            List<StorageObject> objects = new ArrayList<StorageObject>();
            objects.add(
                ObjectUtils.createObjectForUpload(
                    mediumFile.getName(),
                    mediumFile,
                    null, // encryptionUtil
                    false // gzipFile
                ));

            multipartUtils.uploadObjects(bucketName, service, objects, null);

            S3Object completedObject = (S3Object) service.getObjectDetails(
                bucketName, mediumFile.getName());
            assertEquals(mediumFile.length(), completedObject.getContentLength());
            // Confirm object's mimetype metadata was applied
            assertEquals("text/plain", completedObject.getContentType());

            /*
             * Upload large-sized file as object in multiple parts
             */
            objects = new ArrayList<StorageObject>();
            objects.add(
                ObjectUtils.createObjectForUpload(
                    largeFile.getName(),
                    largeFile,
                    null, // encryptionUtil
                    false // gzipFile
                ));

            multipartUtils.uploadObjects(bucketName, service, objects, null);

            completedObject = (S3Object) service.getObjectDetails(
                bucketName, largeFile.getName());
            assertEquals(largeFile.length(), completedObject.getContentLength());
        } finally {
            cleanupBucketForTest("testMultipartUtils");
        }
    }

    public void testMultipartUploads() throws Exception {
        RestS3Service service = (RestS3Service) getStorageService(getCredentials());
        StorageBucket bucket = createBucketForTest("testMultipartUploads");
        String bucketName = bucket.getName();

        try {
            // Check stripping of double-quote characters from etag
            MultipartPart testEtagSanitized = new MultipartPart(
                1, new Date(), "\"fakeEtagWithDoubleQuotes\"", 0l);
            assertEquals("fakeEtagWithDoubleQuotes", testEtagSanitized.getEtag());

            // Create 5MB of test data
            int fiveMB = 5 * 1024 * 1024;
            byte[] fiveMBTestData = new byte[fiveMB];
            for (int offset = 0; offset < fiveMBTestData.length; offset++) {
                fiveMBTestData[offset] = (byte) (offset % 256);
            }

            // Define name and String metadata values for multipart upload object
            String objectKey = "multipart-object.txt";
            Map<String, Object> metadata = new HashMap<String, Object>();
            metadata.put("test-md-value", "testing, testing, 123");
            metadata.put("test-timestamp-value", System.currentTimeMillis());

            // Start a multipart upload
            MultipartUpload testMultipartUpload =
                service.multipartStartUpload(bucketName, objectKey, metadata);

            assertEquals(bucketName, testMultipartUpload.getBucketName());
            assertEquals(objectKey, testMultipartUpload.getObjectKey());

            // List all ongoing multipart uploads
            List<MultipartUpload> uploads = service.multipartListUploads(bucketName);

            assertTrue("Expected at least one ongoing upload", uploads.size() >= 1);

            // Confirm our newly-created multipart upload is present in listing
            boolean foundNewUpload = false;
            for (MultipartUpload upload: uploads) {
                if (upload.getUploadId().equals(testMultipartUpload.getUploadId())) {
                    foundNewUpload = true;
                }
            }
            assertTrue("Expected to find the new upload in listing", foundNewUpload);

            // Start a second multipart upload
            MultipartUpload testMultipartUpload2 =
                service.multipartStartUpload(bucketName, objectKey + "2", metadata);

            // List multipart uploads with markers -- Find second upload only
            uploads = service.multipartListUploads(bucketName,
                "multipart-object.txt",
                testMultipartUpload.getUploadId(),
                10);
            assertEquals(1, uploads.size());
            assertEquals(objectKey + "2", uploads.get(0).getObjectKey());

            // Delete incomplete/unwanted multipart upload
            service.multipartAbortUpload(testMultipartUpload2);

            // Ensure the incomplete multipart upload has been deleted
            uploads = service.multipartListUploads(bucketName);
            for (MultipartUpload upload: uploads) {
                if (upload.getUploadId().equals(testMultipartUpload2.getUploadId()))
                {
                    fail("Expected multipart upload " + upload.getUploadId()
                        + " to be deleted");
                }
            }

            int partNumber = 0;

            // Upload a first part, must be 5MB+
            S3Object partObject = new S3Object(
                testMultipartUpload.getObjectKey(), fiveMBTestData);
            MultipartPart uploadedPart = service.multipartUploadPart(
                testMultipartUpload, ++partNumber, partObject);
            assertEquals(uploadedPart.getPartNumber().longValue(), partNumber);
            assertEquals(uploadedPart.getEtag(), partObject.getETag());
            assertEquals(uploadedPart.getSize().longValue(), partObject.getContentLength());

            // List multipart parts that have been received by the service
            List<MultipartPart> listedParts = service.multipartListParts(testMultipartUpload);
            assertEquals(listedParts.size(), 1);
            assertEquals(listedParts.get(0).getSize().longValue(), partObject.getContentLength());

            // Upload a second part by copying an object already in S3, must be >= 5 MB
            S3Object objectToCopy = service.putObject(bucketName,
                new S3Object("objectToCopy.txt", fiveMBTestData));
            MultipartPart copiedPart = service.multipartUploadPartCopy(testMultipartUpload,
                ++partNumber, bucketName, objectToCopy.getKey());
            assertEquals(copiedPart.getPartNumber().longValue(), partNumber);
            assertEquals(copiedPart.getEtag(), objectToCopy.getETag());
            // Note: result part from copy operation does *not* include correct part size, due
            // to lack of this info in the CopyPartResult XML response.
            // assertEquals(copiedPart.getSize().longValue(), partObject.getContentLength());

            // List multipart parts that have been received by the service
            listedParts = service.multipartListParts(testMultipartUpload);
            assertEquals(listedParts.size(), 2);
            assertEquals(listedParts.get(1).getSize().longValue(), objectToCopy.getContentLength());

            // TODO Test multipart upload copy with version ID
            // TODO Test multipart upload copy with byte range (need object >= 5 GB !)
            // TODO Test multipart upload copy with ETag (mis)match test
            // TODO Test multipart upload copy with (un)modified since test

            // Upload a third and final part, can be as small as 1 byte
            partObject = new S3Object(
                testMultipartUpload.getObjectKey(), new byte[] {fiveMBTestData[0]});
            uploadedPart = service.multipartUploadPart(
                testMultipartUpload, ++partNumber, partObject);
            assertEquals(uploadedPart.getPartNumber().longValue(), partNumber);
            assertEquals(uploadedPart.getEtag(), partObject.getETag());
            assertEquals(uploadedPart.getSize().longValue(), partObject.getContentLength());

            // List multipart parts that have been received by the service
            listedParts = service.multipartListParts(testMultipartUpload);
            assertEquals(listedParts.size(), 3);
            assertEquals(listedParts.get(2).getSize().longValue(), partObject.getContentLength());

            // Reverse order of parts to ensure multipartCompleteUpload corrects the problem
            Collections.reverse(listedParts);

            // Complete multipart upload, despite badly ordered parts.
            MultipartCompleted multipartCompleted = service.multipartCompleteUpload(
                testMultipartUpload, listedParts);
            assertEquals(multipartCompleted.getBucketName(), testMultipartUpload.getBucketName());
            assertEquals(multipartCompleted.getObjectKey(), testMultipartUpload.getObjectKey());

            // Confirm completed object exists and has expected size and metadata
            S3Object completedObject = (S3Object) service.getObjectDetails(
                bucketName, testMultipartUpload.getObjectKey());
            assertEquals(completedObject.getContentLength(), fiveMBTestData.length * 2 + 1);
            assertEquals(
                metadata.get("test-md-value"),
                completedObject.getMetadata("test-md-value"));
            assertEquals(
                metadata.get("test-timestamp-value").toString(),
                completedObject.getMetadata("test-timestamp-value").toString());
        } finally {
            cleanupBucketForTest("testMultipartUploads");
        }
    }

    public void testMultipartUploadWithConvenienceMethod() throws Exception {
        RestS3Service service = (RestS3Service) getStorageService(getCredentials());
        StorageBucket bucket = createBucketForTest("testMultipartUploadWithConvenienceMethod");
        String bucketName = bucket.getName();

        try {
            int fiveMB = 5 * 1024 * 1024;

            byte[] testDataOverLimit = new byte[fiveMB + 100];
            for (int i = 0; i < testDataOverLimit.length; i++) {
                testDataOverLimit[i] = (byte) (i % 256);
            }

            // Confirm that non-file-based objects are not accepted
            try {
                StorageObject myObject = new StorageObject();
                service.putObjectMaybeAsMultipart(bucketName, myObject, fiveMB);
                fail("");
            } catch (ServiceException se) {
            }

            // Create file for testing
            File testDataFile = File.createTempFile("JetS3t-testMultipartUploadWithConvenienceMethod", ".txt");
            BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(testDataFile));
            bos.write(testDataOverLimit);
            bos.close();
            testDataOverLimit = null; // Free up a some memory

            // Setup file-based object
            StorageObject objectViaConvenienceMethod = new StorageObject(testDataFile);
            objectViaConvenienceMethod.setKey("multipart-object-via-convenience-method.txt");
            objectViaConvenienceMethod.addMetadata("my-metadata", "convenient? yes!");
            objectViaConvenienceMethod.setAcl(AccessControlList.REST_CANNED_PUBLIC_READ);
            objectViaConvenienceMethod.setStorageClass(S3Object.STORAGE_CLASS_REDUCED_REDUNDANCY);

            // Upload object
            service.putObjectMaybeAsMultipart(bucketName, objectViaConvenienceMethod, fiveMB);

            // Confirm completed object exists and has expected metadata
            objectViaConvenienceMethod = service.getObjectDetails(
                bucketName, objectViaConvenienceMethod.getKey());
            assertEquals(
                "convenient? yes!",
                objectViaConvenienceMethod.getMetadata("my-metadata"));

            // Confirm completed object was indeed uploaded as a multipart upload,
            // not a standard PUT (ETag is not a valid MD5 hash in this case)
            assertFalse(ServiceUtils.isEtagAlsoAnMD5Hash(
                objectViaConvenienceMethod.getETag()));

            /*
             * Perform a threaded multipart upload
             */
            String objectKeyForThreaded = "threaded-multipart-object.txt";
            Map<String, Object> metadataForThreaded = new HashMap<String, Object>();

            // Start threaded upload using normal service.
            MultipartUpload threadedMultipartUpload =
                service.multipartStartUpload(bucketName, objectKeyForThreaded, metadataForThreaded);

            // Create 5MB of test data
            byte[] fiveMBTestData = new byte[fiveMB];
            for (int offset = 0; offset < fiveMBTestData.length; offset++) {
                fiveMBTestData[offset] = (byte) (offset % 256);
            }

            // Prepare objects for upload (2 * 5MB, and 1 * 1 byte)
            S3Object[] objectsForThreadedUpload = new S3Object[] {
                new S3Object(threadedMultipartUpload.getObjectKey(), fiveMBTestData),
                new S3Object(threadedMultipartUpload.getObjectKey(), fiveMBTestData),
                new S3Object(threadedMultipartUpload.getObjectKey(), new byte[] {fiveMBTestData[0]}),
            };

            // Create threaded service and perform upload in multiple threads
            ThreadedS3Service threadedS3Service = new ThreadedS3Service(service,
                new S3ServiceEventAdaptor());
            List<MultipartUploadAndParts> uploadAndParts = new ArrayList<MultipartUploadAndParts>();
            uploadAndParts.add(new MultipartUploadAndParts(
                threadedMultipartUpload, Arrays.asList(objectsForThreadedUpload)));
            threadedS3Service.multipartUploadParts(uploadAndParts);

            // Complete threaded multipart upload using automatic part listing and normal service.
            MultipartCompleted threadedMultipartCompleted = service.multipartCompleteUpload(
                threadedMultipartUpload);

            // Confirm completed object exists and has expected size
            S3Object finalObjectForThreaded = (S3Object) service.getObjectDetails(
                bucketName, threadedMultipartUpload.getObjectKey());
            assertEquals(fiveMB * 2 + 1, finalObjectForThreaded.getContentLength());
        } finally {
            cleanupBucketForTest("testMultipartUploadWithConvenienceMethod");
        }
    }

    public void testS3WebsiteConfig() throws Exception {
        // Testing takes place in the us-west-1 location
        S3Service s3Service = (S3Service) getStorageService(getCredentials());
        StorageBucket bucket = createBucketForTest(
            "testS3WebsiteConfig",
            // Standard US Bucket location
            S3Bucket.LOCATION_US_WEST);
        String bucketName = bucket.getName();

        String s3WebsiteURL = "http://" + bucketName + "."
            // Website location must correspond to bucket location, in this case
            // the US Standard. For website endpoints see:
            // docs.amazonwebservices.com/AmazonS3/latest/dev/WebsiteEndpoints.html
            + "s3-website-us-west-1"
            + ".amazonaws.com";

        try {
            HttpClient httpClient = new DefaultHttpClient();
            HttpGet getMethod = null;

            // Check no existing website config
            try {
                s3Service.getWebsiteConfig(bucketName);
                fail("Unexpected website config for bucket " + bucketName);
            } catch (S3ServiceException e) { }

            // Set index document
            s3Service.setWebsiteConfig(bucketName,
                new WebsiteConfig("index.html"));

            Thread.sleep(5000);

            // Confirm index document set
            WebsiteConfig config = s3Service.getWebsiteConfig(bucketName);
            assertTrue(config.isWebsiteConfigActive());
            assertEquals("index.html", config.getIndexDocumentSuffix());
            assertNull(config.getErrorDocumentKey());

            // Upload public index document
            S3Object indexObject = new S3Object("index.html", "index.html contents");
            indexObject.setAcl(AccessControlList.REST_CANNED_PUBLIC_READ);
            s3Service.putObject(bucketName, indexObject);

            // Confirm index document is served at explicit path
            getMethod = new HttpGet(s3WebsiteURL + "/index.html");
            HttpResponse response = httpClient.execute(getMethod);
            assertEquals(200, response.getStatusLine().getStatusCode());
            assertEquals("index.html contents", EntityUtils.toString(response.getEntity()));

            // Confirm index document is served at root path
            // (i.e. website config is effective)
            getMethod = new HttpGet(s3WebsiteURL + "/");
            response = httpClient.execute(getMethod);
            assertEquals(200, response.getStatusLine().getStatusCode());
            assertEquals("index.html contents", EntityUtils.toString(response.getEntity()));

            // Set index document and error document
            s3Service.setWebsiteConfig(bucketName,
                new WebsiteConfig("index.html", "error.html"));

            Thread.sleep(5000);

            // Confirm index document and error document set
            config = s3Service.getWebsiteConfig(bucketName);
            assertTrue(config.isWebsiteConfigActive());
            assertEquals("index.html", config.getIndexDocumentSuffix());
            assertEquals("error.html", config.getErrorDocumentKey());

            // Upload public error document
            S3Object errorObject = new S3Object("error.html", "error.html contents");
            errorObject.setAcl(AccessControlList.REST_CANNED_PUBLIC_READ);
            s3Service.putObject(bucketName, errorObject);

            // Confirm error document served at explicit path
            getMethod = new HttpGet(s3WebsiteURL + "/error.html");
            response = httpClient.execute(getMethod);
            assertEquals(200, response.getStatusLine().getStatusCode());
            assertEquals("error.html contents", EntityUtils.toString(response.getEntity()));

            // Confirm error document served instead of 404 Not Found
            getMethod = new HttpGet(s3WebsiteURL + "/does-not-exist");
            response = httpClient.execute(getMethod);
            assertEquals(403, response.getStatusLine().getStatusCode()); // TODO: Why a 403?
            assertEquals("error.html contents", EntityUtils.toString(response.getEntity()));

            // Upload private document
            S3Object privateObject = new S3Object("private.html", "private.html contents");
            s3Service.putObject(bucketName, privateObject);

            // Confirm error document served instead for 403 Forbidden
            getMethod = new HttpGet(s3WebsiteURL + "/private.html");
            response = httpClient.execute(getMethod);
            assertEquals(403, response.getStatusLine().getStatusCode());

            // Delete website config
            s3Service.deleteWebsiteConfig(bucketName);

            Thread.sleep(5000);

            // Confirm website config deleted
            try {
                s3Service.getWebsiteConfig(bucketName);
                fail("Unexpected website config for bucket " + bucketName);
            } catch (S3ServiceException e) { }
        } finally {
            cleanupBucketForTest("testS3WebsiteConfig");
        }
    }

    public void testNotificationConfig() throws Exception {
        // Testing takes place in the us-west-1 location
        S3Service s3Service = (S3Service) getStorageService(getCredentials());
        StorageBucket bucket = createBucketForTest("testNotificationConfig");
        String bucketName = bucket.getName();

        try {
            // Check no existing notification config
            NotificationConfig notificationConfig =
                s3Service.getNotificationConfig(bucketName);
            assertEquals(0, notificationConfig.getTopicConfigs().size());

            // Public SNS topic for testing
            String topicArn =
                "arn:aws:sns:us-east-1:916472402845:"
                + "JetS3t-Test-S3-Bucket-NotificationConfig";
            String event = NotificationConfig.EVENT_REDUCED_REDUNDANCY_LOST_OBJECT;

            // Set notification config
            notificationConfig = new NotificationConfig();
            notificationConfig.addTopicConfig(notificationConfig.new TopicConfig(topicArn, event));
            s3Service.setNotificationConfig(bucketName, notificationConfig);

            Thread.sleep(5000);

            // Get notification config
            notificationConfig = s3Service.getNotificationConfig(bucketName);
            assertEquals(1, notificationConfig.getTopicConfigs().size());
            TopicConfig topicConfig = notificationConfig.getTopicConfigs().get(0);
            assertEquals(topicArn, topicConfig.getTopic());
            assertEquals(event, topicConfig.getEvent());

            // Unset/clear notification config
            s3Service.unsetNotificationConfig(bucketName);

            Thread.sleep(5000);

            // Confirm notification config is no longer set
            notificationConfig = s3Service.getNotificationConfig(bucketName);
            assertEquals(0, notificationConfig.getTopicConfigs().size());
        } finally {
            cleanupBucketForTest("testNotificationConfig");
        }
    }

    public void testServerSideEncryption() throws Exception {
        S3Service s3Service = (S3Service) getStorageService(getCredentials());
        StorageBucket bucket = createBucketForTest("testServerSideEncryption");
        String bucketName = bucket.getName();

        try {
            // NONE server-side encryption variable == null
            assertEquals(S3Object.SERVER_SIDE_ENCRYPTION__NONE, null);

            // Create a normal object
            S3Object object = new S3Object("unencrypted-object", "Some data");
            object.setServerSideEncryptionAlgorithm(S3Object.SERVER_SIDE_ENCRYPTION__NONE);
            s3Service.putObject(bucketName, object);
            // Confirm object is not encrypted
            StorageObject objDetails = s3Service.getObjectDetails(bucketName, object.getKey());
            assertEquals(null, objDetails.getServerSideEncryptionAlgorithm());

            // Fail to create an encrypted object, due to invalid algorithm
            object = new S3Object("failed-encrypted-object", "Some data");
            object.setServerSideEncryptionAlgorithm("AES999");
            try {
                s3Service.putObject(bucketName, object);
                fail("Expected error about invalid server-side encryption algorithm");
            } catch (S3ServiceException e) {
                assertEquals("InvalidEncryptionAlgorithmError", e.getErrorCode());
            }

            // Create an encrypted object, set explicitly
            object = new S3Object("encrypted-object", "Some data");
            object.setServerSideEncryptionAlgorithm(S3Object.SERVER_SIDE_ENCRYPTION__AES256);
            s3Service.putObject(bucketName, object);
            // Confirm object is encrypted
            objDetails = s3Service.getObjectDetails(bucketName, object.getKey());
            assertEquals(S3Object.SERVER_SIDE_ENCRYPTION__AES256, objDetails.getMetadata("server-side-encryption"));
            assertEquals(S3Object.SERVER_SIDE_ENCRYPTION__AES256, objDetails.getServerSideEncryptionAlgorithm());

            // Create an encrypted object, per default algorithm set in service properties
            Jets3tProperties properties = new Jets3tProperties();
            properties.setProperty("s3service.server-side-encryption",
                S3Object.SERVER_SIDE_ENCRYPTION__AES256);
            s3Service = (S3Service) getStorageService(getCredentials(), properties);
            object = new S3Object("encrypted-object-as-default", "Some data");
            s3Service.putObject(bucketName, object);
            // Confirm object is encrypted
            objDetails = s3Service.getObjectDetails(bucketName, object.getKey());
            assertEquals(S3Object.SERVER_SIDE_ENCRYPTION__AES256, objDetails.getMetadata("server-side-encryption"));
            assertEquals(S3Object.SERVER_SIDE_ENCRYPTION__AES256, objDetails.getServerSideEncryptionAlgorithm());

        } finally {
            cleanupBucketForTest("testServerSideEncryption");
        }
    }

}

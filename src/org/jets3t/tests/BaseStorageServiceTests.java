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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.TimeZone;

import junit.framework.TestCase;

import org.jets3t.service.Constants;
import org.jets3t.service.S3ObjectsChunk;
import org.jets3t.service.S3Service;
import org.jets3t.service.S3ServiceException;
import org.jets3t.service.acl.AccessControlList;
import org.jets3t.service.acl.GroupGrantee;
import org.jets3t.service.acl.Permission;
import org.jets3t.service.impl.rest.httpclient.RestS3Service;
import org.jets3t.service.model.S3Bucket;
import org.jets3t.service.model.S3Object;
import org.jets3t.service.model.S3Owner;
import org.jets3t.service.security.ProviderCredentials;
import org.jets3t.service.utils.Mimetypes;
import org.jets3t.service.utils.RestUtils;
import org.jets3t.service.utils.ServiceUtils;

/**
 * Runs generic S3Service-related functional tests that any S3Service implementation should be
 * able to perform.
 * <p>
 * Any test case for S3Service implementations should extend this class as a starting point, then
 * add test cases specific to that particular implementation.
 *
 * @author James Murty
 */
public abstract class BaseStorageServiceTests extends TestCase {
    protected String TEST_PROPERTIES_FILENAME = "test.properties";
    protected Properties testProperties = null;

    public BaseStorageServiceTests() throws Exception {
        // Load test properties
        InputStream propertiesIS =
            ClassLoader.getSystemResourceAsStream(TEST_PROPERTIES_FILENAME);
        if (propertiesIS == null) {
            throw new Exception("Unable to load test properties file from classpath: "
                + TEST_PROPERTIES_FILENAME);
        }
        this.testProperties = new Properties();
        this.testProperties.load(propertiesIS);
    }

    protected abstract ProviderCredentials getCredentials() throws Exception;

    protected abstract S3Service getStorageService(ProviderCredentials credentials) throws Exception;

    /**
     * @param testName
     * @return unique per-account and per-test bucket name
     */
    protected String getBucketNameForTest(String testName) throws Exception {
        return
            "test-"
            + getCredentials().getAccessKey().toLowerCase()
            + "-"
            + testName.toLowerCase();
    }

    protected S3Bucket createBucketForTest(String testName) throws Exception {
        String bucketName = getBucketNameForTest(testName);
        return getStorageService(getCredentials()).createBucket(bucketName);
    }

    protected void cleanupBucketForTest(String testName, boolean deleteAllObjects) {
        try {
            S3Service service = getStorageService(getCredentials());
            String bucketName = getBucketNameForTest(testName);

            if (deleteAllObjects) {
                for (S3Object o: service.listObjects(bucketName)) {
                    service.deleteObject(bucketName, o.getKey());
                }
            }

            service.deleteBucket(bucketName);
        } catch (Exception e) {
            // This shouldn't happen, but if it does don't ruin the test
            e.printStackTrace();
        }
    }

    protected void cleanupBucketForTest(String testName) {
        this.cleanupBucketForTest(testName, false);
    }

    /////////////////////////////
    // Actual tests start here //
    /////////////////////////////

    public void testListBuckets() throws Exception {
        // List without credentials
        try {
            getStorageService(null).listAllBuckets();
            fail("Bucket listing should fail without authentication");
        } catch (S3ServiceException e) {
        }

        // List with credentials
        getStorageService(getCredentials()).listAllBuckets();

        // Ensure newly-created bucket is listed
        String bucketName = createBucketForTest("testListBuckets").getName();
        try {
            S3Bucket[] buckets = getStorageService(getCredentials()).listAllBuckets();
            boolean found = false;
            for (S3Bucket bucket: buckets) {
                found = (bucket.getName().equals(bucketName)) || found;
            }
            assertTrue("Newly-created bucket was not listed", found);
        } finally {
            cleanupBucketForTest("testListBuckets");
        }
    }

    public void testBucketManagement() throws Exception {
        S3Service s3Service = getStorageService(getCredentials());

        try {
            s3Service.createBucket(new S3Bucket());
            fail("Cannot create a bucket with name unset");
        } catch (S3ServiceException e) {
        }

        try {
            s3Service.createBucket("");
            fail("Cannot create a bucket with empty name");
        } catch (S3ServiceException e) {
        }

        try {
            s3Service.createBucket("test");
            fail("Cannot create a bucket with non-unique name");
        } catch (S3ServiceException e) {
        }

        String bucketName = createBucketForTest("testBucketManagement").getName();

        boolean bucketExists = s3Service.isBucketAccessible(bucketName);
        assertTrue("Bucket should exist", bucketExists);

        try {
            s3Service.deleteBucket((S3Bucket) null);
            fail("Cannot delete a bucket with null name");
        } catch (S3ServiceException e) {
        }

        try {
            s3Service.deleteBucket("");
            fail("Cannot delete a bucket with empty name");
        } catch (S3ServiceException e) {
        }

        try {
            s3Service.deleteBucket("test");
            fail("Cannot delete a bucket you don't own");
        } catch (S3ServiceException e) {
        }

        // Ensure we can delete our bucket
        s3Service.deleteBucket(bucketName);
    }

    public void testBucketStatusLookup() throws Exception {
        String bucketName = getBucketNameForTest("testBucketStatusLookup");
        S3Service s3Service = getStorageService(getCredentials());

        // Non-existent bucket
        int status = s3Service.checkBucketStatus(bucketName);
        assertEquals(S3Service.BUCKET_STATUS__DOES_NOT_EXIST, status);

        // Bucket is owned by someone else
        status = s3Service.checkBucketStatus("test");
        assertEquals(S3Service.BUCKET_STATUS__ALREADY_CLAIMED, status);

        try {
            s3Service.createBucket(bucketName);
            // Bucket now exists and is owned by me.
            status = s3Service.checkBucketStatus(bucketName);
            assertEquals(S3Service.BUCKET_STATUS__MY_BUCKET, status);
        } finally {
            // Clean up
            s3Service.deleteBucket(bucketName);
        }
    }

    public void testObjectManagement() throws Exception {
        String bucketName = createBucketForTest("testObjectManagement").getName();
        S3Service s3Service = getStorageService(getCredentials());

        try {
            S3Object object = new S3Object("TestObject");

            try {
                s3Service.putObject((S3Bucket) null, null);
                fail("Cannot create an object without a valid bucket");
            } catch (S3ServiceException e) {
            }

            try {
                s3Service.putObject((S3Bucket) null, object);
                fail("Cannot create an object without a valid bucket");
            } catch (S3ServiceException e) {
            }

            try {
                s3Service.putObject(bucketName, new S3Object());
                fail("Cannot create an object without a valid object");
            } catch (S3ServiceException e) {
            }

            // Create basic object with no content type (use the default) and no data.
            S3Object basicObject = s3Service.putObject(bucketName, object);

            // Note that we can't trust the content type from Google Storage until we
            // explicitly re-retrieve the object...
            // TODO: Is GS returning HTML upon PUT deliberate?
            assertTrue("Unexpected default content type",
                Mimetypes.MIMETYPE_OCTET_STREAM.equals(basicObject.getContentType()) // S3 is correct
                || Mimetypes.MIMETYPE_HTML.equals(basicObject.getContentType()) // GS is HTML unless re-retrieved
                );

            // Re-retrieve object to ensure it was correctly created.
            basicObject = s3Service.getObject(bucketName, object.getKey());
            assertEquals("Unexpected content type",
                Mimetypes.MIMETYPE_OCTET_STREAM, basicObject.getContentType());
            assertEquals("Unexpected size for 'empty' object", 0, basicObject.getContentLength());
            basicObject.closeDataInputStream();

            // Make sure bucket cannot be removed while it has contents.
            try {
                s3Service.deleteBucket(bucketName);
                fail("Should not be able to delete a bucket containing objects");
            } catch (S3ServiceException e) {
            }

            // Update/overwrite object to be a 'directory' object which has a
            // specific content type and no data.
            String contentType = Mimetypes.MIMETYPE_JETS3T_DIRECTORY;
            object.setContentType(contentType);
            S3Object directoryObject = s3Service.putObject(bucketName, object);
            // TODO: Remove separate fetch if Google Storage S3 compatibility improves
            directoryObject = s3Service.getObject(bucketName, object.getKey());
            assertEquals("Unexpected content type", contentType, directoryObject.getContentType());

            // Retrieve object to ensure it was correctly created.
            directoryObject = s3Service.getObject(bucketName, object.getKey());
            assertEquals("Unexpected default content type", contentType, directoryObject
                .getContentType());
            assertEquals("Unexpected size for 'empty' object", 0, directoryObject.getContentLength());
            basicObject.closeDataInputStream();

            // Update/overwrite object with real data content and some metadata.
            contentType = "text/plain";
            String objectData = "Just some rubbish text to include as data";
            String dataMd5HashAsHex = ServiceUtils.toHex(
                ServiceUtils.computeMD5Hash(objectData.getBytes()));
            HashMap<String, String> metadata = new HashMap<String, String>();
            metadata.put("creator", "testObjectManagement");
            metadata.put("purpose", "For testing purposes");
            object.replaceAllMetadata(metadata);
            object.setContentType(contentType);
            object.setDataInputStream(new ByteArrayInputStream(objectData.getBytes()));
            S3Object dataObject = s3Service.putObject(bucketName, object);
            // TODO: Remove separate fetch if Google Storage S3 compatibility improves
            dataObject = s3Service.getObject(bucketName, object.getKey());
            assertEquals("Unexpected content type", contentType, dataObject.getContentType());
            assertEquals("Mismatching MD5 hex hash", dataMd5HashAsHex, dataObject.getETag());

            // Retrieve data object to ensure it was correctly created, the server-side hash matches
            // what we expect, and we get our metadata back.
            dataObject = s3Service.getObject(bucketName, object.getKey());
            assertEquals("Unexpected default content type", "text/plain", dataObject.getContentType());
            // TODO: Google Storage doesn't return Content-Length in a GET?
            assertEquals("Unexpected content-length for object",
                objectData.length(), dataObject.getContentLength());
            assertEquals("Mismatching hash", dataMd5HashAsHex, dataObject.getETag());
            assertEquals("Missing creator metadata", "S3ServiceTest", dataObject.getMetadata(
                "creator"));
            assertEquals("Missing purpose metadata", "For testing purposes",
                dataObject.getMetadata("purpose"));
            assertNotNull("Expected data input stream to be available", dataObject.getDataInputStream());
            // Ensure we can get the data from S3.
            StringBuffer sb = new StringBuffer();
            int b = -1;
            while ((b = dataObject.getDataInputStream().read()) != -1) {
                sb.append((char) b);
            }
            dataObject.closeDataInputStream();
            assertEquals("Mismatching data", objectData, sb.toString());

            // Retrieve only HEAD of data object (all metadata is available, but not the object content
            // data input stream)
            dataObject = s3Service.getObjectDetails(bucketName, object.getKey());
            assertEquals("Unexpected default content type", "text/plain", dataObject.getContentType());
            assertEquals("Mismatching hash", dataMd5HashAsHex, dataObject.getETag());
            assertEquals("Missing creator metadata", "S3ServiceTest", dataObject.getMetadata(
                "creator"));
            assertEquals("Missing purpose metadata", "For testing purposes",
                dataObject.getMetadata("purpose"));
            assertNull("Expected data input stream to be unavailable", dataObject.getDataInputStream());
            assertEquals("Unexpected size for object", objectData.length(), dataObject.getContentLength());

            // Test object GET constraints.
            Calendar objectCreationTimeCal = Calendar.getInstance(TimeZone.getTimeZone("GMT"), Locale.US);
            objectCreationTimeCal.setTime(dataObject.getLastModifiedDate());

            Calendar yesterday = (Calendar) objectCreationTimeCal.clone();
            yesterday.add(Calendar.DAY_OF_YEAR, -1);
            Calendar tomorrow = (Calendar) objectCreationTimeCal.clone();
            tomorrow.add(Calendar.DAY_OF_YEAR, +2);

            // Precondition: Modified since yesterday
            s3Service.getObjectDetails(bucketName, object.getKey(), yesterday, null, null, null);
            // Precondition: Mot modified since after creation date.
            try {
                s3Service.getObjectDetails(bucketName, object.getKey(), objectCreationTimeCal, null, null, null);
                fail("Cannot have been modified since object was created");
            } catch (S3ServiceException e) { }
            // Precondition: Not modified since yesterday
            try {
                s3Service.getObjectDetails(bucketName, object.getKey(), null, yesterday, null, null);
                fail("Cannot be unmodified since yesterday");
            } catch (S3ServiceException e) { }
            // Precondition: Not modified since tomorrow
            s3Service.getObjectDetails(bucketName, object.getKey(), null, tomorrow, null, null);
            // Precondition: matches correct hash
            s3Service.getObjectDetails(bucketName, object.getKey(), null, null, new String[] {dataMd5HashAsHex}, null);
            // Precondition: doesn't match incorrect hash
            try {
                s3Service.getObjectDetails(bucketName, object.getKey(), null, null,
                    new String[] {"__" + dataMd5HashAsHex.substring(2)}, null);
                fail("Hash values should not match");
            } catch (S3ServiceException e) {
            }
            // Precondition: doesn't match correct hash
            try {
                s3Service.getObjectDetails(bucketName, object.getKey(), null, null, null, new String[] {dataMd5HashAsHex});
                fail("Hash values should mis-match");
            } catch (S3ServiceException e) {
            }
            // Precondition: doesn't match incorrect hash
            s3Service.getObjectDetails(bucketName, object.getKey(), null, null, null,
                new String[] {"__" + dataMd5HashAsHex.substring(2)});

            // Retrieve only a limited byte-range of the data, with a start and end.
            Long byteRangeStart = new Long(3);
            Long byteRangeEnd = new Long(12);
            dataObject = s3Service.getObject(bucketName, object.getKey(), null, null, null, null, byteRangeStart, byteRangeEnd);
            String dataReceived = ServiceUtils.readInputStreamToString(
                dataObject.getDataInputStream(), Constants.DEFAULT_ENCODING);
            String dataExpected = objectData.substring(byteRangeStart.intValue(), byteRangeEnd.intValue() + 1);
            assertEquals("Mismatching data from range precondition", dataExpected, dataReceived);

            // Retrieve only a limited byte-range of the data, with a start range only.
            byteRangeStart = new Long(7);
            byteRangeEnd = null;
            dataObject = s3Service.getObject(bucketName, object.getKey(), null, null, null, null, byteRangeStart, byteRangeEnd);
            dataReceived = ServiceUtils.readInputStreamToString(
                dataObject.getDataInputStream(), Constants.DEFAULT_ENCODING);
            dataExpected = objectData.substring(byteRangeStart.intValue());
            assertEquals("Mismatching data from range precondition", dataExpected, dataReceived);

            // Retrieve only a limited byte-range of the data, with an end range only.
            byteRangeStart = null;
            byteRangeEnd = new Long(13);
            dataObject = s3Service.getObject(bucketName, object.getKey(), null, null, null, null, byteRangeStart, byteRangeEnd);
            dataReceived = ServiceUtils.readInputStreamToString(
                dataObject.getDataInputStream(), Constants.DEFAULT_ENCODING);
            dataExpected = objectData.substring(objectData.length() - byteRangeEnd.intValue());
            assertEquals("Mismatching data from range precondition", dataExpected, dataReceived);

            // Clean-up.
            s3Service.deleteObject(bucketName, object.getKey());

            // Create object with tricky key.
            String trickyKey = "http://example.site.com/some/path/document name.html?param1=a@b#c$d&param2=(089)";
            S3Object trickyObject = s3Service.putObject(bucketName,
                new S3Object(trickyKey, "Some test data"));
            assertEquals("Tricky key name mistmatch", trickyKey, trickyObject.getKey());

            // Make sure the tricky named object really exists with its full name.
            S3Object[] objects = s3Service.listObjects(bucketName);
            boolean trickyNamedObjectExists = false;
            for (int i = 0; !trickyNamedObjectExists && i < objects.length; i++) {
                if (trickyKey.equals(objects[i].getKey())) {
                    trickyNamedObjectExists = true;
                }
            }
            assertTrue("Tricky key name object does not exist with its full name", trickyNamedObjectExists);

            // Delete object with tricky key.
            s3Service.deleteObject(bucketName, trickyObject.getKey());

        } finally {
            cleanupBucketForTest("testObjectManagement", true);
        }
    }

    public void testACLManagement() throws Exception {
        String s3Url = "https://s3.amazonaws.com";

        // Access public-readable third-party bucket: jets3t
        S3Service anonymousS3Service = getStorageService(null);
        boolean jets3tBucketAvailable = anonymousS3Service.isBucketAccessible("jets3t");
        assertTrue("Cannot find public jets3t bucket", jets3tBucketAvailable);

        S3Service s3Service = getStorageService(getCredentials());

        String bucketName = createBucketForTest("testACLManagement").getName();
        S3Bucket bucket = new S3Bucket(bucketName);
        S3Object object = null;

        try {
            // Create private object (default permissions).
            String privateKey = "Private Object #1";
            object = new S3Object(bucket, privateKey, "Private object sample text");
            s3Service.putObject(bucket, object);
            URL url = new URL(s3Url + "/" + bucketName + "/" + RestUtils.encodeUrlString(privateKey));
            assertEquals("Expected denied access (403) error", 403, ((HttpURLConnection) url
                .openConnection()).getResponseCode());

            // Get ACL details for private object so we can determine the bucket owner.
            AccessControlList bucketACL = s3Service.getBucketAcl(bucket);
            S3Owner bucketOwner = bucketACL.getOwner();

            // Create a public object.
            String publicKey = "Public Object #1";
            object = new S3Object(bucket, publicKey, "Public object sample text");
            AccessControlList acl = new AccessControlList();
            acl.setOwner(bucketOwner);
            acl.grantPermission(GroupGrantee.ALL_USERS, Permission.PERMISSION_READ);
            object.setAcl(acl);
            s3Service.putObject(bucket, object);
            url = new URL(s3Url + "/" + bucketName + "/" + RestUtils.encodeUrlString(publicKey));
            assertEquals("Expected access (200)",
                    200, ((HttpURLConnection)url.openConnection()).getResponseCode());

            // Update ACL to make private object public.
            AccessControlList privateToPublicACL = s3Service.getObjectAcl(bucket, privateKey);
            privateToPublicACL.grantPermission(GroupGrantee.ALL_USERS, Permission.PERMISSION_READ);
            object.setKey(privateKey);
            object.setAcl(privateToPublicACL);
            s3Service.putObjectAcl(bucket, object);
            url = new URL(s3Url + "/" + bucketName + "/" + RestUtils.encodeUrlString(privateKey));
            assertEquals("Expected access (200)", 200, ((HttpURLConnection) url.openConnection())
                .getResponseCode());

            // Create a non-standard uncanned public object.
            String publicKey2 = "Public Object #2";
            object = new S3Object(publicKey2);
            object.setAcl(privateToPublicACL); // This ACL has ALL_USERS READ permission set above.
            s3Service.putObject(bucket, object);
            url = new URL(s3Url + "/" + bucketName + "/" + RestUtils.encodeUrlString(publicKey2));
            assertEquals("Expected access (200)", 200, ((HttpURLConnection) url.openConnection())
                .getResponseCode());

            // Update ACL to make public object private.
            AccessControlList publicToPrivateACL = s3Service.getObjectAcl(bucket, publicKey);
            publicToPrivateACL.revokeAllPermissions(GroupGrantee.ALL_USERS);
            object.setKey(publicKey);
            object.setAcl(publicToPrivateACL);
            s3Service.putObjectAcl(bucket, object);
            url = new URL(s3Url + "/" + bucketName + "/" + RestUtils.encodeUrlString(publicKey));
            assertEquals("Expected denied access (403) error", 403, ((HttpURLConnection) url
                .openConnection()).getResponseCode());

            // Clean-up.
            s3Service.deleteObject(bucket, privateKey);
            s3Service.deleteObject(bucket, publicKey);
            s3Service.deleteObject(bucket, publicKey2);
        } finally {
            cleanupBucketForTest("testACLManagement");
        }
    }

    public void testS3RestCannedACL() throws Exception {
        S3Service s3Service = getStorageService(getCredentials());
        S3Bucket bucket = createBucketForTest("testRestCannedACL");

        try {
            // Try to create REST canned public object.
            String publicKey = "PublicObject";
            S3Object object = new S3Object(publicKey);
            object.setAcl(AccessControlList.REST_CANNED_PUBLIC_READ);
            object.setOwner(bucket.getOwner());

            try {
                s3Service.putObject(bucket, object);
                URL url = new URL("https://" + s3Service.getEndpoint()
                    + "/" + bucket.getName() + "/" + publicKey);
                assertEquals("Expected public access (200)",
                        200, ((HttpURLConnection)url.openConnection()).getResponseCode());
            } finally {
                s3Service.deleteObject(bucket, object.getKey());
            }
        } finally {
            cleanupBucketForTest("testRestCannedACL");
        }
    }

    public void testObjectListing() throws Exception {
        S3Service s3Service = getStorageService(getCredentials());
        S3Bucket bucket = createBucketForTest("testObjectListing");

        try {
            // Represent a directory structure in S3.
            List<S3Object> objectsList = new ArrayList<S3Object>();
            objectsList.add(new S3Object(bucket, "dir1"));
            objectsList.add(new S3Object(bucket, "dir1/doc1Level1"));
            objectsList.add(new S3Object(bucket, "dir1/doc2level1"));
            objectsList.add(new S3Object(bucket, "dir1/dir1Level1"));
            objectsList.add(new S3Object(bucket, "dir1/dir1Level1/doc1Level2"));
            objectsList.add(new S3Object(bucket, "dir1/dir1Level1/dir1Level2"));
            objectsList.add(new S3Object(bucket, "dir1/dir1Level1/dir1Level2/doc1Level3"));

            // Create objects
            for (S3Object object: objectsList) {
                s3Service.putObject(bucket, object);
            }

            S3Object[] objects = null;

            // List all items in directory.
            objects = s3Service.listObjects(bucket);
            assertEquals("Incorrect number of objects in directory structure",
                objectsList.size(), objects.length);

            // List items in chunks of size 2, ensure we get a total of seven.
            int chunkedObjectsCount = 0;
            int chunkedIterationsCount = 0;
            String priorLastKey = null;
            do {
                S3ObjectsChunk chunk = s3Service.listObjectsChunked(
                    bucket.getName(), null, null, 2, priorLastKey);
                priorLastKey = chunk.getPriorLastKey();
                chunkedObjectsCount += chunk.getObjects().length;
                chunkedIterationsCount++;
            } while (priorLastKey != null);
            assertEquals("Chunked bucket listing retreived incorrect number of objects",
                objectsList.size(), chunkedObjectsCount);
            assertEquals("Chunked bucket listing ran for an unexpected number of iterations",
                (objectsList.size() + 1) / 2, chunkedIterationsCount);

            // List objects with a prefix and delimiter to check common prefixes.
            S3ObjectsChunk chunk = s3Service.listObjectsChunked(
                bucket.getName(), "dir1/", "/", 100, null);
            assertEquals("Chunked bucket listing with prefix and delimiter retreived incorrect number of objects",
                3, chunk.getObjects().length);
            assertEquals("Chunked bucket listing with prefix and delimiter retreived incorrect number of common prefixes",
                1, chunk.getCommonPrefixes().length);

            // List the same items with a prefix.
            objects = s3Service.listObjects(bucket, "dir1", null);
            assertEquals("Incorrect number of objects matching prefix", 7, objects.length);

            // List items up one directory with a prefix (will include dir1Level1)
            objects = s3Service.listObjects(bucket, "dir1/dir1Level1", null);
            assertEquals("Incorrect number of objects matching prefix", 4, objects.length);

            // List items up one directory with a prefix (will not include dir1Level1)
            objects = s3Service.listObjects(bucket, "dir1/dir1Level1/", null);
            assertEquals("Incorrect number of objects matching prefix", 3, objects.length);

            // Try a prefix matching no object keys.
            objects = s3Service.listObjects(bucket, "dir1-NonExistent", null);
            assertEquals("Expected no results", 0, objects.length);

            // Use delimiter with an partial prefix.
            objects = s3Service.listObjects(bucket, "dir", "/");
            assertEquals("Expected no results", 1, objects.length);

            // Use delimiter to find item dir1 only.
            objects = s3Service.listObjects(bucket, "dir1", "/");
            assertEquals("Incorrect number of objects matching prefix and delimiter", 1, objects.length);

            // Use delimiter to find items within dir1 only.
            objects = s3Service.listObjects(bucket, "dir1/", "/");
            assertEquals("Incorrect number of objects matching prefix and delimiter", 3, objects.length);

            // List items up one directory with prefix and delimiter (will include only dir1Level1)
            objects = s3Service.listObjects(bucket, "dir1/dir1Level1", "/");
            assertEquals("Incorrect number of objects matching prefix", 1, objects.length);

            // List items up one directory with prefix and delimiter (will include only contents of dir1Level1)
            objects = s3Service.listObjects(bucket, "dir1/dir1Level1/", "/");
            assertEquals("Incorrect number of objects matching prefix", 2, objects.length);

            // Clean up.
            for (S3Object object: objectsList) {
                s3Service.deleteObject(bucket, object.getKey());
            }
        } finally {
            cleanupBucketForTest("testObjectListing");
        }
    }

    public void testUrlSigning() throws Exception {
        S3Service s3Service = getStorageService(getCredentials());
        S3Bucket bucket = createBucketForTest("testUrlSigning");

        try {
            // Create test object, with private ACL
            String dataString = "Text for the URL Signing test object...";
            S3Object object = new S3Object(bucket, "Testing URL Signing", dataString);
            object.setContentType("text/html");
            object.addMetadata(s3Service.getRestMetadataPrefix() + "example-header", "example-value");
            object.setAcl(AccessControlList.REST_CANNED_PRIVATE);

            // Determine what the time will be in 5 minutes.
            Calendar cal = Calendar.getInstance();
            cal.add(Calendar.MINUTE, 5);
            Date expiryDate = cal.getTime();

            // Create a signed HTTP PUT URL.
            String signedPutUrl = s3Service.createSignedPutUrl(bucket.getName(), object.getKey(),
                object.getMetadataMap(), expiryDate, false);

            // Put the object in S3 using the signed URL (no AWS credentials required)
            RestS3Service restS3Service = new RestS3Service(null);
            restS3Service.putObjectWithSignedUrl(signedPutUrl, object);

            // Ensure the object was created.
            S3Object objects[] = s3Service.listObjects(bucket, object.getKey(), null);
            assertEquals("Signed PUT URL failed to put/create object", objects.length, 1);

            // Change the object's content-type and ensure the signed PUT URL disallows the put.
            object.setContentType("application/octet-stream");
            try {
                restS3Service.putObjectWithSignedUrl(signedPutUrl, object);
                fail("Should not be able to use a signed URL for an object with a changed content-type");
            } catch (S3ServiceException e) {
                object.setContentType("text/html");
            }

            // Add an object header and ensure the signed PUT URL disallows the put.
            object.addMetadata(s3Service.getRestMetadataPrefix() + "example-header-2", "example-value");
            try {
                restS3Service.putObjectWithSignedUrl(signedPutUrl, object);
                fail("Should not be able to use a signed URL for an object with changed metadata");
            } catch (S3ServiceException e) {
                object.removeMetadata(s3Service.getRestMetadataPrefix() + "example-header-2");
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
            String objectWithoutETagSignedPutURL = s3Service.createSignedPutUrl(
                bucket.getName(), objectWithoutETag.getKey(), objectWithoutETag.getMetadataMap(),
                expiryDate, false);
            objectWithoutETag.setDataInputStream(new ByteArrayInputStream(dataString.getBytes()));
            objectWithoutETag.setContentLength(dataString.getBytes().length);
            restS3Service.putObjectWithSignedUrl(objectWithoutETagSignedPutURL, objectWithoutETag);
            s3Service.deleteObject(bucket, objectWithoutETag.getKey());

            // Ensure we can't get the object with a normal URL.
            String s3Url = "https://s3.amazonaws.com";
            URL url = new URL(s3Url + "/" + bucket.getName() + "/" + RestUtils.encodeUrlString(object.getKey()));
            assertEquals("Expected denied access (403) error", 403, ((HttpURLConnection) url
                .openConnection()).getResponseCode());

            // Create a signed HTTP GET URL.
            String signedGetUrl = s3Service.createSignedGetUrl(bucket.getName(), object.getKey(),
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

            // Clean up.
            s3Service.deleteObject(bucket, object.getKey());
        } finally {
            cleanupBucketForTest("testUrlSigning");
        }
    }

    public void testHashVerifiedUploads() throws Exception {
        S3Service s3Service = getStorageService(getCredentials());
        S3Bucket bucket = createBucketForTest("testHashVerifiedUploads");

        try {
            // Create test object with an MD5 hash of the data.
            String dataString = "Text for MD5 hashing...";
            S3Object object = new S3Object(bucket, "Testing MD5 Hashing", dataString);
            object.setContentType("text/plain");

            // Calculate hash data for object.
            byte[] md5Hash = ServiceUtils.computeMD5Hash(dataString.getBytes());

            // Ensure that using an invalid hash value fails.
            try {
                object.addMetadata("Content-MD5", "123");
                s3Service.putObject(bucket, object);
                fail("Should have failed due to invalid hash value");
            } catch (S3ServiceException e) {
                assertTrue("Expected error code indicating invalid md5 hash",
                    "InvalidDigest".equals(e.getS3ErrorCode())  // S3 error code
                    || "BadDigest".equals(e.getS3ErrorCode())   // GS error code
                    );
            }
            object = new S3Object(bucket, "Testing MD5 Hashing", dataString);

            // Ensure that using the wrong hash value fails.
            try {
                byte[] incorrectHash = new byte[md5Hash.length];
                System.arraycopy(md5Hash, 0, incorrectHash, 0, incorrectHash.length);
                incorrectHash[0] = incorrectHash[1];
                object.setMd5Hash(incorrectHash);
                s3Service.putObject(bucket, object);
                fail("Should have failed due to incorrect hash value");
            } catch (S3ServiceException e) {
                assertEquals("Expected error code indicating invalid md5 hash", "BadDigest", e.getS3ErrorCode());
            }
            object = new S3Object(bucket, "Testing MD5 Hashing", dataString);

            // Ensure that correct hash value succeeds.
            object.setMd5Hash(md5Hash);
            S3Object resultObject = s3Service.putObject(bucket, object);

            // Ensure the ETag result matches the hex-encoded MD5 hash.
            assertEquals("Hex-encoded MD5 hash should match ETag", resultObject.getETag(),
                ServiceUtils.toHex(md5Hash));

            // Ensure we can convert the hex-encoded ETag to Base64 that matches the Base64 md5 hash.
            String md5HashBase64 = ServiceUtils.toBase64(md5Hash);
            String eTagBase64 = ServiceUtils.toBase64(ServiceUtils.fromHex(resultObject.getETag()));
            assertEquals("Could not convert ETag and MD5 hash to matching Base64-encoded strings",
                md5HashBase64, eTagBase64);

            // Clean up.
            s3Service.deleteObject(bucket, object.getKey());
        } finally {
            cleanupBucketForTest("testHashVerifiedUploads");
        }
    }

}

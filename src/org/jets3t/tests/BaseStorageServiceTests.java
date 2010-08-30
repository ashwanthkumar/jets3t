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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Calendar;
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
import org.jets3t.service.impl.rest.httpclient.RestStorageService;
import org.jets3t.service.model.S3Owner;
import org.jets3t.service.model.StorageBucket;
import org.jets3t.service.model.StorageObject;
import org.jets3t.service.security.ProviderCredentials;
import org.jets3t.service.utils.Mimetypes;
import org.jets3t.service.utils.RestUtils;
import org.jets3t.service.utils.ServiceUtils;

/**
 * Runs generic functional tests that any storage service implementation should be
 * able to perform.
 * <p>
 * Any test cases for specific StorageService implementations should extend this class as a
 * starting point, then add test cases specific to that particular implementation.
 *
 * @author James Murty
 */
public abstract class BaseStorageServiceTests extends TestCase {
    public static final String TARGET_SERVICE_S3 = "AmazonS3";
    public static final String TARGET_SERVICE_GS = "GoogleStorage";

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

    protected abstract RestStorageService getStorageService(ProviderCredentials credentials) throws Exception;

    protected abstract String getTargetService();

    protected abstract StorageObject buildStorageObject(String name, String data) throws Exception;

    protected abstract StorageObject buildStorageObject(String name) throws Exception;

    protected StorageObject buildStorageObject() throws Exception {
        return buildStorageObject(null);
    }

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

    protected StorageBucket createBucketForTest(String testName) throws Exception {
        String bucketName = getBucketNameForTest(testName);
        return getStorageService(getCredentials()).createBucket(bucketName);
    }

    protected void cleanupBucketForTest(String testName, boolean deleteAllObjects) {
        try {
            RestStorageService service = getStorageService(getCredentials());
            String bucketName = getBucketNameForTest(testName);

            if (deleteAllObjects) {
                for (StorageObject o: service.listObjects(bucketName)) {
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
            StorageBucket[] buckets = getStorageService(getCredentials()).listAllBuckets();
            boolean found = false;
            for (StorageBucket bucket: buckets) {
                found = (bucket.getName().equals(bucketName)) || found;
            }
            assertTrue("Newly-created bucket was not listed", found);
        } finally {
            cleanupBucketForTest("testListBuckets");
        }
    }

    public void testBucketManagement() throws Exception {
        RestStorageService service = getStorageService(getCredentials());

        try {
            service.createBucket("");
            fail("Cannot create a bucket with empty name");
        } catch (S3ServiceException e) {
        }

        try {
            service.createBucket("test");
            fail("Cannot create a bucket with non-unique name");
        } catch (S3ServiceException e) {
        }

        String bucketName = createBucketForTest("testBucketManagement").getName();

        boolean bucketExists = service.isBucketAccessible(bucketName);
        assertTrue("Bucket should exist", bucketExists);

        try {
            service.deleteBucket((String) null);
            fail("Cannot delete a bucket with null name");
        } catch (S3ServiceException e) {
        }

        try {
            service.deleteBucket("");
            fail("Cannot delete a bucket with empty name");
        } catch (S3ServiceException e) {
        }

        try {
            service.deleteBucket("test");
            fail("Cannot delete a bucket you don't own");
        } catch (S3ServiceException e) {
        }

        // Ensure we can delete our bucket
        service.deleteBucket(bucketName);
    }

    public void testBucketStatusLookup() throws Exception {
        String bucketName = getBucketNameForTest("testBucketStatusLookup");
        RestStorageService service = getStorageService(getCredentials());

        // Non-existent bucket
        int status = service.checkBucketStatus(bucketName);
        assertEquals(S3Service.BUCKET_STATUS__DOES_NOT_EXIST, status);

        // Bucket is owned by someone else
        status = service.checkBucketStatus("test");
        assertEquals(S3Service.BUCKET_STATUS__ALREADY_CLAIMED, status);

        try {
            service.createBucket(bucketName);
            // Bucket now exists and is owned by me.
            status = service.checkBucketStatus(bucketName);
            assertEquals(S3Service.BUCKET_STATUS__MY_BUCKET, status);
        } finally {
            // Clean up
            service.deleteBucket(bucketName);
        }
    }

    public void testObjectManagement() throws Exception {
        String bucketName = createBucketForTest("testObjectManagement").getName();
        RestStorageService service = getStorageService(getCredentials());

        try {
            StorageObject object = buildStorageObject("TestObject");

            try {
                service.putObject((String) null, null);
                fail("Cannot create an object without a valid bucket");
            } catch (S3ServiceException e) {
            }

            try {
                service.putObject((String) null, object);
                fail("Cannot create an object without a valid bucket");
            } catch (S3ServiceException e) {
            }

            try {
                service.putObject(bucketName, buildStorageObject());
                fail("Cannot create an object without a valid object");
            } catch (S3ServiceException e) {
            }

            // Create basic object with no content type (use the default) and no data.
            StorageObject basicObject = service.putObject(bucketName, object);

            // Ensure Content-Type is set to binary by default
            // TODO: Google Storage bug: Content type returned on initial PUT is always "text/html"
            if (!TARGET_SERVICE_GS.equals(getTargetService())) {
                assertTrue("Unexpected default content type",
                    Mimetypes.MIMETYPE_OCTET_STREAM.equals(basicObject.getContentType()));
            }

            // Re-retrieve object to ensure it was correctly created.
            basicObject = service.getObject(bucketName, object.getKey());
            assertEquals("Unexpected content type",
                Mimetypes.MIMETYPE_OCTET_STREAM, basicObject.getContentType());
            assertEquals("Unexpected size for 'empty' object", 0, basicObject.getContentLength());
            basicObject.closeDataInputStream();

            // Make sure bucket cannot be removed while it has contents.
            try {
                service.deleteBucket(bucketName);
                fail("Should not be able to delete a bucket containing objects");
            } catch (S3ServiceException e) {
            }

            // Update/overwrite object with real data content and some metadata.
            String contentType = "text/plain";
            String objectData = "Just some rubbish text to include as data";
            String dataMd5HashAsHex = ServiceUtils.toHex(
                ServiceUtils.computeMD5Hash(objectData.getBytes()));
            HashMap<String, Object> metadata = new HashMap<String, Object>();
            metadata.put("creator", "testObjectManagement");
            metadata.put("purpose", "For testing purposes");
            object.replaceAllMetadata(metadata);
            object.setContentType(contentType);
            object.setDataInputStream(new ByteArrayInputStream(objectData.getBytes()));
            StorageObject dataObject = service.putObject(bucketName, object);
            // TODO: Google Storage bug: Content type returned on initial PUT is always "text/html"
            if (TARGET_SERVICE_GS.equals(getTargetService())) {
                dataObject = service.getObject(bucketName, object.getKey());
            }
            assertEquals("Unexpected content type", contentType, dataObject.getContentType());
            assertEquals("Mismatching MD5 hex hash", dataMd5HashAsHex, dataObject.getETag());

            // Retrieve data object to ensure it was correctly created, the server-side hash matches
            // what we expect, and we get our metadata back.
            dataObject = service.getObject(bucketName, object.getKey());
            assertEquals("Unexpected default content type", "text/plain", dataObject.getContentType());
            // TODO: Google Storage doesn't return Content-Length in a GET!
            if (!TARGET_SERVICE_GS.equals(getTargetService())) {
                assertEquals("Unexpected content-length for object",
                    objectData.length(), dataObject.getContentLength());
            }
            assertEquals("Mismatching hash", dataMd5HashAsHex, dataObject.getETag());
            assertEquals("Missing creator metadata", "testObjectManagement",
                dataObject.getMetadata("creator"));
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
            dataObject = service.getObjectDetails(bucketName, object.getKey());
            assertEquals("Unexpected default content type", "text/plain", dataObject.getContentType());
            assertEquals("Mismatching hash", dataMd5HashAsHex, dataObject.getETag());
            assertEquals("Missing creator metadata", "testObjectManagement",
                dataObject.getMetadata("creator"));
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
            service.getObjectDetails(bucketName, object.getKey(), yesterday, null, null, null);
            // Precondition: Mot modified since after creation date.
            try {
                service.getObjectDetails(bucketName, object.getKey(), objectCreationTimeCal, null, null, null);
                fail("Cannot have been modified since object was created");
            } catch (S3ServiceException e) { }
            // Precondition: Not modified since yesterday
            try {
                service.getObjectDetails(bucketName, object.getKey(), null, yesterday, null, null);
                fail("Cannot be unmodified since yesterday");
            } catch (S3ServiceException e) { }
            // Precondition: Not modified since tomorrow
            service.getObjectDetails(bucketName, object.getKey(), null, tomorrow, null, null);
            // Precondition: matches correct hash
            service.getObjectDetails(bucketName, object.getKey(), null, null, new String[] {dataMd5HashAsHex}, null);
            // Precondition: doesn't match incorrect hash
            try {
                service.getObjectDetails(bucketName, object.getKey(), null, null,
                    new String[] {"__" + dataMd5HashAsHex.substring(2)}, null);
                fail("Hash values should not match");
            } catch (S3ServiceException e) {
            }
            // Precondition: doesn't match correct hash
            try {
                service.getObjectDetails(bucketName, object.getKey(), null, null, null, new String[] {dataMd5HashAsHex});
                fail("Hash values should mis-match");
            } catch (S3ServiceException e) {
            }
            // Precondition: doesn't match incorrect hash
            service.getObjectDetails(bucketName, object.getKey(), null, null, null,
                new String[] {"__" + dataMd5HashAsHex.substring(2)});

            // Retrieve only a limited byte-range of the data, with a start and end.
            Long byteRangeStart = new Long(3);
            Long byteRangeEnd = new Long(12);
            dataObject = service.getObject(bucketName, object.getKey(), null, null, null, null, byteRangeStart, byteRangeEnd);
            String dataReceived = ServiceUtils.readInputStreamToString(
                dataObject.getDataInputStream(), Constants.DEFAULT_ENCODING);
            String dataExpected = objectData.substring(byteRangeStart.intValue(), byteRangeEnd.intValue() + 1);
            assertEquals("Mismatching data from range precondition", dataExpected, dataReceived);

            // Retrieve only a limited byte-range of the data, with a start range only.
            byteRangeStart = new Long(7);
            byteRangeEnd = null;
            dataObject = service.getObject(bucketName, object.getKey(), null, null, null, null, byteRangeStart, byteRangeEnd);
            dataReceived = ServiceUtils.readInputStreamToString(
                dataObject.getDataInputStream(), Constants.DEFAULT_ENCODING);
            dataExpected = objectData.substring(byteRangeStart.intValue());
            assertEquals("Mismatching data from range precondition", dataExpected, dataReceived);

            // Retrieve only a limited byte-range of the data, with an end range only.
            byteRangeStart = null;
            byteRangeEnd = new Long(13);
            dataObject = service.getObject(bucketName, object.getKey(), null, null, null, null, byteRangeStart, byteRangeEnd);
            dataReceived = ServiceUtils.readInputStreamToString(
                dataObject.getDataInputStream(), Constants.DEFAULT_ENCODING);
            dataExpected = objectData.substring(objectData.length() - byteRangeEnd.intValue());
            assertEquals("Mismatching data from range precondition", dataExpected, dataReceived);

            // Clean-up.
            service.deleteObject(bucketName, object.getKey());

            // Create object with tricky key.
            String trickyKey = "http://example.site.com/some/path/document name.html?param1=a@b#c$d&param2=(089)";
            StorageObject trickyObject = service.putObject(bucketName,
                buildStorageObject(trickyKey, "Some test data"));
            assertEquals("Tricky key name mistmatch", trickyKey, trickyObject.getKey());

            // Make sure the tricky named object really exists with its full name.
            StorageObject[] objects = service.listObjects(bucketName);
            boolean trickyNamedObjectExists = false;
            for (int i = 0; !trickyNamedObjectExists && i < objects.length; i++) {
                if (trickyKey.equals(objects[i].getKey())) {
                    trickyNamedObjectExists = true;
                }
            }
            assertTrue("Tricky key name object does not exist with its full name", trickyNamedObjectExists);

            // Delete object with tricky key.
            service.deleteObject(bucketName, trickyObject.getKey());

        } finally {
            cleanupBucketForTest("testObjectManagement", true);
        }
    }

    public void testDirectoryPlaceholderObjects() throws Exception {
        String bucketName = createBucketForTest("testDirectoryPlaceholderObjects").getName();
        RestStorageService service = getStorageService(getCredentials());

        try {
            // Create new-style place-holder object (compatible with Amazon's AWS Console
            // and Panic's Transmit) -- note trailing slash
            StorageObject requestObject = buildStorageObject("DirPlaceholderObject/");
            requestObject.setContentLength(0);
            requestObject.setContentType(Mimetypes.MIMETYPE_BINARY_OCTET_STREAM);
            service.putObject(bucketName, requestObject);
            StorageObject resultObject = service.getObjectDetails(bucketName, requestObject.getKey());
            assertTrue(resultObject.isDirectoryPlaceholder());

            // Create legacy-style place-holder object (compatible with objects stored using
            // JetS3t applications prior to version 0.8.0) -- note content type
            requestObject = buildStorageObject("LegacyDirPlaceholderObject");
            requestObject.setContentLength(0);
            requestObject.setContentType(Mimetypes.MIMETYPE_JETS3T_DIRECTORY);
            service.putObject(bucketName, requestObject);
            resultObject = service.getObjectDetails(bucketName, requestObject.getKey());
            assertTrue(resultObject.isDirectoryPlaceholder());

            // Create place-holder object compatible with the S3 Organizer Firefox extension
            // -- note object name suffix.
            requestObject = buildStorageObject("S3OrganizerDirPlaceholderObject_$folder$");
            requestObject.setContentLength(0);
            service.putObject(bucketName, requestObject);
            resultObject = service.getObjectDetails(bucketName, requestObject.getKey());
            assertTrue(resultObject.isDirectoryPlaceholder());
        } finally {
            cleanupBucketForTest("testDirectoryPlaceholderObjects", true);
        }
    }

    public void testUnicodeData() throws Exception {
        String bucketName = createBucketForTest("testUnicodeData").getName();
        RestStorageService service = getStorageService(getCredentials());

        try {
            // Unicode object name
            String unicodeText = "テストオブジェクト";
            StorageObject requestObject = buildStorageObject("1." + unicodeText);
            service.putObject(bucketName, requestObject);
            StorageObject resultObject = service.getObjectDetails(bucketName, requestObject.getKey());
            assertEquals("1." + unicodeText, resultObject.getKey());

            // Unicode data content
            requestObject = buildStorageObject("2." + unicodeText, unicodeText);
            service.putObject(bucketName, requestObject);
            resultObject = service.getObject(bucketName, requestObject.getKey());
            String data = ServiceUtils.readInputStreamToString(
                resultObject.getDataInputStream(), "UTF-8");
            assertEquals(unicodeText, data);

            // Unicode metadata values are not supported
            requestObject = buildStorageObject("3." + unicodeText);
            requestObject.addMetadata("testing", unicodeText);
            try {
                service.putObject(bucketName, requestObject);
            } catch (S3ServiceException e) {
            }

            // Unicode metadata values can be encoded
            requestObject = buildStorageObject("4." + unicodeText);
            requestObject.addMetadata("testing", URLEncoder.encode(unicodeText, "UTF-8"));
            service.putObject(bucketName, requestObject);
            resultObject = service.getObjectDetails(bucketName, requestObject.getKey());
            assertEquals(unicodeText, URLDecoder.decode(
                (String) resultObject.getMetadata("testing"), "UTF-8"));

            // Unicode metadata names are not possible with HTTP
            requestObject = buildStorageObject("5." + unicodeText);
            requestObject.addMetadata(unicodeText, "value");
            try {
                service.putObject(bucketName, requestObject);
                fail("Illegal to use non-ASCII characters in HTTP headers");
            } catch (S3ServiceException e) {
            }

            // Unicode HTTP headers (via RFC 5987 encoding) -- not working...
            /*
            requestObject = buildStorageObject("6." + unicodeText);
            requestObject.setContentDisposition(
                "attachment; filename*=UTF-8''" + RestUtils.encodeUrlString(unicodeText + ".txt"));
            service.putObject(bucketName, requestObject);
            resultObject = service.getObjectDetails(bucketName, requestObject.getKey());
            assertEquals(
                "attachment; filename=" + unicodeText + "", resultObject.getContentDisposition());
            */
        } finally {
            cleanupBucketForTest("testUnicodeData", true);
        }
    }

    public void testACLManagement() throws Exception {
        String s3Url = "https://s3.amazonaws.com";

        // Access public-readable third-party bucket: jets3t
        RestStorageService anonymousS3Service = getStorageService(null);
        boolean jets3tBucketAvailable = anonymousS3Service.isBucketAccessible("jets3t");
        assertTrue("Cannot find public jets3t bucket", jets3tBucketAvailable);

        RestStorageService service = getStorageService(getCredentials());

        StorageBucket bucket = createBucketForTest("testACLManagement");
        String bucketName = bucket.getName();
        StorageObject object = null;

        try {
            // Create private object (default permissions).
            String privateKey = "Private Object #1";
            object = buildStorageObject(privateKey, "Private object sample text");
            service.putObject(bucketName, object);
            URL url = new URL(s3Url + "/" + bucketName + "/" + RestUtils.encodeUrlString(privateKey));
            // TODO: Google Storage bug: Returns 404 for private object?
            if (TARGET_SERVICE_GS.equals(getTargetService())) {
                assertEquals(404, ((HttpURLConnection) url.openConnection()).getResponseCode());
            } else {
                assertEquals("Expected denied access (403) error", 403, ((HttpURLConnection) url
                    .openConnection()).getResponseCode());
            }

            // Get ACL details for private object so we can determine the bucket owner.
            AccessControlList bucketACL = service.getBucketAcl(bucketName);
            S3Owner bucketOwner = bucketACL.getOwner();

            // TODO: Google Storage bug: GS doesn't support the ALL_USERS public ACL grantee
            if (TARGET_SERVICE_GS.equals(getTargetService())) {
                return;
            }

            // Create a public object.
            String publicKey = "Public Object #1";
            object = buildStorageObject(publicKey, "Public object sample text");
            AccessControlList acl = new AccessControlList();
            acl.setOwner(bucketOwner);
            acl.grantPermission(GroupGrantee.ALL_USERS, Permission.PERMISSION_READ);
            object.setAcl(acl);
            service.putObject(bucketName, object);
            url = new URL(s3Url + "/" + bucketName + "/" + RestUtils.encodeUrlString(publicKey));
            assertEquals("Expected access (200)",
                    200, ((HttpURLConnection)url.openConnection()).getResponseCode());

            // Update ACL to make private object public.
            AccessControlList privateToPublicACL = service.getObjectAcl(bucketName, privateKey);
            privateToPublicACL.grantPermission(GroupGrantee.ALL_USERS, Permission.PERMISSION_READ);
            object.setKey(privateKey);
            object.setAcl(privateToPublicACL);
            service.putObjectAcl(bucketName, object);
            url = new URL(s3Url + "/" + bucketName + "/" + RestUtils.encodeUrlString(privateKey));
            assertEquals("Expected access (200)", 200, ((HttpURLConnection) url.openConnection())
                .getResponseCode());

            // Create a non-standard uncanned public object.
            String publicKey2 = "Public Object #2";
            object = buildStorageObject(publicKey2);
            object.setAcl(privateToPublicACL); // This ACL has ALL_USERS READ permission set above.
            service.putObject(bucketName, object);
            url = new URL(s3Url + "/" + bucketName + "/" + RestUtils.encodeUrlString(publicKey2));
            assertEquals("Expected access (200)", 200, ((HttpURLConnection) url.openConnection())
                .getResponseCode());

            // Update ACL to make public object private.
            AccessControlList publicToPrivateACL = service.getObjectAcl(bucketName, publicKey);
            publicToPrivateACL.revokeAllPermissions(GroupGrantee.ALL_USERS);
            object.setKey(publicKey);
            object.setAcl(publicToPrivateACL);
            service.putObjectAcl(bucketName, object);
            url = new URL(s3Url + "/" + bucketName + "/" + RestUtils.encodeUrlString(publicKey));
            assertEquals("Expected denied access (403) error", 403, ((HttpURLConnection) url
                .openConnection()).getResponseCode());

            // Clean-up.
            service.deleteObject(bucketName, privateKey);
            service.deleteObject(bucketName, publicKey);
            service.deleteObject(bucketName, publicKey2);
        } finally {
            cleanupBucketForTest("testACLManagement", true);
        }
    }

    public void testObjectListing() throws Exception {
        RestStorageService service = getStorageService(getCredentials());
        StorageBucket bucket = createBucketForTest("testObjectListing");
        String bucketName = bucket.getName();

        try {
            // Represent a directory structure in S3.
            List<StorageObject> objectsList = new ArrayList<StorageObject>();
            objectsList.add(buildStorageObject("dir1"));
            objectsList.add(buildStorageObject("dir1/doc1Level1"));
            objectsList.add(buildStorageObject("dir1/doc2level1"));
            objectsList.add(buildStorageObject("dir1/dir1Level1"));
            objectsList.add(buildStorageObject("dir1/dir1Level1/doc1Level2"));
            objectsList.add(buildStorageObject("dir1/dir1Level1/dir1Level2"));
            objectsList.add(buildStorageObject("dir1/dir1Level1/dir1Level2/doc1Level3"));

            // Create objects
            for (StorageObject object: objectsList) {
                service.putObject(bucketName, object);
            }

            StorageObject[] objects = null;

            // List all items in directory.
            objects = service.listObjects(bucketName);
            assertEquals("Incorrect number of objects in directory structure",
                objectsList.size(), objects.length);

            // List items in chunks of size 2, ensure we get a total of seven.
            int chunkedObjectsCount = 0;
            int chunkedIterationsCount = 0;
            String priorLastKey = null;
            do {
                S3ObjectsChunk chunk = service.listObjectsChunked(
                    bucketName, null, null, 2, priorLastKey);
                priorLastKey = chunk.getPriorLastKey();
                chunkedObjectsCount += chunk.getObjects().length;
                chunkedIterationsCount++;
            } while (priorLastKey != null);
            assertEquals("Chunked bucket listing retreived incorrect number of objects",
                objectsList.size(), chunkedObjectsCount);
            assertEquals("Chunked bucket listing ran for an unexpected number of iterations",
                (objectsList.size() + 1) / 2, chunkedIterationsCount);

            // List objects with a prefix and delimiter to check common prefixes.
            S3ObjectsChunk chunk = service.listObjectsChunked(
                bucketName, "dir1/", "/", 100, null);
            assertEquals("Chunked bucket listing with prefix and delimiter retreived incorrect number of objects",
                3, chunk.getObjects().length);
            assertEquals("Chunked bucket listing with prefix and delimiter retreived incorrect number of common prefixes",
                1, chunk.getCommonPrefixes().length);

            // List the same items with a prefix.
            objects = service.listObjects(bucketName, "dir1", null);
            assertEquals("Incorrect number of objects matching prefix", 7, objects.length);

            // List items up one directory with a prefix (will include dir1Level1)
            objects = service.listObjects(bucketName, "dir1/dir1Level1", null);
            assertEquals("Incorrect number of objects matching prefix", 4, objects.length);

            // List items up one directory with a prefix (will not include dir1Level1)
            objects = service.listObjects(bucketName, "dir1/dir1Level1/", null);
            assertEquals("Incorrect number of objects matching prefix", 3, objects.length);

            // Try a prefix matching no object keys.
            objects = service.listObjects(bucketName, "dir1-NonExistent", null);
            assertEquals("Expected no results", 0, objects.length);

            // Use delimiter with an partial prefix.
            objects = service.listObjects(bucketName, "dir", "/");
            assertEquals("Expected no results", 1, objects.length);

            // Use delimiter to find item dir1 only.
            objects = service.listObjects(bucketName, "dir1", "/");
            assertEquals("Incorrect number of objects matching prefix and delimiter", 1, objects.length);

            // Use delimiter to find items within dir1 only.
            objects = service.listObjects(bucketName, "dir1/", "/");
            assertEquals("Incorrect number of objects matching prefix and delimiter", 3, objects.length);

            // List items up one directory with prefix and delimiter (will include only dir1Level1)
            objects = service.listObjects(bucketName, "dir1/dir1Level1", "/");
            assertEquals("Incorrect number of objects matching prefix", 1, objects.length);

            // List items up one directory with prefix and delimiter (will include only contents of dir1Level1)
            objects = service.listObjects(bucketName, "dir1/dir1Level1/", "/");
            assertEquals("Incorrect number of objects matching prefix", 2, objects.length);

            // Clean up.
            for (StorageObject object: objectsList) {
                service.deleteObject(bucketName, object.getKey());
            }
        } finally {
            cleanupBucketForTest("testObjectListing");
        }
    }

    public void testHashVerifiedUploads() throws Exception {
        RestStorageService service = getStorageService(getCredentials());
        StorageBucket bucket = createBucketForTest("testHashVerifiedUploads");
        String bucketName = bucket.getName();

        try {
            // Create test object with an MD5 hash of the data.
            String dataString = "Text for MD5 hashing...";
            StorageObject object = buildStorageObject("Testing MD5 Hashing", dataString);
            object.setContentType("text/plain");

            // Calculate hash data for object.
            byte[] md5Hash = ServiceUtils.computeMD5Hash(dataString.getBytes());

            // Ensure that using an invalid hash value fails.
            try {
                object.addMetadata("Content-MD5", "123");
                service.putObject(bucketName, object);
                fail("Should have failed due to invalid hash value");
            } catch (S3ServiceException e) {
                assertTrue("Expected error code indicating invalid md5 hash",
                    "InvalidDigest".equals(e.getS3ErrorCode())  // S3 error code
                    || "BadDigest".equals(e.getS3ErrorCode())   // GS error code
                    );
            }
            object = buildStorageObject("Testing MD5 Hashing", dataString);

            // Ensure that using the wrong hash value fails.
            try {
                byte[] incorrectHash = new byte[md5Hash.length];
                System.arraycopy(md5Hash, 0, incorrectHash, 0, incorrectHash.length);
                incorrectHash[0] = incorrectHash[1];
                object.setMd5Hash(incorrectHash);
                service.putObject(bucketName, object);
                fail("Should have failed due to incorrect hash value");
            } catch (S3ServiceException e) {
                assertEquals("Expected error code indicating invalid md5 hash", "BadDigest", e.getS3ErrorCode());
            }
            object = buildStorageObject("Testing MD5 Hashing", dataString);

            // Ensure that correct hash value succeeds.
            object.setMd5Hash(md5Hash);
            StorageObject resultObject = service.putObject(bucketName, object);

            // Ensure the ETag result matches the hex-encoded MD5 hash.
            assertEquals("Hex-encoded MD5 hash should match ETag", resultObject.getETag(),
                ServiceUtils.toHex(md5Hash));

            // Ensure we can convert the hex-encoded ETag to Base64 that matches the Base64 md5 hash.
            String md5HashBase64 = ServiceUtils.toBase64(md5Hash);
            String eTagBase64 = ServiceUtils.toBase64(ServiceUtils.fromHex(resultObject.getETag()));
            assertEquals("Could not convert ETag and MD5 hash to matching Base64-encoded strings",
                md5HashBase64, eTagBase64);

            // Clean up.
            service.deleteObject(bucketName, object.getKey());
        } finally {
            cleanupBucketForTest("testHashVerifiedUploads");
        }
    }

}

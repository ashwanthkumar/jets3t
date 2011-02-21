/*
 * JetS3t : Java S3 Toolkit
 * Project hosted at http://bitbucket.org/jmurty/jets3t/
 *
 * Copyright 2011 James Murty
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

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jets3t.service.Constants;
import org.jets3t.service.S3Service;
import org.jets3t.service.ServiceException;
import org.jets3t.service.acl.AccessControlList;
import org.jets3t.service.io.SegmentedRepeatableFileInputStream;
import org.jets3t.service.model.MultipartCompleted;
import org.jets3t.service.model.MultipartPart;
import org.jets3t.service.model.MultipartUpload;
import org.jets3t.service.model.S3Object;
import org.jets3t.service.multi.s3.ThreadedS3Service;

public class MultipartUtils {
    private static final Log log = LogFactory.getLog(MultipartUtils.class);

    /**
     * Minimum multipart upload part size supported by S3: 5 MB
     */
    public static final long MIN_PART_SIZE = 5 * (1024 * 1024);

    /**
     * Minimum object size supported by S3: 5 GB
     */
    public static final long MAX_OBJECT_SIZE = 5 * (1024 * 1024 * 1024);


    protected long maxPartSize = MAX_OBJECT_SIZE;


    /**
     * @param maxPartSize
     * the maximum size of objects that will be generated or upload by this instance,
     * must be between {@link #MIN_PART_SIZE} and {@link #MAX_OBJECT_SIZE}.
     */
    public MultipartUtils(long maxPartSize) {
        if (maxPartSize < MIN_PART_SIZE) {
            throw new IllegalArgumentException("Maximum part size parameter " + maxPartSize
                + " is less than the minimum legal part size " + MIN_PART_SIZE);
        }
        if (maxPartSize > MAX_OBJECT_SIZE) {
            throw new IllegalArgumentException("Maximum part size parameter " + maxPartSize
                + " is greater than the maximum legal upload object size " + MAX_OBJECT_SIZE);
        }
        this.maxPartSize = maxPartSize;
    }

    /**
     * Use default value for maximum part size: {@link #MAX_OBJECT_SIZE}.
     */
    public MultipartUtils() {
    }

    public long getMaxPartSize() {
        return maxPartSize;
    }

    /**
     * @param file
     * @return
     * true if the given file is larger than the maximum part size defined in this instances.
     */
    public boolean isFileLargerThanMaxPartSize(File file) {
        return file.length() > maxPartSize;
    }

    /**
     * Split the given file into objects such that no object has a size greater than
     * the defined maximum part size. Each object uses a
     * {@link SegmentedRepeatableFileInputStream} input stream to manage its own
     * part of the underlying file.
     *
     * @param file
     * @return
     * an ordered list of objects that can be uploaded as multipart parts to S3 to
     * re-constitute the given file in the service.
     *
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    public List<S3Object> splitFileIntoObjectsByMaxPartSize(String objectKey, File file)
        throws IOException, NoSuchAlgorithmException
    {
        long fileLength = file.length();
        long partCount = fileLength / maxPartSize + (fileLength % maxPartSize > 0 ? 1 : 0);

        if (log.isDebugEnabled()) {
            log.debug("Splitting file " + file.getAbsolutePath() + " of "
                + fileLength + " bytes into " + partCount
                + " object parts with a maximum part size of " + maxPartSize);
        }

        ArrayList<S3Object> multipartPartList = new ArrayList<S3Object>();
        SegmentedRepeatableFileInputStream segFIS = null;

        for (long offset = 0; offset < partCount; offset++) {
            S3Object object = new S3Object(objectKey);
            if (offset < partCount - 1) {
                object.setContentLength(maxPartSize);
                segFIS = new SegmentedRepeatableFileInputStream(
                    file, offset * maxPartSize, maxPartSize);
            } else {
                // Last part, may not be full size.
                long partLength = fileLength % maxPartSize;
                // Handle edge-case where last part is exactly the size of maxPartSize
                if (partLength == 0) {
                    partLength = maxPartSize;
                }
                object.setContentLength(partLength);
                segFIS = new SegmentedRepeatableFileInputStream(
                    file, offset * maxPartSize, partLength);
            }
            object.setContentLength(segFIS.available());
            object.setDataInputStream(segFIS);

            // Calculate part's MD5 hash and reset stream
            object.setMd5Hash(ServiceUtils.computeMD5Hash(segFIS));
            segFIS.reset();

            multipartPartList.add(object);
        }
        return multipartPartList;
    }

    /**
     * Upload a file to S3 using a multipart upload where each part is
     * uploaded in series (i.e. one at a time).
     *
     * This method performs all the work of an upload, including creating
     * and completing the multipart upload job.
     *
     * @param file
     * @param service
     * @param bucketName
     * @param metadata
     * @param acl
     * @param storageClass
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws ServiceException
     */
    public MultipartCompleted uploadFile(File file, S3Service service, String bucketName,
        Map<String, Object> metadata, AccessControlList acl, String storageClass)
        throws NoSuchAlgorithmException, IOException, ServiceException
    {
        MultipartUpload upload = null;
        try {
            if (metadata == null) {
                metadata = new HashMap<String, Object>();
            }
            if (!metadata.containsKey(S3Object.METADATA_HEADER_CONTENT_TYPE)) {
                metadata.put(S3Object.METADATA_HEADER_CONTENT_TYPE,
                    Mimetypes.getInstance().getMimetype(file));
            }
            if (!metadata.containsKey(Constants.METADATA_JETS3T_LOCAL_FILE_DATE)) {
                metadata.put(Constants.METADATA_JETS3T_LOCAL_FILE_DATE,
                    ServiceUtils.formatIso8601Date(new Date(file.lastModified())));
            }
            upload = service.multipartStartUpload(
                bucketName, file.getName(), metadata, acl, storageClass);
            List<MultipartPart> parts = uploadFile(file, service, upload);
            return service.multipartCompleteUpload(upload, parts);
        } catch (Exception e) {
            if (upload != null) {
                service.multipartAbortUpload(upload);
            }
            if (e instanceof ServiceException) {
                throw (ServiceException) e;
            } else {
                throw new ServiceException(e);
            }
        }
    }

    /**
     * Upload a file to S3 using an existing multipart upload; each part is
     * uploaded in series (i.e. one at a time). It is the caller's responsibility
     * to complete the multipart upload job by calling
     * {@link S3Service#multipartCompleteUpload(MultipartUpload, List)} or
     * {@link S3Service#multipartCompleteUpload(MultipartUpload)}.
     *
     * @param file
     * @param service
     * @param upload
     * @return
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws ServiceException
     */
    public List<MultipartPart> uploadFile(File file, S3Service service, MultipartUpload upload)
        throws NoSuchAlgorithmException, IOException, ServiceException
    {
        List<S3Object> objects = splitFileIntoObjectsByMaxPartSize(upload.getObjectKey(), file);
        List<MultipartPart> parts = new ArrayList<MultipartPart>();
        int partNumber = 1;
        for (S3Object object: objects) {
            parts.add(
                service.multipartUploadPart(upload, partNumber, object));
            partNumber++;
        }
        return parts;
    }

    /**
     * Upload a file to S3 using an existing multipart upload; each part is
     * uploaded in parallel according to the threading and connection settings
     * of the givent {@link ThreadedS3Service}.
     * It is the caller's responsibility to complete the multipart upload job by
     * calling {@link S3Service#multipartCompleteUpload(MultipartUpload, List)}
     * or {@link S3Service#multipartCompleteUpload(MultipartUpload)}.
     *
     * @param file
     * @param service
     * @param upload
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */
    public void uploadFile(File file, ThreadedS3Service service, MultipartUpload upload)
        throws NoSuchAlgorithmException, IOException
    {
        List<S3Object> objects = splitFileIntoObjectsByMaxPartSize(upload.getObjectKey(), file);
        service.multipartUploadParts(upload, objects);
    }

}

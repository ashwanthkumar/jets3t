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
package org.jets3t.service.multi;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jets3t.service.io.GZipInflatingOutputStream;
import org.jets3t.service.model.StorageObject;
import org.jets3t.service.security.EncryptionUtil;

/**
 * A simple container object to associate one of an {@link StorageObject} or a signed URL string
 * with an output file or output stream to which the object's data will be written.
 * <p>
 * This class is used by
 * {@link StorageServiceMulti#downloadObjects(DownloadPackage[])}
 * to download objects.
 *
 * @author James Murty
 */
public class DownloadPackage {
    private static final Log log = LogFactory.getLog(DownloadPackage.class);

    private StorageObject object = null;
    private String signedUrl = null;

    private File outputFile = null;
    private OutputStream outputStream = null;
    private boolean isUnzipping = false;
    private EncryptionUtil encryptionUtil = null;

    private boolean appendToFile = false;

    public DownloadPackage(StorageObject object, File outputFile) {
        this(object, outputFile, false, null);
    }

    public DownloadPackage(StorageObject object, File outputFile, boolean isUnzipping,
        EncryptionUtil encryptionUtil)
    {
        this.object = object;
        this.outputFile = outputFile;
        this.isUnzipping = isUnzipping;
        this.encryptionUtil = encryptionUtil;
    }

    public DownloadPackage(String signedUrl, File outputFile, boolean isUnzipping,
        EncryptionUtil encryptionUtil)
    {
        this.signedUrl = signedUrl;
        this.outputFile = outputFile;
        this.isUnzipping = isUnzipping;
        this.encryptionUtil = encryptionUtil;
    }

    public DownloadPackage(StorageObject object, OutputStream outputStream) {
        this(object, outputStream, false, null);
    }

    public DownloadPackage(StorageObject object, OutputStream outputStream, boolean isUnzipping,
        EncryptionUtil encryptionUtil)
    {
        this.object = object;
        this.outputStream = outputStream;
        this.isUnzipping = isUnzipping;
        this.encryptionUtil = encryptionUtil;
    }

    public DownloadPackage(String signedUrl, OutputStream outputStream, boolean isUnzipping,
        EncryptionUtil encryptionUtil)
    {
        this.signedUrl = signedUrl;
        this.outputStream = outputStream;
        this.isUnzipping = isUnzipping;
        this.encryptionUtil = encryptionUtil;
    }

    public StorageObject getObject() {
        return object;
    }

    public void setObject(StorageObject object) {
        this.object = object;
    }

    /**
     * @return the target output file for data, or null if this package
     * has an output stream as its target.
     */
    public File getDataFile() {
        return outputFile;
    }

    public String getSignedUrl() {
        return signedUrl;
    }

    public void setSignedUrl(String url) {
        signedUrl = url;
    }

    public boolean isSignedDownload() {
        return signedUrl != null;
    }

    public boolean isAppendToFile() {
        return appendToFile;
    }

    /**
     * Data will be appended to the target file instead of overwriting it.
     * This option is relevant only for packages with a target file, not
     * those with a target output stream.
     *
     * @param appendToFile
     */
    public void setAppendToFile(boolean appendToFile) {
        this.appendToFile = appendToFile;
    }

    /**
     * Creates an output stream to receive the object's data. The output stream is either
     * the output stream provided to this package in its constructor, or an
     * automatically-created FileOutputStream if a File object was provided as the target
     * output object. The output stream will also be wrapped in a GZipInflatingOutputStream if
     * isUnzipping is true and/or a decrypting output stream if this package has an associated
     * non-null EncryptionUtil.
     *
     * @return
     * an output stream that writes data to the output target managed by this class.
     *
     * @throws Exception
     */
    public OutputStream getOutputStream() throws Exception {
        OutputStream outputStream = null;
        if (outputFile != null) {
            // Create parent directories for file, if necessary.
            if (outputFile.getParentFile() != null) {
                outputFile.getParentFile().mkdirs();
            }

            outputStream = new FileOutputStream(outputFile, appendToFile);
        } else {
            outputStream = this.outputStream;
        }

        if (isUnzipping) {
            log.debug("Inflating gzipped data for object: " + object.getKey());
            outputStream = new GZipInflatingOutputStream(outputStream);
        }
        if (encryptionUtil != null) {
            log.debug("Decrypting encrypted data for object: " + object.getKey());
            outputStream = encryptionUtil.decrypt(outputStream);
        }
        return outputStream;
    }

}

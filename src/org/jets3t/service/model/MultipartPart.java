/*
 * JetS3t : Java S3 Toolkit
 * Project hosted at http://bitbucket.org/jmurty/jets3t/
 *
 * Copyright 2010 James Murty
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
package org.jets3t.service.model;

import java.util.Date;


/**
 * Represents a Part of a MultipartUpload operation.
 *
 * @author James Murty
 */
public class MultipartPart {
    private Integer partNumber;
    private Date lastModified;
    private String etag;
    private Long size;

    public MultipartPart(Integer partNumber, Date lastModified, String etag, Long size)
    {
        this.partNumber = partNumber;
        this.lastModified = lastModified;
        this.etag = etag;
        this.size = size;
    }

    @Override
    public String toString() {
        return this.getClass().getName() + " ["
            + "partNumber=" + getPartNumber()
            + ", lastModified=" + getLastModified()
            + ", etag=" + getEtag()
            + ", size=" + getSize()
            + "]";
    }

    public String getEtag() {
        return etag;
    }

    public Long getSize() {
        return size;
    }

    public Integer getPartNumber() {
        return partNumber;
    }

    public Date getLastModified() {
        return lastModified;
    }

}

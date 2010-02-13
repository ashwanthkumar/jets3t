/*
 * jets3t : Java Extra-Tasty S3 Toolkit (for Amazon S3 online storage service)
 * This is a java.net project, see https://jets3t.dev.java.net/
 *
 * Copyright 2009 James Murty
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
package org.jets3t.service.model.cloudfront;


public class OriginAccessIdentityConfig {
    private String callerReference = null;
    private String comment = null;
    private String etag = null;

    public OriginAccessIdentityConfig(String callerReference, String comment)
    {
        this.callerReference = callerReference;
        this.comment = comment;
    }

    public String getCallerReference() {
    	return callerReference;
    }

    public String getComment() {
    	return comment;
    }

    public String getEtag() {
        return etag;
    }

    public void setEtag(String etag) {
        this.etag = etag;
    }

    public String toString() {
        return "CloudFrontOriginAccessIdentityConfig: " +
            "callerReference=" + callerReference + ", comment=" + comment +
            (etag != null ? ", etag=" + etag : "");
    }

}

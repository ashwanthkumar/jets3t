/*
 * jets3t : Java Extra-Tasty S3 Toolkit (for Amazon S3 online storage service)
 * This is a java.net project, see https://jets3t.dev.java.net/
 * 
 * Copyright 2008 James Murty
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

import java.util.Arrays;


public class DistributionConfig {
    private String origin = null;
    private String callerReference = null;
    private String[] cnames = new String[0];
    private String comment = null;
    private boolean enabled = false;       
    private String etag = null;
    private LoggingStatus loggingStatus = null;
    
    public DistributionConfig(String origin, String callerReference, 
        String[] cnames, String comment, boolean enabled,
        LoggingStatus loggingStatus) 
    {
        this.origin = origin;
        this.callerReference = callerReference;
        this.cnames = cnames;
        this.comment = comment;        
        this.enabled = enabled;
        this.loggingStatus = loggingStatus;
    }
    
    public String getOrigin() {
        return origin;
    }

    public String getCallerReference() {
        return callerReference;
    }
    
    public String[] getCNAMEs() {
        return this.cnames;
    }

    public String getComment() {
        return comment;
    }

    public boolean isEnabled() {
        return enabled;
    }
    
    public String getEtag() {
        return etag;
    }
    
    public void setEtag(String etag) {
        this.etag = etag;
    }

    public LoggingStatus getLoggingStatus() {
    	return loggingStatus;
    }
    
    public boolean isLoggingEnabled() {
        return this.loggingStatus != null;
    }    

    public String toString() {
        return "CloudFrontDistributionConfig: origin=" + origin +
            ", callerReference=" + callerReference + ", comment=" + comment +
            ", enabled=" + enabled +
            (etag != null ? ", etag=" + etag : "") +
            ", LoggingStatus: " + 
            (!isLoggingEnabled() 
        		? 	"null"
            	: 	"bucket=" + loggingStatus.getBucket() +
            		", prefix=" + loggingStatus.getPrefix()) +
            ", CNAMEs=" + Arrays.asList(cnames);
    }

}

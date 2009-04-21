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
import java.util.Date;

public class Distribution {
    private static final String DEFAULT_ORIGIN_SUFFIX = ".s3.amazonaws.com";
    
    private String id = null;
    private String status = null;        
    private Date lastModifiedTime = null;
    private String domainName = null;
    private String origin = null;
    private String cnames[] = new String[0];
    private String comment = null;
    private boolean enabled = false;
    private DistributionConfig config = null;
    
    public Distribution(String id, String status, Date lastModifiedDate,
        String domainName, String origin, String[] cnames, String comment, 
        boolean enabled) 
    {
        this.id = id;
        this.status = status;
        this.lastModifiedTime = lastModifiedDate;
        this.domainName = domainName;
        this.origin = origin;
        this.cnames = cnames;
        this.comment = comment;
        this.enabled = enabled;
    }
    
    public Distribution(String id, String status, Date lastModifiedDate,
        String domainName, DistributionConfig config) 
    {
        this.id = id;
        this.status = status;
        this.lastModifiedTime = lastModifiedDate;
        this.domainName = domainName;
        this.config = config;
    }

    public boolean isSummary() {
        return getConfig() == null;
    }
    
    public String getComment() {
        return comment;
    }
    public String getDomainName() {
        return domainName;
    }
    public String getId() {
        return id;
    }
    public Date getLastModifiedTime() {
        return lastModifiedTime;
    }
    public String getOrigin() {
        return origin;
    }
    
    /**
     * @return
     * the origin bucket's name, without the suffix ".s3.amazonaws.com"
     */
    public String getOriginAsBucketName() {
        if (origin.endsWith(DEFAULT_ORIGIN_SUFFIX)) {
            return origin.substring(0, origin.length() - DEFAULT_ORIGIN_SUFFIX.length());
        } else {
            return origin;
        }
    }
    
    public String[] getCNAMEs() {
        return cnames;
    }
    public boolean isEnabled() {
        return enabled;
    }
    
    public String getStatus() {
        return status;
    }
    
    /**
     * @return
     * true if this distribution's status is "Deployed".
     */
    public boolean isDeployed() {
        return "Deployed".equals(getStatus());
    }

    public DistributionConfig getConfig() {
        return config;
    }
    
    public String toString() {
        return "CloudFrontDistribution: id=" + id + ", status=" + status + 
            ", domainName=" + domainName + ", lastModifiedTime=" + lastModifiedTime +
            (isSummary()
                ? ", origin=" + origin + ", comment=" + comment
                    + ", enabled=" + enabled + ", CNAMEs=" + Arrays.asList(cnames)                    
                : ", config=[" + config + "]");
    }

}

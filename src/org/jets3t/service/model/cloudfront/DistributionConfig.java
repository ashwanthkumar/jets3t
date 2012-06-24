/*
 * JetS3t : Java S3 Toolkit
 * Project hosted at http://bitbucket.org/jmurty/jets3t/
 *
 * Copyright 2008-2012 James Murty
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

import java.util.ArrayList;
import java.util.Arrays;

import org.jets3t.service.model.cloudfront.CacheBehavior.ViewerProtocolPolicy;


public class DistributionConfig {
    private Origin[] origins = null;
    private String callerReference = null;
    private String[] cnames = new String[0];
    private String comment = null;
    private boolean enabled = false;
    private String etag = null;
    private LoggingStatus loggingStatus = null;
    private CacheBehavior defaultCacheBehavior = new CacheBehavior();
    private CacheBehavior[] cacheBehaviors = new CacheBehavior[] {};
    private String defaultRootObject;

    /**
     * Construct a distribution configuration compatible with CloudFront API versions
     * 2012-05-05 and later (i.e. including cache behaviors and multiple origins)
     *
     * @param origins
     * @param callerReference
     * @param cnames
     * @param comment
     * @param enabled
     * @param loggingStatus
     * @param defaultCacheBehavior
     * @param cacheBehaviors
     */
    public DistributionConfig(Origin[] origins, String callerReference,
        String[] cnames, String comment, boolean enabled,
        LoggingStatus loggingStatus, CacheBehavior defaultCacheBehavior,
        CacheBehavior[] cacheBehaviors)
    {
        this.origins = origins;
        this.callerReference = callerReference;
        this.cnames = cnames;
        this.comment = comment;
        this.enabled = enabled;
        this.loggingStatus = loggingStatus;
        this.defaultCacheBehavior = defaultCacheBehavior;
        this.cacheBehaviors = cacheBehaviors;
    }

    /**
     * Construct a distribution configuration.
     *
     * @deprecated as of 2012-05-05 API version.
     *
     * @param origin
     * @param callerReference
     * @param cnames
     * @param comment
     * @param enabled
     * @param loggingStatus
     * @param trustedSignerSelf
     * @param trustedSignerAwsAccountNumbers
     * @param requiredProtocols
     * @param defaultRootObject
     * @param minTTL
     */
    @Deprecated
    public DistributionConfig(Origin origin, String callerReference,
        String[] cnames, String comment, boolean enabled,
        LoggingStatus loggingStatus, boolean trustedSignerSelf,
        String[] trustedSignerAwsAccountNumbers,
        String[] requiredProtocols, String defaultRootObject,
        Long minTTL)
    {
        this.origins = new Origin[] {origin};
        this.callerReference = callerReference;
        this.cnames = cnames;
        this.comment = comment;
        this.enabled = enabled;
        this.loggingStatus = loggingStatus;
        this.defaultRootObject = defaultRootObject;
        // Convert pre 2012-05-05 version trusted signer parameters into default cache behavior setting
        ArrayList<String> myTrustedSignerAwsAccountNumber = new ArrayList<String>();
        if (trustedSignerSelf) {
            myTrustedSignerAwsAccountNumber.add("self");
        }
        if (trustedSignerAwsAccountNumbers != null) {
            for (String trustedSigner: trustedSignerAwsAccountNumbers) {
                myTrustedSignerAwsAccountNumber.add(trustedSigner);
            }
        }
        this.getDefaultCacheBehavior().setTrustedSignerAwsAccountNumbers(
            myTrustedSignerAwsAccountNumber.toArray(new String[] {}));
        this.setRequiredProtocols(requiredProtocols);
        this.getDefaultCacheBehavior().setMinTTL(minTTL);
    }

    /**
     * @deprecated as of 2012-05-05 API version.
     *
     * @param origin
     * @param callerReference
     * @param cnames
     * @param comment
     * @param enabled
     * @param loggingStatus
     */
    @Deprecated
    public DistributionConfig(Origin origin, String callerReference,
            String[] cnames, String comment, boolean enabled,
            LoggingStatus loggingStatus)
    {
        this(origin, callerReference, cnames, comment, enabled,
                loggingStatus, false, null, null, null, null);
    }

    /**
     * @deprecated as of 2012-05-05 API update
     * @return
     * The first of multiple possible origins
     * (retained for compatibility with applications written before 2012-05-05 API update)
     */
    @Deprecated
    public Origin getOrigin() {
        return origins[0];
    }

    public Origin[] getOrigins() {
        return origins;
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

    public CacheBehavior getDefaultCacheBehavior() {
        return defaultCacheBehavior;
    }

    public CacheBehavior[] getCacheBehaviors() {
        return cacheBehaviors;
    }

    public boolean hasCacheBehaviors() {
        return cacheBehaviors != null && cacheBehaviors.length > 0;
    }

    public boolean isStreamingDistributionConfig() {
        return (this instanceof StreamingDistributionConfig);
    }

    public String getDefaultRootObject() {
        return defaultRootObject;
    }

    /**
     * @deprecated as of 2012-05-05 API version.
     *
     * @return
     * true if the distribution is private.
     */
    @Deprecated
    public boolean isPrivate() {
        return (this.getOrigin() instanceof S3Origin
            && ((S3Origin)this.getOrigin()).getOriginAccessIdentity() != null);
    }

    /**
     * @deprecated as of 2012-05-05 API version, instead use {@link #getDefaultCacheBehavior()}
     */
    @Deprecated
    public String[] getTrustedSignerAwsAccountNumbers() {
        return this.getDefaultCacheBehavior().getTrustedSignerAwsAccountNumbers();
    }

    /**
     * @deprecated as of 2012-05-05 API version, instead use {@link #getDefaultCacheBehavior()}
     */
    @Deprecated
    public boolean isTrustedSignerSelf() {
        return this.getDefaultCacheBehavior().isTrustedSignerSelf();
    }

    /**
     * @deprecated as of 2012-05-05 API version, instead use {@link #getDefaultCacheBehavior()}
     */
    @Deprecated
    public boolean hasTrustedSignerAwsAccountNumbers() {
        return getTrustedSignerAwsAccountNumbers() != null
            && getTrustedSignerAwsAccountNumbers().length > 0;
    }

    /**
     * @deprecated as of 2012-05-05 API version, instead use {@link #getDefaultCacheBehavior()}
     */
    @Deprecated
    public boolean isUrlSigningRequired() {
        return isTrustedSignerSelf() || hasTrustedSignerAwsAccountNumbers();
    }

    /**
     * @deprecated as of 2012-05-05 API version, instead use {@link #getDefaultCacheBehavior()}
     */
    @Deprecated
    public void setRequiredProtocols(String[] protocols) {
        // Convert pre 2012-05-05 version requiredProtocol into default cache behavior setting
        if (protocols != null && protocols.length > 0) {
            if (protocols.length > 1 || !"https".equals(protocols[0])) {
                throw new IllegalArgumentException(
                    "if set, the requiredProtocols argument may contain only a single string"
                    + " value \"https\"");
            }
            // If a required protocol is set, and is set correctly, it must be HTTPS_ONLY
            this.getDefaultCacheBehavior().setViewerProtocolPolicy(ViewerProtocolPolicy.HTTPS_ONLY);
        } else {
            this.getDefaultCacheBehavior().setViewerProtocolPolicy(ViewerProtocolPolicy.ALLOW_ALL);
        }
    }

    /**
     * @deprecated as of 2012-05-05 API version, instead use {@link #getDefaultCacheBehavior()}
     */
    @Deprecated
    public String[] getRequiredProtocols() {
        if (this.getDefaultCacheBehavior().getViewerProtocolPolicy() == ViewerProtocolPolicy.HTTPS_ONLY)
        {
            return new String[] {"https"};
        } else {
            return null;
        }
    }

    /**
     * @deprecated as of 2012-05-05 API version, instead use {@link #getDefaultCacheBehavior()}
     */
    @Deprecated
    public boolean isHttpsProtocolRequired() {
        return this.getRequiredProtocols() != null
            && this.getRequiredProtocols().length == 1
            && "https".equals(this.getRequiredProtocols()[0]);
    }

    /**
     * @deprecated as of 2012-05-05 API version, instead use {@link #getDefaultCacheBehavior()}
     */
    @Deprecated
    public void setHttpsProtocolRequired(boolean value) {
        if (value) {
            this.setRequiredProtocols(new String[] {"https"});
        } else {
            this.setRequiredProtocols(null);
        }
    }

    /**
     * @deprecated as of 2012-05-05 API version, instead use {@link #getDefaultCacheBehavior()}
     */
    @Deprecated
    public void setMinTTL(Long minTTL) {
        this.getDefaultCacheBehavior().setMinTTL(minTTL);
    }

    /**
     * @deprecated as of 2012-05-05 API version, instead use {@link #getDefaultCacheBehavior()}
     */
    @Deprecated
    public Long getMinTTL() {
        return this.getDefaultCacheBehavior().getMinTTL();
    }

    /**
     * @deprecated as of 2012-05-05 API version, instead use {@link #getDefaultCacheBehavior()}
     */
    @Deprecated
    public boolean hasMinTTL() {
        return this.getDefaultCacheBehavior().hasMinTTL();
    }

    @Override
    public String toString() {
        return
            (isStreamingDistributionConfig()
                ? "StreamingDistributionConfig: "
                : "DistributionConfig: ")
            + "callerReference=" + callerReference
            + ", origins=" + Arrays.asList(origins)
            + ", comment=" + comment
            + ", enabled=" + enabled
            + ", defaultCacheBehavior=" + defaultCacheBehavior
            + (!this.hasCacheBehaviors()
                ? ""
                : ", cacheBehaviors=" + getCacheBehaviors())
            + (etag != null ? ", etag=" + etag : "")
            + (!isLoggingEnabled()
                ? ""
                : ", LoggingStatus: bucket=" + loggingStatus.getBucket()
                  + ", prefix=" + loggingStatus.getPrefix()) +
            ", CNAMEs=" + Arrays.asList(cnames) +
                ", defaultRootObject=" + defaultRootObject;
    }

}

/*
 * JetS3t : Java S3 Toolkit
 * Project hosted at http://bitbucket.org/jmurty/jets3t/
 *
 * Copyright 2014 James Murty
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
package org.jets3t.service.impl.rest.httpclient;

import java.net.URI;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.apache.http.client.methods.HttpUriRequest;
import org.jets3t.service.utils.ServiceUtils;

/**
 * Cache to store mappings from a bucket name to a region, used to help with
 * request signing for AWS version 4 requests where you need to know a bucket's
 * region before you can correctly sign requests that operate on that bucket.
 *
 * @author jmurty
 */
public class RegionEndpointCache {

    Map<String, String> bucketNameToRegionMap = new HashMap<String, String>();

    /**
     * Figure out the bucket name referred to by a request, if any, from the
     * its Host name or URL path.
     * @param host
     * @param path
     * @return
     */
    protected String deriveBucketName(String host, String path) {
        // Check whether this is a virtual host Host name, in which case the
        // bucket name is everything before the AWS portion of the hostname.
        String[] hostSplit = host.split("\\.");

        int firstAwsHostnameOffset = hostSplit.length - 3;
        String firstAwsHostname = hostSplit[firstAwsHostnameOffset];

        // Handle awkward unusual naming convention for eu-central-1 Host names
        // which may be "s3-eu-central-1" or "s3.eu-central-1"
        if ("eu-central-1".equals(firstAwsHostname)) {
            firstAwsHostnameOffset -= 1;
            firstAwsHostname = hostSplit[firstAwsHostnameOffset];
        }

        if ("s3".equals(firstAwsHostname)
            || firstAwsHostname.startsWith("s3-"))
        {
            // This is the first portion of the AWS hostname, anything prior
            // in the Host name is a virutal host bucket name.
            if (firstAwsHostnameOffset > 0) {
                return ServiceUtils.join(
                    Arrays.copyOfRange(hostSplit, 0, firstAwsHostnameOffset),
                    ".");
            }
        }

        // If we get this far we haven't detected a virtual host bucket name, so
        // the first /-delimited portion of the URI path must be the bucket name.
        String[] pathSplit = path.split("\\.");
        if (pathSplit.length > 0) {
            return pathSplit[0];
        } else {
            return null;
        }
    }

    /**
     *
     * @param httpMethod
     * @return cached region name associated with a request's bucket name.
     */
    public String get(HttpUriRequest httpMethod) {
        URI uri = httpMethod.getURI();
        String bucketName = deriveBucketName(uri.getHost(), uri.getPath());
        return get(bucketName);
    }

    public String get(String bucketName) {
        if (bucketNameToRegionMap.containsKey(bucketName)) {
            return bucketNameToRegionMap.get(bucketName);
        } else {
            return null;
        }
    }

    public String put(HttpUriRequest httpMethod, String region) {
        URI uri = httpMethod.getURI();
        String bucketName = deriveBucketName(uri.getHost(), uri.getPath());
        return put(bucketName, region);
    }

    public String put(String bucketName, String region) {
        if (bucketName != null && region != null) {
            return bucketNameToRegionMap.put(bucketName, region);
        } else {
            return null;
        }
    }

    public boolean containsKey(String bucketName) {
        return bucketNameToRegionMap.containsKey(bucketName);
    }

    public boolean containsValue(String region) {
        return bucketNameToRegionMap.containsValue(region);
    }

    public String remove(String bucketName) {
        return bucketNameToRegionMap.remove(bucketName);
    }

    public void clear() {
        bucketNameToRegionMap.clear();
    }

}

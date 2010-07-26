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
package org.jets3t.samples;

import org.jets3t.service.impl.rest.httpclient.GoogleStorageService;
import org.jets3t.service.model.S3Bucket;
import org.jets3t.service.security.GSCredentials;

/**
 * This class includes all the code samples as listed in the Google Storage
 * <a href="http://code.google.com/apis/storage/docs/developer-guide.html">Developer's Guide</a>.
 * <p>
 * This code is provided as a convenience for those who are reading through the guide and don't want
 * to type out the examples themselves.
 * </p>
 *
 * @author Google Developers
 */
public class GSCodeSamples {

    private static final String BUCKET_NAME = "test-bucket";

    public static void main(String[] args) throws Exception {
        /* ************
         * Code Samples
         * ************
         */

        /*
         * Connecting to Google Storage
         */

        // Your Google Storage (GS) login credentials are required to manage GS accounts.
        // These credentials are stored in an GSCredentials object:

        GSCredentials gsCredentials = SamplesUtils.loadGSCredentials();

        // To communicate with S3, create a class that implements an S3Service.
        // We will use the REST/HTTP implementation based on HttpClient, as this is the most
        // robust implementation provided with jets3t.

        GoogleStorageService gsService = new GoogleStorageService(gsCredentials);

        // A good test to see if your GoogleStorageService can connect to GS is to list all the buckets you own.
        // If a bucket listing produces no exceptions, all is well.

        S3Bucket[] myBuckets = gsService.listAllBuckets();
        System.out.println("How many buckets to I have in GS? " + myBuckets.length);

        /*
         * Create a bucket
         */

        // To store data in GS you must first create a bucket, a container for objects.

        S3Bucket testBucket = gsService.createBucket(BUCKET_NAME);
        System.out.println("Created test bucket: " + testBucket.getName());

        // If you try using a common name, you will probably not be able to create the
        // bucket as someone else will already have a bucket of that name.

    }

}

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

import java.net.HttpURLConnection;
import java.net.URL;

import org.jets3t.service.Constants;
import org.jets3t.service.Jets3tProperties;
import org.jets3t.service.S3ServiceException;
import org.jets3t.service.acl.AccessControlList;
import org.jets3t.service.impl.rest.httpclient.RestS3Service;
import org.jets3t.service.impl.rest.httpclient.RestStorageService;
import org.jets3t.service.model.S3Object;
import org.jets3t.service.model.StorageBucket;
import org.jets3t.service.model.StorageObject;
import org.jets3t.service.security.GSCredentials;
import org.jets3t.service.security.ProviderCredentials;

/**
 * Test the S3-targetted RestS3Service against the Google Storage endpoint.
 *
 * @author James Murty
 */
public class TestRestS3ServiceToGoogleStorage extends BaseStorageServiceTests {

    public TestRestS3ServiceToGoogleStorage() throws Exception {
        super();
    }

    @Override
    protected String getTargetService() {
        return TARGET_SERVICE_GS;
    }

    @Override
    protected ProviderCredentials getCredentials() {
        return new GSCredentials(
            testProperties.getProperty("gsservice.accesskey"),
            testProperties.getProperty("gsservice.secretkey"));
    }

    @Override
    protected RestStorageService getStorageService(ProviderCredentials credentials) throws S3ServiceException {
        Jets3tProperties properties = new Jets3tProperties();
        properties.setProperty("s3service.s3-endpoint", Constants.GS_DEFAULT_HOSTNAME);
        return new RestS3Service(credentials, null, null, properties);
    }

    @Override
    protected AccessControlList buildAccessControlList() {
        return new AccessControlList();
    }

    /*
     * S3 Features supported by Google Storage
     */

}

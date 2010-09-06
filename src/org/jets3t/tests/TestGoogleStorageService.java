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

import org.jets3t.service.S3ServiceException;
import org.jets3t.service.acl.AccessControlList;
import org.jets3t.service.acl.gs.GSAccessControlList;
import org.jets3t.service.impl.rest.httpclient.GoogleStorageService;
import org.jets3t.service.impl.rest.httpclient.RestStorageService;
import org.jets3t.service.model.GSObject;
import org.jets3t.service.model.StorageObject;
import org.jets3t.service.security.GSCredentials;
import org.jets3t.service.security.ProviderCredentials;

/**
 * Test cases specific to general S3 compatibility -- that is, features supported by
 * both S3 and Google Storage.
 *
 * @author James Murty
 */
public class TestGoogleStorageService extends BaseStorageServiceTests {

    public TestGoogleStorageService() throws Exception {
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
        return new GoogleStorageService(credentials);
    }

    @Override
    protected StorageObject buildStorageObject(String name, String data) throws Exception {
        return new GSObject(name, data);
    }

    @Override
    protected StorageObject buildStorageObject(String name) throws Exception {
        return new GSObject(name);
    }

    @Override
    protected AccessControlList buildAccessControlList() {
        return new GSAccessControlList();
    }

    /*
     * Features specific to Google Storage
     */

}

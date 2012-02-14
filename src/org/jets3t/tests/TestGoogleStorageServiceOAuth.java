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

import org.jets3t.service.security.OAuth2Credentials;
import org.jets3t.service.security.ProviderCredentials;

/**
 * Test Google Storage OAuth Access.
 */
public class TestGoogleStorageServiceOAuth extends TestGoogleStorageService {

    private static OAuth2Credentials savedCredentials;

    public TestGoogleStorageServiceOAuth() throws Exception {
        super();
    }

    @Override
    protected String getTargetService() {
        return TARGET_SERVICE_GS;
    }

    @Override
    protected String getBucketNameForTest(String testName) throws Exception {
        return "test-"
                + getCredentials().getAccessKey().toLowerCase().substring(0, 7)
                + "-"
                + testName.toLowerCase();
    }

    @Override
    protected ProviderCredentials getCredentials() {
        //I've made the credentials a singleton object because otherwise
        //JUnit tries to get a bunch of access tokens, which I suspect is being
        //flagged as a DoS attempt, and hence starts failing  after the first
        //few token fetches.
        synchronized(getClass()) {
            if(savedCredentials == null) {
                savedCredentials = new OAuth2Credentials(
                        testProperties.getProperty("gsservice.client_id"),
                        testProperties.getProperty("gsservice.client_secret"),
                        null,
                        testProperties.getProperty("gsservice.refresh_token"));
            }
        }
        return savedCredentials;
    }
}

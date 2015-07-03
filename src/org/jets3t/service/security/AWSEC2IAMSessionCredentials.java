/*
 * JetS3t : Java S3 Toolkit
 * Project hosted at http://bitbucket.org/jmurty/jets3t/
 *
 * Copyright 2006-2015 James Murty
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
package org.jets3t.service.security;

import java.io.IOException;
import java.text.ParseException;
import java.util.Date;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.JsonProcessingException;
import org.codehaus.jackson.map.ObjectMapper;
import org.jets3t.service.utils.RestUtils;
import org.jets3t.service.utils.ServiceUtils;

/**
 * Class to fetch, re-fetch, and contain the temporary (session-based)
 * Amazon Web Services (AWS) credentials of an Identity and Access Management
 * (IAM) role provided via EC2 instance data.
 *
 * @author James Murty
 */
public class AWSEC2IAMSessionCredentials extends AWSSessionCredentials {

    private static final Log log = LogFactory.getLog(AWSEC2IAMSessionCredentials.class);

    protected String roleName = null;
    protected Date expiration = null;
    protected boolean automaticRefreshEnabled = true;

    /**
     * Construct credentials.
     *
     * @param awsAccessKey
     * AWS access key for an Amazon S3 account.
     * @param awsSecretAccessKey
     * AWS secret key for an Amazon S3 account.
     * @param sessionToken
     * AWS session token for temporary/session-based account credentials.
     * @param roleName
     * IAM role name from which session credentials were loaded.
     * @param expiration
     * Expiration date of session credentials.
     * @param automaticRefreshEnabled
     * if true, credentials will be automatically refreshed when session
     * token expiration is within 15 minutes
     */
    public AWSEC2IAMSessionCredentials(
        String awsAccessKey, String awsSecretAccessKey, String sessionToken,
        String roleName, Date expiration, boolean automaticRefreshEnabled)
    {
        super(awsAccessKey, awsSecretAccessKey, sessionToken, null);
        this.roleName = roleName;
        this.expiration = expiration;
        this.automaticRefreshEnabled = automaticRefreshEnabled;
    }

    @Override
    protected String getTypeName() {
        return "ec2-iam-session";
    }

    /**
     * @return
     * if true, credentials will be automatically refreshed when session
     * token expiration is within 15 minutes
     */
    public boolean isAutomaticRefreshEnabled() {
        return this.automaticRefreshEnabled;
    }

    /**
     * @return
     * The AWS session token for temporary/session-based account credentials.
     */
    @Override
    public String getSessionToken() {
        refreshFromEC2InstanceDataIfNearExpiration();
        return this.sessionToken;
    }

    /**
     * @return
     * the Access Key.
     */
    @Override
    public String getAccessKey() {
        refreshFromEC2InstanceDataIfNearExpiration();
        return accessKey;
    }

    /**
     * @return
     * the Secret Key.
     */
    @Override
    public String getSecretKey() {
        refreshFromEC2InstanceDataIfNearExpiration();
        return secretKey;
    }

    /**
     * @return
     * IAM role name from which session credentials were loaded.
     */
    public String getRoleName() {
        refreshFromEC2InstanceDataIfNearExpiration();
        return roleName;
    }

    /**
     * @return
     * expiration date of session token.
     */
    public Date getExpiration() {
        refreshFromEC2InstanceDataIfNearExpiration();
        return expiration;
    }

    /**
     * @return
     * true if the expiration date from {@link #getExpiration()} is
     * 15 minutes or less from the current time.
     */
    public boolean isNearExpiration() {
        Date now = new Date();
        long difference = expiration.getTime() - now.getTime();
        long diffOf15MinsInMS = 15 * 60 * 1000;
        return difference <= diffOf15MinsInMS;
    }

    /**
     * Fetch IAM role credentials from EC2 instance data and re-populate
     * this object.
     */
    public void refreshFromEC2InstanceData() {
        AWSEC2IAMSessionCredentials loadedCredentials =
            AWSEC2IAMSessionCredentials.loadFromEC2InstanceData(
                this.roleName, this.automaticRefreshEnabled);
        this.accessKey = loadedCredentials.getAccessKey();
        this.secretKey = loadedCredentials.getSecretKey();
        this.sessionToken = loadedCredentials.getSessionToken();
        this.expiration = loadedCredentials.getExpiration();
    }

    /**
     * If {@link #isAutomaticRefreshEnabled()} and {@link #isNearExpiration()}
     * fetch the latest IAM role credentials from EC2 instance data and
     * re-populate this object (via {@link #refreshFromEC2InstanceData()}.
     */
    public synchronized void refreshFromEC2InstanceDataIfNearExpiration() {
        if (this.automaticRefreshEnabled && this.isNearExpiration()) {
            try {
                this.refreshFromEC2InstanceData();
            } catch (Exception ex) {
                log.warn("Failed to automatically refresh IAM role credentials"
                         + " from EC2 instance data", ex);
            }
        }
    }

    /**
     * Fetch AWS session credentials from EC2 instance data available at the
     * given URL prefix (in case you are using a EC2-like service with
     * alternate instance data endpoint) with the given role name.
     *
     * @param urlPrefix
     * URL prefix for EC2 instance data. If you are using plain EC2 you should
     * prefer the simpler {@link #loadFromEC2InstanceData(String, boolean)}
     * constructor.
     * @param roleName
     * Name of the IAM role provided in the EC2 to supply S3 access credentials
     * @param automaticRefreshEnabled
     * if true, the returned credentials object will automatically refresh
     * the session token and credentials if they are nearly expired
     * @return
     * populated credentials object
     */
    public static AWSEC2IAMSessionCredentials loadFromEC2InstanceData(
        String urlPrefix, String roleName, boolean automaticRefreshEnabled)
    {
        try {
            // Construct complete URL to EC2 IAM instance data including role name
            String url = urlPrefix;
            if (!url.endsWith("/")) {
                url += "/";
            }
            url += roleName;

            String iamRoleData = RestUtils.httpGetUrlAsString(url);

            return AWSEC2IAMSessionCredentials.parseEC2InstanceData(
                iamRoleData, roleName, automaticRefreshEnabled);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * Fetch AWS session credentials from EC2 instance data available
     * with the given role name.
     *
     * Instance data is expected at the default EC2 endpoint:
     * http://169.254.169.254/latest/meta-data/iam/security-credentials/<roleName>
     *
     * @param roleName
     * Name of the IAM role provided in the EC2 to supply S3 access credentials
     * @param automaticRefreshEnabled
     * if true, the returned credentials object will automatically refresh
     * the session token and credentials if they are nearly expired
     * @return
     * populated credentials object
     */
    public static AWSEC2IAMSessionCredentials loadFromEC2InstanceData(
        String roleName, boolean automaticRefreshEnabled)
    {
        return AWSEC2IAMSessionCredentials.loadFromEC2InstanceData(
            "http://169.254.169.254/latest/meta-data/iam/security-credentials",
            roleName, automaticRefreshEnabled);
    }

    /**
     * Parse AWS session credentials from the IAM role JSON blob returned from
     * a lookup of the EC2 instance data service.
     *
     * NOTE: This method is not intended for general use, it's only public
     * to aid testing.
     *
     * @param iamRoleData
     * @param roleName
     * @param automaticRefreshEnabled
     * @return
     * populated credentials object
     * @throws JsonProcessingException
     * @throws IOException
     * @throws ParseException
     */
    public static AWSEC2IAMSessionCredentials parseEC2InstanceData(
        String iamRoleData, String roleName, boolean automaticRefreshEnabled)
        throws JsonProcessingException, IOException, ParseException
    {
        ObjectMapper jsonMapper = new ObjectMapper();
        JsonNode node = jsonMapper.readTree(iamRoleData);
        String resultCode = node.findValuesAsText("Code").get(0);

        if (!resultCode.equals("Success")) {
            throw new RuntimeException("Status 'Code' != 'Success'");
        }

        String accessKey = node.findValuesAsText("AccessKeyId").get(0);
        String secretKey = node.findValuesAsText("SecretAccessKey").get(0);
        String sessionToken = node.findValuesAsText("Token").get(0);
        Date expiration = ServiceUtils.parseIso8601Date(
            node.findValuesAsText("Expiration").get(0));

        return new AWSEC2IAMSessionCredentials(
            accessKey, secretKey, sessionToken, roleName, expiration,
            automaticRefreshEnabled);
    }

}

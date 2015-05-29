package org.jets3t.service.security;

import java.io.IOException;
import java.text.ParseException;
import java.util.Date;

import org.codehaus.jackson.JsonProcessingException;
import org.jets3t.service.utils.ServiceUtils;

import junit.framework.TestCase;

public class AWSEC2IAMSessionCredentialsTest extends TestCase {

    public void testParseEC2InstanceDataSuccess()
        throws JsonProcessingException, IOException, ParseException
    {
        String iamRoleData =
            "{\n" +
            "  \"Code\" : \"Success\",\n" +
            "  \"LastUpdated\" : \"2012-04-26T16:39:16Z\",\n" +
            "  \"Type\" : \"AWS-HMAC\",\n" +
            "  \"AccessKeyId\" : \"ABCDEFGHIJKLMNOP\",\n" +
            "  \"SecretAccessKey\" : \"afsdjkafsjdklajfdksa;jfkd;afjdks\",\n" +
            "  \"Token\" : \"TokeNtOkEn\",\n" +
            "  \"Expiration\" : \"2015-05-29T13:32:52Z\"\n" +
            "}";

        AWSEC2IAMSessionCredentials credentials =
            AWSEC2IAMSessionCredentials.parseEC2InstanceData(
                iamRoleData, "thisIsARole", false);

        this.assertEquals("ABCDEFGHIJKLMNOP", credentials.getAccessKey());
        this.assertEquals("afsdjkafsjdklajfdksa;jfkd;afjdks", credentials.getSecretKey());
        this.assertEquals("TokeNtOkEn", credentials.getSessionToken());
        this.assertEquals(
            ServiceUtils.parseIso8601Date("2015-05-29T13:32:52Z"),
            credentials.getExpiration());
        this.assertEquals("thisIsARole", credentials.getRoleName());
        this.assertFalse(credentials.isAutomaticRefreshEnabled());
    }

    public void testParseEC2InstanceDataError()
        throws JsonProcessingException, IOException, ParseException
    {
        String iamRoleData =
            "{\n" +
            "  \"Code\" : \"UhOhNoes\",\n" +
            "  \"LastUpdated\" : \"2012-04-26T16:39:16Z\",\n" +
            "  \"Type\" : \"AWS-HMAC\",\n" +
            "  \"AccessKeyId\" : \"ABCDEFGHIJKLMNOP\",\n" +
            "  \"SecretAccessKey\" : \"afsdjkafsjdklajfdksa;jfkd;afjdks\",\n" +
            "  \"Token\" : \"TokeNtOkEn\",\n" +
            "  \"Expiration\" : \"2015-05-29T13:32:52Z\"\n" +
            "}";

        try {
            AWSEC2IAMSessionCredentials.parseEC2InstanceData(
                iamRoleData, "thisIsARole", false);
            this.fail("Expected failure");
        } catch (RuntimeException ex) {
            this.assertEquals("Status 'Code' != 'Success'", ex.getMessage());
        }
    }

}

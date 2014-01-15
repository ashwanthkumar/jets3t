package org.jets3t.apps.utils;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

import org.jets3t.service.S3Service;
import org.jets3t.service.impl.rest.httpclient.RestS3Service;
import org.jets3t.service.model.MultipartUpload;
import org.jets3t.service.security.AWSCredentials;
import org.jets3t.service.security.AWSDevPayCredentials;

/**
 * Simple command-line utility to delete lingering in-progress Multipart
 * Upload parts from S3 when they pass a given age, since they are
 * probably orphaned uploads that will never be completed.
 *
 * @author jmurty
 */
public class DeleteMultipartUploads {

    public static void main(String[] args) throws Exception {
        // Get required information from command line arguments
        if (args.length != 4 && args.length != 6) {
            System.err.println("Required arguments: "
                + "<BucketName> <HoursAgo> <AWSAccessKey> <AWSSecretKey> "
                + "[ <DevPayUserToken> <DevPayProductToken> ]");
            System.exit(1);
        }
        String bucketName = args[0];
        int hoursAgo = Integer.parseInt(args[1]);
        String accessKey = args[2];
        String secretKey = args[3];

        // Create DevPay credentials and a service that uses them.
        AWSCredentials credentials = null;
        if (args.length == 4) {
            credentials = new AWSCredentials(accessKey, secretKey);
        } else {
            String userToken = args[4];
            String productToken = args[5];
            credentials = new AWSDevPayCredentials(accessKey, secretKey, userToken, productToken);
        }
        S3Service service = new RestS3Service(credentials);

        // Find all current multipart uploads
        List<MultipartUpload> multipartUploads =
            service.multipartListUploads(bucketName);

        // Identify only multipart uploads older than a certain date
        // (to try and avoid killing off an in-progress upload)
        long CUTOFF = System.currentTimeMillis() - (hoursAgo * 60 * 60 * 1000);
        List<MultipartUpload> oldMultipartUploads = new ArrayList<MultipartUpload>();
        for (MultipartUpload multipartUpload: multipartUploads) {
            if (multipartUpload.getInitiatedDate().getTime() < CUTOFF) {
                oldMultipartUploads.add(multipartUpload);
            }
        }
        System.out.println("Of " + multipartUploads.size() + " multipart upload(s) in "
            + bucketName + ", " + oldMultipartUploads.size() + " are older than "
            + hoursAgo + " hours ago");

        // If no candidates for deletion, no work to do
        if (oldMultipartUploads.size() < 1) {
            return;
        }

        // Prompt user to confirm deletion
        System.out.print("About to delete " + oldMultipartUploads.size()
            + " multipart uploads, is this OK? (y/n) ");
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        String response = br.readLine();
        if (!"y".equals(response.toLowerCase()) && !"yes".equals(response.toLowerCase())) {
            System.out.println("Aborting");
            return;
        }

        // Delete old multipart uploads
        for (MultipartUpload multipartUpload: oldMultipartUploads) {
            System.out.print("Deleting (aborting) " + multipartUpload + " ...");
            service.multipartAbortUpload(multipartUpload);
            System.out.println(" done.");
        }
    }

}

/*
 * jets3t : Java Extra-Tasty S3 Toolkit (for Amazon S3 online storage service)
 * This is a java.net project, see https://jets3t.dev.java.net/
 * 
 * Copyright 2006 James Murty
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
package org.jets3t.service.utils.signedurl;

import org.jets3t.service.S3Service;
import org.jets3t.service.S3ServiceException;
import org.jets3t.service.acl.AccessControlList;
import org.jets3t.service.model.S3Object;

/**
 * Interface for classes that can manage objects in S3 using only signed URLs. Such a class nees no
 * knowledge of S3 as such, but merely has to be able to perform the HTTP PUT, GET, HEAD or DELETE
 * operation corresponding to the signed URL.
 * 
 * @author James Murty
 */
public interface SignedUrlHandler {

    /**
     * Puts an object using a pre-signed PUT URL generated for that object.
     * This method is an implementation of the interface {@link SignedUrlHandler}. 
     * <p>
     * This operation does not required any S3 functionality as it merely 
     * uploads the object by performing a standard HTTP PUT using the signed URL.
     * 
     * @param signedPutUrl
     * a signed PUT URL generated with {@link S3Service.createSignedPutUrl()}.
     * @param object
     * the object to upload, which must correspond to the object for which the URL was signed.
     * The object <b>must</b> have the correct content length set, and to apply a non-standard
     * ACL policy only the REST canned ACLs can be used
     * (eg {@link AccessControlList.REST_CANNED_PUBLIC_READ_WRITE}). 
     * 
     * @return
     * the S3Object put to S3. The S3Object returned will be identical to the object provided, 
     * except that the data input stream (if any) will have been consumed.
     * 
     * @throws S3ServiceException
     */
    public S3Object putObjectWithSignedUrl(String signedPutUrl, S3Object object) throws S3ServiceException;

    /**
     * Deletes an object using a pre-signed DELETE URL generated for that object.
     * This method is an implementation of the interface {@link SignedUrlHandler}. 
     * <p>
     * This operation does not required any S3 functionality as it merely 
     * deletes the object by performing a standard HTTP DELETE using the signed URL.
     * 
     * @param signedDeleteUrl
     * a signed DELETE URL generated with {@link S3Service.createSignedDeleteUrl}.
     * 
     * @throws S3ServiceException
     */
    public void deleteObjectWithSignedUrl(String signedDeleteUrl) throws S3ServiceException;
    
    /**
     * Gets an object using a pre-signed GET URL generated for that object.
     * This method is an implementation of the interface {@link SignedUrlHandler}. 
     * <p>
     * This operation does not required any S3 functionality as it merely 
     * uploads the object by performing a standard HTTP GET using the signed URL.
     * 
     * @param signedGetUrl
     * a signed GET URL generated with {@link S3Service.createSignedGetUrl()}.
     * 
     * @return
     * the S3Object in S3 including all metadata and the object's data input stream.
     * 
     * @throws S3ServiceException
     */
    public S3Object getObjectWithSignedUrl(String signedGetUrl) throws S3ServiceException;
    
    /**
     * Gets an object's details using a pre-signed HEAD URL generated for that object.
     * This method is an implementation of the interface {@link SignedUrlHandler}. 
     * <p>
     * This operation does not required any S3 functionality as it merely 
     * uploads the object by performing a standard HTTP HEAD using the signed URL.
     * 
     * @param signedHeadUrl
     * a signed HEAD URL generated with {@link S3Service.createSignedHeadUrl()}.
     * 
     * @return
     * the S3Object in S3 including all metadata, but without the object's data input stream.
     * 
     * @throws S3ServiceException
     */
    public S3Object getObjectDetailsWithSignedUrl(String signedHeadUrl) throws S3ServiceException;
    
}
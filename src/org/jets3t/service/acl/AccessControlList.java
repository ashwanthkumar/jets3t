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
package org.jets3t.service.acl;

import com.jamesmurty.utils.XMLBuilder;

import org.jets3t.service.Constants;
import org.jets3t.service.S3ServiceException;
import org.jets3t.service.model.S3Owner;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.xml.parsers.FactoryConfigurationError;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

/**
 * Represents an Amazon S3 Access Control List (ACL), including the ACL's set of grantees and the
 * permissions assigned to each grantee.
 * <p>
 *
 * </p>
 *
 * @author James Murty
 *
 */
public class AccessControlList implements Serializable {
    private static final long serialVersionUID = 8095040648034788376L;

    /**
     * A pre-canned REST ACL to set an object's permissions to Private (only owner can read/write)
     */
    public static final AccessControlList REST_CANNED_PRIVATE = new AccessControlList();

    /**
     * A pre-canned REST ACL to set an object's permissions to Public Read (anyone can read, only owner
     * can write)
     */
    public static final AccessControlList REST_CANNED_PUBLIC_READ = new AccessControlList();

    /**
     * A pre-canned REST ACL to set an object's permissions to Public Read and Write (anyone can
     * read/write)
     */
    public static final AccessControlList REST_CANNED_PUBLIC_READ_WRITE = new AccessControlList();

    /**
     * A pre-canned REST ACL to set an object's permissions to Authenticated Read (authenticated Amazon
     * users can read, only owner can write)
     */
    public static final AccessControlList REST_CANNED_AUTHENTICATED_READ = new AccessControlList();

    protected final HashSet grants = new HashSet();
    protected S3Owner owner = null;

    /**
     * Returns a string representation of the ACL contents, useful for debugging.
     */
    public String toString() {
        return "AccessControlList [owner=" + owner + ", grants=" + getGrants() + "]";
    }

    public S3Owner getOwner() {
        return owner;
    }

    public void setOwner(S3Owner owner) {
        this.owner = owner;
    }

    /**
     * Adds a grantee to the ACL with the given permission. If this ACL already contains the grantee
     * (ie the same grantee object) the permission for the grantee will be updated.
     *
     * @param grantee
     *        the grantee to whom the permission will apply
     * @param permission
     *        the permission to apply to the grantee.
     */
    public void grantPermission(GranteeInterface grantee, Permission permission) {
        grants.add(new GrantAndPermission(grantee, permission));
    }

    /**
     * Adds a set of grantee/permission pairs to the ACL, where each item in the set is a
     * {@link GrantAndPermission} object.
     *
     * @deprecated Version 0.7.4, use type-safe
     * {@link #grantAllPermissions(GrantAndPermission[])} instead.
     *
     * @param grants
     * a set of {@link GrantAndPermission} objects
     */
    public void grantAllPermissions(Set grants) {
        for (Iterator iter = grants.iterator(); iter.hasNext();) {
            GrantAndPermission gap = (GrantAndPermission) iter.next();
            grantPermission(gap.getGrantee(), gap.getPermission());
        }
    }

    /**
     * Adds a set of grantee/permission pairs to the ACL, where each item in the set is a
     * {@link GrantAndPermission} object.
     *
     * @param grantAndPermissions
     * the grant and permission combinations to add.
     */
    public void grantAllPermissions(GrantAndPermission[] grantAndPermissions) {
        for (int i = 0; i < grantAndPermissions.length; i++) {
            GrantAndPermission gap = grantAndPermissions[i];
            grantPermission(gap.getGrantee(), gap.getPermission());
        }
    }

    /**
     * Revokes the permissions of a grantee by removing the grantee from the ACL.
     *
     * @param grantee
     *        the grantee to remove from this ACL.
     */
    public void revokeAllPermissions(GranteeInterface grantee) {
        ArrayList grantsToRemove = new ArrayList();
        for (Iterator iter = grants.iterator(); iter.hasNext();) {
            GrantAndPermission gap = (GrantAndPermission) iter.next();
            if (gap.getGrantee().equals(grantee)) {
                grantsToRemove.add(gap);
            }
        }
        grants.removeAll(grantsToRemove);
    }

    /**
     * @deprecated Version 0.7.4, use type-safe
     * {@link #getGrantAndPermissions()} instead
     *
     * @return
     * the set of {@link GrantAndPermission} objects in this ACL.
     */
    public Set getGrants() {
        return grants;
    }

    /**
     * @return
     * the grant and permission collections in this ACL.
     */
    public GrantAndPermission[] getGrantAndPermissions() {
        return (GrantAndPermission[]) grants.toArray(
            new GrantAndPermission[grants.size()]);
    }

    public XMLBuilder toXMLBuilder() throws S3ServiceException, ParserConfigurationException,
        FactoryConfigurationError, TransformerException
    {
        if (owner == null) {
            throw new S3ServiceException("Invalid AccessControlList: missing an S3Owner");
        }
        XMLBuilder builder = XMLBuilder.create("AccessControlPolicy")
            .attr("xmlns", Constants.XML_NAMESPACE)
            .elem("Owner")
                .elem("ID").text(owner.getId()).up()
                .elem("DisplayName").text(owner.getDisplayName()).up()
            .up();

        XMLBuilder accessControlList = builder.elem("AccessControlList");
        Iterator grantIter = grants.iterator();
        while (grantIter.hasNext()) {
            GrantAndPermission gap = (GrantAndPermission) grantIter.next();
            GranteeInterface grantee = gap.getGrantee();
            Permission permission = gap.getPermission();
            accessControlList
                .elem("Grant")
                    .importXMLBuilder(grantee.toXMLBuilder())
                    .elem("Permission").text(permission.toString());
        }
        return builder;
    }

    /**
     * @return
     * an XML representation of the Access Control List object, suitable to send in a request to S3.
     */
    public String toXml() throws S3ServiceException {
        try {
            return toXMLBuilder().asString();
        } catch (Exception e) {
            throw new S3ServiceException("Failed to build XML document for ACL", e);
        }
    }

    /**
     * @return
     * true if this ACL is a REST pre-canned one, in which case REST/HTTP implementations can use
     * the <tt>x-amz-acl</tt> header as a short-cut to set permissions on upload rather than using
     * a full ACL XML document.
     */
    public boolean isCannedRestACL() {
        return (this.equals(AccessControlList.REST_CANNED_AUTHENTICATED_READ)
            || this.equals(AccessControlList.REST_CANNED_PRIVATE)
            || this.equals(AccessControlList.REST_CANNED_PUBLIC_READ)
            || this.equals(AccessControlList.REST_CANNED_PUBLIC_READ_WRITE));
    }

}

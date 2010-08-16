/*
 * JetS3t : Java S3 Toolkit
 * Project hosted at http://bitbucket.org/jmurty/jets3t/
 *
 * Copyright 2007 James Murty
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
package org.jets3t.service.impl.rest;

import org.jets3t.service.acl.AccessControlList;
import org.jets3t.service.acl.AllAuthenticatedUsersGrantee;
import org.jets3t.service.acl.AllUsersGrantee;
import org.jets3t.service.acl.CanonicalGrantee;
import org.jets3t.service.acl.GSAccessControlList;
import org.jets3t.service.acl.GroupByDomainGrantee;
import org.jets3t.service.acl.GroupByEmailAddressGrantee;
import org.jets3t.service.acl.GroupByIdGrantee;
import org.jets3t.service.acl.Permission;
import org.jets3t.service.acl.UserByEmailAddressGrantee;
import org.jets3t.service.acl.UserByIdGrantee;
import org.jets3t.service.model.S3Owner;
import org.xml.sax.Attributes;

/**
  * Handler for GSAccessControlList response XML documents.
  * The document is parsed into an {@link AccessControlList} object available via the
  * {@link #getAccessControlList()} method.
  *
  * @author Google Developers
  *
  */
public class GSAccessControlListHandler extends AccessControlListHandler {

   protected String scopeType = null;

   public void startElement(String name, Attributes attrs) {
       if (name.equals("Owner")) {
           owner = new S3Owner();
       } else if (name.equals("Entries")) {
           accessControlList = new GSAccessControlList();
           accessControlList.setOwner(owner);
           insideACL = true;
       } else if (name.equals("Scope")) {
           scopeType = attrs.getValue("type");
           if (scopeType.equals("UserById")) {
               currentGrantee = new UserByIdGrantee();
           } else if (scopeType.equals("UserByEmail")) {
               currentGrantee = new UserByEmailAddressGrantee();
           } else if (scopeType.equals("GroupById")) {
               currentGrantee = new GroupByIdGrantee();
           } else if (scopeType.equals("GroupByEmail")) {
               currentGrantee = new GroupByEmailAddressGrantee();
           } else if (scopeType.equals("GroupByDomain")) {
               currentGrantee = new GroupByDomainGrantee();
           } else if (scopeType.equals("AllUsers")) {
               currentGrantee = new AllUsersGrantee();
           } else if (scopeType.equals("AllAuthenticatedUsers")) {
               currentGrantee = new AllAuthenticatedUsersGrantee();
           }
       }
   }

   public void endElement(String name, String elementText) {
       // Owner details.
       if (name.equals("ID") && !insideACL) {
           owner.setId(elementText);
       } else if (name.equals("Name") && !insideACL) {
           owner.setDisplayName(elementText);
       }
       // ACL details.
       else if (name.equals("ID")) {
           currentGrantee.setIdentifier(elementText);
       } else if (name.equals("EmailAddress")) {
           currentGrantee.setIdentifier(elementText);
       } else if (name.equals("URI")) {
           currentGrantee.setIdentifier(elementText);
       } else if (name.equals("Name")) {
           ((CanonicalGrantee) currentGrantee).setDisplayName(elementText);
       } else if (name.equals("Permission")) {
           currentPermission = Permission.parsePermission(elementText);
       } else if (name.equals("Entry")) {
           accessControlList.grantPermission(currentGrantee, currentPermission);
       } else if (name.equals("Entries")) {
           insideACL = false;
       }
   }
}

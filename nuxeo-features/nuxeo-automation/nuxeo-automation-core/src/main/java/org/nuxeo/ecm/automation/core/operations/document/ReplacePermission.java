/*
 * (C) Copyright 2015 Nuxeo SA (http://nuxeo.com/) and contributors.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl-2.1.html
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * Contributors:
 *     Vladimir Pasquier <vpasquier@nuxeo.com>
 */
package org.nuxeo.ecm.automation.core.operations.document;

import java.io.Serializable;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

import org.nuxeo.ecm.automation.core.Constants;
import org.nuxeo.ecm.automation.core.annotations.Context;
import org.nuxeo.ecm.automation.core.annotations.Operation;
import org.nuxeo.ecm.automation.core.annotations.OperationMethod;
import org.nuxeo.ecm.automation.core.annotations.Param;
import org.nuxeo.ecm.automation.core.collectors.DocumentModelCollector;
import org.nuxeo.ecm.core.api.ClientException;
import org.nuxeo.ecm.core.api.CoreSession;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.DocumentRef;
import org.nuxeo.ecm.core.api.security.ACE;
import org.nuxeo.ecm.core.api.security.ACL;

/**
 * Replaces a given ACE.
 *
 * @since 7.10
 */
@Operation(id = ReplacePermission.ID, category = Constants.CAT_DOCUMENT, label = "Replace Permission", description = "Replace a given permission on the input document(s). Returns the document(s).")
public class ReplacePermission {

    public static final String ID = "Document.ReplacePermission";

    public static final String NOTIFY_KEY = "notify";

    public static final String COMMENT_KEY = "comment";

    @Context
    protected CoreSession session;

    @Param(name = "username", alias = "user", description = "ACE target user/group.")
    protected String user;

    @Param(name = "permission", description = "ACE permission.")
    String permission;

    @Param(name = "acl", required = false, values = { ACL.LOCAL_ACL }, description = "ACL name.")
    String aclName = ACL.LOCAL_ACL;

    @Param(name = "begin", required = false, description = "ACE begin date.")
    Calendar begin;

    @Param(name = "end", required = false, description = "ACE end date.")
    Calendar end;

    @Param(name = "id", description = "ACE id.")
    String id;

    @Param(name = "notify", required = false, description = "Notify the user or not")
    Boolean notify;

    @Param(name = "comment", required = false, description = "Comment")
    String comment;

    @OperationMethod(collector = DocumentModelCollector.class)
    public DocumentModel run(DocumentModel doc) throws ClientException {
        replacePermission(doc);
        return session.getDocument(doc.getRef());
    }

    @OperationMethod(collector = DocumentModelCollector.class)
    public DocumentModel run(DocumentRef docRef) throws ClientException {
        DocumentModel doc = session.getDocument(docRef);
        replacePermission(doc);
        return doc;
    }

    protected void replacePermission(DocumentModel doc) throws ClientException {
        Map<String, Serializable> contextData = new HashMap<>();
        if (notify != null && notify) {
            contextData.put(NOTIFY_KEY, true);
            if (comment != null) {
                contextData.put(COMMENT_KEY, comment);
            }
        }

        ACE oldACE = ACE.fromId(id);

        ACE newACE = ACE.builder(user, permission)
                        .creator(session.getPrincipal().getName())
                        .begin(begin)
                        .end(end)
                        .contextData(contextData)
                        .build();

        session.replaceACE(doc.getRef(), aclName, oldACE, newACE);
    }

}
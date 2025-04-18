// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.rest.v1;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.ws.rs.core.Response;

import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.netscape.security.pkcs.PKCS7;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.CertPrettyPrint;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.pkcs11.PK11Cert;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.certsrv.base.UserNotFoundException;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.group.GroupMemberData;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.ConfigRoleEvent;
import com.netscape.certsrv.user.UserCertCollection;
import com.netscape.certsrv.user.UserCertData;
import com.netscape.certsrv.user.UserCollection;
import com.netscape.certsrv.user.UserData;
import com.netscape.certsrv.user.UserMembershipCollection;
import com.netscape.certsrv.user.UserMembershipData;
import com.netscape.certsrv.user.UserResource;
import com.netscape.certsrv.usrgrp.EUsrGrpException;
import com.netscape.cms.password.PasswordChecker;
import com.netscape.cms.servlet.admin.GroupMemberProcessor;
import com.netscape.cms.servlet.base.SubsystemService;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.usrgrp.Group;
import com.netscape.cmscore.usrgrp.UGSubsystem;
import com.netscape.cmscore.usrgrp.User;

/**
 * @author Endi S. Dewata
 */
public class UserService extends SubsystemService implements UserResource {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(UserService.class);

    public final static String BACK_SLASH = "\\";
    public final static String SYSTEM_USER = "$System$";

    public UserData createUserData(User user) throws Exception {

        UserData userData = new UserData();

        String userID = user.getUserID();
        if (!StringUtils.isEmpty(userID)) {
            userData.setID(userID);
            userData.setUserID(userID);
        }

        String fullName = user.getFullName();
        if (!StringUtils.isEmpty(fullName)) userData.setFullName(fullName);

        return userData;
    }

    /**
     * Searches for users in LDAP directory.
     *
     * Request/Response Syntax:
     * http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     */
    @Override
    public Response findUsers(String filter, Integer start, Integer size) {

        if (filter != null && filter.length() < MIN_FILTER_LENGTH) {
            throw new BadRequestException("Filter is too short.");
        }

        start = start == null ? 0 : start;
        size = size == null ? DEFAULT_SIZE : size;

        UserCollection response = new UserCollection();

        try {
            CMSEngine engine = getCMSEngine();
            UGSubsystem userGroupManager = engine.getUGSubsystem();
            Enumeration<User> users = userGroupManager.findUsersByKeyword(filter);

            int i = 0;

            // skip to the start of the page
            for ( ; i<start && users.hasMoreElements(); i++) users.nextElement();

            // return entries up to the page size
            for ( ; i<start+size && users.hasMoreElements(); i++) {
                User user = users.nextElement();
                response.addEntry(createUserData(user));
            }

            // count the total entries
            for ( ; users.hasMoreElements(); i++) users.nextElement();
            response.setTotal(i);

            return createOKResponse(response);

        } catch (EUsrGrpException e) {
            // Workaround for ticket #914.
            // If no users found, return empty result.
            if (CMS.getUserMessage("CMS_USRGRP_USER_NOT_FOUND").equals(e.getMessage())) {
                logger.debug("UserService.findUsers(): " + e.getMessage());
                return createOKResponse(response);
            }

            logger.error("UserService: " + e.getMessage(), e);
            throw new PKIException(e);

        } catch (Exception e) {
            logger.error("UserService: " + e.getMessage(), e);
            throw new PKIException(e);
        }
    }

    /**
     * List user information. Certificates covered in a separate
     * protocol for findUserCerts(). List of group memberships are
     * also provided.
     *
     * Request/Response Syntax:
     * http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     */
    @Override
    public Response getUser(String userID) {
        return createOKResponse(getUserData(userID));
    }

    public UserData getUserData(String userID) {
        try {
            if (userID == null) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID", headers));
            }

            CMSEngine engine = getCMSEngine();
            EngineConfig cs = engine.getConfig();
            UGSubsystem userGroupManager = engine.getUGSubsystem();
            User user;

            try {
                user = userGroupManager.getUser(userID);
            } catch (Exception e) {
                throw new PKIException(getUserMessage("CMS_INTERNAL_ERROR", headers));
            }

            if (user == null) {
                logger.error(CMS.getLogMessage("USRGRP_SRVLT_USER_NOT_EXIST"));
                throw new UserNotFoundException(userID);
            }

            UserData userData = createUserData(user);

            String email = user.getEmail();
            if (!StringUtils.isEmpty(email)) userData.setEmail(email);

            String phone = user.getPhone();
            if (!StringUtils.isEmpty(phone)) userData.setPhone(phone);

            String state = user.getState();
            if (!StringUtils.isEmpty(state)) userData.setState(state);

            String type = user.getUserType();
            if (!StringUtils.isEmpty(type)) userData.setType(type);

            // TODO: refactor into TPSUserService
            String csType = engine.getName();
            if (csType.equals("TPS")) {

                List<String> profiles = user.getTpsProfiles();
                if (profiles != null) {
                    StringBuilder sb = new StringBuilder();
                    String prefix = "";
                    for (String profile: profiles) {
                        sb.append(prefix);
                        prefix = ",";
                        sb.append(profile);
                    }

                    userData.setAttribute(ATTR_TPS_PROFILES, sb.toString());
                }
            }

            return userData;

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            throw new PKIException(e.getMessage());
        }
    }

    /**
     * Adds a new user to LDAP server
     * <P>
     *
     * Request/Response Syntax: http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_ROLE used when configuring role information (anything under
     * users/groups)
     * </ul>
     * @throws UnsupportedEncodingException
     */

    @Override
    public Response addUser(UserData userData) {

        logger.debug("UserService.addUser()");

        if (userData == null) throw new BadRequestException("User data is null.");

        String userID = userData.getUserID();
        logger.debug("User ID: " + userID);

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            if (userID == null) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID", headers));
            }

            if (userID.indexOf(BACK_SLASH) != -1) {
                // backslashes (BS) are not allowed
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_RS_ID_BS"));
                throw new BadRequestException(getUserMessage("CMS_ADMIN_SRVLT_RS_ID_BS", headers));
            }

            if (userID.equals(SYSTEM_USER)) {
                // backslashes (BS) are not allowed
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_SPECIAL_ID", userID));
                throw new ForbiddenException(getUserMessage("CMS_ADMIN_SRVLT_SPECIAL_ID", headers, userID));
            }

            CMSEngine engine = getCMSEngine();
            EngineConfig cs = engine.getConfig();
            UGSubsystem userGroupManager = engine.getUGSubsystem();
            User user = userGroupManager.createUser(userID);

            String fname = userData.getFullName();
            logger.debug("Full name: " + fname);

            if (fname == null || fname.length() == 0) {
                String msg = getUserMessage("CMS_USRGRP_USER_ADD_FAILED_1", headers, "full name");
                logger.error(msg);
                throw new BadRequestException(msg);
            }
            user.setFullName(fname);

            String email = userData.getEmail();
            logger.debug("Email: " + email);

            if (email != null) {
                user.setEmail(email);
            } else {
                user.setEmail("");
            }

            String pword = userData.getPassword();
            logger.debug("Password: " + (pword == null ? null : "********"));

            if (pword != null && !pword.equals("")) {
                PasswordChecker passwdCheck = engine.getPasswordChecker();

                if (!passwdCheck.isGoodPassword(pword)) {
                    throw new EUsrGrpException(passwdCheck.getReason());
                }

                user.setPassword(pword);
            } else {
                user.setPassword("");
            }

            String phone = userData.getPhone();
            logger.debug("Phone: " + phone);

            if (phone != null) {
                user.setPhone(phone);
            } else {
                user.setPhone("");
            }

            String type = userData.getType();
            logger.debug("Type: " + type);

            if (type != null) {
                user.setUserType(type);
            } else {
                user.setUserType("");
            }

            String state = userData.getState();
            logger.debug("State: " + state);

            if (state != null) {
                user.setState(state);
            }

            // TODO: refactor into TPSUserService
            String csType = engine.getName();
            if (csType.equals("TPS")) {

                String tpsProfiles = userData.getAttribute(ATTR_TPS_PROFILES);
                logger.debug("TPS profiles: " + tpsProfiles);
                if (tpsProfiles != null) { // update profiles if specified

                    String[] profiles;
                    if (StringUtils.isEmpty(tpsProfiles)) {
                        profiles = new String[0];
                    } else {
                        profiles = tpsProfiles.split(",");
                    }

                    user.setTpsProfiles(Arrays.asList(profiles));
                }
            }

            userGroupManager.addUser(user);

            auditAddUser(userID, userData, ILogger.SUCCESS);

            // read the data back
            userData = getUserData(userID);

            String encodedUserID = URLEncoder.encode(userID, "UTF-8");
            URI uri = uriInfo
                    .getBaseUriBuilder()
                    .path(UserResource.class)
                    .path("{userID}")
                    .build(encodedUserID);
            return createCreatedResponse(userData, uri);

        } catch (PKIException e) {
            auditAddUser(userID, userData, ILogger.FAILURE);
            throw e;

        } catch (EBaseException | UnsupportedEncodingException e) {
            auditAddUser(userID, userData, ILogger.FAILURE);
            throw new PKIException(e.getMessage());
        }
    }

    /**
     * Modifies an existing user in local scope.
     * <P>
     *
     * Request/Response Syntax: http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_ROLE used when configuring role information (anything under
     * users/groups)
     * </ul>
     */
    @Override
    public Response modifyUser(String userID, UserData userData) {

        logger.debug("UserService.modifyUser(" + userID + ")");

        if (userData == null) throw new BadRequestException("User data is null.");

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            if (userID == null) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID", headers));
            }

            CMSEngine engine = getCMSEngine();
            EngineConfig cs = engine.getConfig();
            UGSubsystem userGroupManager = engine.getUGSubsystem();
            User user = userGroupManager.createUser(userID);

            String fullName = userData.getFullName();
            logger.debug("Full name: " + fullName);
            if (fullName != null) {
                user.setFullName(fullName);
            }

            String email = userData.getEmail();
            logger.debug("Email: " + email);
            if (email != null) {
                user.setEmail(email);
            }

            String pword = userData.getPassword();
            if (pword != null && !pword.equals("")) {
                PasswordChecker passwdCheck = engine.getPasswordChecker();

                if (!passwdCheck.isGoodPassword(pword)) {
                    throw new EUsrGrpException(passwdCheck.getReason());
                }

                user.setPassword(pword);
            }

            String phone = userData.getPhone();
            logger.debug("Phone: " + phone);
            if (phone != null) {
                user.setPhone(phone);
            }

            String state = userData.getState();
            logger.debug("State: " + state);
            if (state != null) {
                user.setState(state);
            }

            // TODO: refactor into TPSUserService
            String csType = engine.getName();
            if (csType.equals("TPS")) {

                String tpsProfiles = userData.getAttribute(ATTR_TPS_PROFILES);
                logger.debug("TPS Profiles: " + tpsProfiles);
                if (tpsProfiles != null) { // update profiles if specified

                    String[] profiles;
                    if (StringUtils.isEmpty(tpsProfiles)) {
                        profiles = new String[0];
                    } else {
                        profiles = tpsProfiles.split(",");
                    }

                    user.setTpsProfiles(Arrays.asList(profiles));
                }
            }

            userGroupManager.modifyUser(user);

            auditModifyUser(userID, userData, ILogger.SUCCESS);

            // read the data back
            userData = getUserData(userID);

            return createOKResponse(userData);

        } catch (PKIException e) {
            auditModifyUser(userID, userData, ILogger.FAILURE);
            throw e;

        } catch (EBaseException e) {
            auditModifyUser(userID, userData, ILogger.FAILURE);
            throw new PKIException(e.getMessage());
        }
    }

    /**
     * removes a user. user not removed if belongs to any group
     * (Administrators should remove the user from "uniquemember" of
     * any group he/she belongs to before trying to remove the user
     * itself.
     * <P>
     *
     * Request/Response Syntax: http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_ROLE used when configuring role information (anything under
     * users/groups)
     * </ul>
     */
    @Override
    public Response removeUser(String userID) {

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            if (userID == null) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID", headers));
            }

            // get list of groups, and see if uid belongs to any
            CMSEngine engine = getCMSEngine();
            UGSubsystem userGroupManager = engine.getUGSubsystem();
            Enumeration<Group> groups = userGroupManager.findGroups("*");

            while (groups.hasMoreElements()) {
                Group group = groups.nextElement();
                if (!group.isMember(userID)) continue;

                userGroupManager.removeUserFromGroup(group, userID);
            }

            // comes out clean of group membership...now remove user
            userGroupManager.removeUser(userID);

            auditDeleteUser(userID, ILogger.SUCCESS);

            return createNoContentResponse();

        } catch (PKIException e) {
            auditDeleteUser(userID, ILogger.FAILURE);
            throw e;

        } catch (EBaseException e) {
            auditDeleteUser(userID, ILogger.FAILURE);
            throw new PKIException(e.getMessage());
        }
    }

    public UserCertData createUserCertData(String userID, X509Certificate cert) throws Exception {

        UserCertData userCertData = new UserCertData();

        userCertData.setVersion(cert.getVersion());
        userCertData.setSerialNumber(new CertId(cert.getSerialNumber()));
        userCertData.setIssuerDN(cert.getIssuerDN().toString());
        userCertData.setSubjectDN(cert.getSubjectDN().toString());

        userID = URLEncoder.encode(userID, "UTF-8");

        return userCertData;
    }

    /**
     * List user certificate(s)
     *
     * Request/Response Syntax:
     * http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     */
    @Override
    public Response findUserCerts(String userID, Integer start, Integer size) {
        try {
            start = start == null ? 0 : start;
            size = size == null ? DEFAULT_SIZE : size;

            if (userID == null) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID", headers));
            }

            CMSEngine engine = getCMSEngine();
            UGSubsystem userGroupManager = engine.getUGSubsystem();
            User user = null;

            try {
                user = userGroupManager.getUser(userID);
            } catch (Exception e) {
                throw new PKIException(getUserMessage("CMS_USRGRP_SRVLT_USER_NOT_EXIST", headers));
            }

            if (user == null) {
                logger.error(CMS.getLogMessage("USRGRP_SRVLT_USER_NOT_EXIST"));
                throw new UserNotFoundException(userID);
            }

            X509Certificate[] certs = user.getX509Certificates();
            if (certs == null) certs = new X509Certificate[0];
            Iterator<X509Certificate> entries = Arrays.asList(certs).iterator();

            UserCertCollection response = new UserCertCollection();
            int i = 0;

            // skip to the start of the page
            for ( ; i<start && entries.hasNext(); i++) entries.next();

            // return entries up to the page size
            for ( ; i<start+size && entries.hasNext(); i++) {
                response.addEntry(createUserCertData(userID, entries.next()));
            }

            // count the total entries
            for ( ; entries.hasNext(); i++) entries.next();
            response.setTotal(i);

            return createOKResponse(response);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            throw new PKIException(e.getMessage());
        }
    }

    @Override
    public Response getUserCert(String userID, String certID) {
        return createOKResponse(getUserCertData(userID, certID));
    }

    public UserCertData getUserCertData(String userID, String certID) {

        if (certID == null) throw new BadRequestException("Certificate ID is null.");

        try {
            if (userID == null) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID", headers));
            }

            CMSEngine engine = getCMSEngine();
            UGSubsystem userGroupManager = engine.getUGSubsystem();
            User user = null;

            try {
                user = userGroupManager.getUser(userID);
            } catch (Exception e) {
                throw new PKIException(getUserMessage("CMS_USRGRP_SRVLT_USER_NOT_EXIST", headers));
            }

            if (user == null) {
                logger.error(CMS.getLogMessage("USRGRP_SRVLT_USER_NOT_EXIST"));
                throw new UserNotFoundException(userID);
            }

            X509Certificate[] certs = user.getX509Certificates();

            if (certs == null) {
                throw new ResourceNotFoundException("No certificates found for " + userID);
            }

            try {
                certID = URLDecoder.decode(certID, "UTF-8");
            } catch (Exception e) {
                throw new PKIException(e.getMessage());
            }

            for (X509Certificate cert : certs) {

                UserCertData userCertData = createUserCertData(userID, cert);

                if (!userCertData.getID().equals(certID)) continue;

                CertPrettyPrint print = new CertPrettyPrint(cert);
                userCertData.setPrettyPrint(print.toString(getLocale(headers)));

                // add base64 encoding
                String base64 = CertUtil.toPEM(cert);
                userCertData.setEncoded(base64);

                return userCertData;
            }

            throw new ResourceNotFoundException("No certificates found for " + userID);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            throw new PKIException(e.getMessage());
        }
    }

    /**
     * Adds a certificate to a user
     * <P>
     *
     * Request/Response Syntax: http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_ROLE used when configuring role information (anything under
     * users/groups)
     * </ul>
     */
    @Override
    public Response addUserCert(String userID, UserCertData userCertData) {

        if (userCertData == null) throw new BadRequestException("Certificate data is null.");

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            if (userID == null) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID", headers));
            }

            CMSEngine engine = getCMSEngine();
            UGSubsystem userGroupManager = engine.getUGSubsystem();
            User user = userGroupManager.createUser(userID);

            String encoded = userCertData.getEncoded();

            // no cert is a success
            if (encoded == null) {
                auditAddUserCert(userID, userCertData, ILogger.SUCCESS);
                return createOKResponse();
            }

            // only one cert added per operation
            X509Certificate cert = null;

            // Base64 decode cert
            byte binaryCert[] = Cert.parseCertificate(encoded);

            try {
                cert = new X509CertImpl(binaryCert);

            } catch (CertificateException e) {
                logger.warn("UserService: Submitted data is not an X.509 certificate: " + e.getMessage(), e);
                // ignore
            }

            if (cert == null) {
                // TODO: Remove this code. Importing PKCS #7 is not supported.

                // cert chain direction
                boolean assending = true;

                // could it be a pkcs7 blob?
                logger.debug("UserService: " + CMS.getLogMessage("ADMIN_SRVLT_IS_PK_BLOB"));

                try {
                    CryptoManager manager = CryptoManager.getInstance();

                    PKCS7 pkcs7 = new PKCS7(binaryCert);

                    X509Certificate p7certs[] = pkcs7.getCertificates();

                    if (p7certs.length == 0) {
                        logger.error("UserService: PKCS #7 data contains no certificates");
                        throw new BadRequestException("PKCS #7 data contains no certificates");
                    }

                    // fix for 370099 - cert ordering can not be assumed
                    // find out the ordering ...

                    // self-signed and alone? take it. otherwise test
                    // the ordering
                    if (p7certs[0].getSubjectDN().toString().equals(
                            p7certs[0].getIssuerDN().toString()) &&
                            (p7certs.length == 1)) {
                        cert = p7certs[0];
                        logger.debug("UserService: " + CMS.getLogMessage("ADMIN_SRVLT_SINGLE_CERT_IMPORT"));

                    } else if (p7certs[0].getIssuerDN().toString().equals(p7certs[1].getSubjectDN().toString())) {
                        cert = p7certs[0];
                        logger.debug("UserService: " + CMS.getLogMessage("ADMIN_SRVLT_CERT_CHAIN_ACEND_ORD"));

                    } else if (p7certs[1].getIssuerDN().toString().equals(p7certs[0].getSubjectDN().toString())) {
                        assending = false;
                        logger.debug("UserService: " + CMS.getLogMessage("ADMIN_SRVLT_CERT_CHAIN_DESC_ORD"));
                        cert = p7certs[p7certs.length - 1];

                    } else {
                        // not a chain, or in random order
                        logger.error("UserService: " + CMS.getLogMessage("ADMIN_SRVLT_CERT_BAD_CHAIN"));
                        throw new BadRequestException(getUserMessage("CMS_USRGRP_SRVLT_CERT_ERROR", headers));
                    }

                    logger.debug("UserService: "
                            + CMS.getLogMessage("ADMIN_SRVLT_CHAIN_STORED_DB", String.valueOf(p7certs.length)));

                    int j = 0;
                    int jBegin = 0;
                    int jEnd = 0;

                    if (assending == true) {
                        jBegin = 1;
                        jEnd = p7certs.length;
                    } else {
                        jBegin = 0;
                        jEnd = p7certs.length - 1;
                    }

                    // store the chain into cert db, except for the user cert
                    for (j = jBegin; j < jEnd; j++) {
                        logger.debug("UserService: "
                                + CMS.getLogMessage("ADMIN_SRVLT_CERT_IN_CHAIN", String.valueOf(j),
                                        String.valueOf(p7certs[j].getSubjectDN())));
                        org.mozilla.jss.crypto.X509Certificate leafCert =
                                manager.importCACertPackage(p7certs[j].getEncoded());

                        if (leafCert == null) {
                            logger.warn("UserService: missing leaf certificate");
                            logger.error(CMS.getLogMessage("ADMIN_SRVLT_LEAF_CERT_NULL"));
                        } else {
                            logger.debug("UserService: " + CMS.getLogMessage("ADMIN_SRVLT_LEAF_CERT_NON_NULL"));
                        }

                        if (leafCert instanceof PK11Cert) {
                            leafCert.setSSLTrust(
                                    PK11Cert.VALID_CA |
                                    PK11Cert.TRUSTED_CA |
                                    PK11Cert.TRUSTED_CLIENT_CA);
                        } else {
                            logger.error(CMS.getLogMessage("ADMIN_SRVLT_NOT_INTERNAL_CERT",
                                    String.valueOf(p7certs[j].getSubjectDN())));
                        }
                    }

                    /*
                    } catch (CryptoManager.UserCertConflictException e) {
                        // got a "user cert" in the chain, most likely the CA
                        // cert of this instance, which has a private key.  Ignore
                        logger.error(CMS.getLogMessage("ADMIN_SRVLT_PKS7_IGNORED", e.toString()));
                    */
                } catch (PKIException e) {
                    logger.error("UserService: Unable to import user certificate from PKCS #7 data: " + e);
                    logger.error(CMS.getLogMessage("USRGRP_SRVLT_CERT_ERROR", e.toString()));
                    throw e;

                } catch (Exception e) {
                    logger.error("UserService: " + e.getMessage(), e);
                    logger.error(CMS.getLogMessage("USRGRP_SRVLT_CERT_ERROR", e.toString()));
                    throw new PKIException("Unable to import user certificate from PKCS #7 data: " + e.getMessage(), e);
                }
            }

            try {
                logger.debug("UserService: " + CMS.getLogMessage("ADMIN_SRVLT_BEFORE_VALIDITY"));
                cert.checkValidity(); // throw exception if fails

                user.setX509Certificates(new X509Certificate[] { cert });
                userGroupManager.addUserCert(userID, cert);

                auditAddUserCert(userID, userCertData, ILogger.SUCCESS);

                // read the data back

                userCertData.setVersion(cert.getVersion());
                userCertData.setSerialNumber(new CertId(cert.getSerialNumber()));
                userCertData.setIssuerDN(cert.getIssuerDN().toString());
                userCertData.setSubjectDN(cert.getSubjectDN().toString());
                String certID = userCertData.getID();

                String encodedCertID = URLEncoder.encode(certID, "UTF-8");
                userCertData = getUserCertData(userID, encodedCertID);
                String encodedUserID = URLEncoder.encode(userID, "UTF-8");
                URI uri = uriInfo
                        .getBaseUriBuilder()
                        .path(UserResource.class)
                        .path("{userID}/certs/{certID}")
                        .build(encodedUserID, encodedCertID);
                return createCreatedResponse(userCertData, uri);

            } catch (CertificateExpiredException e) {
                logger.error("UserService: Certificate expired: " + e.getMessage(), e);
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_ADD_CERT_EXPIRED",
                        String.valueOf(cert.getSubjectDN())));
                throw new BadRequestException("Certificate expired: " + e.getMessage(), e);

            } catch (CertificateNotYetValidException e) {
                logger.error("UserService: Certificate not yet valid: " + e.getMessage(), e);
                logger.error(CMS.getLogMessage("USRGRP_SRVLT_CERT_NOT_YET_VALID",
                        String.valueOf(cert.getSubjectDN())));
                throw new BadRequestException("Certificate not yet valid: " + e.getMessage(), e);
            }

        } catch (PKIException e) {
            logger.error("UserService: Unable to import user certificate: " + e.getMessage(), e);
            auditAddUserCert(userID, userCertData, ILogger.FAILURE);
            throw e;

        } catch (Exception e) {
            logger.error("UserService: " + e.getMessage(), e);
            auditAddUserCert(userID, userCertData, ILogger.FAILURE);
            throw new PKIException("Unable to import user certificate: " + e.getMessage(), e);
        }
    }

    /**
     * Removes a certificate for a user
     * <P>
     *
     * Request/Response Syntax: http://warp.mcom.com/server/certificate/columbo/design/
     * ui/admin-protocol-definition.html#user-admin
     * <P>
     *
     * In this method, "certDN" is actually a combination of version, serialNumber, issuerDN, and SubjectDN.
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_ROLE used when configuring role information (anything under
     * users/groups)
     * </ul>
     */
    @Override
    public Response removeUserCert(String userID, String certID) {

        if (userID == null) throw new BadRequestException("User ID is null.");
        if (certID == null) throw new BadRequestException("Certificate ID is null.");

        try {
            certID = URLDecoder.decode(certID, "UTF-8");
        } catch (Exception e) {
            throw new PKIException(e.getMessage());
        }

        UserCertData userCertData = new UserCertData();
        userCertData.setID(certID);
        removeUserCert(userID, userCertData);

        return createNoContentResponse();
    }

    public void removeUserCert(String userID, UserCertData userCertData) {

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            if (userID == null) {
                logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
                throw new BadRequestException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID", headers));
            }

            CMSEngine engine = getCMSEngine();
            UGSubsystem userGroupManager = engine.getUGSubsystem();
            String certID = userCertData.getID();

            // no certDN is a success
            if (certID == null) {
                auditDeleteUserCert(userID, userCertData, ILogger.SUCCESS);
                return;
            }

            userGroupManager.removeUserCert(userID, certID);

            auditDeleteUserCert(userID, userCertData, ILogger.SUCCESS);

        } catch (PKIException e) {
            auditDeleteUserCert(userID, userCertData, ILogger.FAILURE);
            throw e;

        } catch (Exception e) {
            logger.error("Error: " + e.getMessage(), e);
            auditDeleteUserCert(userID, userCertData, ILogger.FAILURE);
            throw new PKIException(getUserMessage("CMS_USRGRP_USER_MOD_FAILED", headers));
        }
    }


    public UserMembershipData createUserMembershipData(String userID, String groupID) {

        UserMembershipData userMembershipData = new UserMembershipData();
        userMembershipData.setID(groupID);
        userMembershipData.setUserID(userID);

        return userMembershipData;
    }

    @Override
    public Response findUserMemberships(String userID, String filter, Integer start, Integer size) {

        logger.debug("UserService.findUserMemberships(" + userID + ", " + filter + ")");

        if (userID == null) {
            logger.error(CMS.getLogMessage("ADMIN_SRVLT_NULL_RS_ID"));
            throw new BadRequestException(getUserMessage("CMS_ADMIN_SRVLT_NULL_RS_ID", headers));
        }

        if (filter != null && filter.length() < 3) {
            throw new BadRequestException("Filter is too short.");
        }

        start = start == null ? 0 : start;
        size = size == null ? DEFAULT_SIZE : size;

        try {
            CMSEngine engine = getCMSEngine();
            UGSubsystem userGroupManager = engine.getUGSubsystem();
            User user = userGroupManager.getUser(userID);

            if (user == null) {
                logger.error(CMS.getLogMessage("USRGRP_SRVLT_USER_NOT_EXIST"));
                throw new UserNotFoundException(userID);
            }

            Enumeration<Group> groups = userGroupManager.findGroupsByUser(user.getUserDN(), filter);

            UserMembershipCollection response = new UserMembershipCollection();
            int i = 0;

            // skip to the start of the page
            for ( ; i<start && groups.hasMoreElements(); i++) groups.nextElement();

            // return entries up to the page size
            for ( ; i<start+size && groups.hasMoreElements(); i++) {
                Group group = groups.nextElement();
                response.addEntry(createUserMembershipData(userID, group.getName()));
            }

            // count the total entries
            for ( ; groups.hasMoreElements(); i++) groups.nextElement();
            response.setTotal(i);

            return createOKResponse(response);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage(), e);
        }
    }

    @Override
    public Response addUserMembership(String userID, String groupID) {

        if (userID == null) throw new BadRequestException("User ID is null.");
        if (groupID == null) throw new BadRequestException("Group ID is null.");

        CMSEngine engine = getCMSEngine();
        User user = null;

        try {
            UGSubsystem userGroupManager = engine.getUGSubsystem();
            user = userGroupManager.getUser(userID);
        } catch (Exception e) {
            throw new PKIException(getUserMessage("CMS_USRGRP_SRVLT_USER_NOT_EXIST", headers));
        }

        if (user == null) {
            logger.error(CMS.getLogMessage("USRGRP_SRVLT_USER_NOT_EXIST"));
            throw new UserNotFoundException(userID);
        }

        try {
            GroupMemberData groupMemberData = new GroupMemberData();
            groupMemberData.setID(userID);
            groupMemberData.setGroupID(groupID);

            GroupMemberProcessor processor = new GroupMemberProcessor(getLocale(headers));
            processor.setCMSEngine(engine);
            processor.init();

            processor.setUriInfo(uriInfo);
            processor.addGroupMember(groupMemberData);

            UserMembershipData userMembershipData = createUserMembershipData(userID, groupID);

            URI uri = uriInfo
                    .getBaseUriBuilder()
                    .path(UserResource.class)
                    .path("{userID}/memberships/{groupID}")
                    .build(URLEncoder.encode(userID, "UTF-8"),
                            URLEncoder.encode(groupID, "UTF-8"));
            return createCreatedResponse(userMembershipData, uri);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage(), e);
        }
    }

    @Override
    public Response removeUserMembership(String userID, String groupID) {

        if (userID == null) throw new BadRequestException("User ID is null.");
        if (groupID == null) throw new BadRequestException("Group ID is null.");

        try {
            GroupMemberProcessor processor = new GroupMemberProcessor(getLocale(headers));
            processor.setCMSEngine(getCMSEngine());
            processor.init();

            processor.setUriInfo(uriInfo);
            processor.removeGroupMember(groupID, userID);

            return createNoContentResponse();

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException(e.getMessage(), e);
        }
    }

    public void auditAddUser(String id, UserData userData, String status) {
        auditUser(OpDef.OP_ADD, id, getParams(userData), status);
    }

    public void auditModifyUser(String id, UserData userData, String status) {
        auditUser(OpDef.OP_MODIFY, id, getParams(userData), status);
    }

    public void auditDeleteUser(String id, String status) {
        auditUser(OpDef.OP_DELETE, id, null, status);
    }

    public void auditAddUserCert(String id, UserCertData userCertData, String status) {
        auditUserCert(OpDef.OP_ADD, id, getParams(userCertData), status);
    }

    public void auditDeleteUserCert(String id, UserCertData userCertData, String status) {
        auditUserCert(OpDef.OP_DELETE, id, getParams(userCertData), status);
    }

    public void auditUser(String type, String id, Map<String, String> params, String status) {

        CMSEngine engine = getCMSEngine();
        Auditor auditor = engine.getAuditor();

        auditor.log(new ConfigRoleEvent(
                auditor.getSubjectID(),
                status,
                auditor.getParamString(ScopeDef.SC_USERS, type, id, params)));
    }

    public void auditUserCert(String type, String id, Map<String, String> params, String status) {

        CMSEngine engine = getCMSEngine();
        Auditor auditor = engine.getAuditor();

        auditor.log(new ConfigRoleEvent(
                auditor.getSubjectID(),
                status,
                auditor.getParamString(ScopeDef.SC_USER_CERTS, type, id, params)));
    }
}

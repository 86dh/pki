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
// (C) 2011 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.kra.rest.v1;

import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.kra.KRAEngine;
import org.mozilla.jss.crypto.SymmetricKey;

import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.authorization.EAuthzUnknownRealm;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.base.RESTMessage;
import com.netscape.certsrv.base.UnauthorizedException;
import com.netscape.certsrv.dbs.keydb.KeyId;
import com.netscape.certsrv.key.AsymKeyGenerationRequest;
import com.netscape.certsrv.key.KeyArchivalRequest;
import com.netscape.certsrv.key.KeyRecoveryRequest;
import com.netscape.certsrv.key.KeyRequestInfo;
import com.netscape.certsrv.key.KeyRequestInfoCollection;
import com.netscape.certsrv.key.KeyRequestResource;
import com.netscape.certsrv.key.KeyRequestResponse;
import com.netscape.certsrv.key.SymKeyGenerationRequest;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.AsymKeyGenerationEvent;
import com.netscape.certsrv.logging.event.SecurityDataArchivalRequestEvent;
import com.netscape.certsrv.logging.event.SecurityDataRecoveryEvent;
import com.netscape.certsrv.logging.event.SecurityDataRecoveryStateChangeEvent;
import com.netscape.certsrv.logging.event.SymKeyGenerationEvent;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestNotFoundException;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cms.servlet.base.SubsystemService;
import com.netscape.cms.servlet.key.KeyRequestDAO;
import com.netscape.cmscore.authorization.AuthzSubsystem;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmsutil.ldap.LDAPUtil;

/**
 * @author alee
 *
 */
public class KeyRequestService extends SubsystemService implements KeyRequestResource {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(KeyRequestService.class);

    public static final int DEFAULT_START = 0;
    public static final int DEFAULT_PAGESIZE = 20;
    public static final int DEFAULT_MAXRESULTS = 100;
    public static final int DEFAULT_MAXTIME = 10;

    public static final Map<String, SymmetricKey.Type> SYMKEY_TYPES;
    static {
        SYMKEY_TYPES = new HashMap<>();
        SYMKEY_TYPES.put(KeyRequestResource.DES_ALGORITHM, SymmetricKey.DES);
        SYMKEY_TYPES.put(KeyRequestResource.DESEDE_ALGORITHM, SymmetricKey.DES3);
        SYMKEY_TYPES.put(KeyRequestResource.DES3_ALGORITHM, SymmetricKey.DES3);
        SYMKEY_TYPES.put(KeyRequestResource.RC2_ALGORITHM, SymmetricKey.RC2);
        SYMKEY_TYPES.put(KeyRequestResource.RC4_ALGORITHM, SymmetricKey.RC4);
        SYMKEY_TYPES.put(KeyRequestResource.AES_ALGORITHM, SymmetricKey.AES);
    }

    /**
     * Used to retrieve key request info for a specific request
     */
    @Override
    public Response getRequestInfo(RequestId id) {
        if (id == null) {
            logger.error("getRequestInfo: is is null");
            throw new BadRequestException("Unable to get Request: invalid ID");
        }
        // auth and authz
        KeyRequestDAO dao = new KeyRequestDAO();
        KeyRequestInfo info;
        try {
            info = dao.getRequest(id, uriInfo, getAuthToken());
        } catch (EAuthzAccessDenied e) {
            throw new UnauthorizedException("Not authorized to get request");
        } catch (EBaseException e) {
            // log error
            e.printStackTrace();
            throw new PKIException(e.getMessage(), e);
        }
        if (info == null) {
            // request does not exist
            throw new RequestNotFoundException(id);
        }
        return createOKResponse(info);
    }

    public Response archiveKey(KeyArchivalRequest data) throws Exception {
        // auth and authz
        // Catch this before internal server processing has to deal with it

        if (data == null) {
            throw new BadRequestException("Missing key archival request");
        }

        logger.debug("Request:\n" + data.toJSON());

        if (data.getClientKeyId() == null || data.getDataType() == null) {
            throw new BadRequestException("Invalid key archival request.");
        }

        String algorithmOID = data.getAlgorithmOID();
        logger.info("KeyRequestService: algorithm OID: " + algorithmOID);

        if (data.getWrappedPrivateData() != null) {
            if (data.getTransWrappedSessionKey() == null ||
                algorithmOID == null ||
                data.getSymmetricAlgorithmParams() == null) {
                throw new BadRequestException(
                        "Invalid key archival request.  " +
                        "Missing wrapped session key, algoriithmOIS or symmetric key parameters");
            }
        } else if (data.getPKIArchiveOptions() == null) {
            throw new BadRequestException(
                    "Invalid key archival request.  No data to archive");
        }

        String dataType = data.getDataType();
        logger.info("KeyRequestService: data type: " + dataType);

        String keyAlgorithm = data.getKeyAlgorithm();
        logger.info("KeyRequestService: key algorithm: " + keyAlgorithm);

        if (dataType.equals(KeyRequestResource.SYMMETRIC_KEY_TYPE) &&
                (keyAlgorithm == null || !SYMKEY_TYPES.containsKey(keyAlgorithm))) {
            throw new BadRequestException("Invalid symmetric key algorithm: " + keyAlgorithm);
        }

        KRAEngine engine = (KRAEngine) getCMSEngine();
        Auditor auditor = engine.getAuditor();

        KeyRequestDAO dao = new KeyRequestDAO();
        KeyRequestResponse response;
        try {
            if (getRequestor() == null) {
                throw new UnauthorizedException("Archival must be performed by an agent");
            }

            String realm = data.getRealm();
            if (realm != null) {
                AuthzSubsystem authz = engine.getAuthzSubsystem();
                authz.checkRealm(realm, getAuthToken(), null, "certServer.kra.requests.archival", "execute");
            }
            response = dao.submitRequest(data, uriInfo, getRequestor());

            auditor.log(SecurityDataArchivalRequestEvent.createSuccessEvent(
                    getRequestor(),
                    null,
                    response.getRequestInfo().getRequestID(),
                    data.getClientKeyId()));

            logger.debug("Response:\n" + response.toJSON());

            return createCreatedResponse(response, new URI(response.getRequestInfo().getRequestURL()));

        } catch (EAuthzAccessDenied e) {

            auditor.log(SecurityDataArchivalRequestEvent.createFailureEvent(
                    getRequestor(),
                    null,
                    null,
                    data.getClientKeyId(),
                    e));

            throw new UnauthorizedException("Not authorized to generate request in this realm", e);

        } catch (EAuthzUnknownRealm e) {

            auditor.log(SecurityDataArchivalRequestEvent.createFailureEvent(
                    getRequestor(),
                    null,
                    null,
                    data.getClientKeyId(),
                    e));
            throw new BadRequestException("Invalid realm", e);

        } catch (EBaseException | URISyntaxException e) {

            auditor.log(SecurityDataArchivalRequestEvent.createFailureEvent(
                    getRequestor(),
                    null,
                    null,
                    data.getClientKeyId(),
                    e));

            throw new PKIException(e.toString(), e);
        }
    }

    public Response recoverKey(KeyRecoveryRequest data) {
        // auth and authz

        //Check for entirely illegal data combination here
        //Catch this before the internal server processing has to deal with it
        //If data has been provided, we need at least the wrapped session key,
        //or the command is invalid.

        KeyRequestDAO dao = new KeyRequestDAO();
        KeyRequestResponse response;
        try {
            response = (data.getCertificate() != null)?
                    dao.submitAsyncKeyRecoveryRequest(data, uriInfo, getRequestor(), getAuthToken()):
                    dao.submitRequest(data, uriInfo, getRequestor(), getAuthToken());
            auditRecoveryRequestMade(response.getRequestInfo().getRequestID(),
                    ILogger.SUCCESS, data.getKeyId());

            return createCreatedResponse(response, new URI(response.getRequestInfo().getRequestURL()));

        } catch (EBaseException | URISyntaxException e) {
            e.printStackTrace();
            auditRecoveryRequestMade(null, ILogger.FAILURE, data.getKeyId());
            throw new PKIException(e.toString(), e);
        }
    }

    @Override
    public Response approveRequest(RequestId id) {
        if (id == null) {
            throw new BadRequestException("Invalid request id.");
        }
        KeyRequestDAO dao = new KeyRequestDAO();
        if (getRequestor() == null) {
            throw new UnauthorizedException("Request approval must be initiated by an agent");
        }
        try {
            dao.approveRequest(id, getRequestor(), getAuthToken());
            auditRecoveryRequestChange(id, ILogger.SUCCESS, "approve");
        } catch (EAuthzAccessDenied e) {
            throw new UnauthorizedException("Not authorized to approve request", e);
        } catch (EBaseException e) {
            e.printStackTrace();
            auditRecoveryRequestChange(id, ILogger.FAILURE, "approve");
            throw new PKIException(e.toString(), e);
        }

        return createNoContentResponse();
    }

    @Override
    public Response rejectRequest(RequestId id) {
        if (id == null) {
            throw new BadRequestException("Invalid request id.");
        }
        // auth and authz
        KeyRequestDAO dao = new KeyRequestDAO();
        try {
            dao.rejectRequest(id, getAuthToken());
            auditRecoveryRequestChange(id, ILogger.SUCCESS, "reject");
        }catch (EAuthzAccessDenied e) {
            throw new UnauthorizedException("Not authorized to reject request", e);
        } catch (EBaseException e) {
            e.printStackTrace();
            auditRecoveryRequestChange(id, ILogger.FAILURE, "reject");
            throw new PKIException(e.toString(), e);
        }

        return createNoContentResponse();
    }

    @Override
    public Response cancelRequest(RequestId id) {
        if (id == null) {
            throw new BadRequestException("Invalid request id.");
        }
        // auth and authz
        KeyRequestDAO dao = new KeyRequestDAO();
        try {
            dao.cancelRequest(id, getAuthToken());
            auditRecoveryRequestChange(id, ILogger.SUCCESS, "cancel");
        } catch (EAuthzAccessDenied e) {
            throw new UnauthorizedException("Not authorized to cancel request", e);
        } catch (EBaseException e) {
            e.printStackTrace();
            auditRecoveryRequestChange(id, ILogger.FAILURE, "cancel");
            throw new PKIException(e.toString(), e);
        }

        return createNoContentResponse();
    }

    /**
     * Used to generate list of key requests based on the search parameters
     */
    @Override
    public Response listRequests(String requestState, String requestType, String clientKeyID,
            RequestId start, Integer pageSize, Integer maxResults, Integer maxTime, String realm) {

        logger.info("KeyRequestService: Listing key requests");

        logger.debug("KeyRequestService: request state: " + requestState);
        logger.debug("KeyRequestService: request type: " + requestType);
        logger.debug("KeyRequestService: client key ID: " + clientKeyID);
        logger.debug("KeyRequestService: realm: " + realm);

        KRAEngine engine = (KRAEngine) getCMSEngine();

        if (realm != null) {
            try {
                AuthzSubsystem authz = engine.getAuthzSubsystem();
                authz.checkRealm(realm, getAuthToken(), null, "certServer.kra.requests", "list");
            } catch (EAuthzAccessDenied e) {
                throw new UnauthorizedException("Not authorized to list these requests", e);
            } catch (EAuthzUnknownRealm e) {
                throw new BadRequestException("Invalid realm", e);
            } catch (EBaseException e) {
                logger.error("KeyRequestService: Unable to authorize realm: " + e.getMessage(), e);
                throw new PKIException(e.toString(), e);
            }
        }

        // get ldap filter
        String filter = createSearchFilter(requestState, requestType, clientKeyID, realm);
        logger.debug("KeyRequestService: filter: " + filter);

        start = start == null ? new RequestId(KeyRequestService.DEFAULT_START) : start;
        pageSize = pageSize == null ? DEFAULT_PAGESIZE : pageSize;
        maxResults = maxResults == null ? DEFAULT_MAXRESULTS : maxResults;
        maxTime = maxTime == null ? DEFAULT_MAXTIME : maxTime;

        KeyRequestDAO reqDAO = new KeyRequestDAO();
        KeyRequestInfoCollection requests;
        try {
            requests = reqDAO.listRequests(filter, start, pageSize, maxResults, maxTime, uriInfo);
        } catch (EBaseException e) {
            logger.error("KeyRequestService: Unable to obtain request results: " + e.getMessage(), e);
            throw new PKIException(e.toString(), e);
        }

        return createOKResponse(requests);
    }

    private String createSearchFilter(String requestState, String requestType, String clientKeyID,
            String realm) {
        String filter = "";
        int matches = 0;

        if ((requestState == null) && (requestType == null) && (clientKeyID == null)) {
            filter = "(requeststate=*)";
            matches ++;
        }

        if (requestState != null) {
            filter += "(requeststate=" + LDAPUtil.escapeFilter(requestState) + ")";
            matches++;
        }

        if (requestType != null) {
            filter += "(requesttype=" + LDAPUtil.escapeFilter(requestType) + ")";
            matches++;
        }

        if (clientKeyID != null) {
            filter += "(clientID=" + LDAPUtil.escapeFilter(clientKeyID) + ")";
            matches++;
        }

        if (realm != null) {
            filter += "(realm=" + LDAPUtil.escapeFilter(realm) + ")";
            matches++;
        } else {
            filter += "(!(realm=*))";
            matches++;
        }

        if (matches > 1) {
            filter = "(&" + filter + ")";
        }

        return filter;
    }

    public void auditRecoveryRequestChange(RequestId requestId, String status, String operation) {
        Auditor auditor = getCMSEngine().getAuditor();
        auditor.log(new SecurityDataRecoveryStateChangeEvent(
                getRequestor(),
                status,
                requestId,
                operation));
    }

    public void auditRecoveryRequestMade(RequestId requestId, String status, KeyId dataId) {
        Auditor auditor = getCMSEngine().getAuditor();
        auditor.log(new SecurityDataRecoveryEvent(
                getRequestor(),
                status,
                requestId,
                dataId,
                null));
    }

    public void auditSymKeyGenRequestMade(RequestId requestId, String status, String clientKeyID) {
        Auditor auditor = getCMSEngine().getAuditor();
        auditor.log(new SymKeyGenerationEvent(
                getRequestor(),
                status,
                requestId,
                clientKeyID));
    }

    public void auditAsymKeyGenRequestMade(RequestId requestId, String status, String clientKeyID) {
        Auditor auditor = getCMSEngine().getAuditor();
        auditor.log(new AsymKeyGenerationEvent(
                getRequestor(),
                status,
                requestId,
                clientKeyID));
    }

    @Override
    public Response submitRequest(MultivaluedMap<String, String> form) throws Exception {
        RESTMessage data = new RESTMessage(form);
        return submitRequest(data);
    }

    @Override
    public Response submitRequest(RESTMessage data) throws Exception {

        Object request = null;

        try {
            Class<?> requestClazz = Class.forName(data.getClassName());
            request = requestClazz.getDeclaredConstructor(RESTMessage.class).newInstance(data);
        } catch (ClassNotFoundException | NoSuchMethodException | SecurityException | InstantiationException
                | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            throw new BadRequestException("Invalid request class." + e, e);
        }

        logger.info("KeyRequestService: Request class: " + request.getClass().getSimpleName());

        if (request instanceof KeyArchivalRequest) {
            return archiveKey(new KeyArchivalRequest(data));

        } else if (request instanceof KeyRecoveryRequest) {
            return recoverKey(new KeyRecoveryRequest(data));

        } else if (request instanceof SymKeyGenerationRequest) {
            return generateSymKey(new SymKeyGenerationRequest(data));

        } else if (request instanceof AsymKeyGenerationRequest) {
            return generateAsymKey(new AsymKeyGenerationRequest(data));

        } else {
            throw new BadRequestException("Invalid request class.");
        }
    }

    public Response generateSymKey(SymKeyGenerationRequest data) {
        if (data == null) {
            throw new BadRequestException("Invalid key generation request.");
        }

        String realm = data.getRealm();

        KRAEngine engine = (KRAEngine) getCMSEngine();

        KeyRequestDAO dao = new KeyRequestDAO();
        KeyRequestResponse response;
        try {
            if (getRequestor() == null) {
                throw new UnauthorizedException("Key generation must be performed by an agent");
            }

            if (realm != null) {
                AuthzSubsystem authz = engine.getAuthzSubsystem();
                authz.checkRealm(realm, getAuthToken(), null, "certServer.kra.requests.symkey", "execute");
            }

            response = dao.submitRequest(data, uriInfo, getRequestor());
            auditSymKeyGenRequestMade(response.getRequestInfo().getRequestID(), ILogger.SUCCESS,
                    data.getClientKeyId());

            return createCreatedResponse(response, new URI(response.getRequestInfo().getRequestURL()));

        } catch (EAuthzAccessDenied e) {
            logger.error("KeyRequestService: Unauthorized access to realm " + realm, e);
            auditSymKeyGenRequestMade(null, ILogger.FAILURE, data.getClientKeyId());
            throw new UnauthorizedException("Unauthorized access to realm " + realm, e);

        } catch (EAuthzUnknownRealm e) {
            logger.error("KeyRequestService: Unknown realm: " + realm, e);
            auditSymKeyGenRequestMade(null, ILogger.FAILURE, data.getClientKeyId());
            throw new BadRequestException("Unknown realm: " + realm);

        } catch (EBaseException | URISyntaxException e) {
            logger.error("KeyRequestService: Unable to generate symmetric key: " + e.getMessage(), e);
            auditSymKeyGenRequestMade(null, ILogger.FAILURE, data.getClientKeyId());
            throw new PKIException(e.toString(), e);
        }
    }

    public Response generateAsymKey(AsymKeyGenerationRequest data) {
        if (data == null) {
            throw new BadRequestException("Invalid key generation request.");
        }

        KRAEngine engine = (KRAEngine) getCMSEngine();

        KeyRequestDAO dao = new KeyRequestDAO();
        KeyRequestResponse response;
        try {
            if (getRequestor() == null) {
                throw new UnauthorizedException("Key generation must be performed by an agent");
            }

            String realm = data.getRealm();
            if (realm != null) {
                AuthzSubsystem authz = engine.getAuthzSubsystem();
                authz.checkRealm(realm, getAuthToken(), null, "certServer.kra.requests.asymkey", "execute");
            }

            response = dao.submitRequest(data, uriInfo, getRequestor());
            auditAsymKeyGenRequestMade(response.getRequestInfo().getRequestID(), ILogger.SUCCESS,
                    data.getClientKeyId());

            return createCreatedResponse(response, new URI(response.getRequestInfo().getRequestURL()));
        } catch (EAuthzAccessDenied e) {
            auditAsymKeyGenRequestMade(null, ILogger.FAILURE, data.getClientKeyId());
            throw new UnauthorizedException("Not authorized to generate request in this realm", e);
        } catch (EAuthzUnknownRealm e) {
            auditAsymKeyGenRequestMade(null, ILogger.FAILURE, data.getClientKeyId());
            throw new BadRequestException("Invalid realm", e);
        } catch (EBaseException | URISyntaxException e) {
            e.printStackTrace();
            auditAsymKeyGenRequestMade(null, ILogger.FAILURE, data.getClientKeyId());
            throw new PKIException(e.toString(), e);
        }
    }

    private AuthToken getAuthToken() {
        Principal principal = servletRequest.getUserPrincipal();
        PKIPrincipal pkiprincipal = (PKIPrincipal) principal;
        AuthToken authToken = pkiprincipal.getAuthToken();
        return authToken;
    }

    private String getRequestor() {
        return servletRequest.getUserPrincipal().getName();
    }
}

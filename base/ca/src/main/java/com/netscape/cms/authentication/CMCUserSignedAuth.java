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
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
// package statement //
///////////////////////

package com.netscape.cms.authentication;

///////////////////////
// import statements //
///////////////////////

/* cert server imports */
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Vector;

import org.dogtagpki.server.authentication.AuthManager;
import org.dogtagpki.server.authentication.AuthManagerConfig;
import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authentication.AuthenticationConfig;
import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.dogtagpki.util.cert.CRMFUtil;
import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.BIT_STRING;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.DigestAlgorithm;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.netscape.security.extensions.CertInfo;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.KeyIdentifier;
import org.mozilla.jss.netscape.security.x509.PKIXExtensions;
import org.mozilla.jss.netscape.security.x509.SubjectKeyIdentifierExtension;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.mozilla.jss.pkcs10.CertificationRequest;
import org.mozilla.jss.pkcs11.PK11ECPublicKey;
import org.mozilla.jss.pkcs11.PK11PubKey;
import org.mozilla.jss.pkix.cert.Certificate;
import org.mozilla.jss.pkix.cert.CertificateInfo;
import org.mozilla.jss.pkix.cmc.PKIData;
import org.mozilla.jss.pkix.cmc.TaggedAttribute;
import org.mozilla.jss.pkix.cmc.TaggedCertificationRequest;
import org.mozilla.jss.pkix.cmc.TaggedRequest;
import org.mozilla.jss.pkix.cms.EncapsulatedContentInfo;
import org.mozilla.jss.pkix.cms.IssuerAndSerialNumber;
import org.mozilla.jss.pkix.cms.SignedData;
import org.mozilla.jss.pkix.cms.SignerIdentifier;
import org.mozilla.jss.pkix.crmf.CertReqMsg;
import org.mozilla.jss.pkix.crmf.CertRequest;
import org.mozilla.jss.pkix.crmf.CertTemplate;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;
import org.mozilla.jss.pkix.primitive.Name;
import org.mozilla.jss.pkix.primitive.SubjectPublicKeyInfo;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.authentication.AuthCredentials;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IExtendedPluginInfo;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.CMCUserSignedRequestSigVerifyEvent;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.request.Request;
import com.netscape.cmsutil.crypto.CryptoUtil;

//import com.netscape.cmscore.util.*;
//////////////////////
// class definition //
//////////////////////

/**
 * User Signed CMC authentication plug-in
 * note:
 * - this version differs from CMCAuth in that it allows non-agent users
 * to sign own cmc requests; It is expected to be used with
 * CMCUserSignedSubjectNameDefault and CMCUserSignedSubjectNameConstraint
 * so that the resulting cert will bear the same subjectDN of that of the CMC
 * signing cert
 * - it originates from CMCAuth with modification for user-signed cmc
 *
 * @author cfu - user signed cmc authentication
 *         <P>
 *
 * @version $Revision$, $Date$
 */
public class CMCUserSignedAuth extends AuthManager implements IExtendedPluginInfo {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CMCUserSignedAuth.class);

    ////////////////////////
    // default parameters //
    ////////////////////////

    // only one request for self-signed
    boolean selfSigned = false;
    SubjectKeyIdentifierExtension selfsign_skiExtn = null;
    PK11PubKey selfsign_pubK = null;
    byte[] selfsign_digest = null;

    /////////////////////////////
    // IAuthManager parameters //
    /////////////////////////////

    public static final String TOKEN_CERT_SERIAL = "certSerialToRevoke";
    public static final String REASON_CODE = "reasonCode";

    /* authentication plug-in fields */

    /* authentication plug-in values */

    /* authentication plug-in properties */

    /* required credentials to authenticate. UID and CMC are strings. */
    public static final String CRED_CMC = "cmcRequest";

    protected static String[] mRequiredCreds = {};

    ////////////////////////////////////
    // IExtendedPluginInfo parameters //
    ////////////////////////////////////

    /* Vector of extendedPluginInfo strings */
    protected static Vector<String> mExtendedPluginInfo = null;
    //public static final String AGENT_AUTHMGR_ID = "agentAuthMgr";
    //public static final String AGENT_PLUGIN_ID = "agentAuthPlugin";

    /* actual help messages */
    static {
        mExtendedPluginInfo = new Vector<>();

        mExtendedPluginInfo
                .add(IExtendedPluginInfo.HELP_TEXT +
                        ";Authenticate the CMC request. The \"Authentication Instance ID\" must be named \"CMCUserSignedAuth\"");
        mExtendedPluginInfo.add(IExtendedPluginInfo.HELP_TOKEN +
                ";configuration-authentication");
    }

    ///////////////////////
    // Logger parameters //
    ///////////////////////

    private final static String SIGNED_AUDIT_ENROLLMENT_REQUEST_TYPE = "enrollment";
    private final static String SIGNED_AUDIT_REVOCATION_REQUEST_TYPE = "revocation";

    /////////////////////
    // default methods //
    /////////////////////

    /**
     * Default constructor, initialization must follow.
     */
    public CMCUserSignedAuth() {
    }

    //////////////////////////
    // IAuthManager methods //
    //////////////////////////

    /**
     * Initializes the CMCUserSignedAuth authentication plug-in.
     * <p>
     *
     * @param name The name for this authentication plug-in instance.
     * @param implName The name of the authentication plug-in.
     * @param config - The configuration store for this instance.
     * @exception EBaseException If an error occurs during initialization.
     */
    @Override
    public void init(
            AuthenticationConfig authenticationConfig,
            String name, String implName, AuthManagerConfig config)
            throws EBaseException {
        this.authenticationConfig = authenticationConfig;
        mName = name;
        mImplName = implName;
        mConfig = config;
    }

    /**
     * Authenticates user by their CMC;
     * resulting AuthToken sets a TOKEN_SUBJECT for the subject name.
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CMC_USER_SIGNED_REQUEST_SIG_VERIFY used when CMC
     *  (user-pre-signed or self-signed) cert
     * requests or revocation requests are submitted and signature is verified
     * </ul>
     *
     * @param authCred Authentication credentials, CRED_UID and CRED_CMC.
     * @return an AuthToken
     * @exception com.netscape.certsrv.authentication.EMissingCredential
     *                If a required authentication credential is missing.
     * @exception com.netscape.certsrv.authentication.EInvalidCredentials
     *                If credentials failed authentication.
     * @exception com.netscape.certsrv.base.EBaseException
     *                If an internal error occurred.
     * @see org.dogtagpki.server.authentication.AuthToken
     */
    @Override
    public AuthToken authenticate(AuthCredentials authCred) throws EMissingCredential, EInvalidCredentials,
            EBaseException {
        String method = "CMCUserSignedAuth: authenticate: ";
        String msg = "";
        logger.debug(method + "begins");

        CAEngine caEngine = (CAEngine) engine;
        CAEngineConfig cs = caEngine.getConfig();

        Auditor auditor = engine.getAuditor();
        String auditSubjectID = getAuditSubjectID();
        String auditReqType = ILogger.UNIDENTIFIED;
        String requestCertSubject = ILogger.UNIDENTIFIED;
        String auditSignerInfo = ILogger.UNIDENTIFIED;

        SessionContext auditContext = SessionContext.getExistingContext();

        // create audit context if clientCert exists
        X509Certificate clientCert =
               (X509Certificate) auditContext.get(SessionContext.SSL_CLIENT_CERT);
        // null is okay, as it is not required in case of self-sign;
        // will be checked later
        if (clientCert != null) {
            try {
                createAuditSubjectFromCert(auditContext, clientCert);
            } catch (IOException e) {
               //unlikely, and not necessarily required at this point
               logger.warn("CMSUserSignedAuth: authenticate: after createAuditSubjectFromCert call: " + e.getMessage(), e);
            }
        }

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            // get the CMC.

            Object argblock = authCred.getArgBlock();
            Object returnVal = null;
            if (argblock == null) {
                returnVal = authCred.get("cert_request");
                if (returnVal == null)
                    returnVal = authCred.get(CRED_CMC);
            } else {
                returnVal = authCred.get("cert_request");
                if (returnVal == null)
                    returnVal = authCred.getArgBlock().get(CRED_CMC);
            }
            String cmc = (String) returnVal;
            if (cmc == null) {
                logger.error(method + " Authentication failed. Missing CMC.");

                throw new EMissingCredential(CMS.getUserMessage(
                        "CMS_AUTHENTICATION_NULL_CREDENTIAL", CRED_CMC));
            }

            if (cmc.equals("")) {
                msg = "attempted login with empty cert_request in authCred.";
                logger.error(method + msg);

                throw new EInvalidCredentials(msg);
            }

            // authenticate by checking CMC.

            // everything OK.
            // now formulate the certificate info.
            // set the subject name at a minimum.
            // set anything else like version, extensions, etc.
            // if nothing except subject name is set the rest of
            // cert info will be filled in by policies and CA defaults.

            AuthToken authToken = new AuthToken(this);

            try {
                byte[] cmcBlob = CertUtil.parseCSR(cmc);
                ByteArrayInputStream cmcBlobIn = new ByteArrayInputStream(cmcBlob);

                org.mozilla.jss.pkix.cms.ContentInfo cmcReq = (org.mozilla.jss.pkix.cms.ContentInfo) org.mozilla.jss.pkix.cms.ContentInfo
                        .getTemplate().decode(
                                cmcBlobIn);

                String userid = ILogger.UNIDENTIFIED;
                String uid = ILogger.UNIDENTIFIED;

                SignedData cmcFullReq = null;
                OCTET_STRING content = null;
                OBJECT_IDENTIFIER id = null;
                org.mozilla.jss.pkix.cms.SignerInfo selfsign_signerInfo = null;
                if (cmcReq.getContentType().equals(
                        org.mozilla.jss.pkix.cms.ContentInfo.SIGNED_DATA)) {
                    logger.debug(method + "cmc request content is signed data");
                    cmcFullReq = (SignedData) cmcReq.getInterpretedContent();

                    boolean checkSignerInfo = cs.getBoolean("cmc.signerInfo.verify", true);
                    if (checkSignerInfo) {
                        // selfSigned will be set in verifySignerInfo if applicable
                        AuthToken userToken = verifySignerInfo(auditContext, authToken, cmcFullReq);
                        if (userToken == null) {
                            msg = "userToken null; verifySignerInfo failure";
                            logger.error(method + msg);
                            throw new EBaseException(msg);
                        }
                        if (selfSigned) {
                            logger.debug(method
                                    + " self-signed cmc request will not have user identification info at this point.");
                            auditSignerInfo = "selfSigned";
                        } else {
                            logger.debug(method + "signed with user cert");
                            userid = userToken.getInString("userid");
                            uid = userToken.getInString("id");
                            if (userid == null && uid == null) {
                                msg = " verifySignerInfo failure... missing id";
                                logger.error(method + msg);
                                throw new EBaseException(msg);
                            }
                            // reset value of auditSignerInfo
                            if (uid != null && !uid.equals(ILogger.UNIDENTIFIED)) {
                                //logger.debug(method + "setting auditSignerInfo to uid:" + uid.trim());
                                //auditSignerInfo = uid.trim();
                                auditSubjectID = uid.trim();
                                authToken.set(AuthToken.USER_ID, auditSubjectID);
                            } else if (userid != null && !userid.equals(ILogger.UNIDENTIFIED)) {
                                //logger.debug(method + "setting auditSignerInfo to userid:" + userid);
                                //auditSignerInfo = userid.trim();
                                auditSubjectID = userid.trim();
                                authToken.set(AuthToken.USER_ID, auditSubjectID);
                            }
                        }
                    } else {
                        logger.debug(method + " signerInfo verification bypassed");
                    }

                    EncapsulatedContentInfo ci = cmcFullReq.getContentInfo();
                    SET sis = cmcFullReq.getSignerInfos();
                    // only one SignerInfo for selfSigned
                    selfsign_signerInfo = (org.mozilla.jss.pkix.cms.SignerInfo) sis.elementAt(0);

                    id = ci.getContentType();

                    if (!id.equals(OBJECT_IDENTIFIER.id_cct_PKIData) ||
                            !ci.hasContent()) {
                        msg = "request EncapsulatedContentInfo content type not OBJECT_IDENTIFIER.id_cct_PKIData";
                        logger.error(method + msg);

                        throw new EBaseException(msg);
                    }

                    content = ci.getContent();
                } else if (cmcReq.getContentType().equals( //unsigned
                        org.mozilla.jss.pkix.cms.ContentInfo.DATA)) {
                    logger.debug(method + "cmc request content is unsigned data...verifySignerInfo will not be called;");
                    content = (OCTET_STRING) cmcReq.getInterpretedContent();
                } else {
                    cmcBlobIn.close();
                    msg = "unsupported cmc rquest content type; must be either ContentInfo.SIGNED_DATA or ContentInfo.DATA;";
                    logger.error(msg);
                    throw new EBaseException(msg);
                }

                ByteArrayInputStream s = new ByteArrayInputStream(content.toByteArray());
                PKIData pkiData = (PKIData) (new PKIData.Template()).decode(s);

                SEQUENCE reqSequence = pkiData.getReqSequence();

                int numReqs = reqSequence.size();

                if (numReqs == 0) {
                    logger.debug(method + "numReqs 0, assume revocation request");
                    // revocation request

                    // reset value of auditReqType
                    auditReqType = SIGNED_AUDIT_REVOCATION_REQUEST_TYPE;

                    SEQUENCE controlSequence = pkiData.getControlSequence();
                    int controlSize = controlSequence.size();

                    if (controlSize > 0) {
                        for (int i = 0; i < controlSize; i++) {
                            TaggedAttribute taggedAttribute = (TaggedAttribute) controlSequence.elementAt(i);
                            OBJECT_IDENTIFIER type = taggedAttribute.getType();

                            if (type.equals(
                                    OBJECT_IDENTIFIER.id_cmc_revokeRequest)) {
                                //further checks and actual revocation happen in CMCOutputTemplate

                                // if( i ==1 ) {
                                //     taggedAttribute.getType() ==
                                //       OBJECT_IDENTIFIER.id_cmc_revokeRequest
                                // }

                                SET values = taggedAttribute.getValues();
                                int numVals = values.size();
                                BigInteger[] bigIntArray = null;

                                bigIntArray = new BigInteger[numVals];
                                for (int j = 0; j < numVals; j++) {
                                    // serialNumber    INTEGER

                                    // SEQUENCE RevokeRequest = (SEQUENCE)
                                    //     values.elementAt(j);
                                    byte[] encoded = ASN1Util.encode(
                                            values.elementAt(j));
                                    org.mozilla.jss.asn1.ASN1Template template = new org.mozilla.jss.pkix.cmc.RevokeRequest.Template();
                                    org.mozilla.jss.pkix.cmc.RevokeRequest revRequest = (org.mozilla.jss.pkix.cmc.RevokeRequest) ASN1Util
                                            .decode(template, encoded);

                                    // SEQUENCE RevokeRequest = (SEQUENCE)
                                    //     ASN1Util.decode(
                                    //         SEQUENCE.getTemplate(),
                                    //         ASN1Util.encode(
                                    //         values.elementAt(j)));

                                    // SEQUENCE RevokeRequest =
                                    //     values.elementAt(j);
                                    // int revReqSize = RevokeRequest.size();
                                    // if( revReqSize > 3 ) {
                                    //     INTEGER serialNumber =
                                    //         new INTEGER((long)0);
                                    // }

                                    INTEGER temp = revRequest.getSerialNumber();

                                    bigIntArray[j] = temp;
                                    authToken.set(TOKEN_CERT_SERIAL, bigIntArray);

                                    long reasonCode = revRequest.getReason().getValue();
                                    Integer IntObject = Integer.valueOf((int) reasonCode);
                                    authToken.set(REASON_CODE, IntObject);

                                    ANY issuerANY = revRequest.getIssuerName();
                                    // handling of faillures with issuer is deferred
                                    // to CMCOutputTemplate so that we can
                                    // have a chance to capture user identification info
                                    if (issuerANY != null) {
                                        // get CA signing cert
                                        CertificateAuthority ca = caEngine.getCA();
                                        X500Name caName = ca.getX500Name();

                                        try {
                                            byte[] issuerBytes = issuerANY.getEncoded();
                                            X500Name reqIssuerName = new X500Name(issuerBytes);
                                            String reqIssuerNameStr = reqIssuerName.getName();
                                            logger.debug(method + "revRequest issuer name = " + reqIssuerNameStr);
                                            if (reqIssuerNameStr.equalsIgnoreCase(caName.getName())) {
                                                // making sure it's identical, even in encoding
                                                reqIssuerName = caName;
                                            } else {
                                                // not this CA; will be bumped off later;
                                                // make a note in debug anyway
                                                logger.debug(method + "revRequest issuer name doesn't match our CA; will be bumped off later;");
                                            }
                                            // capture issuer principal to be checked against
                                            // cert issuer principal later in CMCOutputTemplate
                                            auditContext.put(SessionContext.CMC_ISSUER_PRINCIPAL, reqIssuerName);
                                        } catch (Exception e) {
                                            logger.warn(method + "failed getting issuer from RevokeRequest: " + e.getMessage(), e);
                                        }
                                    }

                                    //authToken.set("uid", uid);
                                    //authToken.set("userid", userid);

                                }
                            }
                        }

                    }
                } else {
                    logger.debug(method + "numReqs not 0, assume enrollment request");
                    // enrollment request

                    // reset value of auditReqType
                    auditReqType = SIGNED_AUDIT_ENROLLMENT_REQUEST_TYPE;

                    X509CertInfo[] certInfoArray = new X509CertInfo[numReqs];
                    String[] reqIdArray = new String[numReqs];

                    for (int i = 0; i < numReqs; i++) {
                        // decode message.
                        TaggedRequest taggedRequest = (TaggedRequest) reqSequence.elementAt(i);

                        TaggedRequest.Type type = taggedRequest.getType();

                        if (type.equals(TaggedRequest.PKCS10)) {
                            logger.debug(method + " type is PKCS10");
                            authToken.set("cert_request_type", "cmc-pkcs10");

                            TaggedCertificationRequest tcr = taggedRequest.getTcr();
                            int p10Id = tcr.getBodyPartID().intValue();

                            reqIdArray[i] = String.valueOf(p10Id);

                            CertificationRequest p10 = tcr.getCertificationRequest();

                            // transfer to sun class
                            ByteArrayOutputStream ostream = new ByteArrayOutputStream();

                            p10.encode(ostream);
                            boolean sigver = true;
                            boolean tokenSwitched = false;
                            CryptoManager cm = null;
                            CryptoToken signToken = null;
                            CryptoToken savedToken = null;

                            // for PKCS10, "sigver" would offer the POP
                            sigver = cs.getBoolean("ca.requestVerify.enabled", true);
                            try {
                                cm = CryptoManager.getInstance();
                                if (sigver == true) {
                                    String tokenName = cs.getString("ca.requestVerify.token", CryptoUtil.INTERNAL_TOKEN_NAME);
                                    savedToken = cm.getThreadToken();
                                    signToken = CryptoUtil.getCryptoToken(tokenName);
                                    if (!savedToken.getName().equals(signToken.getName())) {
                                        cm.setThreadToken(signToken);
                                        tokenSwitched = true;
                                    }
                                }

                                PKCS10 pkcs10 = new PKCS10(ostream.toByteArray(), sigver);
                                // reset value of requestCertSubject
                                X500Name tempName = pkcs10.getSubjectName();
                                logger.debug(method + "request subject name=" + tempName.toString());
                                if (tempName != null) {
                                    requestCertSubject = tempName.toString().trim();
                                    if (requestCertSubject.equals("")) {
                                        requestCertSubject = ILogger.SIGNED_AUDIT_EMPTY_VALUE;
                                    }
                                    authToken.set(AuthToken.TOKEN_CERT_SUBJECT,
                                            requestCertSubject/*tempName.toString()*/);
                                    auditContext.put(SessionContext.CMC_REQUEST_CERT_SUBJECT, requestCertSubject);
                                }

                                if (selfSigned) {
                                    // prepare for checking SKI extension
                                    try {
                                        selfsign_skiExtn = (SubjectKeyIdentifierExtension) CryptoUtil
                                                .getExtensionFromPKCS10(pkcs10, "SubjectKeyIdentifier");
                                        if (selfsign_skiExtn != null)
                                            logger.debug(method + "SubjectKeyIdentifierExtension found:");
                                        else {
                                            msg = "missing SubjectKeyIdentifierExtension in request";
                                            logger.error(method + msg);
                                            throw new EBaseException(msg);
                                        }
                                    } catch (IOException e) {
                                        msg = method + "SubjectKeyIdentifierExtension not found:" + e;
                                        logger.error(msg);
                                        throw new EBaseException(msg);
                                    } catch (Exception e) {
                                        msg = method + "SubjectKeyIdentifierExtension not found: " + e.getMessage();
                                        logger.error(msg, e);
                                        throw new EBaseException(msg);
                                    }

                                    X509Key pubKey = pkcs10.getSubjectPublicKeyInfo();
                                    PrivateKey.Type keyType = null;
                                    String alg = pubKey.getAlgorithm();

                                    if (alg.equals("RSA")) {
                                        logger.debug(method + "signing key alg=RSA");
                                        keyType = PrivateKey.RSA;
                                        selfsign_pubK = PK11PubKey.fromRaw(keyType, pubKey.getKey());
                                    } else if (alg.equals("EC")) {
                                        logger.debug(method + "signing key alg=EC");
                                        keyType = PrivateKey.EC;
                                        byte publicKeyData[] = (pubKey).getEncoded();
                                        selfsign_pubK = PK11ECPublicKey.fromSPKI(/*keyType,*/ publicKeyData);
                                    } else {
                                        msg = "unsupported signature algorithm: " + alg;
                                        logger.error(method + msg);
                                        throw new EInvalidCredentials(msg);
                                    }
                                    logger.debug(method + "public key retrieved");
                                    verifySelfSignedCMC(selfsign_signerInfo, id);

                                } //selfSigned

                                // xxx do we need to do anything else?
                                X509CertInfo certInfo = new CertInfo();

                                // fillPKCS10(certInfo,pkcs10,authToken,null);

                                // authToken.set(
                                //     pkcs10.getSubjectPublicKeyInfo());

                                /*
                                authToken.set("uid", uid);
                                authToken.set("userid", userid);
                                */

                                certInfoArray[i] = certInfo;
                            } catch (Exception e) {
                                e.printStackTrace();
                                throw new EBaseException(e.toString());
                            } finally {
                                if ((sigver == true) && (tokenSwitched == true)) {
                                    cm.setThreadToken(savedToken);
                                }
                            }
                        } else if (type.equals(TaggedRequest.CRMF)) {

                            logger.debug(method + " type is CRMF");
                            authToken.set("cert_request_type", "cmc-crmf");
                            try {
                                CertReqMsg crm = taggedRequest.getCrm();
                                CertRequest certReq = crm.getCertReq();
                                INTEGER reqID = certReq.getCertReqId();
                                reqIdArray[i] = reqID.toString();
                                CertTemplate template = certReq.getCertTemplate();
                                Name name = template.getSubject();

                                // xxx do we need to do anything else?
                                X509CertInfo certInfo = new CertInfo();

                                // reset value of requestCertSubject
                                if (name != null) {
                                    String ss = name.getRFC1485();

                                    logger.debug(method + "setting requestCertSubject to: " + ss);
                                    requestCertSubject = ss;
                                    if (requestCertSubject.equals("")) {
                                        requestCertSubject = ILogger.SIGNED_AUDIT_EMPTY_VALUE;
                                    }
                                    authToken.set(AuthToken.TOKEN_CERT_SUBJECT, ss);
                                    auditContext.put(SessionContext.CMC_REQUEST_CERT_SUBJECT, requestCertSubject);
                                    //authToken.set("uid", uid);
                                    //authToken.set("userid", userid);
                                }
                                certInfoArray[i] = certInfo;

                                if (selfSigned) {
                                    selfsign_skiExtn = (SubjectKeyIdentifierExtension) CRMFUtil
                                            .getExtensionFromCertTemplate(template, PKIXExtensions.SubjectKey_Id);
                                    if (selfsign_skiExtn != null) {
                                        logger.debug(method +
                                                "SubjectKeyIdentifierExtension found");
                                    } else {
                                        logger.debug(method +
                                                "SubjectKeyIdentifierExtension not found");
                                    }

                                    // get public key for verifying signature later
                                    SubjectPublicKeyInfo pkinfo = template.getPublicKey();
                                    PrivateKey.Type keyType = null;
                                    String alg = pkinfo.getAlgorithm();
                                    byte[] publicKeyData = null;

                                    if (alg.equals("RSA")) {
                                        BIT_STRING bitString = pkinfo.getSubjectPublicKey();
                                        publicKeyData = bitString.getBits();
                                        logger.debug(method + "signing key alg=RSA");
                                        keyType = PrivateKey.RSA;
                                        selfsign_pubK = PK11PubKey.fromRaw(keyType, publicKeyData);
                                    } else if (alg.equals("EC")) {
                                        logger.debug(method + "signing key alg=EC");
                                        keyType = PrivateKey.EC;
                                        X509Key pubKey = CRMFUtil.getX509KeyFromCRMFMsg(crm);
                                        logger.debug(method + "got X509Key ");
                                        publicKeyData = (pubKey).getEncoded();
                                        selfsign_pubK = PK11ECPublicKey.fromSPKI(/*keyType,*/ publicKeyData);
                                    } else {
                                        msg = "unsupported signature algorithm: " + alg;
                                        logger.error(method + msg);
                                        throw new EInvalidCredentials(msg);
                                    }
                                    logger.debug(method + "public key retrieved");

                                    verifySelfSignedCMC(selfsign_signerInfo, id);
                                } //selfSigned

                            } catch (Exception e) {
                                e.printStackTrace();
                                cmcBlobIn.close();
                                s.close();
                                throw new EBaseException(e.toString());
                            }
                        }

                    }
                }

                authToken.set("uid", uid);
                authToken.set("userid", userid);
            } catch (EMissingCredential e) {
                throw e;
            } catch (EInvalidCredentials e) {
                throw e;
            } catch (Exception e) {
                //logger.error(method + e.getMessage(), e);
                //throw new EInvalidCredentials(e.toString());
                throw e;
            }

            // For accuracy, make sure revocation by shared secret doesn't
            // log successful CMC_USER_SIGNED_REQUEST_SIG_VERIFY audit event
            if (authToken.get(AuthManager.CRED_CMC_SIGNING_CERT) != null ||
                    authToken.get(AuthManager.CRED_CMC_SELF_SIGNED) != null) {

                auditor.log(
                        CMCUserSignedRequestSigVerifyEvent.createSuccessEvent(
                        getAuditSubjectID(),
                        auditReqType,
                        getRequestCertSubject(auditContext),
                        getAuditSignerInfo(auditContext)));

            } else {
                logger.warn(method
                        + "successful CMC_USER_SIGNED_REQUEST_SIG_VERIFY audit event not logged due to unsigned data for revocation with shared secret.");
            }

            logger.debug(method + "ends successfully; returning authToken");
            return authToken;
        } catch (EMissingCredential eAudit1) {
            logger.error(method + eAudit1.getMessage(), eAudit1);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (EInvalidCredentials eAudit2) {
            logger.error(method + eAudit2.getMessage(), eAudit2);

            auditor.log(
                    CMCUserSignedRequestSigVerifyEvent.createFailureEvent(
                    getAuditSubjectID(),
                    auditReqType,
                    getRequestCertSubject(auditContext),
                    getAuditSignerInfo(auditContext),
                    eAudit2.toString()));

            // rethrow the specific exception to be handled later
            throw eAudit2;
        } catch (EBaseException eAudit3) {
            logger.error(method + eAudit3.getMessage(), eAudit3);

            auditor.log(
                    CMCUserSignedRequestSigVerifyEvent.createFailureEvent(
                    getAuditSubjectID(),
                    auditReqType,
                    getRequestCertSubject(auditContext),
                    getAuditSignerInfo(auditContext),
                    eAudit3.toString()));

            // rethrow the specific exception to be handled later
            throw eAudit3;
        } catch (Exception eAudit4) {
            logger.error(method + eAudit4.getMessage(), eAudit4);

            auditor.log(
                    CMCUserSignedRequestSigVerifyEvent.createFailureEvent(
                    getAuditSubjectID(),
                    auditReqType,
                    getRequestCertSubject(auditContext),
                    getAuditSignerInfo(auditContext),
                    eAudit4.toString()));

            // rethrow the exception to be handled later
            throw new EBaseException(eAudit4);
        }
    }

    /*
    * verifySelfSignedCMC() verifies the following
    * a. the required (per RFC 5272) SKI extension in the request matches that in the
    *    SignerIdentifier
    * b. the signature in the request
    */
    protected void verifySelfSignedCMC(
            org.mozilla.jss.pkix.cms.SignerInfo signerInfo,
            OBJECT_IDENTIFIER id)
            throws EBaseException {
        String method = "CMCUserSignedAuth: verifySelfSignedCMC: ";
        logger.debug(method + "begins");
        try {
            SignerIdentifier sid = signerInfo.getSignerIdentifier();
            OCTET_STRING subjKeyId = sid.getSubjectKeyIdentifier();
            KeyIdentifier keyIdObj =
                    (KeyIdentifier) selfsign_skiExtn.get(SubjectKeyIdentifierExtension.KEY_ID);
            boolean match = CryptoUtil.compare(subjKeyId.toByteArray(), keyIdObj.getIdentifier());
            if (match) {
                logger.debug(method +
                        " SignerIdentifier SUBJECT_KEY_IDENTIFIER matches SKI of request");
            } else {
                logger.error(method +
                        " SignerIdentifier SUBJECT_KEY_IDENTIFIER failed to match");
                throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
            }
            // verify sig using public key in request
            logger.debug(method + "verifying request signature with public key");
            signerInfo.verify(selfsign_digest, id, selfsign_pubK);
            logger.debug(method + " signature verified");
        } catch (Exception e) {
            logger.error(method + e.getMessage(), e);
            throw new EBaseException(method + e.toString());
        }
    }

    /**
     * get the list of required credentials.
     * <p>
     *
     * @return list of required credentials as strings.
     */
    @Override
    public String[] getRequiredCreds() {
        return (mRequiredCreds);
    }

    /**
     * prepares for shutdown.
     */
    @Override
    public void shutdown() {
    }

    /////////////////////////////////
    // IExtendedPluginInfo methods //
    /////////////////////////////////

    /**
     * Activate the help system.
     * <p>
     *
     * @return help messages
     */
    @Override
    public String[] getExtendedPluginInfo() {
        String method = "CMCUserSignedAuth: getExtendedPluginInfo: ";
        logger.debug(method + " begins");
        String[] s = Utils.getStringArrayFromVector(mExtendedPluginInfo);

        logger.debug(method + " s.length = " + s.length);
        for (int i = 0; i < s.length; i++) {
            logger.debug("" + i + " " + s[i]);
        }
        return s;
    }

    /**
     * User-signed CMC requests can be signed in two ways:
     * a. signed with previously issued user signing cert
     * b. self-signed with the private key paired with the public key in
     * the request
     *
     * In case "a", the resulting authToke would contain
     * (IAuthManager.CRED_CMC_SIGNING_CERT, signing cert serial number)
     * In case "b", the resulting authToke would not contain the attribute
     * IAuthManager.CRED_CMC_SIGNING_CERT
     */
    protected AuthToken verifySignerInfo(
            SessionContext auditContext, // to capture info in case of failure
            AuthToken authToken,
            SignedData cmcFullReq)
            throws EBaseException, EInvalidCredentials, EMissingCredential {
        String method = "CMCUserSignedAuth: verifySignerInfo: ";
        String msg = "";
        logger.debug(method + "begins");

        CAEngine caEngine = (CAEngine) engine;
        CAEngineConfig cs = caEngine.getConfig();

        EncapsulatedContentInfo ci = cmcFullReq.getContentInfo();
        OBJECT_IDENTIFIER id = ci.getContentType();
        OCTET_STRING content = ci.getContent();

        boolean tokenSwitched = false;
        CryptoToken signToken = null;
        CryptoToken savedToken = null;
        CryptoManager cm = null;
        try {
            cm = CryptoManager.getInstance();
            ByteArrayInputStream s = new ByteArrayInputStream(content.toByteArray());
            PKIData pkiData = (PKIData) (new PKIData.Template()).decode(s);

            SET dais = cmcFullReq.getDigestAlgorithmIdentifiers();
            int numDig = dais.size();
            Hashtable<String, byte[]> digs = new Hashtable<>();

            //if request key is used for signing, there MUST be only one signerInfo
            //object in the signedData object.
            for (int i = 0; i < numDig; i++) {
                AlgorithmIdentifier dai = (AlgorithmIdentifier) dais.elementAt(i);
                String name = DigestAlgorithm.fromOID(dai.getOID()).toString();

                MessageDigest md = MessageDigest.getInstance(name);

                byte[] digest = md.digest(content.toByteArray());

                digs.put(name, digest);
            }

            SET sis = cmcFullReq.getSignerInfos();
            int numSis = sis.size();

            for (int i = 0; i < numSis; i++) {
                org.mozilla.jss.pkix.cms.SignerInfo si = (org.mozilla.jss.pkix.cms.SignerInfo) sis.elementAt(i);
                //selfsign_SignerInfo = (org.mozilla.jss.pkix.cms.SignerInfo) sis.elementAt(i);

                String name = si.getDigestAlgorithm().toString();
                byte[] digest = digs.get(name);

                if (digest == null) {
                    MessageDigest md = MessageDigest.getInstance(name);
                    ByteArrayOutputStream ostream = new ByteArrayOutputStream();

                    pkiData.encode(ostream);
                    digest = md.digest(ostream.toByteArray());

                }

                // signed  by  previously certified signature key
                SignerIdentifier sid = si.getSignerIdentifier();
                if (sid.getType().equals(SignerIdentifier.ISSUER_AND_SERIALNUMBER)) {
                    logger.debug(method + "SignerIdentifier type: ISSUER_AND_SERIALNUMBER");
                    selfSigned = false;
                    logger.debug(method + "selfSigned is false");

                    IssuerAndSerialNumber issuerAndSerialNumber = sid.getIssuerAndSerialNumber();
                    // find from the certs in the signedData
                    java.security.cert.X509Certificate cert = null;

                    if (cmcFullReq.hasCertificates()) {
                        SET certs = cmcFullReq.getCertificates();
                        int numCerts = certs.size();
                        X509Certificate[] x509Certs = new X509Certificate[1];

                        for (int j = 0; j < numCerts; j++) {
                            Certificate certJss = (Certificate) certs.elementAt(j);
                            CertificateInfo certI = certJss.getInfo();
                            Name issuer = certI.getIssuer();

                            byte[] issuerB = ASN1Util.encode(issuer);
                            INTEGER sn = certI.getSerialNumber();
                            // if this cert is the signer cert, not a cert in the chain
                            if (new String(issuerB).equals(new String(
                                    ASN1Util.encode(issuerAndSerialNumber.getIssuer())))
                                    && sn.toString().equals(issuerAndSerialNumber.getSerialNumber().toString())) {
                                ByteArrayOutputStream os = new ByteArrayOutputStream();

                                certJss.encode(os);
                                os.toByteArray();

                                X509CertImpl tempcert = new X509CertImpl(os.toByteArray());

                                cert = tempcert;
                                x509Certs[0] = cert;
                                // xxx validate the cert length

                            }
                        }

                        logger.debug(method + "start checking signature");
                        if (cert == null) {
                            // find from certDB
                            logger.debug(method + "verifying signature");
                            si.verify(digest, id);
                        } else {
                            logger.debug(method + "found CMC signing cert... verifying");

                            X509Certificate clientCert =
                                    (X509Certificate) auditContext.get(SessionContext.SSL_CLIENT_CERT);
                            // user-signed case requires ssl client authentication
                            if (clientCert == null) {
                                createAuditSubjectFromCert(auditContext, x509Certs[0]);
                                msg = "missing SSL client authentication certificate;";
                                logger.error(method + msg);
                                s.close();
                                throw new EMissingCredential(
                                        CMS.getUserMessage("CMS_AUTHENTICATION_NO_CERT"));
                            }
                            org.mozilla.jss.netscape.security.x509.X500Name clientPrincipal =
                                    (X500Name) clientCert.getSubjectDN();

                            org.mozilla.jss.netscape.security.x509.X500Name cmcPrincipal =
                                    (X500Name) x509Certs[0].getSubjectDN();

                            // capture signer principal to be checked against
                            // cert subject principal later in CMCOutputTemplate
                            // in case of user signed revocation
                            auditContext.put(SessionContext.CMC_SIGNER_PRINCIPAL, cmcPrincipal);
                            auditContext.put(SessionContext.CMC_SIGNER_INFO,
                                cmcPrincipal.toString());

                            // check ssl client cert against cmc signer
                            if (clientPrincipal.equals(cmcPrincipal)) {
                                logger.debug(method + "ssl client cert principal and cmc signer principal match");
                            } else {
                                msg = "SSL client authentication certificate and CMC signer do not match";
                                logger.error(method + msg);
                                s.close();
                                throw new EInvalidCredentials(
                                        CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL") + ":" + msg);
                            }

                            PublicKey signKey = cert.getPublicKey();
                            PrivateKey.Type keyType = null;
                            String alg = signKey.getAlgorithm();

                            PK11PubKey pubK = null;
                            if (alg.equals("RSA")) {
                                logger.debug(method + "signing key alg=RSA");
                                keyType = PrivateKey.RSA;
                                pubK = PK11PubKey.fromRaw(keyType, ((X509Key) signKey).getKey());
                            } else if (alg.equals("EC")) {
                                logger.debug(method + "signing key alg=EC");
                                keyType = PrivateKey.EC;
                                byte publicKeyData[] = ((X509Key) signKey).getEncoded();
                                pubK = PK11ECPublicKey.fromSPKI(/*keyType,*/ publicKeyData);
                            } else {
                                msg = "unsupported signature algorithm: " + alg;
                                logger.error(method +  msg);
                                s.close();
                                throw new EInvalidCredentials(
                                        CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL") + ":" + msg);
                            }

                            String tokenName = cs.getString("ca.requestVerify.token", CryptoUtil.INTERNAL_TOKEN_NAME);
                            // by default JSS will use internal crypto token
                            if (!CryptoUtil.isInternalToken(tokenName)) {
                                savedToken = cm.getThreadToken();
                                signToken = CryptoUtil.getCryptoToken(tokenName);
                                if (signToken != null) {
                                    cm.setThreadToken(signToken);
                                    tokenSwitched = true;
                                    logger.debug(method + "verifySignerInfo token switched:" + tokenName);
                                } else {
                                    logger.debug(method + "verifySignerInfo token not found:" + tokenName
                                            + ", trying internal");
                                }
                            }

                            logger.debug(method + "verifying signature with public key");
                            si.verify(digest, id, pubK);
                        }
                        logger.debug(method + "finished checking signature");

                        // At this point, the signature has been verified;
                        // now check revocation status of the cert
                        if (engine.isRevoked(x509Certs)) {
                            msg = "CMC signing cert is a revoked certificate";
                            logger.error(method + msg);
                            s.close();
                            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL") + ":" + msg);
                        }
                        try { //do this again anyways
                            cert.checkValidity();
                        } catch (CertificateExpiredException e) {
                            msg = "CMC signing cert is an expired certificate";
                            logger.error(method + msg, e);
                            s.close();
                            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL") + ":" + msg);
                        } catch (Exception e) {
                            logger.error(method + e.getMessage(), e);
                            s.close();
                            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL") + ":" + e.toString());
                        }

                        AuthToken tempToken = new AuthToken(null);
                        org.mozilla.jss.netscape.security.x509.X500Name tempPrincipal = (X500Name) x509Certs[0].getSubjectDN();
                        String ID = tempPrincipal.getName(); //tempToken.get("userid");
                        logger.debug(method + " Principal name = " + ID);
                        authToken.set(AuthToken.TOKEN_AUTHENTICATED_CERT_SUBJECT, ID);

                        BigInteger certSerial = x509Certs[0].getSerialNumber();
                        logger.debug(method + " verified cert serial=" + certSerial.toString());
                        authToken.set(AuthManager.CRED_CMC_SIGNING_CERT, certSerial.toString());
                        tempToken.set("id", ID);

                        s.close();
                        return tempToken;

                    }
                    msg = "no certificate found in cmcFullReq";
                    logger.error(method + msg);
                    throw new EMissingCredential(msg);
                } else if (sid.getType().equals(SignerIdentifier.SUBJECT_KEY_IDENTIFIER)) {
                    logger.debug(method + "SignerIdentifier type: SUBJECT_KEY_IDENTIFIER");
                    logger.debug(method + "selfSigned is true");
                    selfSigned = true;
                    selfsign_digest = digest;

                    AuthToken tempToken = new AuthToken(null);
                    authToken.set(AuthManager.CRED_CMC_SELF_SIGNED, "true");
                    s.close();
                    return tempToken;
                } else {
                    msg = "unsupported SignerIdentifier type";
                    logger.error(method + msg);
                    throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL") + ":" + msg);
                }
            } //for

        } catch (EMissingCredential e) {
            throw e;
        } catch (EInvalidCredentials e) {
            throw e;
        } catch (InvalidBERException e) {
            logger.warn(method + e.getMessage(), e);
        } catch (Exception e) {
            logger.warn(method + e.getMessage(), e);
        } finally {
            if ((tokenSwitched == true) && (savedToken != null)) {
                cm.setThreadToken(savedToken);
                logger.debug(method + "verifySignerInfo token restored");
            }
        }
        return null;

    }

    private void createAuditSubjectFromCert (
            SessionContext auditContext,
            X509Certificate cert)
            throws IOException {
        String method = "CMCUserSignedAuth:createAuditSubjectFromCert: ";

        // capture auditSubjectID first in case of failure
        org.mozilla.jss.netscape.security.x509.X500Name principal =
                (X500Name) cert.getSubjectDN();

        logger.debug(method + " Principal name = " + principal.toString());
        auditContext.put(SessionContext.USER_ID, principal.toString());
    }

    // Profile-related methods

    @Override
    public void init(ConfigStore config) throws EProfileException {
    }

    /**
     * Retrieves the localizable name of this policy.
     */
    @Override
    public String getName(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_AUTHENTICATION_CMS_SIGN_NAME");
    }

    /**
     * Retrieves the localizable description of this policy.
     */
    @Override
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_AUTHENTICATION_CMS_SIGN_TEXT");
    }

    /**
     * Retrieves a list of names of the value parameter.
     */
    @Override
    public Enumeration<String> getValueNames() {
        Vector<String> v = new Vector<>();
        v.addElement("cert_request");
        return v.elements();
    }

    @Override
    public boolean isValueWriteable(String name) {
        return false;
    }

    /**
     * Retrieves the descriptor of the given value
     * parameter by name.
     */
    @Override
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        if (name.equals(CRED_CMC)) {
            return new Descriptor(IDescriptor.STRING_LIST, null, null,
                    "CMC request");
        }
        return null;
    }

    @Override
    public void populate(AuthToken token, Request request)
            throws EProfileException {
        String method = "CMCUserSignedAuth: populate: ";
        String authenticatedDN = token.getInString(AuthToken.TOKEN_AUTHENTICATED_CERT_SUBJECT);
        if (authenticatedDN != null) {
            request.setExtData(AuthManager.AUTHENTICATED_NAME,
                    authenticatedDN);
            logger.debug(method + "AuthToken.TOKEN_AUTHENTICATED_CERT_SUBJECT is: "+
                    authenticatedDN);
        } else {
            logger.warn(method + "AuthToken.TOKEN_AUTHENTICATED_CERT_SUBJECT is null; self-signed?");
        }
    }

    @Override
    public boolean isSSLClientRequired() {
        return false;
    }

    /**
     * Signed Audit Log Subject ID
     *
     * This method is called to obtain the "SubjectID" for
     * a signed audit log message.
     * <P>
     *
     * @return id string containing the signed audit log message SubjectID
     */
    private String getAuditSubjectID() {

        String subjectID = null;

        // Initialize subjectID
        SessionContext auditContext = SessionContext.getExistingContext();

        if (auditContext != null) {
            subjectID = (String) auditContext.get(SessionContext.USER_ID);

            if (subjectID != null) {
                subjectID = subjectID.trim();
            } else {
                subjectID = ILogger.NONROLEUSER;
            }
        } else {
            subjectID = ILogger.UNIDENTIFIED;
        }

        return subjectID;
    }

    private String getAuditSignerInfo(SessionContext auditContext) {
        String signerSubject = (String)auditContext.get(SessionContext.CMC_SIGNER_INFO);
        if (signerSubject == null)
            signerSubject = "$Unidentified$";

        return signerSubject;
    }

    private String getRequestCertSubject(SessionContext auditContext) {
        String certSubject = (String)auditContext.get(SessionContext.CMC_REQUEST_CERT_SUBJECT);
        if (certSubject == null)
            certSubject = "$Unidentified$";

        return certSubject;
    }

}

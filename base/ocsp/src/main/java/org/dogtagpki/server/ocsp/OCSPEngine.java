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
// (C) 2018 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.ocsp;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.security.auth.x500.X500Principal;

import org.mozilla.jss.netscape.security.x509.X509CRLImpl;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback.ValidityStatus;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.Subsystem;
import com.netscape.cms.ocsp.LDAPStore;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.base.ConfigStorage;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.dbs.CRLIssuingPointRecord;
import com.netscape.ocsp.OCSPAuthority;

public class OCSPEngine extends CMSEngine {

    static OCSPEngine instance;

    public OCSPEngine() {
        super("OCSP");
        instance = this;
    }

    public static OCSPEngine getInstance() {
        return instance;
    }

    @Override
    public OCSPEngineConfig createConfig(ConfigStorage storage) throws Exception {
        return new OCSPEngineConfig(storage);
    }

    @Override
    public OCSPEngineConfig getConfig() {
        return (OCSPEngineConfig) mConfig;
    }

    public OCSPAuthority getOCSP() {
        return (OCSPAuthority) getSubsystem(OCSPAuthority.ID);
    }

    @Override
    public void initSubsystem(Subsystem subsystem, ConfigStore subsystemConfig) throws Exception {

        if (subsystem instanceof OCSPAuthority) {
            // skip initialization during installation
            if (isPreOpMode()) return;
        }

        super.initSubsystem(subsystem, subsystemConfig);
        if (subsystem instanceof OCSPAuthority) {
            subsystem.startup();
        }
    }


    protected void startupSubsystems() throws Exception {

        for (Subsystem subsystem : subsystems.values()) {
            logger.info("CMSEngine: Starting " + subsystem.getId() + " subsystem");
            if (!(subsystem instanceof OCSPAuthority))
                subsystem.startup();
        }

        // global admin servlet. (anywhere else more fit for this ?)
    }
    @Override
    protected void initSequence() throws Exception {


        initDebug();
        init();
        initPasswordStore();
        initSubsystemListeners();
        initSecurityProvider();
        initPluginRegistry();
        initAuditor();
        initLogSubsystem();

        initClientSocketListener();
        initServerSocketListener();

        testLDAPConnections();
        initDatabase();

        initJssSubsystem();
        initDBSubsystem();
        initUGSubsystem();
        initOIDLoaderSubsystem();
        initX500NameSubsystem();
        // skip TP subsystem;
        // problem in needing dbsubsystem in constructor. and it's not used.
        initRequestSubsystem();


        startupSubsystems();

        initAuthSubsystem();
        initAuthzSubsystem();
        initCMSGateway();
        initJobsScheduler();

        configureAutoShutdown();
        configureServerCertNickname();

        initSecurityDomain();
    }

    @Override
    public boolean isRevoked(X509Certificate[] certificates) {
        LDAPStore crlStore = null;
        for (Subsystem subsystem : subsystems.values()) {
            if (subsystem instanceof OCSPAuthority) {
                OCSPAuthority ocsp = (OCSPAuthority) subsystem;
                if (ocsp.getDefaultStore() instanceof LDAPStore) {
                    crlStore = (LDAPStore) ocsp.getDefaultStore();
                }
                break;
            }
        }

        if (crlStore == null || !crlStore.isCRLCheckAvailable()) {
            return super.isRevoked(certificates);
        }

        for (X509Certificate cert: certificates) {
            if(crlCertValid(crlStore, cert, null)) {
                return false;
            }
        }
        return true;

    }


    private boolean crlCertValid(LDAPStore crlStore, X509Certificate certificate, ValidityStatus currentStatus) {
        logger.info("OCSPEngine: validate of peer's certificate for the connection " + certificate.getSubjectX500Principal().toString());
        CRLIssuingPointRecord pt = null;
        try {
            Enumeration<CRLIssuingPointRecord> eCRL = crlStore.searchAllCRLIssuingPointRecord(-1);
            while (eCRL.hasMoreElements() && pt == null) {
                CRLIssuingPointRecord tPt = eCRL.nextElement();
                logger.debug("OCSPEngine: CRL check issuer  " + tPt.getId());
                if(certificate.getIssuerX500Principal().equals(new X500Principal(tPt.getId()))) {
                    pt = tPt;
                }
            }
        } catch (EBaseException e) {
            logger.error("OCSPEngine: problem find CRL issuing point for " + certificate.getIssuerX500Principal().toString());
            return false;
        }
        if (pt == null) {
            logger.error("OCSPEngine: CRL issuing point not found for " + certificate.getIssuerX500Principal().toString());
            return false;
        }
        try {
            X509CRLImpl crl = new X509CRLImpl(pt.getCRL());
            X509CRLEntry crlentry = crl.getRevokedCertificate(certificate.getSerialNumber());

            if (crlentry == null && crlStore.isNotFoundGood()) {
                return true;
            }
        } catch (Exception e) {
            logger.error("OCSPEngine: crl check error. " + e.getMessage());
        }
        logger.info("OCSPEngine: peer certificate not valid");
        return false;
    }

}

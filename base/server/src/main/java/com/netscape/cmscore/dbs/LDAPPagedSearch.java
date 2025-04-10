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
// (C) 2023 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmscore.dbs;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.DBPagedSearch;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.certsrv.ldap.LDAPExceptionConverter;
import com.netscape.cmscore.apps.CMS;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPControl;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchConstraints;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPSortKey;
import netscape.ldap.LDAPv3;
import netscape.ldap.controls.LDAPPagedResultsControl;
import netscape.ldap.controls.LDAPSortControl;

/**
 * Perform consecutive paged search until entries are available.
 *
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public class LDAPPagedSearch<E extends IDBObj>  extends DBPagedSearch<E> {
    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(LDAPPagedSearch.class);

    private Class<E> contentClassType;
    private DBRegistry registry;
    private LDAPConnection conn = null;
    private String base = null;
    private String filter = null;
    private String[] attrs = null;
    private String[] sortKeys = null;
    private LDAPSearchResults res = null;

    public LDAPPagedSearch(Class<E> contentClassType, DBRegistry registry, LDAPConnection conn, String base, String filter, String[] attrs,
            String sortKey) throws EBaseException {
        this.contentClassType = contentClassType;
        this.registry = registry;
        this.base = base;
        this.filter = filter;
        this.attrs = attrs;
        if (sortKey != null) {
            this.sortKeys = new String[1];
            this.sortKeys[0] = sortKey;
        }
        try {
            this.conn = (LDAPConnection) conn.clone();
        } catch (Exception e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CONN_FAILED",
                        e.toString()), e);
        }
    }

    public LDAPPagedSearch(Class<E> contentClassType, DBRegistry registry, LDAPConnection conn, String base, String filter, String[] attrs,
            String[] sortKeys) throws EBaseException {
        this.contentClassType = contentClassType;
        this.registry = registry;
        this.base = base;
        this.filter = filter;
        this.attrs = attrs;
        this.sortKeys = sortKeys;
        try {
            this.conn = (LDAPConnection) conn.clone();
        } catch (Exception e) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_CONN_FAILED",
                        e.toString()), e);
        }
    }

    @Override
    public List<E> getPage()
        throws EBaseException {
        return getPage(LDAPSession.MAX_PAGED_SEARCH_SIZE);
    }

    @Override
    public List<E> getPage(int size)
            throws EBaseException {

        logger.info("LDAPPagedSearch: Searching {}", base);

        try {
            LDAPSearchConstraints cons = new LDAPSearchConstraints();
            LDAPPagedResultsControl pageCtrl = null;
            LDAPSortControl sortCtrl = generateSortControl(sortKeys);
            String[] ldapattrs = null;
            if (attrs != null) {
                ldapattrs = registry.getLDAPAttributes(attrs);
            }

            String ldapfilter = registry.getFilter(filter);
            logger.info("LDAPPagedSearch: filter: {}", ldapfilter);

            byte[] cookie = null;
            ArrayList<E> entries = new ArrayList<>();
            if (res != null) {
                for (LDAPControl c: res.getResponseControls()){
                    if(c instanceof LDAPPagedResultsControl resC){
                        cookie = resC.getCookie();
                    }
                }
                if (cookie == null) {
                    return entries;
                }
            }
            if (res == null) {
                pageCtrl = new LDAPPagedResultsControl(false, Math.min(size, LDAPSession.MAX_PAGED_SEARCH_SIZE));
            } else {
                pageCtrl = new LDAPPagedResultsControl(false, Math.min(size, LDAPSession.MAX_PAGED_SEARCH_SIZE), cookie);
            }
            if (sortCtrl != null) {
                LDAPControl[] controls = {sortCtrl, pageCtrl};
                cons.setServerControls(controls);
            } else {
                cons.setServerControls(pageCtrl);
            }
            res = conn.search(base,
                    LDAPv3.SCOPE_ONE, ldapfilter, ldapattrs, false, cons);
            DBSearchResults sr = new DBSearchResults(registry, res);
            while (sr.hasMoreElements()) {
                entries.add(contentClassType.cast(sr.nextElement()));
            }
            return entries;

        } catch (LDAPException e) {
            throw LDAPExceptionConverter.toDBException(e);
        }
    }

    private LDAPSortControl generateSortControl(String[] sortKeys) throws EBaseException {

        if (sortKeys == null || sortKeys.length == 0)
            return null;

        LDAPSortKey[] mKeys = new LDAPSortKey[sortKeys.length];
        String[] la = null;
        synchronized (this) {
            la = registry.getLDAPAttributes(sortKeys);
        }
        if (la == null) {
            logger.debug("LDAPPagedSearch.generateSortControl: cannot convert search keys {}", Arrays.toString(sortKeys));
            throw new EBaseException("sort keys cannot be null");
        }
        for (int i = 0; i < la.length; i++) {
            mKeys[i] = new LDAPSortKey(la[i]);
        }
        return new LDAPSortControl(mKeys, true);
    }
}

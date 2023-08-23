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
package com.netscape.cms.profile.common;

import java.util.Enumeration;
import java.util.Locale;
import java.util.Map;

import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.EPropertyException;
import com.netscape.certsrv.property.IConfigTemplate;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.cmscore.request.Request;

/**
 * This interface represents a output policy which
 * provides information on how to build the result
 * page for the enrollment.
 *
 * @version $Revision$, $Date$
 */
public abstract class ProfileOutput implements IConfigTemplate {

    /**
     * Initializes this default policy.
     *
     * @param config configuration store
     * @exception EProfileException failed to initialize
     */
    public abstract void init(ProfileOutputConfig config) throws EProfileException;

    /**
     * Retrieves configuration store.
     *
     * @return configuration store
     */
    public abstract ProfileOutputConfig getConfigStore();

    /**
     * Populates the request with this policy default.
     *
     * @param ctx profile context
     * @param request request
     * @exception EProfileException failed to populate
     */
    public abstract void populate(Map<String, String> ctx, Request request)
            throws EProfileException;

    /**
     * Retrieves the localizable name of this policy.
     *
     * @param locale user locale
     * @return output policy name
     */
    public abstract String getName(Locale locale);

    /**
     * Retrieves the localizable description of this policy.
     *
     * @param locale user locale
     * @return output policy description
     */
    public abstract String getText(Locale locale);

    /**
     * Retrieves a list of names of the value parameter.
     *
     * @return a list of property names
     */
    public abstract Enumeration<String> getValueNames();

    /**
     * Retrieves the descriptor of the given value
     * parameter by name.
     *
     * @param locale user locale
     * @param name property name
     * @return property descriptor
     */
    public abstract IDescriptor getValueDescriptor(Locale locale, String name);

    /**
     * Retrieves the value of the given value parameter by name.
     *
     * @param name property name
     * @param locale user locale
     * @param request request
     * @return property value
     * @exception EProfileException failed to retrieve value
     */
    public abstract String getValue(String name, Locale locale, Request request)
            throws EProfileException;

    /**
     * Sets the value of the given value parameter by name.
     *
     * @param name property name
     * @param locale user locale
     * @param request request
     * @param value property value
     */
    public abstract void setValue(String name, Locale locale, Request request,
            String value) throws EPropertyException;
}

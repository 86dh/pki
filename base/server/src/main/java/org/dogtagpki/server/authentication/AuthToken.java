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
package org.dogtagpki.server.authentication;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;

import org.mozilla.jss.netscape.security.util.DerInputStream;
import org.mozilla.jss.netscape.security.util.DerOutputStream;
import org.mozilla.jss.netscape.security.util.DerValue;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.usrgrp.Certificates;

/**
 * Authentication token returned by Authentication Managers.
 * Upon return, it contains authentication/identification information
 * as well as information retrieved from the database where the
 * authentication was done against. Each authentication manager has
 * its own list of such information. See individual authenticaiton
 * manager for more details.
 * <p>
 *
 * @version $Revision$, $Date$
 */
public class AuthToken implements IAuthToken {
    protected Hashtable<String, Object> mAttrs = null;

    public AuthToken() {
    }

    /**
     * Constructs an instance of a authentication token.
     * The token by default contains the following attributes: <br>
     *
     * <pre>
     * 	"authMgrInstName" - The authentication manager instance name.
     * 	"authTime" - The - The time of authentication.
     * </pre>
     *
     * @param authMgr The authentication manager that created this Token.
     */
    public AuthToken(AuthManager authMgr) {
        mAttrs = new Hashtable<>();
        if (authMgr != null) {
            set(TOKEN_AUTHMGR_INST_NAME, authMgr.getName());
        }
        set(TOKEN_AUTHTIME, new Date());
    }

    /**
     * Gets an attribute value.
     *
     * @param name the name of the attribute to return.
     * @exception EBaseException on attribute handling errors.
     * @return the attribute value
     */
    public Object get(String attrName) {
        return mAttrs.get(attrName);
    }

    /**
     * Gets an attribute value.
     *
     * @param name the name of the attribute to return.
     * @exception EBaseException on attribute handling errors.
     * @return the attribute value
     */
    public String getInString(String attrName) {
        return (String) mAttrs.get(attrName);
    }

    /**
     * Sets an attribute value within this AttrSet.
     *
     * @param attrName the name of the attribute
     * @param value the attribute object.
     * @return false on an error
     */
    public boolean set(String attrName, String value) {
        if (value == null) {
            return false;
        }
        mAttrs.put(attrName, value);
        return true;
    }

    /**
     * Removes an attribute in the AuthToken
     *
     * @param attrName The name of the attribute to remove.
     */
    public void delete(String attrName) {
        mAttrs.remove(attrName);
    }

    /**
     * Enumerate all attribute names in the AuthToken.
     *
     * @return Enumeration of all attribute names in this AuthToken.
     */
    public Enumeration<String> getElements() {
        return (mAttrs.keys());
    }

    /************
     * Helpers for non-string sets and gets.
     * These are needed because AuthToken is stored in Request (which can
     * only store string values
     */

    /**
     * Retrieves the byte array value for name. The value should have been
     * previously stored as a byte array (it will be CMS.AtoB decoded).
     *
     * @param name The attribute name.
     * @return The byte array or null on error.
     */
    public byte[] getInByteArray(String name) {
        String value = getInString(name);
        if (value == null) {
            return null;
        }
        return Utils.base64decode(value);
    }

    /**
     * Stores the byte array with the associated key.
     *
     * @param name The attribute name.
     * @param value The value to store
     * @return false on an error
     */
    public boolean set(String name, byte[] value) {
        if (value == null) {
            return false;
        }
        return set(name, Utils.base64encode(value, true));
    }

    /**
     * Retrieves the Integer value for name.
     *
     * @param name The attribute name.
     * @return The Integer or null on error.
     */
    public Integer getInInteger(String name) {
        String strVal = getInString(name);
        if (strVal == null) {
            return null;
        }
        try {
            return Integer.valueOf(strVal);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * Stores the Integer with the associated key.
     *
     * @param name The attribute name.
     * @param value The value to store
     * @return false on an error
     */
    public boolean set(String name, Integer value) {
        if (value == null) {
            return false;
        }
        return set(name, value.toString());
    }

    /**
     * Retrieves the BigInteger array value for name.
     *
     * @param name The attribute name.
     * @return The value or null on error.
     */
    public BigInteger[] getInBigIntegerArray(String name) {
        String value = getInString(name);
        if (value == null) {
            return null;
        }
        String[] values = value.split(",");
        if (values.length == 0) {
            return null;
        }
        BigInteger[] result = new BigInteger[values.length];
        for (int i = 0; i < values.length; i++) {
            try {
                result[i] = new BigInteger(values[i]);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return result;
    }

    /**
     * Stores the BigInteger array with the associated key.
     *
     * @param name The attribute name.
     * @param value The value to store
     * @return false on an error
     */
    public boolean set(String name, BigInteger[] value) {
        if (value == null) {
            return false;
        }
        StringBuffer buffer = new StringBuffer();
        for (int i = 0; i < value.length; i++) {
            if (i != 0) {
                buffer.append(",");
            }
            buffer.append(value[i].toString());
        }
        return set(name, buffer.toString());
    }

    /**
     * Retrieves the Date value for name.
     *
     * @param name The attribute name.
     * @return The value or null on error.
     */
    public Date getInDate(String name) {
        String value = getInString(name);
        if (value == null) {
            return null;
        }
        try {
            return new Date(Long.parseLong(value));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * Stores the Date with the associated key.
     *
     * @param name The attribute name.
     * @param value The value to store
     * @return false on an error
     */
    public boolean set(String name, Date value) {
        if (value == null) {
            return false;
        }
        return set(name, String.valueOf(value.getTime()));
    }

    /**
     * Retrieves the String array value for name.
     *
     * @param name The attribute name.
     * @return The value or null on error.
     */
    public String[] getInStringArray(String name) {
        String[] stringValues;

        byte[] byteValue = getInByteArray(name);
        if (byteValue == null) {
            return null;
        }
        try {
            DerInputStream in = new DerInputStream(byteValue);
            DerValue[] derValues = in.getSequence(5);
            stringValues = new String[derValues.length];
            for (int i = 0; i < derValues.length; i++) {
                stringValues[i] = derValues[i].getAsString();
            }
        } catch (IOException e) {
            return null;
        }
        return stringValues;
    }

    /**
     * Stores the String array with the associated key.
     *
     * @param name The attribute name.
     * @param value The value to store
     * @return False on error.
     */
    public boolean set(String name, String[] value) {
        if (value == null) {
            return false;
        }

        DerValue[] derValues = new DerValue[value.length];
        try (DerOutputStream out = new DerOutputStream()) {
            for (int i = 0; i < value.length; i++) {
                derValues[i] = new DerValue(value[i]);
            }
            out.putSequence(derValues);
            return set(name, out.toByteArray());
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Retrieves the X509CertImpl value for name.
     *
     * @param name The attribute name.
     * @return The value or null on error.
     */
    public X509CertImpl getInCert(String name) {
        byte[] data = getInByteArray(name);
        if (data == null) {
            return null;
        }
        try {
            return new X509CertImpl(data);
        } catch (CertificateException e) {
            return null;
        }
    }

    /**
     * Stores the X509CertImpl with the associated key.
     *
     * @param name The attribute name.
     * @param value The value to store
     * @return false on error
     */
    public boolean set(String name, X509CertImpl value) {
        if (value == null) {
            return false;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            value.encode(out);
        } catch (CertificateEncodingException e) {
            return false;
        }
        return set(name, out.toByteArray());
    }

    /**
     * Retrieves the CertificateExtensions value for name.
     *
     * @param name The attribute name.
     * @return The value.
     * @throws IOException
     */
    public CertificateExtensions getInCertExts(String name) throws IOException {
        CertificateExtensions exts = null;
        byte[] data = getInByteArray(name);
        if (data != null) {
            exts = new CertificateExtensions();
            // exts.decode() doesn't work for empty CertExts
            exts.decodeEx(new ByteArrayInputStream(data));
        }
        return exts;
    }

    /**
     * Stores the CertificateExtensions with the associated key.
     *
     * @param name The attribute name.
     * @param value The value to store
     * @return false on error
     */
    public boolean set(String name, CertificateExtensions value) {
        if (value == null) {
            return false;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            value.encode(out);
        } catch (IOException e) {
            return false;
        } catch (CertificateException e) {
            return false;
        }
        return set(name, out.toByteArray());
    }

    /**
     * Retrieves the Certificates value for name.
     *
     * @param name The attribute name.
     * @return The value.
     * @throws IOException
     * @throws CertificateException
     */
    public Certificates getInCertificates(String name) throws IOException, CertificateException {
        X509CertImpl[] certArray;

        byte[] byteValue = getInByteArray(name);
        if (byteValue == null) {
            return null;
        }

        DerInputStream in = new DerInputStream(byteValue);
        DerValue[] derValues = in.getSequence(5);
        certArray = new X509CertImpl[derValues.length];
        for (int i = 0; i < derValues.length; i++) {
            byte[] certData = derValues[i].toByteArray();
            certArray[i] = new X509CertImpl(certData);
        }
        return new Certificates(certArray);
    }

    /**
     * Stores the Certificates with the associated key.
     *
     * @param name The attribute name.
     * @param value The value to store
     * @return false on error
     */
    public boolean set(String name, Certificates value) {
        if (value == null) {
            return false;
        }
        X509Certificate[] certArray = value.getCertificates();
        DerValue[] derValues = new DerValue[certArray.length];
        try (DerOutputStream derStream = new DerOutputStream()) {
            for (int i = 0; i < certArray.length; i++) {
                ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
                try {
                    X509CertImpl certImpl = (X509CertImpl) certArray[i];
                    certImpl.encode(byteStream);
                    derValues[i] = new DerValue(byteStream.toByteArray());
                } catch (CertificateEncodingException e) {
                    return false;
                } catch (ClassCastException e) {
                    return false;
                }
            }
            derStream.putSequence(derValues);
            return set(name, derStream.toByteArray());
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Retrieves the byte[][] value for name.
     *
     * @param name The attribute name.
     * @return The value.
     * @throws IOException
     */
    public byte[][] getInByteArrayArray(String name) throws IOException {
        byte[][] retval;

        byte[] byteValue = getInByteArray(name);
        if (byteValue == null) {
            return null;
        }
        DerInputStream in = new DerInputStream(byteValue);
        DerValue[] derValues = in.getSequence(5);
        retval = new byte[derValues.length][];
        for (int i = 0; i < derValues.length; i++) {
            retval[i] = derValues[i].getOctetString();
        }
        return retval;
    }

    /**
     * Stores the byte[][] with the associated key.
     *
     * @param name The attribute name.
     * @param value The value to store
     * @return false on error
     */
    public boolean set(String name, byte[][] value) {
        if (value == null) {
            return false;
        }

        DerValue[] derValues = new DerValue[value.length];
        try (DerOutputStream out = new DerOutputStream()) {
            for (int i = 0; i < value.length; i++) {
                derValues[i] = new DerValue(DerValue.tag_OctetString, value[i]);
            }
            out.putSequence(derValues);
            return set(name, out.toByteArray());
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Enumerate all attribute values in the AuthToken.
     *
     * @return Enumeration of all attribute names in this AuthToken.
     */
    public Enumeration<Object> getVals() {
        return (mAttrs.elements());
    }

    /**
     * Gets the name of the authentication manager instance that created
     * this token.
     *
     * @return The name of the authentication manager instance that created
     *         this token.
     */
    public String getAuthManagerInstName() {
        return ((String) mAttrs.get(TOKEN_AUTHMGR_INST_NAME));
    }

    /**
     * Gets the time of authentication.
     *
     * @return The time of authentication
     */
    public Date getAuthTime() {
        return ((Date) mAttrs.get(TOKEN_AUTHTIME));
    }
}

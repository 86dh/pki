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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.tps.channel;

import java.io.IOException;

import org.dogtagpki.server.tps.TPSEngine;
import org.dogtagpki.server.tps.TPSEngineConfig;
import org.dogtagpki.server.tps.processor.TPSProcessor;
import org.dogtagpki.tps.apdu.APDU;
import org.dogtagpki.tps.apdu.APDUResponse;
import org.dogtagpki.tps.apdu.ClearKeySlotsAPDU;
import org.dogtagpki.tps.apdu.CreateObjectAPDU;
import org.dogtagpki.tps.apdu.CreatePinAPDU;
import org.dogtagpki.tps.apdu.DeleteFileAPDU;
import org.dogtagpki.tps.apdu.DeleteFileGP211APDU;
import org.dogtagpki.tps.apdu.DeleteKeysAPDU;
import org.dogtagpki.tps.apdu.ExternalAuthenticateAPDU;
import org.dogtagpki.tps.apdu.ExternalAuthenticateAPDU.SecurityLevel;
import org.dogtagpki.tps.apdu.ExternalAuthenticateAPDUGP211;
import org.dogtagpki.tps.apdu.GenerateKeyAPDU;
import org.dogtagpki.tps.apdu.GenerateKeyECCAPDU;
import org.dogtagpki.tps.apdu.ImportKeyEncAPDU;
import org.dogtagpki.tps.apdu.InstallAppletAPDU;
import org.dogtagpki.tps.apdu.InstallAppletAPDUGP211;
import org.dogtagpki.tps.apdu.InstallLoadAPDU;
import org.dogtagpki.tps.apdu.InstallLoadGP211APDU;
import org.dogtagpki.tps.apdu.LifecycleAPDU;
import org.dogtagpki.tps.apdu.LoadFileAPDU;
import org.dogtagpki.tps.apdu.LoadFileAPDUGP211;
import org.dogtagpki.tps.apdu.PutKeyAPDU;
import org.dogtagpki.tps.apdu.ReadObjectAPDU;
import org.dogtagpki.tps.apdu.SetIssuerInfoAPDU;
import org.dogtagpki.tps.apdu.SetPinAPDU;
import org.dogtagpki.tps.apdu.WriteObjectAPDU;
import org.dogtagpki.tps.apdu.ReadBufferAPDU;
import org.dogtagpki.tps.main.TPSBuffer;
import org.dogtagpki.tps.main.TPSException;
import org.dogtagpki.tps.main.Util;
import org.dogtagpki.tps.msg.EndOpMsg.TPSStatus;
import org.mozilla.jss.pkcs11.PK11SymKey;
import org.mozilla.jss.pkcs11.PKCS11Constants;

import com.netscape.certsrv.base.EBaseException;

import java.util.Arrays;

public class SecureChannel {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SecureChannel.class);

    // Have not written all code to use all of these as of yet.

    public TPSProcessor processor;
    private PK11SymKey sessionKey;

    //SCP01 or SCP02  or SCP03 key
    private PK11SymKey encSessionKey;


    //SCP02 session keys
    private PK11SymKey cmacSessionKey;
    //Used for security level we do not yet suport.

    private PK11SymKey rmacSessionKey;
    private PK11SymKey dekSessionKey;

    //SCP03
    private PK11SymKey macSessionKey;

    private TPSBuffer dekSessionKeyWrapped;

    private TPSBuffer drmDesKey;

    private TPSBuffer drmAesKey;
    private TPSBuffer aesDesKey;


    //SCP01 kek key
    private TPSBuffer kekDesKey;
    private TPSBuffer kekAesKey;
    private TPSBuffer keyCheck;
    private TPSBuffer keyDiversificationData;
    private TPSBuffer cardChallenge;
    private TPSBuffer cardCryptogram;
    private TPSBuffer hostChallenge;
    private TPSBuffer hostCryptogram;
    private TPSBuffer icv;
    private TPSBuffer keyInfoData;
    private TPSBuffer sequenceCounter;
    private ExternalAuthenticateAPDU.SecurityLevel secLevel;
    private PlatformAndSecChannelProtoInfo platProtInfo;
    private ExternalAuthenticateAPDUGP211.SecurityLevel secLevelGP211;

    public enum TokenKeyType {
        KEY_TYPE_ENCRYPTION,
        KEY_TYPE_SIGNING,
        KEY_TYPE_SIGNING_AND_ENCRYPTION
    }

    public final static byte GP211_SCP02_IMPL_15 = 0x15;
    public final static String GP201 = "2.0.1";
    public final static String GP211 = "2.1.1";

    public final static byte SECURE_PROTO_01 = 1;
    public final static byte SECURE_PROTO_02 = 2;
    public final static byte SECURE_PROTO_03 = 3;

    public final static byte[] GP211_GET_DATA_CARD_DATA = { 0x00, (byte) 0x66 };
    public final static byte[] GP211_GET_DATA_KEY_INFO = { 0x00, (byte) 0xe0 };
    public final static byte[] GP201_GET_DATA_CPLC_WHOLE_CPLC = { (byte) 0x9F, (byte) 0x7F };
    public final static byte[] GP211_GET_DATA_CPLC_WHOLE_CPLC = { (byte) 0x9F, (byte) 0x7F };

    // SCP02
    public final static byte[] C_MACDerivationConstant = { 0x01, 0x01 };
    public final static byte[] ENCDerivationConstant = { (byte) 0x01, (byte) 0x82 };
    public final static byte[] DEKDerivationConstant = { 0x01, (byte) 0x81 };
    public final static byte[] R_MACDerivationConstant = { 0x01, 0x02 };

    //SCP03 encryption counter

    private TPSBuffer encryptionCounter;


    //For SCP03

    public SecureChannel(TPSProcessor processor,  PK11SymKey encSessionKey, PK11SymKey macSessionKey, PK11SymKey dekSessionKey,
            TPSBuffer drmDesKey,TPSBuffer kekDesKey,
             TPSBuffer keyCheck, TPSBuffer keyDiversificationData, TPSBuffer cardChallenge,
            TPSBuffer cardCryptogram, TPSBuffer hostChallenge, TPSBuffer hostCryptogram, TPSBuffer keyInfoData,
            PlatformAndSecChannelProtoInfo platformInfo)
            throws TPSException {

        if (processor == null ||  encSessionKey == null || keyDiversificationData == null
                || cardChallenge == null || cardCryptogram == null || hostChallenge == null || hostCryptogram == null
                || keyInfoData == null) {
            throw new TPSException("SecureChannel.SecureChannel: Invalid data in constructor!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        logger.debug("SecureChannel.SecureChannel: For SCP03. :  ");

        //if (keyCheck != null)
        //    logger.debug("keyCheck: " + keyCheck.toHexString());

        this.platProtInfo = platformInfo;
        this.processor = processor;
        this.encSessionKey = encSessionKey;
        this.macSessionKey = macSessionKey;
        this.dekSessionKey = dekSessionKey;

        this.drmDesKey = drmDesKey;
        this.setKekDesKey(kekDesKey);

        this.keyCheck = keyCheck;
        this.keyDiversificationData = keyDiversificationData;
        this.cardChallenge = cardChallenge;
        this.cardCryptogram = cardCryptogram;
        this.hostChallenge = hostChallenge;
        this.hostCryptogram = hostCryptogram;

        //16 bytes of chaining value
        this.icv = new TPSBuffer(16);

        this.keyInfoData = keyInfoData;

        this.secLevel = SecurityLevel.SECURE_MSG_NONE;
        this.secLevelGP211 = ExternalAuthenticateAPDUGP211.SecurityLevel.CDEC_CMAC;
        encryptionCounter = new TPSBuffer(16);

    }

    //For SCP01
    public SecureChannel(TPSProcessor processor, PK11SymKey sessionKey, PK11SymKey encSessionKey, TPSBuffer drmDesKey,
            TPSBuffer kekDesKey, TPSBuffer keyCheck, TPSBuffer keyDiversificationData, TPSBuffer cardChallenge,
            TPSBuffer cardCryptogram, TPSBuffer hostChallenge, TPSBuffer hostCryptogram, TPSBuffer keyInfoData,
            PlatformAndSecChannelProtoInfo platformInfo)
            throws TPSException {

        if (processor == null || sessionKey == null | encSessionKey == null || keyDiversificationData == null
                || cardChallenge == null || cardCryptogram == null || hostChallenge == null || hostCryptogram == null
                || keyInfoData == null) {
            throw new TPSException("SecureChannel.SecureChannel: Invalid data in constructor!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        logger.debug("SecureChannel.SecureChannel: For SCP01. ");

        this.platProtInfo = platformInfo;
        this.processor = processor;
        this.sessionKey = sessionKey;
        this.encSessionKey = encSessionKey;
        this.drmDesKey = drmDesKey;
        this.setKekDesKey(kekDesKey);
        this.keyCheck = keyCheck;
        this.keyDiversificationData = keyDiversificationData;
        this.cardChallenge = cardChallenge;
        this.cardCryptogram = cardCryptogram;
        this.hostChallenge = hostChallenge;
        this.hostCryptogram = hostCryptogram;
        this.icv = new TPSBuffer(8);
        this.keyInfoData = keyInfoData;

        this.secLevel = SecurityLevel.SECURE_MSG_MAC_ENC;

    }

    //For SCP02
    public SecureChannel(TPSProcessor processor, PK11SymKey encSessionKey, PK11SymKey cmacSessionKey,
            PK11SymKey rmacSessionKey, PK11SymKey dekSessionKey, TPSBuffer drmDesKey,
            TPSBuffer kekDesKey, TPSBuffer keyCheck,
            TPSBuffer keyDiversificationData,
            TPSBuffer keyInfoData, TPSBuffer sequenceCounter, TPSBuffer hostChallenge, TPSBuffer cardChallenge,
            TPSBuffer cardCryptogram, PlatformAndSecChannelProtoInfo platformInfo)
            throws TPSException {

        if (processor == null || encSessionKey == null | cmacSessionKey == null || rmacSessionKey == null
                || dekSessionKey == null || keyDiversificationData == null || hostChallenge == null
                || cardChallenge == null || cardCryptogram == null
                || keyInfoData == null || platformInfo == null) {
            throw new TPSException("SecureChannel.SecureChannel: Invalid data in constructor!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        this.sequenceCounter = sequenceCounter;
        this.platProtInfo = platformInfo;
        this.processor = processor;

        this.encSessionKey = encSessionKey;
        this.cmacSessionKey = cmacSessionKey;
        this.setRmacSessionKey(rmacSessionKey);

        this.keyDiversificationData = keyDiversificationData;

        this.icv = new TPSBuffer(8);
        this.keyInfoData = keyInfoData;
        this.cardChallenge = cardChallenge;
        this.cardCryptogram = cardCryptogram;
        this.hostChallenge = hostChallenge;
        this.drmDesKey = drmDesKey;
        this.kekDesKey = kekDesKey;

        //SCP02
        this.secLevelGP211 = ExternalAuthenticateAPDUGP211.SecurityLevel.CDEC_CMAC;
        this.keyCheck = keyCheck;

        byte finalKeyIndex = gp211CalculateLatestKeySet(platformInfo.getKeysetInfoData());

        logger.debug("SecureChannel.SecureChannel: For SCP02: calculated latest key index: " + finalKeyIndex);

    }

    private byte gp211CalculateLatestKeySet(TPSBuffer keysetInfoData) throws TPSException {

        if (keysetInfoData == null) {

            throw new TPSException("SecureChannel.gp211calculateKeyInfoData invalid input data!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);

        }

        logger.debug("SecureChannel.gp211calculateKeyInfoData: input keysetInfoData: " + keysetInfoData.toHexString());

        int pos = 0;
        byte next = keysetInfoData.at(pos++);

        if (next != (byte) 0xE0) {
            throw new TPSException("SecureChannel.gp211calculateKeyInfoData: malformed input data!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        next = keysetInfoData.at(pos++);

        int numKeys = (next) / 6;

        int remainder = (next) % 6;

        if (remainder != 0) {
            throw new TPSException("SecureChannel.gp211calculateKeyInfoData: malformed input data!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        logger.debug("SecureChannel.gp211calculateKeyInfoData: number of keys: " + numKeys);

        int numKeySets = numKeys / 3; //Three keys per set

        logger.debug("SecureChannel.gp211calculateKeyInfoData: number of keysets: " + numKeySets);

        int offset = (numKeySets - 1) * 6 * 3 + 3;

        logger.debug("SecureChannel.gp211calculateKeyInfoData: offset " + offset);

        offset += pos;

        if (offset > keysetInfoData.size()) {
            throw new TPSException("SecureChannel.gp211calculateKeyInfoData: malformed input data!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        byte finalKeyIndex = keysetInfoData.at(offset);

        return finalKeyIndex;

    }

    public void appendPKCS11Attribute(TPSBuffer buffer, long type, TPSBuffer attribute) {

        buffer.addLong4Bytes(type);

        buffer.addInt2Bytes(attribute.size());
        buffer.add(attribute);
    }

    public void appendKeyCapabilities(TPSBuffer buffer, String keyTypePrefix, String keyType) throws TPSException {

        if (buffer == null || keyTypePrefix == null || keyType == null) {
            throw new TPSException("SecureChannel.appdndKeyCabalities: Invalid input datat.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        TPSEngineConfig configStore = this.getConfigStore();

        final String keyCapabilities = "keyCapabilities";

        try {

            boolean value = false;
            String configName = keyTypePrefix + "." + keyType + "." + keyCapabilities + "." + "encrypt";

            value = configStore.getBoolean(configName);

            TPSBuffer attr = new TPSBuffer(Util.bool2Byte(value));
            appendPKCS11Attribute(buffer, PKCS11Constants.CKA_ENCRYPT, attr);

            configName = keyTypePrefix + "." + keyType + "." + keyCapabilities + "." + "sign";
            value = configStore.getBoolean(configName);
            attr = new TPSBuffer(Util.bool2Byte(value));
            appendPKCS11Attribute(buffer, PKCS11Constants.CKA_SIGN, attr);

            configName = keyTypePrefix + "." + keyType + "." + keyCapabilities + "." + "signRecover";
            value = configStore.getBoolean(configName);
            attr = new TPSBuffer(Util.bool2Byte(value));
            appendPKCS11Attribute(buffer, PKCS11Constants.CKA_SIGN_RECOVER, attr);

            configName = keyTypePrefix + "." + keyType + "." + keyCapabilities + "." + "decrypt";
            value = configStore.getBoolean(configName);
            attr = new TPSBuffer(Util.bool2Byte(value));
            appendPKCS11Attribute(buffer, PKCS11Constants.CKA_DECRYPT, attr);

            configName = keyTypePrefix + "." + keyType + "." + keyCapabilities + "." + "derive";
            value = configStore.getBoolean(configName);
            attr = new TPSBuffer(Util.bool2Byte(value));
            appendPKCS11Attribute(buffer, PKCS11Constants.CKA_DERIVE, attr);

            configName = keyTypePrefix + "." + keyType + "." + keyCapabilities + "." + "unwrap";
            value = configStore.getBoolean(configName);
            attr = new TPSBuffer(Util.bool2Byte(value));
            appendPKCS11Attribute(buffer, PKCS11Constants.CKA_UNWRAP, attr);

            configName = keyTypePrefix + "." + keyType + "." + keyCapabilities + "." + "wrap";
            value = configStore.getBoolean(configName);
            attr = new TPSBuffer(Util.bool2Byte(value));
            appendPKCS11Attribute(buffer, PKCS11Constants.CKA_WRAP, attr);

            configName = keyTypePrefix + "." + keyType + "." + keyCapabilities + "." + "verifyRecover";
            value = configStore.getBoolean(configName);
            attr = new TPSBuffer(Util.bool2Byte(value));
            appendPKCS11Attribute(buffer, PKCS11Constants.CKA_VERIFY_RECOVER, attr);

            configName = keyTypePrefix + "." + keyType + "." + keyCapabilities + "." + "verify";
            value = configStore.getBoolean(configName);
            attr = new TPSBuffer(Util.bool2Byte(value));
            appendPKCS11Attribute(buffer, PKCS11Constants.CKA_VERIFY, attr);

            configName = keyTypePrefix + "." + keyType + "." + keyCapabilities + "." + "sensitive";
            value = configStore.getBoolean(configName);
            attr = new TPSBuffer(Util.bool2Byte(value));
            appendPKCS11Attribute(buffer, PKCS11Constants.CKA_SENSITIVE, attr);

            configName = keyTypePrefix + "." + keyType + "." + keyCapabilities + "." + "private";
            value = configStore.getBoolean(configName);
            attr = new TPSBuffer(Util.bool2Byte(value));
            appendPKCS11Attribute(buffer, PKCS11Constants.CKA_PRIVATE, attr);

            configName = keyTypePrefix + "." + keyType + "." + keyCapabilities + "." + "token";
            value = configStore.getBoolean(configName);
            attr = new TPSBuffer(Util.bool2Byte(value));
            appendPKCS11Attribute(buffer, PKCS11Constants.CKA_TOKEN, attr);

            //logger.debug("SecureChannel.appendKeyCapabilities: returning: " + buffer.toHexString());
            logger.debug("SecureChannel.appendKeyCapabilities: returning");

        } catch (EBaseException e) {
            throw new TPSException("SecureChannel.appentKeyCapabilities. Can't obtain config value!",
                    TPSStatus.STATUS_ERROR_MISCONFIGURATION);
        }
    }

    public void externalAuthenticate() throws TPSException, IOException {

        String method = "SecureChannel.externalAuthenticate.";
        logger.debug(method + ": entering. &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&");

        TPSBuffer calculatedCardCryptogram = null;
        if(platProtInfo.isSCP03()) {
            logger.debug("SecureChannel.externalAuthenticate: Attempting an External Authenticate for SCP03!");

            TPSBuffer context = new TPSBuffer(hostChallenge);
            context.add(cardChallenge);
            try {
                calculatedCardCryptogram = SecureChannelProtocol.compute_AES_CMAC_Cryptogram(macSessionKey, context, SecureChannelProtocol.CARD_CRYPTO_KDF_CONSTANT_SCP03);
            } catch (EBaseException e) {
                throw new TPSException(method + "Failed to calculate card cryptogram!", TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
            }

            //if(cardCryptogram != null)
            //    logger.debug(method + " actual card cryptogram " + cardCryptogram.toHexString());

            //if(calculatedCardCryptogram != null)
            //    logger.debug(method + " calculated card cryptogram " + calculatedCardCryptogram.toHexString());

            ExternalAuthenticateAPDUGP211 externalAuth = new ExternalAuthenticateAPDUGP211(hostCryptogram,
                    /* secLevel */secLevelGP211);

            computeAPDUMacSCP03(externalAuth);

            APDUResponse response = processor.handleAPDURequest(externalAuth);

            if (!response.checkResult()) {
                throw new TPSException(
                        "SecureChannel.eternalAuthenticate SCP03. Failed to external authenticate to token.",
                        TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
            }

        }


        if (platProtInfo.isSCP02()) {
            logger.debug("SecureChannel.externalAuthenticate: Attempting an External Authenticate for SCP02!");

            calculatedCardCryptogram = computeCardCryptogramSCP02(encSessionKey);

            if (false == cardCryptogram.equals(calculatedCardCryptogram)) {

                logger.debug("SecureChannel.externalAuthenticate. Failed to match calculated to returned card cryptogram!. cardCryptogram: "
                        + cardCryptogram.toHexString()
                        + " calculatedCardCryptogram: "
                        + calculatedCardCryptogram.toHexString());
                throw new TPSException(
                        "SecureChannel.externalAuthenticate. Failed to match calculated to returned card cryptogram!.",
                        TPSStatus.STATUS_ERROR_SECURE_CHANNEL);

            }

            TPSBuffer calculatedHostCryptogram = computeHostCryptogramSCP02(encSessionKey);
            this.hostCryptogram = calculatedHostCryptogram;

            ExternalAuthenticateAPDUGP211 externalAuth = new ExternalAuthenticateAPDUGP211(hostCryptogram,
                    /* secLevel */secLevelGP211);

            logger.debug("SecureChannel.externalAuthenticate: about to call computeAPDUMacSCP02. &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&");
            computeAPDUMacSCP02(externalAuth);

            APDUResponse response = processor.handleAPDURequest(externalAuth);

            if (!response.checkResult()) {
                throw new TPSException(
                        "SecureChannel.eternalAuthenticate SCP02. Failed to external authenticate to token.",
                        TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
            }

            logger.debug("SecureChannel.externalAuthenticate: SCP02 external authenticate returns Success!!!");

        } else  if(platProtInfo.isSCP01()){ //SCP01

            ExternalAuthenticateAPDU externalAuth = new ExternalAuthenticateAPDU(hostCryptogram,
                    /* secLevel */ExternalAuthenticateAPDU.SecurityLevel.SECURE_MSG_MAC_ENC);

            logger.debug("SecureChannel.externalAuthenticate: about to call computeAPDUMac. &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&");
            computeAPDUMac(externalAuth);

            APDUResponse response = processor.handleAPDURequest(externalAuth);

            if (!response.checkResult()) {
                throw new TPSException(
                        "SecureChannel.externalAuthenticate SCP01. Failed to external authenticate to token.",
                        TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
            }

        }

        logger.debug("SecureChannel.externalAuthenticate: Successfully completed, exiting ...");
    }

    //This method computes the mac AND encryption if needed.
    // Handle SCP02 if required.
    private void computeAPDU(APDU apdu) throws TPSException {

        logger.debug("SecureChannel.computeAPDU: entering..");

        if (apdu == null) {
            throw new TPSException("SecureChannel.computeAPDU: bad input apdu!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        if (isSCP02()) {
            computeAPDU_SCP02(apdu);
            return;

        }

        if (isSCP03() ) {
            computeAPDU_SCP03(apdu);
            return;
        }

        computeAPDUMac(apdu);

        if (secLevel == SecurityLevel.SECURE_MSG_MAC_ENC) {
            try {
                apdu.secureMessage(encSessionKey, (byte) 1);
            } catch (EBaseException e) {
                throw new TPSException("SecureChannel.computeAPDU: Can't encrypt outgoing data! " + e,
                        TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
            }

            logger.debug("SecureChannel.computeAPDU: Successfully encrypted apdu data.");
        }
    }

    private void computeAPDU_SCP03(APDU apdu) throws TPSException {
        String method = "SecureChannel.computeAPDU_SCP03:";

        logger.debug(method + "entering..");
        if (apdu == null) {
            throw new TPSException(method + " bad input apdu!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        if (secLevelGP211 == ExternalAuthenticateAPDUGP211.SecurityLevel.CDEC_CMAC) {
            try {
                this.incrementBuffer(encryptionCounter);
                TPSBuffer currentEncryptionCounter = new TPSBuffer(encryptionCounter);
                apdu.secureMessageSCP03(encSessionKey,currentEncryptionCounter);
            } catch (EBaseException e) {
                throw new TPSException("SecureChannel.computeAPDU_SCP03: Can't encrypt outgoing data! " + e,
                        TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
            }

            logger.debug("SecureChannel.computeAPDU_SCP03: Successfully encrypted apdu data.");
        }

        computeAPDUMacSCP03(apdu);
    }

  //Assume the whole buffer is to be incremented
    //Used for SCP03 encrypted apdu messages
    public void incrementBuffer(TPSBuffer buffer) {

        if(buffer == null)
            return;

        int len = buffer.size();

        if (len < 1)
            return;
        int offset = 0;
        for (short i = (short) (offset + len - 1); i >= offset; i--) {
            byte cur = buffer.at(i);
            if (cur != (byte) 0xFF) {
                    cur++;
                    buffer.setAt(i, cur);
                    break;
            } else
                    buffer.setAt(i,(byte) 0x00);
        }

        System.out.println("enc buffer: " + buffer.toHexString());
    }

    private void computeAPDU_SCP02(APDU apdu) throws TPSException {
        logger.debug("SecureChannel.computeAPDU_SCP02: entering..");

        if (apdu == null) {
            throw new TPSException("SecureChannel.computeAPDU_SCP02: bad input apdu!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        computeAPDUMacSCP02(apdu);

        if (secLevelGP211 == ExternalAuthenticateAPDUGP211.SecurityLevel.CDEC_CMAC) {
            try {
                apdu.secureMessageSCP02(encSessionKey);
            } catch (EBaseException e) {
                throw new TPSException("SecureChannel.computeAPDU_SCP02: Can't encrypt outgoing data! " + e,
                        TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
            }

            logger.debug("SecureChannel.computeAPDU_SCP02: Successfully encrypted apdu data.");
        }

    }

    private void computeAPDUMacSCP03(APDU apdu) throws TPSException {
        TPSBuffer newMac = null;
        TPSBuffer data = null;

        if (apdu == null) {
            throw new TPSException("SecureChannel.computeAPDUMacSCP03: bad input apdu!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        data = apdu.getDataToMAC();

        try {
                TPSBuffer dataToMac = new TPSBuffer(icv);
                /// Prepend the chaining value to the data to be maced.
                dataToMac.add(data);

                newMac = SecureChannelProtocol.computeAES_CMAC(macSessionKey, dataToMac);


        } catch (EBaseException e) {
            logger.debug("SecureChannel.computeAPDUMacSCP03: Can't compute mac. " + e);
            throw new TPSException("SecureChannel.compuatAPDUMacSCP03: Can't compute mac.",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        //logger.debug("SecureChannel.computeAPDUMacSCP03: computed MAC: " /* + newMac.toHexString() */);

        apdu.setMAC(newMac.substr(0,8));
        
        icv.set(newMac);
    }

    private void computeAPDUMacSCP02(APDU apdu) throws TPSException {

        TPSBuffer newMac = null;
        TPSBuffer data = null;
        TPSBuffer singleDes = null;

        if (apdu == null) {
            throw new TPSException("SecureChannel.computeAPDUMacSCP02: bad input apdu!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        data = apdu.getDataToMAC();

        logger.debug("SecureChannel.computeAPDUMacSCP02: data To MAC: " + data.toHexString() + " incoming icv: "
                + icv.toHexString());

        try {

            if (apdu.getType() != APDU.Type.APDU_EXTERNAL_AUTHENTICATE
                    && (secLevelGP211 == ExternalAuthenticateAPDUGP211.SecurityLevel.CMAC || secLevelGP211 == ExternalAuthenticateAPDUGP211.SecurityLevel.CDEC_CMAC)) {
                logger.debug("SecureChannel.computeAPDUMacSCP02: data To MAC, calcuating single des encyption before mac.");

                singleDes = Util.computeEncEcbDes(cmacSessionKey, icv);
                logger.debug("SecureChannel.computeAPDUMacSCP02: data To MAC, calcuating single des encyption before mac. result: "
                        + singleDes.toHexString());

                newMac = Util.computeMACdes3des(cmacSessionKey, data, singleDes);
            } else {
                logger.debug("SecureChannel.computeAPDUMacSCP02: No ecnrypton of ICV.");
                newMac = Util.computeMACdes3des(cmacSessionKey, data, icv);

            }

        } catch (EBaseException e) {
            logger.debug("SecureChannel.computeAPDUMacSCP02: Can't compute mac. " + e);
            throw new TPSException("SecureChannel.compuatAPDUMacSCP02: Can't compute mac.",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        logger.debug("SecureChannel.computeAPDUMacSCP02: computed MAC: " + newMac.toHexString());

        apdu.setMAC(newMac);

        icv.set(newMac);

    }

    // This method computes MAC only.
    private void computeAPDUMac(APDU apdu) throws TPSException {
        TPSBuffer newMac = null;
        TPSBuffer data = null;

        if (apdu == null) {
            throw new TPSException("SecureChannel.computeAPDUMac: bad input apdu!",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        data = apdu.getDataToMAC();

        //logger.debug("SecureChannel.computeAPDUMac: data To MAC: " + data.toHexString());
        logger.debug("SecureChannel.computeAPDUMac: got data To MAC");

        try {
            newMac = Util.computeMAC(sessionKey, data, icv);
        } catch (EBaseException e) {
            logger.debug("SecureChannel.compuatAPDUMac: Can't compute mac. " + e);
            throw new TPSException("SecureChannel.compuatAPDUMac: Can't compute mac.",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        //logger.debug("SecureChannel.computeAPDUMac: computed MAC: " + newMac.toHexString());
        logger.debug("SecureChannel.computeAPDUMac: MAC computed");

        apdu.setMAC(newMac);

        icv.set(newMac);
    }

    public void deleteFileX(TPSBuffer aid) throws TPSException, IOException {
        logger.debug("SecureChannel.deleteFileX: entering...");
        if (aid == null) {
            throw new TPSException("SecureChannel.deleteFileX: no input aid!", TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }

        if (isGP211()) {

            logger.debug("SecureChannel.deleteFileX: attempting gp211...");
            DeleteFileGP211APDU deleteFile = new DeleteFileGP211APDU(aid);

            computeAPDU(deleteFile);

            processor.handleAPDURequest(deleteFile);
        } else {

            logger.debug("SecureChannel.deleteFileX: attempting gp201...");
            DeleteFileAPDU deleteFile = new DeleteFileAPDU(aid);

            computeAPDU(deleteFile);

            processor.handleAPDURequest(deleteFile);

        }

    }

    // Begin process of loading applet onto token.
    public void installLoad(TPSBuffer packageAID, TPSBuffer sdAID, int fileLength) throws TPSException, IOException {

        logger.debug("SecureChannel.installLoad: entering ... packageAID: " + packageAID.toHexString() + " sdAID: "
                + sdAID.toHexString() + " fileLength: " + fileLength);

        if (packageAID == null || sdAID == null || fileLength <= 0) {
            throw new TPSException("SecureChannel.installLoad bad input parameters!",
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }

        TPSBuffer emptySDAID = new TPSBuffer();

        if (isGP211()) {
            logger.debug("SecureChannel.installLoad: isGP211 is true");
            TPSBuffer cardMgrGP211AIDBuff = new TPSBuffer(TPSEngine.CFG_DEF_CARDMGR_211_INSTANCE_AID);
            
            TPSBuffer aidSubStrBuffer = new TPSBuffer(cardMgrGP211AIDBuff.substr(0,sdAID.size()));
            byte[] defaultAIDtoChk = aidSubStrBuffer.toBytesArray();
            
            // Use default AID unless another AID was already selected
            if (!Arrays.equals(sdAID.toBytesArray(),defaultAIDtoChk))
            {
                cardMgrGP211AIDBuff = new TPSBuffer(sdAID);
            } 

            installLoadGP211(packageAID, cardMgrGP211AIDBuff, fileLength);
            return;
        }

        InstallLoadAPDU install = new InstallLoadAPDU(packageAID, emptySDAID, fileLength);

        logger.debug("SecureChannel.installLoad: Pre computed apdu: " + install.getEncoding().toHexString());

        computeAPDU(install);

        APDUResponse response = processor.handleAPDURequest(install);

        if (!response.checkResult()) {
            throw new TPSException("SecureChannel.installLoad. Failed to perform installLoad operation.",
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }

    }

    public void installLoadGP211(TPSBuffer packageAID, TPSBuffer sdAID, int fileLength) throws TPSException,
            IOException {

        logger.debug("SecureChannel.installLoadGP211: entering ...");

        if (packageAID == null || sdAID == null || fileLength <= 0) {
            throw new TPSException("SecureChannel.installLoadGP211 bad input parameters!",
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }

        InstallLoadGP211APDU install = new InstallLoadGP211APDU(packageAID, sdAID,
                fileLength);

        computeAPDU(install);

        APDUResponse response = processor.handleAPDURequest(install);

        if (!response.checkResult()) {
            throw new TPSException("SecureChannel.installLoadGP211. Failed to perform installLoadGP211 operation.",
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }
    }

    //Actually load applet file onto the token.

    public void loadFile(TPSBuffer programFile, int blockSize, int startProgress, int endProgress) throws TPSException,
            IOException {
        logger.debug("SecureChannel.loadFile entering... blockSize: " + blockSize);

        if (programFile == null || blockSize <= 0) {
            throw new TPSException("ScureChannel.loadFile. Bad input data.", TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }

        TPSBuffer length = null;

        TPSBuffer tag = new TPSBuffer(1, (byte) 0xC4);

        int progSize = programFile.size();

        if (progSize < 128) {
            length = new TPSBuffer(1, (byte) progSize);
        } else if (progSize <= 255) {
            length = new TPSBuffer(1, (byte) 0x81);
            length.add((byte) progSize);
        } else {
            length = new TPSBuffer(1, (byte) 0x82);
            length.add((byte) ((progSize >> 8) & 0xff));
            length.add((byte) (progSize & 0xff));

        }

        TPSBuffer tbsProgramFile = new TPSBuffer(tag);
        tbsProgramFile.add(length);
        tbsProgramFile.add(programFile);

        int totalLen = tbsProgramFile.size();
        int sizeToSend = totalLen;

        int finalBlockSize = 0;
        float progressBlockSize = 0;

        if (secLevel == SecurityLevel.SECURE_MSG_MAC_ENC) {
            // need leave room for possible encryption padding
            finalBlockSize = blockSize - 0x10;
        } else {
            finalBlockSize = blockSize - 8;
        }

        //rough number is good enough
        int numLoops = sizeToSend / blockSize;

        if (numLoops == 0) { // We have bogus data here. Good bye.
            throw new TPSException("SecureChannel.loadFile. Bad input data.", TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }
        progressBlockSize = (float) (endProgress - startProgress) / numLoops;

        int count = 0;
        byte refControl = 0x00;

        do {
            if (sizeToSend < finalBlockSize) {
                finalBlockSize = sizeToSend;
                refControl = (byte) 0x80;

            }

            logger.debug("SecureChannel.loadFile: taking data substring from: " + (totalLen - sizeToSend) + " size: "
                    + finalBlockSize + " to: " + ((totalLen - sizeToSend) + finalBlockSize));

            TPSBuffer piece = tbsProgramFile.substr(totalLen - sizeToSend, finalBlockSize);

            logger.debug("SecureChannel.loadFile: attempting to send piece: " + sizeToSend);

            loadFileSegment(refControl, count, piece);

            if (processor.requiresStatusUpdate()) {
                processor.statusUpdate(startProgress + (int) (count * progressBlockSize), "PROGRESS_APPLET_BLOCK");
            }

            sizeToSend -= finalBlockSize;

            count++;

        } while (sizeToSend > 0);

    }

    //Load one piece of the applet file onto the token.
    private void loadFileSegment(byte refControl, int count, TPSBuffer piece) throws TPSException, IOException {

        logger.debug("SecureChannel.loadFileSegment: begins");
        if (piece == null || count < 0) {
            throw new TPSException("SecureChannel.loadFileSegment: invalid input data.",
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }

        //logger.debug("SecureChannel.loadFileSegment: count: " + count + " piece: " + piece.toHexString());

        APDUResponse response = null;

        if (isGP211()) {
            LoadFileAPDUGP211 loadFile = new LoadFileAPDUGP211(refControl, (byte) count, piece);

            computeAPDU(loadFile);

            response = processor.handleAPDURequest(loadFile);
        } else {
            logger.debug("SecureChannel.loadFileSegment: gp211.");
            LoadFileAPDU loadFile = new LoadFileAPDU(refControl, (byte) count, piece);

            computeAPDU(loadFile);

            response = processor.handleAPDURequest(loadFile);

        }

        if (!response.checkResult()) {
            throw new TPSException(
                    "SecureChannel.loadFileSegment. Failed to perform loadFileSegmentInstallLoad operation.",
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }

        logger.debug("SecureChannel.loadFileSegment: ends");
    }

    // Kick off the applet loading process.
    public void installApplet(TPSBuffer netkeyPAIDBuff, TPSBuffer netkeyAIDBuff, byte appPrivileges,
            int channelInstanceSize,
            int channelAppletMemSize) throws TPSException, IOException {

        logger.debug("SecureChannel.installApplet: entering...");

        // Would be tough to put a check on the various input sizes, let the applet
        // decide if the values are appropriate for channelInstanceSize and channelAppletMemSize

        if (netkeyPAIDBuff == null || netkeyAIDBuff == null || channelInstanceSize < 0 || channelAppletMemSize < 0) {
            throw new TPSException("SecureChannel.installApplet. Invalid input parameters!",
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);

        }

        APDUResponse response = null;

        if (isGP211()) {
            InstallAppletAPDUGP211 install = new InstallAppletAPDUGP211(netkeyPAIDBuff, netkeyAIDBuff, appPrivileges,
                    channelInstanceSize, channelAppletMemSize);

            computeAPDU(install);

            response = processor.handleAPDURequest(install);
        } else {

            InstallAppletAPDU install = new InstallAppletAPDU(netkeyPAIDBuff, netkeyAIDBuff, appPrivileges,
                    channelInstanceSize, channelAppletMemSize);

            computeAPDU(install);

            response = processor.handleAPDURequest(install);

        }

        if (!response.checkResult()) {
            throw new TPSException("SecureChannel.installApplet. Failed installApplet operation.",
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }

    }

    // Burn the phone home URL into the token.
    public void setIssuerInfo(TPSBuffer issuerInfoBuff) throws TPSException, IOException {
        logger.debug("SecureChannel.setIssuerInfo entering...");

        final int finalIssuerLength = 224;
        final int approxMinUrlSize = 5;

        if (issuerInfoBuff == null || issuerInfoBuff.size() < approxMinUrlSize) {
            throw new TPSException("SecureChannel.setIssuerInfo: Invalid input data.",
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }

        int issuerLen = issuerInfoBuff.size();

        int paddingLen = finalIssuerLength - issuerLen;

        TPSBuffer paddingBuff = new TPSBuffer(paddingLen, (byte) 0x0);

        TPSBuffer finalIssuerBuff = new TPSBuffer(issuerInfoBuff);

        finalIssuerBuff.add(paddingBuff);

        logger.debug("finalIssuerBuff len: " + finalIssuerBuff.size() + " issuerInfo: " + finalIssuerBuff.toString());
        SetIssuerInfoAPDU setIssuer = new SetIssuerInfoAPDU((byte) 0x0, (byte) 0x0, finalIssuerBuff);

        computeAPDU(setIssuer);

        APDUResponse response = processor.handleAPDURequest(setIssuer);

        if (!response.checkResult()) {
            throw new TPSException("SecureChannel.setIssuerInfo. Failed to set issuer info!",
                    TPSStatus.STATUS_ERROR_UPGRADE_APPLET);
        }

        logger.debug("SecureChannel.setIssuerInfo: leaving...");

    }

    public TPSBuffer getKeyDiversificationData() {
        return keyDiversificationData;
    }

    public TPSBuffer getCardChallenge() {
        return cardChallenge;
    }

    public TPSBuffer getHostChallenge() {
        return hostChallenge;
    }

    public TPSBuffer getHostCryptogram() {
        return hostCryptogram;
    }

    public TPSBuffer getCardCryptogram() {
        return cardCryptogram;
    }

    public TPSBuffer getKeyInfoData() {
        return keyInfoData;
    }

    //Call the applet to clear unused key slots
    /// data is in the fomat of bytes, which is basically the payload of the apdu to be sent
    // [privateKeyIndex] [publicKeyIndex] ... [final privateKeyIndex] [final publicKeyIndex]
    public void clearAppletKeySlotData(TPSBuffer data) {
        String method = "SecureChannel.clearAppletKeySlotData: ";

        logger.debug(method + " entering ...");

        if(data == null) {
            logger.debug(method + " Invalid input data returning...");
            return;
        }

        APDUResponse response;
        try {
            ClearKeySlotsAPDU  clearKey = new ClearKeySlotsAPDU(data.toBytesArray());
            computeAPDU(clearKey);
            response = processor.handleAPDURequest(clearKey);
        } catch (TPSException | IOException e) {
            logger.debug(method + " bad apdu return!");
            return;

        }

        if (!response.checkResult()) {
            logger.debug(method + " bad apdu return!");
        }

        logger.debug(method + " Successful applet key data cleanup operation completed.");

    }

    public void writeObject(TPSBuffer objectID, TPSBuffer objectData) throws TPSException, IOException {
        logger.debug("SecureChannel.writeObject: entering ...");

        if (objectID == null || objectData == null) {
            throw new TPSException("SecureChannel.writeObject: invalid input data.",
                    TPSStatus.STATUS_ERROR_CANNOT_PERFORM_OPERATION);
        }

        final int MAX_WRITE_SIZE = 0xd0;

        int offset = 0;
        int toSend = objectData.size();
        int blockSize = 0;

        boolean moreToGo = true;
        do {

            if (toSend > MAX_WRITE_SIZE) {
                blockSize = MAX_WRITE_SIZE;
            } else {
                blockSize = toSend;
            }

            TPSBuffer blockToSend = objectData.substr(offset, blockSize);

            WriteObjectAPDU write = new WriteObjectAPDU(objectID.toBytesArray(), offset, blockToSend);

            computeAPDU(write);

            APDUResponse response = processor.handleAPDURequest(write);

            if (!response.checkResult()) {
                logger.debug("SecureChannel.writeObject: bad apdu return!");
                //Throw this return code because this happens during enrollment and we don't have
                // a more specific error code.
                throw new TPSException("SecureChannel.writeObject. Failed in middle of writeObject.",
                        TPSStatus.STATUS_ERROR_CANNOT_PERFORM_OPERATION);
            }

            offset += blockSize;
            toSend -= blockSize;

            if (toSend <= 0) {
                moreToGo = false;
            }

        } while (moreToGo);

    }

    public TPSBuffer readObject(TPSBuffer objectID, int offset, int len) throws TPSException, IOException {

        logger.debug("SecureChannel.readObject: entering ...");
        logger.debug("offset: " + offset + " len: " + len + " objectID: " + objectID.toHexString());

        if (objectID == null || len == 0) {
            throw new TPSException("SecureChannel.readObject: invalid input data.",
                    TPSStatus.STATUS_ERROR_CANNOT_PERFORM_OPERATION);
        }

        final int MAX_READ_BUFFER_SIZE = 0xd0;

        ReadObjectAPDU read = null;
        TPSBuffer result = new TPSBuffer();

        int cur_read = 0;
        int cur_offset = 0;
        int sum = 0;

        if (len > MAX_READ_BUFFER_SIZE) {
            cur_offset = offset;
            cur_read = MAX_READ_BUFFER_SIZE;
        } else {
            cur_offset = offset;
            cur_read = len;
        }

        while (sum < len) {

            read = new ReadObjectAPDU(objectID.toBytesArray(), cur_offset, cur_read);
            //RedHat Add a 0x00 Le byte, appease tpsclient if configured
            if(!skipTrailerLeByteScp01()) {
                read.setTrailer(new TPSBuffer((byte) 0x00));
            }

            //logger.debug("read encoding: " + read.getEncoding().toHexString());
            computeAPDU(read);

            APDUResponse response = processor.handleAPDURequest(read);

            if (!response.checkResult()) {
                logger.debug("SecureChannel.readObject: bad apdu return!");
                throw new TPSException("SecureChannel.installApplet. Failed in middle of readObject.",
                        TPSStatus.STATUS_ERROR_CANNOT_PERFORM_OPERATION);
            }

            TPSBuffer resp = response.getResultDataNoCode();

            result.add(resp);

            sum += resp.size();
            cur_offset += resp.size();

            if ((len - sum) < MAX_READ_BUFFER_SIZE) {
                cur_read = len - sum;
            } else {
                cur_read = MAX_READ_BUFFER_SIZE;
            }

        }

        return result;
    }

    public void createObject(TPSBuffer objectID, TPSBuffer permissions, TPSBuffer object) throws TPSException,
            IOException {

        logger.debug("SecureChannel.createObject: with full object. entering...");

        if (objectID == null || permissions == null || object == null) {
            throw new TPSException("SecureChannel.createObject, with full object. Bad input data.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);

        }

        createObject(objectID, permissions, object.size());

        writeObject(objectID, object);

    }

    public void createCertificate(TPSBuffer objectID, TPSBuffer cert) throws TPSException, IOException {
        logger.debug("SecureChannel.createCertificate: entering...");

        if (objectID == null || cert == null) {
            throw new TPSException("SecureChannel.createCertificate. Bad input data.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        byte[] perms = { (byte) 0xff, (byte) 0xff, 0x40, 0x00, 0x40, 0x00 };

        TPSBuffer permissions = new TPSBuffer(perms);

        createObject(objectID, permissions, cert);

    }

    public void createPKCS11CertAttrs(TokenKeyType keyType, String id, String label, TPSBuffer keyid)
            throws TPSException, IOException {

        TPSBuffer buffer = createPKCS11CertAttrsBuffer(keyType, id, label, keyid);

        byte[] perms = { (byte) 0xff, (byte) 0xff, 0x40, 0x00, 0x40, 0x00 };

        TPSBuffer permissions = new TPSBuffer(perms);

        createObject(new TPSBuffer(id), permissions, buffer);

    }

    public TPSBuffer createPKCS11PriKeyAttrsBuffer(String id, String label, TPSBuffer keyid,
            TPSBuffer modulus, String keyTypePrefix) throws TPSException {

        TPSBuffer result = new TPSBuffer();

        logger.debug("SecureChannel.createPKCS11PriKeyAttrsBuffer: entering...");

        if (id == null || label == null || keyid == null || modulus == null || keyTypePrefix == null) {
            throw new TPSException("SecureChannel.craetePKCS11PriKeyAttrsBuffer: invalid input data.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

//        logger.debug("SecureChannel.createPKCS11PriKeyAttrsBuffer:  id: " + id + " label: " + label + " keyid: "
//                + keyid.toHexString());

        byte keytype[] = { 0, 0, 0, 0 };
        byte p11class[] = { 3, 0, 0, 0 };

        appendPKCS11Attribute(result, PKCS11Constants.CKA_MODULUS, modulus);
        appendPKCS11Attribute(result, PKCS11Constants.CKA_KEY_TYPE, new TPSBuffer(keytype));
        appendPKCS11Attribute(result, PKCS11Constants.CKA_CLASS, new TPSBuffer(p11class));
        appendPKCS11Attribute(result, PKCS11Constants.CKA_ID, keyid);
        appendKeyCapabilities(result, keyTypePrefix, "private");

        finalizeObjectBuffer(result, id);

        //logger.debug("SecureChannel.createPKCS11PriKeyAttrsBuffer: returing: " + result.toHexString());
        logger.debug("SecureChannel.createPKCS11PriKeyAttrsBuffer: returing");

        return result;

    }

    public void createPKCS11PriKeyAttrs(String id, String label, TPSBuffer keyid,
            TPSBuffer modulus, String keyTypePrefix) throws TPSException, IOException {

        logger.debug("SecureChannel.createPKCS11PriKeyAttrsBuffer: entering...");

        if (id == null || label == null || keyid == null || modulus == null || keyTypePrefix == null) {
            throw new TPSException("SecureChannel.craetePKCS11PriKeyAttrsBuffer: invalid input data.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        TPSBuffer buffer = createPKCS11PriKeyAttrsBuffer(id, label, keyid, modulus, keyTypePrefix);

        byte[] perms = { (byte) 0xff, (byte) 0xff, 0x40, 0x00, 0x40, 0x00 };

        TPSBuffer permissions = new TPSBuffer(perms);

        createObject(new TPSBuffer(id), permissions, buffer);
    }

    public TPSBuffer createPKCS11PublicKeyAttrsBuffer(String id, String label, TPSBuffer keyid,
            TPSBuffer modulus, TPSBuffer exponent, String keyTypePrefix) throws TPSException {

        TPSBuffer result = new TPSBuffer();
        logger.debug("SecureChannel.createPKCS11PublicKeyAttrsBuffer: entering...");

        if (id == null || label == null || keyid == null || modulus == null || exponent == null
                || keyTypePrefix == null) {
            throw new TPSException("SecureChannel.craetePKCS11PublicKeyAttrsBuffer: invalid input data.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        byte p11class[] = { 2, 0, 0, 0 };

        appendPKCS11Attribute(result, PKCS11Constants.CKA_PUBLIC_EXPONENT, exponent);
        appendPKCS11Attribute(result, PKCS11Constants.CKA_MODULUS, modulus);
        appendPKCS11Attribute(result, PKCS11Constants.CKA_ID, keyid);
        appendPKCS11Attribute(result, PKCS11Constants.CKA_CLASS, new TPSBuffer(p11class));
        appendKeyCapabilities(result, keyTypePrefix, "public");

        finalizeObjectBuffer(result, id);

        //logger.debug("SecureChannel.createPKCS11PublicKeyAttrsBuffer: returing: " + result.toHexString());
        logger.debug("SecureChannel.createPKCS11PublicKeyAttrsBuffer: returing");

        return result;

    }

    public void createPKCS11PublicKeyAttrs(String id, String label, TPSBuffer keyid,
            TPSBuffer modulus, TPSBuffer exponent, String keyTypePrefix) throws TPSException, IOException {

        logger.debug("SecureChannel.createPKCS11PublicKeyAttrsBuffer: entering...");

        if (id == null || label == null || keyid == null || modulus == null || exponent == null
                || keyTypePrefix == null) {
            throw new TPSException("SecureChannel.craetePKCS11PriKeyAttrsBuffer: invalid input data.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        TPSBuffer buffer = createPKCS11PriKeyAttrsBuffer(id, label, keyid, modulus, keyTypePrefix);

        byte[] perms = { (byte) 0xff, (byte) 0xff, 0x40, 0x00, 0x40, 0x00 };

        TPSBuffer permissions = new TPSBuffer(perms);

        createObject(new TPSBuffer(id), permissions, buffer);

    }

    public void finalizeObjectBuffer(TPSBuffer buffer, String id) {

        TPSBuffer header = new TPSBuffer();

        header.add((byte) 0);
        header.add((byte) id.charAt(0));
        header.add((byte) id.charAt(1));
        header.add((byte) 0);
        header.add((byte) 0);

        header.add((byte) ((buffer.size()) / 256));
        header.add((byte) ((buffer.size()) % 256));

        buffer.prepend(header);

    }

    public TPSBuffer createPKCS11CertAttrsBuffer(TokenKeyType keyType, String id, String label, TPSBuffer keyid)
            throws TPSException {

        logger.debug("SecureChannel.createPKCS11CertAttrsBuffer: entering... id: " + id);
        if (keyType == null || id == null || label == null || keyid == null) {
            throw new TPSException("SecureChannel.createPKCS11CertAttrsBuffer. Bad input data.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);

        }

//        logger.debug("SecureChannel.createPKCS11CertAttrsBuffer: ... id: " + id + " label: " + label + " keyid: "
//                + keyid.toHexString());

        byte[] type = { 0x0, 0x0, 0x0, 0x0 };
        byte[] p11class = { 0x1, 0x0, 0x0, 0x0 };
        byte[] tokenFlag = { 0x1 };

        TPSBuffer result = new TPSBuffer();

//        logger.debug("SecureChannel.createPKCS11CertAttrsBuffer: label: " + label + " label bytes: "
//                + (new TPSBuffer(label)).toHexString());

        appendPKCS11Attribute(result, PKCS11Constants.CKA_LABEL, new TPSBuffer(label.getBytes()));
        appendPKCS11Attribute(result, PKCS11Constants.CKA_ID, keyid);
        appendPKCS11Attribute(result, PKCS11Constants.CKA_CERTIFICATE_TYPE, new TPSBuffer(type));
        appendPKCS11Attribute(result, PKCS11Constants.CKA_CLASS, new TPSBuffer(p11class));
        appendPKCS11Attribute(result, PKCS11Constants.CKA_TOKEN, new TPSBuffer(tokenFlag));

        finalizeObjectBuffer(result, id);

        //logger.debug("SecureChannel.createPKCS11CertAttrsBuffer: returing: " + result.toHexString());
        logger.debug("SecureChannel.createPKCS11CertAttrsBuffer: returing");

        return result;

    }

    public void createObject(TPSBuffer objectID, TPSBuffer permissions, int len) throws TPSException, IOException {

        logger.debug("SecureChannel.createObject: entering...");
        if (objectID == null || permissions == null || len <= 0) {
            throw new TPSException("SecureChannel.createObject. Bad input data.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        CreateObjectAPDU create = new CreateObjectAPDU(objectID.toBytesArray(), permissions.toBytesArray(), len);

        computeAPDU(create);

        APDUResponse response = processor.handleAPDURequest(create);

        //Throw this return code because this happens during enrollment and we don't have
        // a more specific error code.
        if (!response.checkResult()) {
            throw new TPSException("SecureChannel.createObject. Failed to create object on token.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

    }

    public int startEnrollment(int pe1, int pe2, TPSBuffer wrappedChallenge, TPSBuffer keyCheck, int algorithm,
            int keySize, int option) throws TPSException, IOException {

        if (wrappedChallenge == null) {
            throw new TPSException("SecureChannel.startEnrollment. Bad input data.",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        logger.debug("SecureChannel.startEnrollment: entering ...");

        boolean isECC = TPSEngine.getInstance().isAlgorithmECC(algorithm);

        GenerateKeyAPDU generate_key_apdu = null;
        GenerateKeyECCAPDU generate_ecc_key_apdu = null;

        APDUResponse response = null;
        if (isECC) {

            generate_ecc_key_apdu = new GenerateKeyECCAPDU((byte) pe1, (byte) pe2, (byte) algorithm, keySize,
                    (byte) option, (byte) 0, wrappedChallenge, keyCheck);

            computeAPDU(generate_ecc_key_apdu);

            response = processor.handleAPDURequest(generate_ecc_key_apdu);

            if (!response.checkResult()) {
                throw new TPSException("SecureChannel.startEnrollment. Failed generate key on token.",
                        TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
            }

        } else {

            generate_key_apdu = new GenerateKeyAPDU((byte) pe1, (byte) pe2, (byte) algorithm, keySize,
                    (byte) option, (byte) 0, wrappedChallenge, keyCheck);

            // RedHat Add a 0x00 Le byte, appease tpsclient if configured.
            if(!skipTrailerLeByteScp01()) {
                generate_key_apdu.setTrailer(new TPSBuffer((byte) 0x00));
            }

            computeAPDU(generate_key_apdu);

            response = processor.handleAPDURequest(generate_key_apdu);

            if (!response.checkResult()) {
                throw new TPSException("SecureChannel.startEnrollment. Failed generate key on token.",
                        TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
            }

        }

        TPSBuffer data = response.getData();

        int size = data.getIntFrom2Bytes(0);

        logger.debug("SecureChannel.startEnrollment: returning key size: " + size);

        return size;

    }

    public int tokenTypeToInt(TokenKeyType type) {

        if (type == TokenKeyType.KEY_TYPE_ENCRYPTION)
            return 0;

        if (type == TokenKeyType.KEY_TYPE_SIGNING)
            return 1;
        else
            return 2;
    }

    public void setLifecycleState(byte flag) throws TPSException, IOException {
        String method = "SecureChannel.setLifecycleState: ";
        logger.debug(method + "flage: " + flag);

        LifecycleAPDU life = new LifecycleAPDU(flag);

        computeAPDU(life);

        APDUResponse response = processor.handleAPDURequest(life);

        if (!response.checkResult()) {
             logger.debug(method + "result.checkResult() returns false; Throwing exception!");
            throw new TPSException("SecureChannel.setLifecycleState. Failed to set Lifecycle State!.",
                    TPSStatus.STATUS_ERROR_MAC_LIFECYCLE_PDU);
        }

        logger.debug(method + "ends");
    }

    public void createPin(int pinNumber, int maxRetries, String pin) throws TPSException, IOException {

        logger.debug("SecureChannel.createPin:  entering...");

        if (pin == null) {
            throw new TPSException("SecureChannel.createPin: invalid input data.",
                    TPSStatus.STATUS_ERROR_MAC_RESET_PIN_PDU);
        }

        TPSBuffer pinBuf = new TPSBuffer(pin.getBytes());
        CreatePinAPDU create = new CreatePinAPDU((byte) pinNumber, (byte) maxRetries, pinBuf);

        computeAPDU(create);

        @SuppressWarnings("unused")
        APDUResponse response = processor.handleAPDURequest(create);

        //If the pin already exists we may get an error here, but we go on.

    }

    public void resetPin(int pinNumber, String new_pin) throws TPSException, IOException {

        logger.debug("SecureChannel.resetPin");

        if (new_pin == null) {
            throw new TPSException("SecureChannel.resetPin: invalid input data.",
                    TPSStatus.STATUS_ERROR_MAC_RESET_PIN_PDU);
        }

        TPSBuffer newPinBuf = new TPSBuffer(new_pin.getBytes());

        SetPinAPDU reset = new SetPinAPDU((byte) 0x0, (byte) 0x0, newPinBuf);

        computeAPDU(reset);

        APDUResponse response = processor.handleAPDURequest(reset);

        if (!response.checkResult()) {
            throw new TPSException("SecureChannel.resetPin: failed to reset pin.",
                    TPSStatus.STATUS_ERROR_MAC_RESET_PIN_PDU);
        }

    }

    public void putKeys(byte curVersion, byte curIndex, TPSBuffer keySetData) throws TPSException, IOException {

        logger.debug("SecureChannel.putKeys: entering.. curVersion: " + curVersion + " curIndex:  " + curIndex
                + " keySetData: " + keySetData);

        if (keySetData == null) {
            throw new TPSException("SecureChannel.putKeys: Invalid input data!", TPSStatus.STATUS_ERROR_KEY_CHANGE_OVER);
        }

        byte keyVersion = curVersion;

        if (curVersion == (byte) 0xff) {
            logger.debug("Setting keyVersion to 0");
            keyVersion = 0x0;
        }

        logger.debug("keyVersion now set to: " + keyVersion);

        PutKeyAPDU putKey = new PutKeyAPDU(keyVersion, (byte) 0x81, keySetData);

        if (isSCP02() || isSCP03()) {
            logger.debug("SecureChannel.putKeys: adding trailing 0 byte");
            TPSBuffer trailer = new TPSBuffer(1);
            putKey.setTrailer(trailer);

        }
        computeAPDU(putKey);

        int kill = 0;
        if (kill == 1) {
            throw new TPSException("putKeys end of progress.", TPSStatus.STATUS_ERROR_KEY_CHANGE_OVER);
        }

        APDUResponse response = processor.handleAPDURequest(putKey);

        if (!response.checkResult()) {
            throw new TPSException("SecureChannel.putKeys: failed to upgrade key set!",
                    TPSStatus.STATUS_ERROR_KEY_CHANGE_OVER);
        }

    }

    public TPSBuffer getDRMWrappedDesKey() {
        return drmDesKey;
    }

    public void setDRMWrappedDesKey(TPSBuffer drmDesKey) {
        this.drmDesKey = drmDesKey;
    }

    public void setDrmWrappedAesKey(TPSBuffer drmAesKey) {
        this.drmAesKey = drmAesKey;
    }

    public TPSBuffer getDRMWrappedAesKey() {
        return drmAesKey;
    }

    public void setAESWrappedDesKey(TPSBuffer aesDesKey) {
        this.aesDesKey = aesDesKey;
    }

    public TPSBuffer getAESWrappedDesKey() {
        return aesDesKey;
    }

    public TPSBuffer getKeyCheck() {
        return keyCheck;
    }

    public void setKeyCheck(TPSBuffer theKeyCheck) {
        this.keyCheck = theKeyCheck;
    }

    public void importKeyEnc(int pe1, int pe2, TPSBuffer data) throws TPSException, IOException {

        logger.debug("SecureChannel.importKeyEnc entering...");

        if (data == null) {
            throw new TPSException("SecureChannel.importKeyEnc: Invalid input data!",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

        ImportKeyEncAPDU importKeyEnc = new ImportKeyEncAPDU((byte) pe1, (byte) pe2, data);

        computeAPDU(importKeyEnc);

        APDUResponse response = processor.handleAPDURequest(importKeyEnc);

        if (!response.checkResult()) {
            throw new TPSException("SecureChannel.importKeyEnc: failed to import private key!",
                    TPSStatus.STATUS_ERROR_MAC_ENROLL_PDU);
        }

    }

    public TPSBuffer readIOBuffer(int offset, int length)  throws IOException, TPSException {
        String method = "SecureChannel.readIOBuffer";

        ReadBufferAPDU readIO = new ReadBufferAPDU (length,offset);
        computeAPDU(readIO);
        APDUResponse respApdu= processor.handleAPDURequest(readIO);

         if (!respApdu.checkResult()) {
             logger.debug(method + " problem reading IOBuffer!");
	     //Keep going since this is not crucial to server operation, debug only,when supported by applet.
             return null;
         }
         TPSBuffer ioBuffData = respApdu.getData();
         // use this method only for debugging the applet, by feault this apdu in the applet is not allowed.
         //logger.debug(method + " returning: " + ioBuffData.toHexString());
         return ioBuffData;

    }

    public TPSBuffer getKekDesKey() {
        return kekDesKey;
    }

    public void setKekDesKey(TPSBuffer kekDesKey) {
        this.kekDesKey = kekDesKey;
    }

    public void setKekAesKey(TPSBuffer kekAesKey) {
        this.kekAesKey = kekAesKey;
    }

    public TPSBuffer getKekAesKey() {
        return kekAesKey;
    }

    public TPSBuffer getSequenceCounter() {
        return sequenceCounter;
    }

    public PlatformAndSecChannelProtoInfo getChannelPlatformAndProtocolInfo() {
        return platProtInfo;
    }

    protected TPSBuffer computeCardCryptogramSCP02(PK11SymKey encSessionKey)
            throws TPSException {

        if (encSessionKey == null) {
            throw new TPSException("TPSProcessor.computeCardCryptogramSCP02: invalide input data",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        TPSBuffer data = new TPSBuffer(hostChallenge);
        data.add(sequenceCounter);
        data.add(cardChallenge);

        if (data.size() != 16) {
            throw new TPSException("calculateCardCryptogramSCP02: card cyrptogram source data incorrect size.",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        TPSBuffer cardCryptogram = null;
        try {
            cardCryptogram = Util.computeMAC(encSessionKey, data, icv);
        } catch (EBaseException e) {
            throw new TPSException("calculateCardCryptogramSCP02: card cyrptogram: Error calculating the MAC value",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        logger.debug("TPSProcessor.calculateCardCrytogramSCP02: returning calculated card cryptogram; "
                + cardCryptogram.toHexString());

        return cardCryptogram;

    }

    protected TPSBuffer computeHostCryptogramSCP02(PK11SymKey encSessionKey)
            throws TPSException {

        if (encSessionKey == null) {
            throw new TPSException("TPSProcessor.computeHostCryptogramSCP02: invalide input data",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        TPSBuffer hostCryptogramSCP02 = null;

        TPSBuffer data = new TPSBuffer(sequenceCounter);
        data.add(cardChallenge);
        data.add(hostChallenge);

        if (data.size() != 16) {
            throw new TPSException("calculateHostCryptogramSCP02: host cyrptogram source data incorrect size.",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        try {
            hostCryptogramSCP02 = Util.computeMAC(encSessionKey, data, icv);
        } catch (EBaseException e) {
            throw new TPSException("calculateHostCryptogramSCP02: host cyrptogram: Error calculating the MAC value",
                    TPSStatus.STATUS_ERROR_SECURE_CHANNEL);
        }

        logger.debug("TPSProcessor.calculateHostCrytogramSCP02: returning calculated host cryptogram; "
                + hostCryptogramSCP02.toHexString());

        return hostCryptogramSCP02;

    }

    public boolean isSCP03() {
        if (platProtInfo.isSCP03())
            return true;
        else
            return false;
    }

    public boolean isSCP02() {
        if (platProtInfo.isGP211() && platProtInfo.isSCP02()) {

            return true;
        }

        return false;
    }

    private boolean isGP211() {

        if (platProtInfo.isGP211()) {
            return true;
        }

        return false;
    }

    public TPSBuffer getDekSessionKeyWrapped() {
        return dekSessionKeyWrapped;
    }

    public void setDekSessionKeyWrapped(TPSBuffer dekSessionKeyWrapped) {
        this.dekSessionKeyWrapped = dekSessionKeyWrapped;
    }

    public PK11SymKey getDekSessionKey() {
        return dekSessionKey;
    }

    public void setDekSessionKey(PK11SymKey dekSessionKey) {
        this.dekSessionKey = dekSessionKey;
    }

    public PK11SymKey getRmacSessionKey() {
        return rmacSessionKey;
    }

    public void setRmacSessionKey(PK11SymKey rmacSessionKey) {
        this.rmacSessionKey = rmacSessionKey;
    }

    /**
     * ** G&D 256 Key Rollover Support **
     * This method constructs the APDU for key deletion and sends the request to the card to 
     * delete keys with the given version.
     *  
     * @param keyVersion the key version to be deleted
     * @throws TPSException
     * @throws IOException 
     *
     */
    public void deleteKeys(byte keyVersion) throws TPSException, IOException {
        String method = "SecureChannel.deleteKeys: keyVersion: " + keyVersion + ": ";

        logger.debug(method + " entering ...");

        APDUResponse response;
        try {
            TPSBuffer data = new TPSBuffer(keyVersion);
            DeleteKeysAPDU  deleteKeyApdu = new DeleteKeysAPDU(data);
            computeAPDU(deleteKeyApdu);
            response = processor.handleAPDURequest(deleteKeyApdu);
        } catch (TPSException | IOException e) {
            logger.debug(method + " bad apdu return!");
            logger.debug(e.toString());
            throw e;
        }

        if (!response.checkResult()) {
            logger.debug(method + " response with unsuccess result");
            throw new TPSException(method + " failed to delete key set!",
                        TPSStatus.STATUS_ERROR_KEY_CHANGE_OVER);
        }

        logger.debug(method + " Successful delete key data operation completed.");
    }

    // RedHat
    //Check config param if we want to not add le bytes for certain scp01 apdu's.
    //default is  false. If method returns false the le byte will be added as before.
    public boolean skipTrailerLeByteScp01() {

        TPSEngineConfig configStore = this.getConfigStore();

        String method = "SecureChannel.skipTrailerLeByteScp01: ";
        boolean skip = false;
        try {
            String configName = "channel.scp01.no.le.byte";

            if(platProtInfo.isSCP01()) {
                skip = configStore.getBoolean(configName,false);
            }
        } catch (Exception e) {
            skip = false;
        }

        logger.debug(method + skip);
        return skip;
    }

    private TPSEngineConfig getConfigStore() {
        TPSEngine engine = TPSEngine.getInstance();
        TPSEngineConfig configStore = engine.getConfig();
        return configStore;
    }

}

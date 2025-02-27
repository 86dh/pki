package org.dogtagpki.server.tks.servlet;

import java.io.ByteArrayOutputStream;
import java.io.CharConversionException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Map;

import org.dogtagpki.server.tks.TKSEngine;
import org.dogtagpki.server.tks.TKSEngineConfig;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.crypto.Cipher;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.EncryptionAlgorithm;
import org.mozilla.jss.crypto.IVParameterSpec;
import org.mozilla.jss.crypto.KeyGenAlgorithm;
import org.mozilla.jss.crypto.KeyGenerator;
import org.mozilla.jss.crypto.KeyWrapAlgorithm;
import org.mozilla.jss.crypto.KeyWrapper;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.SymmetricKey.NotExtractableException;
import org.mozilla.jss.crypto.SymmetricKeyDeriver;
import org.mozilla.jss.crypto.TokenException;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cmscore.security.JssSubsystem;
import com.netscape.cmsutil.crypto.CryptoUtil;

import org.mozilla.jss.pkcs11.PKCS11Constants;

public class SecureChannelProtocol {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SecureChannelProtocol.class);
    static String sharedSecretKeyName = null;
    static String masterKeyPrefix = null;

    static final int DEF_AES_KEYLENGTH = 16;
    static final int DEF_AES_256_KEYLENGTH = 32;
    static final int KEYLENGTH = 16;
    static final int PREFIXLENGHT = 128;
    static final int DES2_LENGTH = 16;
    static final int DES3_LENGTH = 24;
    static final int EIGHT_BYTES = 8;
    static final int KEYNAMELENGTH = PREFIXLENGHT + 7;
    static final String TRANSPORT_KEY_NAME = "sharedSecret";
    static final String DEFKEYSET_NAME = "defKeySet";
    static int protocol = 1;

    public static final String encType = "enc";
    public static final String macType = "mac";
    public static final String kekType = "kek";
    public static final String authType = "auth";
    public static final String dekType = "dek";
    public static final String rmacType = "rmac";
    public static final int PROTOCOL_ONE = 1;
    public static final int PROTOCOL_TWO = 2;
    public static final int PROTOCOL_THREE = 3;
    public static final int HOST_CRYPTOGRAM = 0;
    public static final int CARD_CRYPTOGRAM = 1;

    //Size of long type in bytes, since java7 has no define for this
    static final int LONG_SIZE = 8;

    //  constants

    static final int AES_128_BYTES = 16;
    static final int AES_192_BYTES = 24;
    static final int AES_256_BYTES = 32;

    static final int AES_128_BITS = 128;
    static final int AES_192_BITS = 192;
    static final int AES_256_BITS = 256;

    private static SymmetricKey.Usage session_key_usages[] = {
        SymmetricKey.Usage.WRAP,
        SymmetricKey.Usage.UNWRAP,
        SymmetricKey.Usage.ENCRYPT,
        SymmetricKey.Usage.DECRYPT
    };

    private SymmetricKey transportKey = null;
    CryptoManager cryptoManager = null;

    public SecureChannelProtocol() {
    }

    public SecureChannelProtocol(int theProtocol) {
        protocol = theProtocol;
    }

    public byte[] computeCryptogram_SCP01(
            String selectedToken, String keyNickName, byte[] card_challenge,
            byte[] host_challenge, byte[] keyInfo,
            byte nistSP800_108KdfOnKeyVersion, // AC: KDF SPEC CHANGE - pass in configuration file value
            boolean nistSP800_108KdfUseCuidAsKdd, // AC: KDF SPEC CHANGE - pass in configuration file value
            byte[] xCUID, // AC: KDF SPEC CHANGE - removed duplicative 'CUID' variable and replaced with 'xCUID'
            byte[] xKDD, // AC: KDF SPEC CHANGE - pass in KDD so symkey can make decision about which value (KDD,CUID) to use
            int cryptogramType, byte[] authKeyArray, String useSoftToken_s, String keySet, String transportKeyName)
            throws EBaseException {

        String method = "SecureChannelProtocol.computeCryptogram_SCP01:";

        logger.debug(method + " Entering:  Type:  HOST=0 , CARD=1 : TYPE: " + cryptogramType);

        if ((card_challenge == null || card_challenge.length != EIGHT_BYTES)
                || (host_challenge == null || host_challenge.length != EIGHT_BYTES)) {

            throw new EBaseException(method + " Invalid card challenge or host challenge!");

        }

        if (cryptogramType != HOST_CRYPTOGRAM && cryptogramType != CARD_CRYPTOGRAM) {
            throw new EBaseException(method + " Invalid cyrptgram type!");
        }

        byte[] cryptogram = null;

        SymmetricKey authKey = this.computeSessionKey_SCP01(SecureChannelProtocol.encType, selectedToken, keyNickName,
                card_challenge, host_challenge, keyInfo, nistSP800_108KdfOnKeyVersion, nistSP800_108KdfUseCuidAsKdd,
                xCUID, xKDD, authKeyArray, useSoftToken_s, keySet, transportKeyName);

        byte[] input = new byte[DES2_LENGTH];
        byte[] icv = new byte[EIGHT_BYTES];

        if (cryptogramType == HOST_CRYPTOGRAM) // compute host cryptogram
        {
            /* copy card and host challenge into input buffer */
            for (int i = 0; i < EIGHT_BYTES; i++)
            {
                input[i] = card_challenge[i];
            }
            for (int i = 0; i < EIGHT_BYTES; i++)
            {
                input[EIGHT_BYTES + i] = host_challenge[i];
            }
        } // compute card cryptogram
        else if (cryptogramType == CARD_CRYPTOGRAM)
        {
            for (int i = 0; i < EIGHT_BYTES; i++)
            {
                input[i] = host_challenge[i];
            }
            for (int i = 0; i < EIGHT_BYTES; i++)
            {
                input[EIGHT_BYTES + i] = card_challenge[i];
            }

        }
        cryptogram = computeMAC_SCP01(authKey, input, icv, selectedToken);

        // SecureChannelProtocol.debugByteArray(cryptogram, " Output of computeCrytptogram type: " + cryptogramType);

        return cryptogram;
    }

    public SymmetricKey computeSessionKey_SCP02(
            String selectedToken, String keyNickName,
            byte[] keyInfo,
            byte nistSP800_108KdfOnKeyVersion, // AC: KDF SPEC CHANGE - pass in configuration file value
            boolean nistSP800_108KdfUseCuidAsKdd, byte[] xCUID, byte[] xKDD, byte[] macKeyArray,
            byte[] sequenceCounter, byte[] derivationConstant,
            String useSoftToken_s, String keySet,
            String transportKeyName) throws EBaseException {

        String method = "SecureChannelProtocol.computeSessionKey_SCP01:";

        logger.debug(method + " entering... ");

        throw new EBaseException(method + " Not yet implemented!");
    }

    public int getProtocol() {
        return protocol;
    }

    // Either calculate a full session key, with the KDF applied or
    // Merely calculate the card key. Card key mode is when host_challenge and
    // card_challenge are passed in as null. Card keys are calculated
    // when creating a new keyset to send to the token
    public SymmetricKey computeSessionKey_SCP03(String selectedToken,
            String keyNickName, byte[] keyInfo, String keyType,
            byte[] devKeyArray, String keySet, byte[] xCUID, byte[] xKDD,
            byte[] host_challenge, byte[] card_challenge, String transportKeyName, GPParams params)
            throws EBaseException {

        final byte mac_constant = 0x06;
        final byte enc_constant = 0x04;
        final byte rmac_constant = 0x07;

        final byte enc_constant_gpkmc = 0x01;
        final byte mac_constant_gpkmc = 0x02;
        final byte kek_constant_gpkmc = 0x03;

        boolean noDerive = false;

        byte constant = 0;
        byte constant_gpkmc = 0;

        String method = "SecureChannelProtocol.computeSessionKey_SCP03:";

        if (keyType == null || devKeyArray == null
                || transportKeyName == null) {
            throw new EBaseException(method + " invalid input data");
        }

        if (xCUID == null || xCUID.length <= 0) {
            throw new EBaseException(method + "CUID invalid size!");
        }

        if (xKDD == null || xKDD.length != NistSP800_108KDF.KDD_SIZE_BYTES) {
            throw new EBaseException(method + "KDD invalid size!");
        }


        //Detect card key mode or full derivation mode
        if (card_challenge == null && host_challenge == null) {
            noDerive = true;
        } else {
            if (card_challenge == null || host_challenge == null) {
                throw new EBaseException(method + " Invalid challenge data!");
            }
        }

        logger.debug(method + " entering. nickname: " + keyNickName + " selectedToken: " + selectedToken);

        CryptoManager cm = null;
        CryptoToken token = null;
        CryptoToken internalToken = null;
        try {
            cm = CryptoManager.getInstance();
            token = returnTokenByName(selectedToken, cm);
            internalToken = returnTokenByName("internal", cm);
        } catch (NotInitializedException e) {
            logger.debug(method + " " + e);
            throw new EBaseException(e);

        } catch (NoSuchTokenException e) {
            logger.debug(method + " " + e);
            throw new EBaseException(e);
        }

        sharedSecretKeyName = SecureChannelProtocol.getSharedSecretKeyName(transportKeyName);
        
        transportKey = getSharedSecretKey(internalToken);
        
        //concat host and card challenge:

        byte[] context = null;

        ByteArrayOutputStream contextStream = new ByteArrayOutputStream();

        // Full derivation mode create context used in derivation
        // host_challenge + card_challenge concatenated
        if (noDerive == false) {
            try {
                contextStream.write(host_challenge);
                contextStream.write(card_challenge);
            } catch (IOException e) {
                throw new EBaseException(method + " Error calculating derivation data!");
            }

            context = contextStream.toByteArray();
        }

        //Calculate the constant based on what type of key we want.
        // Note the kek key never goes through final derivation in scp03

        if (keyType.equalsIgnoreCase(SecureChannelProtocol.encType)) {
            constant = enc_constant;
            constant_gpkmc = enc_constant_gpkmc;
        }

        if (keyType.equalsIgnoreCase(SecureChannelProtocol.macType)) {
            constant = mac_constant;
            constant_gpkmc = mac_constant_gpkmc;
        }

        if (keyType.equalsIgnoreCase(SecureChannelProtocol.rmacType)) {
            constant = rmac_constant;
        }

        if (keyType.equalsIgnoreCase(SecureChannelProtocol.kekType)) {
            constant = 0;
            constant_gpkmc = kek_constant_gpkmc;
        }

        String keyNameStr = null;

        SymmetricKey sessionKey = null;
        SymmetricKey masterKey = null;

        if (keyNickName == null) {
            keyNameStr = this.getKeyName(keyInfo);
        } else {
            keyNameStr = keyNickName;
        }

        boolean noDivers = false;

        logger.debug(method + " keyNameStr: " + keyNameStr);

        //Starting with version 1 or factory keyset.
        if ((keyInfo[0] == 0x1 && keyNameStr.contains("#01#")) ||
                (keyInfo[0] == -1 && keyNameStr.indexOf("#FF") != -1))

        {
            String finalKeyType = keyType;
            String devKeyType = params.getDevKeyType();
            logger.debug(method + " Developer key set case: incoming dev key type: " + devKeyType);
            SymmetricKey devSymKey = returnDeveloperSymKey(token, finalKeyType, keySet, devKeyArray,devKeyType);

            NistSP800_108KDF nistKdf = new NistSP800_108KDF(this);
            StandardKDF standard = new StandardKDF(this);
            SymmetricKey divKey = null;

            byte[] keyDiversified = null;

            //Consult the config to determine with diversification method to use.
            if (params.isVer1DiversNone()) {
                logger.debug(method + " No diversifcation requested. ");
                noDivers = true;
            } else if (params.isVer1DiversEmv()) {
                logger.debug(method + " EMV diversification requested. ");
                keyDiversified = KDF.getDiversificationData_EMV(xKDD, keyType);
            } else if (params.isVer1DiversVisa2()) {
                logger.debug(method + " Visa2 diversification requested.");
                keyDiversified = KDF.getDiversificationData_VISA2(xKDD, keyType);
            } else if (params.isVer1DiversGPKMC()) {
                logger.debug(method + " GPKMC diversification requested.");
            } else {
                throw new EBaseException(method + " Invalid diversification method!");
            }

            //Obtain the card key,it may just be the raw developer key
            if (noDivers == true) {
                divKey = devSymKey;
            } else {
                if (GPParams.DES3.equalsIgnoreCase(devKeyType)) {
                    divKey = standard.computeCardKey_SCP03_WithDES3(devSymKey, keyDiversified, token);
                } else if (GPParams.AES.equalsIgnoreCase(devKeyType)) {
                    if(params.isVer1DiversGPKMC()) {
                        divKey = nistKdf.diversifyAESKey(devSymKey, xCUID, constant_gpkmc, token);
                    }
                } else {
                    throw new EBaseException(method + " Invalid developer key type. Does not support diversification: "+ devKeyType);
                }
            }


            //IN scp03, the kek key IS the card key
            if (constant == 0 /* kek key */) {
                sessionKey = divKey;
            } else { // session keys will become AES
                if (noDerive) {
logger.debug("session key = divKey");
                    sessionKey = divKey;
                }
                else {
                    // Use length of divKey for AES CMAC
                    logger.debug(method + "Call to nistKdf.kdf_AES_CMAC_SCP03 divKey length = " + divKey.getLength());
                    byte[] finalKeyBytes = nistKdf.kdf_AES_CMAC_SCP03(divKey, context, constant, divKey.getLength());
                    sessionKey = unwrapAESSymKeyOnToken(token, finalKeyBytes, false);

                    TKSEngine engine = TKSEngine.getInstance();
                    JssSubsystem jssSubsystem = engine.getJSSSubsystem();

                    //The final session key is AES.
                }
            }
        } else { // Creating a session key for the case where we have already upgraded the keys on the token, using the master key
            logger.debug(method + "In master key mode.");

            masterKey = getSymKeyByName(token, keyNameStr);

            String masterKeyType = params.getMasterKeyType();

            logger.debug(method + " Master key case: requested master key type: " + masterKeyType);

            NistSP800_108KDF nistKdf = new NistSP800_108KDF(this);
            StandardKDF standard = new StandardKDF(this);

            byte[] keyDiversified = null;

            if (params.isDiversNone()) {
                if (GPParams.AES.equalsIgnoreCase(masterKeyType)) {
                    logger.debug(method + " Master key case: no diversification requested: With master key type of AES ");
                }
                else {
                    throw new EBaseException(method + " No diversification requested in master key mode. With master key type of DES3: Aborting...");
                }
            } //Allow choice of emv or standard diversification
            else if (params.isDiversEmv()) {
                keyDiversified = KDF.getDiversificationData_EMV(xKDD, keyType);
            } else if (params.isDiversVisa2()) {
                keyDiversified = KDF.getDiversificationData_VISA2(xKDD, keyType);
            }
            SymmetricKey divKey = null;

            if(GPParams.AES.equalsIgnoreCase(masterKeyType)) {
                logger.debug(method + " master key case with AES type.");
                if(params.isDiversGPKMC()) {
                    logger.debug(method + " GPKMC diversification requested.");
                    divKey = nistKdf.diversifyAESKey(masterKey, xCUID, constant_gpkmc, token);
                } else {
                    divKey = masterKey;
                }
            } else {
                divKey = standard.computeCardKey_SCP03_WithDES3(masterKey, keyDiversified, token);
            }

            // The kek session key does not call for derivation
            if (constant == 0 /* kek key */) {
                sessionKey = divKey;
            } else {
                if (noDerive) {
                    sessionKey = divKey;
                }
                else {
                    // Use length of divKey for AES CMAC
                    byte[] finalKeyBytes = nistKdf.kdf_AES_CMAC_SCP03(divKey, context, constant, divKey.getLength());
                    sessionKey = unwrapAESSymKeyOnToken(token, finalKeyBytes, false);

                    TKSEngine engine = TKSEngine.getInstance();
                    JssSubsystem jssSubsystem = engine.getJSSSubsystem();
                    jssSubsystem.obscureBytes(finalKeyBytes);
                }
            }
        }

        return sessionKey;
    }

    public SymmetricKey computeKEKKey_SCP01(
            String selectedToken, String keyNickName,
            byte[] keyInfo,
            byte nistSP800_108KdfOnKeyVersion, // AC: KDF SPEC CHANGE - pass in configuration file value
            boolean nistSP800_108KdfUseCuidAsKdd, // AC: KDF SPEC CHANGE - pass in configuration file value
            byte[] xCUID, // AC: KDF SPEC CHANGE - removed duplicative 'CUID' variable and replaced with 'xCUID'
            byte[] xKDD, // AC: KDF SPEC CHANGE - pass in KDD so symkey can make decision about which value (KDD,CUID) to use
            byte[] devKeyArray, String useSoftToken_s, String keySet, String transportKeyName) throws EBaseException {

        String method = "SecureChannelProtocol.computeKEKKey_SCP01:";

        logger.debug(method + " entering... ");

        return computeSessionKey_SCP01(SecureChannelProtocol.kekType, selectedToken, keyNickName, null, null, keyInfo,
                nistSP800_108KdfOnKeyVersion, nistSP800_108KdfUseCuidAsKdd, xCUID, xKDD, devKeyArray, useSoftToken_s,
                keySet, transportKeyName);

    }

    public SymmetricKey computeSessionKey_SCP01(String keyType,
            String selectedToken, String keyNickName, byte[] card_challenge,
            byte[] host_challenge, byte[] keyInfo,
            byte nistSP800_108KdfOnKeyVersion, // AC: KDF SPEC CHANGE - pass in configuration file value
            boolean nistSP800_108KdfUseCuidAsKdd, // AC: KDF SPEC CHANGE - pass in configuration file value
            byte[] xCUID, // AC: KDF SPEC CHANGE - removed duplicative 'CUID' variable and replaced with 'xCUID'
            byte[] xKDD, // AC: KDF SPEC CHANGE - pass in KDD so symkey can make decision about which value (KDD,CUID) to use
            byte[] devKeyArray, String useSoftToken_s, String keySet, String transportKeyName) throws EBaseException {

        String method = "SecureChannelProtocol.computeSessionKey_SCP01:";

        logger.debug(method + " entering... requested type: " + keyType);

        // This gets set if there is no input card challenge and host challenge
        // Allows this routine to be used for the "encryptData" routine built on top.

        boolean noDerive = false;

        if (keyType == null || devKeyArray == null || keyInfo == null
                || keySet == null || transportKeyName == null || (keyInfo == null || keyInfo.length < 2)) {
            throw new EBaseException(method + "Invalid input!");
        }

        if (xCUID == null || xCUID.length <= 0) {
            throw new EBaseException(method + "CUID invalid size!");
        }

        if (xKDD == null || xKDD.length != NistSP800_108KDF.KDD_SIZE_BYTES) {
            throw new EBaseException(method + "KDD invalid size!");
        }

        if (card_challenge == null && host_challenge == null) {
            noDerive = true;
            logger.debug(method + " NoDerive mode: true");
        } else {
            if (card_challenge == null || host_challenge == null) {
                throw new EBaseException(method + " Invalid input!");
            }

            logger.debug(method + " NoDerive mode: false");
        }

        logger.debug(method + " entering. nickname: " + keyNickName + " selectedToken: " + selectedToken);
        logger.debug(method + " nistSP800_108kdfOnKeyVersion: " + (nistSP800_108KdfOnKeyVersion & 0xFF));

        CryptoManager cm = null;
        CryptoToken token = null;
        CryptoToken internalToken = null;
        try {
            cm = CryptoManager.getInstance();
            token = returnTokenByName(selectedToken, cm);
            internalToken = returnTokenByName(CryptoUtil.INTERNAL_TOKEN_NAME, cm);
        } catch (NotInitializedException e) {
            logger.debug(method + " " + e);
            throw new EBaseException(e);

        } catch (NoSuchTokenException e) {
            logger.debug(method + " " + e);
            throw new EBaseException(e);
        }

        sharedSecretKeyName = SecureChannelProtocol.getSharedSecretKeyName(transportKeyName);

        transportKey = getSharedSecretKey(internalToken);

        String keyNameStr = null;

        SymmetricKey sessionKey = null;
        SymmetricKey masterKey = null;

        if (keyNickName == null) {
            keyNameStr = this.getKeyName(keyInfo);
        } else {
            keyNameStr = keyNickName;
        }

        byte[] context = null;

        if (nistSP800_108KdfUseCuidAsKdd == true &&
                NistSP800_108KDF.useThisKDF(nistSP800_108KdfOnKeyVersion, keyInfo[0])) {
            context = xCUID;
        } else {
            context = xKDD;
        }

        if ((keyInfo[0] == 0x1 && keyInfo[1] == 0x1 && keyNameStr.equals("#01#01")) ||
                (keyInfo[0] == -1 && keyNameStr.indexOf("#FF") != -1))

        {
            /* default manufacturers key */

            String finalKeyType = keyType;

            SymmetricKey devSymKey = returnDeveloperSymKey(token, finalKeyType, keySet, devKeyArray,"DES3");

            // Create the auth with is the same as enc, might need it later.
            if (keyType.equals(encType)) {
                returnDeveloperSymKey(token, authType, keySet, devKeyArray,"DES3");
            }

            if (noDerive == true) {
                sessionKey = devSymKey;
            } else {
                sessionKey = deriveKey_SCP01(token, devSymKey, host_challenge, card_challenge);
            }

        } else {

            SymmetricKey devKey = null;
            logger.debug(method + "In master key mode.");

            masterKey = getSymKeyByName(token, keyNameStr);

            if (NistSP800_108KDF.useThisKDF(nistSP800_108KdfOnKeyVersion, keyInfo[0])) {
                logger.debug(method + " ComputeSessionKey NistSP800_108KDF code: Using NIST SP800-108 KDF.");

                NistSP800_108KDF nistKDF = new NistSP800_108KDF(this);

                Map<String, SymmetricKey> keys = null;
                try {
                    keys = nistKDF.computeCardKeys(masterKey, context, token);
                } catch (EBaseException e) {
                    logger.debug(method + "Can't compute card keys! " + e);
                    throw e;
                }

                devKey = keys.get(keyType);

            } else {
                StandardKDF standardKDF = new StandardKDF(this);
                logger.debug(method + " ComputeSessionKey NistSP800_108KDF code: Using original KDF.");
                byte[] data = KDF.getDiversificationData_VISA2(context, keyType);
                devKey = standardKDF.computeCardKey(masterKey, data, token, PROTOCOL_ONE);
            }

            if (noDerive == true) {
                sessionKey = devKey;
            } else {
                sessionKey = deriveKey_SCP01(token, devKey, host_challenge, card_challenge);
            }
        }

        return sessionKey;
    }

    private SymmetricKey deriveKey_SCP01(CryptoToken token, SymmetricKey cardKey, byte[] host_challenge,
            byte[] card_challenge)
            throws EBaseException {
        String method = "SecureChannelProtocol.deriveKey_SCP01:";
        logger.debug(method + "entering..");

        if (cardKey == null || token == null) {
            throw new EBaseException(method + " Invalid input data!");
        }

        byte[] derivationData = new byte[KEYLENGTH];

        SymmetricKey derivedKey = null;

        for (int i = 0; i < 4; i++)
        {
            derivationData[i] = card_challenge[i + 4];
            derivationData[i + 4] = host_challenge[i];
            derivationData[i + 8] = card_challenge[i];
            derivationData[i + 12] = host_challenge[i + 4];
        }

        SymmetricKeyDeriver encryptDes3;
        byte[] encrypted = null;
        try {
            encryptDes3 = token.getSymmetricKeyDeriver();

            encryptDes3.initDerive(
                    cardKey, /* PKCS11Constants.CKM_DES3_ECB_ENCRYPT_DATA */4354L, derivationData, null,
                    PKCS11Constants.CKM_DES3_ECB, PKCS11Constants.CKA_DERIVE, 16);

            try {
                derivedKey = encryptDes3.derive();
            } catch (TokenException e) {
                logger.debug(method + "Unable to derive the key with the proper mechanism!" + e);
                logger.debug(method + "Now try this the old fashioned way");

                encrypted = computeDes3EcbEncryption(cardKey, token.getName(), derivationData);
                byte[] parityEncrypted = KDF.getDesParity(encrypted);
                logger.debug(method + "encryption completed");

                derivedKey = this.unwrapSymKeyOnToken(token, null, parityEncrypted, false, SymmetricKey.DES3);
            }

        } catch (TokenException | InvalidKeyException | EBaseException e) {
            logger.debug(method + "Unable to derive the key with the proper mechanism!");
            throw new EBaseException(e);
        }

        return derivedKey;
    }

    public SymmetricKey getSharedSecretKey(CryptoToken token) throws EBaseException {

        String method = "SecureChannelProtocol.getSharedSecretKey:";
        logger.debug(method + "entering: transportKey: " + transportKey);

        CryptoToken finalToken = token;
        CryptoToken internalToken = null;
        if (token == null) {

            logger.debug(method + " No token provided assume internal ");
            CryptoManager cm = null;
            try {
                cm = CryptoManager.getInstance();
                internalToken = returnTokenByName(CryptoUtil.INTERNAL_TOKEN_NAME, cm);
                finalToken = internalToken;
            } catch (NotInitializedException e) {
                logger.debug(method + " " + e);
                throw new EBaseException(e);

            } catch (NoSuchTokenException e) {
                logger.debug(method + " " + e);
                throw new EBaseException(e);
            }
        }

        if (transportKey == null) {
            transportKey = getSymKeyByName(finalToken, sharedSecretKeyName);
        }

        if (transportKey == null) {
            throw new EBaseException(method + "Can't locate shared secret key in token db.");
        }

        return transportKey;
    }

    private String getKeyName(byte[] keyVersion) {
        String method = "SecureChannelProtocol.getKeyName:";
        logger.debug(method + " Entering...");
        String keyName = null;

        if (keyVersion == null || keyVersion.length != 2) {
            return null;
        }

//        SecureChannelProtocol.debugByteArray(keyVersion, "keyVersion array:");
        keyName = "#" + String.format("%02X", keyVersion[0]) + "#" + String.format("%02X", keyVersion[1]);

        logger.debug(method + " returning: " + keyName);

        return keyName;
    }

    public static String getSharedSecretKeyName(String name) throws EBaseException {

        String method = "SecureChannelProtocol.getSharedSecretKeyName:";
        logger.debug(method + " Entering...");

        // No longer cache the secret name, there could be a different one for each incoming TPS connection.
        if (name != null) {
            SecureChannelProtocol.sharedSecretKeyName = name;
        }

        if (SecureChannelProtocol.sharedSecretKeyName == null) {
            throw new EBaseException(method + " Can not find shared secret key name!");
        }

        return SecureChannelProtocol.sharedSecretKeyName;
    }

    public static String setSharedSecretKeyName(String name) throws EBaseException {
        return SecureChannelProtocol.getSharedSecretKeyName(name);
    }

    /* This routine will attempt to return one of the well known developer symmetric keys from the token.
    Each key, is merely stored on the token for convenience.
    If the given key is not found on the token it is put there and left on as a permanent key.
    From that point it is a simple matter of retrieving  the desired key from the token.
    No security advantage is implied or desired here.
    */
    public SymmetricKey returnDeveloperSymKey(CryptoToken token, String keyType, String keySet, byte[] inputKeyArray, String keyAlg)
            throws EBaseException {

        SymmetricKey devKey = null;

        String method = "SecureChannelProtocol.returnDeveloperSymKey:";

        logger.debug(method + "keyAlg: " + keyAlg);
        boolean isAES = false;
        String finalAlg = null;
        if(keyAlg == null) {
            finalAlg = "DES3";
        }

        if(keyAlg.equalsIgnoreCase("AES")) {
            isAES = true;
            finalAlg = "AES";
        }

        String devKeyName = keySet + "-" + keyType + "Key"  + "-" + finalAlg;
        logger.debug(method + " entering.. searching for key: " + devKeyName);

        if (token == null || keyType == null || keySet == null) {
            throw new EBaseException(method + "Invalid input data!");
        }

        try {
            logger.debug(method + " requested token: " + token.getName());
        } catch (TokenException e) {
            throw new EBaseException(method + e);
        }

        devKey = getSymKeyByName(token, devKeyName);

        if (devKey == null) {
            //Put the key there and leave it

            byte[] des3InputKey = null;

            if (inputKeyArray == null) {
                throw new EBaseException(method + "Input key is null and has to be non null when importing...");
            }
            int inputLen = inputKeyArray.length;

            logger.debug(method + " inputKeyArray.length: " + inputLen);

            if (!isAES) {
                if (inputLen != DES3_LENGTH && inputLen != DES2_LENGTH) {
                    throw new EBaseException(method + "invalid input key length!");
                }

                if (inputLen == DES2_LENGTH) {
                    des3InputKey = new byte[DES3_LENGTH];
                    System.arraycopy(inputKeyArray, 0, des3InputKey, 0, DES2_LENGTH);
                    System.arraycopy(inputKeyArray, 0, des3InputKey, DES2_LENGTH, EIGHT_BYTES);

                } else {
                    System.arraycopy(inputKeyArray, 0, des3InputKey, 0, DES3_LENGTH);
                }

//                SecureChannelProtocol.debugByteArray(des3InputKey, "Developer key to import: " + keyType + ": ");

                devKey = unwrapSymKeyOnToken(token, des3InputKey, true);

            } else {

                // Allow 256 bit length
                if (inputLen == DEF_AES_KEYLENGTH || inputLen == DEF_AES_256_KEYLENGTH) { // support 128 and 256 bits
                    devKey = unwrapAESSymKeyOnToken(token, inputKeyArray, true);
                }
            }

            devKey.setNickName(devKeyName);
        } else {
            logger.debug(method + " Found sym key: " + devKeyName);
        }
        return devKey;
    }

    //Takes raw des key 16 bytes, such as developer key and returns an AES key of the same size
    //Supports 128 bits for now
    //07-08-2022, Updated to work with both 128 and 256 bits
    public SymmetricKey unwrapAESSymKeyOnToken(CryptoToken token, byte[] inputKeyArray,
            boolean isPerm)
            throws EBaseException {

        String method = "SecureChannelProtocol.unwrapAESSymKeyOnToken:";
        logger.debug(method + "Entering...");

        if(token == null || inputKeyArray == null) {
            throw new EBaseException(method + " Invalid input data!");
        }

        if(inputKeyArray.length < 16) {
            throw new EBaseException(method + " Invalid key size!");
        }

        byte[] finalInputKeyArray = inputKeyArray;

        if(inputKeyArray.length > 32) {
            finalInputKeyArray = new byte[32];
            System.arraycopy(inputKeyArray, 0, finalInputKeyArray, 0, 32);
        }

        KeyGenerator kg;
        SymmetricKey finalAESKey;
        try {
            kg = token.getKeyGenerator(KeyGenAlgorithm.AES);

            SymmetricKey.Usage usages[] = new SymmetricKey.Usage[4];
            usages[0] = SymmetricKey.Usage.WRAP;
            usages[1] = SymmetricKey.Usage.UNWRAP;
            usages[2] = SymmetricKey.Usage.ENCRYPT;
            usages[3] = SymmetricKey.Usage.DECRYPT;

            kg.setKeyUsages(usages);
            kg.temporaryKeys(true);
            // Handle 128 and 256 initialization sizes
            kg.initialize(finalInputKeyArray.length*EIGHT_BYTES);
            SymmetricKey tempKey = kg.generate();

            // Use EncryptionAlgorithm based on key size
            Cipher encryptor;
            if (tempKey.getStrength() == AES_128_BITS)
            {
                encryptor = token.getCipherContext(EncryptionAlgorithm.AES_128_CBC);
            }
            else
            {
                encryptor = token.getCipherContext(EncryptionAlgorithm.AES_256_CBC);
            }
                
            int ivLength = 16;

            byte[] iv = null;

            if (ivLength > 0) {
                iv = new byte[ivLength]; // all zeroes
            }

            encryptor.initEncrypt(tempKey, new IVParameterSpec(iv));
            logger.debug(method + " Did encryptor.initEncrypt successfully...");
            byte[] wrappedKey = encryptor.doFinal(finalInputKeyArray);

            KeyWrapper keyWrap = token.getKeyWrapper(KeyWrapAlgorithm.AES_CBC);
            keyWrap.initUnwrap(tempKey, new IVParameterSpec(iv));

            if(isPerm)
                // Use length of key for finalAESKey
                finalAESKey = keyWrap.unwrapSymmetricPerm(wrappedKey, SymmetricKey.AES, wrappedKey.length);
            else
                // Use length of key for finalAESKey
                finalAESKey = keyWrap.unwrapSymmetric(wrappedKey, SymmetricKey.AES, wrappedKey.length);

        } catch (Exception e) {
            throw new EBaseException(method + " Can't unwrap key onto token!");
        }

        return finalAESKey;
    }

    //Supports 128 bits for now
    //Used to convert a des key (on token) to aes
    //Not used as of now, future if needed
    public SymmetricKey unwrapAESSymKeyOnToken(CryptoToken token, SymmetricKey keyToUnwrap,
            boolean isPerm)
            throws EBaseException {

        String method = "SecureChannelProtocol.unwrapAESSymKeyOnToken:";
        logger.debug(method + "Entering...");

        if(token == null || keyToUnwrap == null) {
            throw new EBaseException(method + " Invalid input data!");
        }

        if(keyToUnwrap.getLength()< 16) {
            throw new EBaseException(method + " Invalid key size!");
        }

        KeyGenerator kg;
        SymmetricKey finalAESKey;
        try {
            kg = token.getKeyGenerator(KeyGenAlgorithm.AES);

            SymmetricKey.Usage usages[] = new SymmetricKey.Usage[4];
            usages[0] = SymmetricKey.Usage.WRAP;
            usages[1] = SymmetricKey.Usage.UNWRAP;
            usages[2] = SymmetricKey.Usage.ENCRYPT;
            usages[3] = SymmetricKey.Usage.DECRYPT;

            kg.setKeyUsages(usages);
            kg.temporaryKeys(true);
            kg.initialize(128);
            SymmetricKey tempKey = kg.generate();

            int ivLength = EncryptionAlgorithm.AES_128_CBC.getIVLength();
            byte[] iv = null;

            if (ivLength > 0) {
                iv = new byte[ivLength]; // all zeroes
            }

            //Wrap the arbitrary key first

            int len = keyToUnwrap.getLength();

            SymmetricKey finalKeyToWrap = null;
            SymmetricKey key16 = null;
            if(len > 16) {
                key16 = extractDes2FromDes3(keyToUnwrap, token.getName());
                if(key16 != null)
                len = key16.getLength();
                finalKeyToWrap = key16;
            } else {
                finalKeyToWrap = keyToUnwrap;
            }

            KeyWrapper keyWrap = token.getKeyWrapper(KeyWrapAlgorithm.AES_CBC);
            
            keyWrap.initWrap(tempKey, new IVParameterSpec(iv));
            byte[] wrappedKey = keyWrap.wrap(finalKeyToWrap);

            //Now unwrap to an AES key

            KeyWrapper keyUnWrap = token.getKeyWrapper(KeyWrapAlgorithm.AES_CBC);
            keyUnWrap.initUnwrap(tempKey, new IVParameterSpec(iv));
            finalAESKey = keyUnWrap.unwrapSymmetric(wrappedKey, SymmetricKey.AES, 16);

            TKSEngine engine = TKSEngine.getInstance();
            JssSubsystem jssSubsystem = engine.getJSSSubsystem();
            jssSubsystem.obscureBytes(wrappedKey);

        } catch (Exception e) {
            throw new EBaseException(method + " Can't unwrap key onto token!");
        }

        return finalAESKey;

    }

    //Final param allows us to request the final type, DES or AES
    public SymmetricKey unwrapSymKeyOnToken(CryptoToken token, SymmetricKey unwrappingKey, byte[] inputKeyArray,
            boolean isPerm, SymmetricKey.Type finalKeyType)
            throws EBaseException {

        String method = "SecureChannelProtocol.unwrapSymKeyOnToken:";
        logger.debug(method + "Entering...");
        SymmetricKey unwrapped = null;
        SymmetricKey tempKey = null;

        if (token == null) {
            throw new EBaseException(method + "Invalid input!");
        }

        // Allow AES-256
        if (inputKeyArray == null || (inputKeyArray.length != DES3_LENGTH && inputKeyArray.length != DES2_LENGTH
                && inputKeyArray.length != DEF_AES_256_KEYLENGTH)) {
            throw new EBaseException(method + "No raw array to use to create key!");
        }

        if (unwrappingKey == null) {
            try {
                // Select algorithm based on key size
                KeyGenerator kg;
                if (inputKeyArray.length == DES3_LENGTH || inputKeyArray.length == DES2_LENGTH)
                {
                    kg = token.getKeyGenerator(KeyGenAlgorithm.DES3);
                }
                else
                {
                    kg = token.getKeyGenerator(KeyGenAlgorithm.AES);
                }
                
                SymmetricKey.Usage usages[] = new SymmetricKey.Usage[4];
                usages[0] = SymmetricKey.Usage.WRAP;
                usages[1] = SymmetricKey.Usage.UNWRAP;
                usages[2] = SymmetricKey.Usage.ENCRYPT;
                usages[3] = SymmetricKey.Usage.DECRYPT;

                kg.setKeyUsages(usages);
                kg.temporaryKeys(true);
                tempKey = kg.generate();
            } catch (NoSuchAlgorithmException | TokenException | IllegalStateException | CharConversionException e) {
                throw new EBaseException(method + "Can't generate temporary key to unwrap the key.");
            }

        }

        byte[] finalKeyArray = null;

        if (inputKeyArray.length == DES2_LENGTH && finalKeyType == SymmetricKey.DES3) {
            finalKeyArray = SecureChannelProtocol.makeDes3FromDes2(inputKeyArray);
        }

        Cipher encryptor = null;
        byte[] wrappedKey = null;

        SymmetricKey encUnwrapKey = null;

        if (tempKey != null) {
            encUnwrapKey = tempKey;
        } else {
            encUnwrapKey = unwrappingKey;
        }

        try {
            //Differentiate between DES3, DES and AES
            if (finalKeyType == SymmetricKey.Type.DES3 || finalKeyType == SymmetricKey.Type.DES)
            {
                encryptor = token.getCipherContext(EncryptionAlgorithm.DES3_ECB);
            }
            else if (finalKeyType == SymmetricKey.Type.AES && inputKeyArray.length == DEF_AES_KEYLENGTH)
            {
                encryptor = token.getCipherContext(EncryptionAlgorithm.AES_128_CBC);
            }
            else
            {
                encryptor = token.getCipherContext(EncryptionAlgorithm.AES_256_CBC);
            }

            encryptor.initEncrypt(encUnwrapKey);

            if (finalKeyArray != null) {
                if(finalKeyType == SymmetricKey.Type.DES3 || finalKeyType == SymmetricKey.Type.DES)
                    wrappedKey = encryptor.doFinal(KDF.getDesParity(finalKeyArray));
                else
                    wrappedKey = encryptor.doFinal(finalKeyArray);
            } else {
                if(finalKeyType == SymmetricKey.Type.DES3 || finalKeyType == SymmetricKey.Type.DES)
                    wrappedKey = encryptor.doFinal(KDF.getDesParity(inputKeyArray));
                else
                    wrappedKey = encryptor.doFinal(inputKeyArray);
            }

            logger.debug(method + " done encrypting data");

            // SecureChannelProtocol.debugByteArray(wrappedKey, " encrypted key");

            //Differentiate between DES3, DES and AES
            KeyWrapper keyWrap = null;
            if(finalKeyType == SymmetricKey.Type.DES3 || finalKeyType == SymmetricKey.Type.DES)
            {
                keyWrap = token.getKeyWrapper(KeyWrapAlgorithm.DES3_ECB);
            }
            else
            {
                keyWrap = token.getKeyWrapper(KeyWrapAlgorithm.AES_CBC);
            }

            keyWrap.initUnwrap(encUnwrapKey, null);

            if (isPerm == true) {
                unwrapped = keyWrap.unwrapSymmetricPerm(wrappedKey,
                        finalKeyType, 0);
            } else {
                unwrapped = keyWrap.unwrapSymmetric(wrappedKey, finalKeyType, 0);
            }

        } catch (Exception e) {
            logger.debug(method + " " + e);
            throw new EBaseException(e);
        } finally {
            if (finalKeyArray != null) {
                Arrays.fill(finalKeyArray, (byte) 0);
            }
        }

        //logger.debug(method + "Returning symkey: length = " + unwrapped.getLength());
        logger.debug(method + "Returning symkey...");

        return unwrapped;
    }

    //Final param allows us to request the final type, DES or AES
    public SymmetricKey unwrapWrappedSymKeyOnToken(CryptoToken token, SymmetricKey unwrappingKey, byte[] inputKeyArray,
            boolean isPerm, SymmetricKey.Type keyType)
            throws EBaseException {

        String method = "SecureChannelProtocol.unwrapWrappedSymKeyOnToken:";
        logger.debug(method + "Entering...");
        SymmetricKey unwrapped = null;
        SymmetricKey finalUnwrapped = null;

        if (token == null || unwrappingKey == null) {
            throw new EBaseException(method + "Invalid input!");
        }

        if (inputKeyArray == null) {
            throw new EBaseException(method + "No raw array to use to create key!");
        }

        if(keyType == SymmetricKey.Type.AES) {
           if(inputKeyArray.length != DEF_AES_KEYLENGTH && inputKeyArray.length != DEF_AES_256_KEYLENGTH)
               throw new EBaseException(method + "Invalid length of raw AES input array.");
        }
        else if(keyType == SymmetricKey.Type.DES ||
                keyType == SymmetricKey.Type.DES3) {
            if(inputKeyArray.length != DES3_LENGTH && inputKeyArray.length != DES2_LENGTH)
                throw new EBaseException(method + "Invalid length of raw DES input array.");
        }

        try {
            KeyWrapper keyWrap;

            if(unwrappingKey.getType() == SymmetricKey.Type.AES)
            {
                // Set iv based on key length
                IVParameterSpec iv = new IVParameterSpec(new byte[unwrappingKey.getLength()]);
                keyWrap = token.getKeyWrapper(KeyWrapAlgorithm.AES_CBC);
                keyWrap.initUnwrap(unwrappingKey, iv);
            }
            else if(unwrappingKey.getType() == SymmetricKey.Type.DES ||
                    unwrappingKey.getType() == SymmetricKey.Type.DES3)
            {
                keyWrap = token.getKeyWrapper(KeyWrapAlgorithm.DES3_ECB);
                keyWrap.initUnwrap(unwrappingKey, null);
            }
            else
                throw new EBaseException(method + " Unsupported transport key type.");

            if (isPerm) {
                unwrapped = keyWrap.unwrapSymmetricPerm(inputKeyArray,
                        keyType, SymmetricKey.Usage.UNWRAP, inputKeyArray.length);
            } else {
                unwrapped = keyWrap.unwrapSymmetric(inputKeyArray, keyType, SymmetricKey.Usage.UNWRAP,
                        inputKeyArray.length);
            }

            if (keyType == SymmetricKey.DES3) {
                finalUnwrapped = makeDes3KeyDerivedFromDes2(unwrapped, token.getName());
            }

        } catch (Exception e) {
            logger.debug(method + " " + e);
            throw new EBaseException(e);
        }

        //logger.debug(method + "Returning symkey: length = " + unwrapped.getLength());
        logger.debug(method + "Returning symkey...");

        if (finalUnwrapped != null)
            return finalUnwrapped;
        else
            return unwrapped;
    }

    public SymmetricKey unwrapSymKeyOnToken(CryptoToken token, byte[] inputKeyArray, boolean isPerm)
            throws EBaseException {

        String method = "SecureChannelProtocol.unwrapSymKeyOnToken:";
        logger.debug(method + "Entering...");
        SymmetricKey unwrapped = null;

        if (token == null) {
            throw new EBaseException(method + "Invalid crypto token!");
        }

        if (inputKeyArray == null || (inputKeyArray.length != DES3_LENGTH && inputKeyArray.length != DES2_LENGTH)) {
            throw new EBaseException(method + "No raw array to use to create key!");
        }

        //RedHat For DES3 don's use the AES shared secret as wrapping key
        unwrapped = this.unwrapSymKeyOnToken(token, null, inputKeyArray, isPerm, SymmetricKey.DES3);

        logger.debug(method + "Returning symkey: length = " + unwrapped.getLength());
        //logger.debug(method + "Returning symkey: " + unwrapped);

        return unwrapped;
    }

    public static SymmetricKey getSymKeyByName(CryptoToken token, String name) throws EBaseException {

        String method = "SecureChannelProtocol.getSymKeyByName:";
        if (token == null || name == null) {
            throw new EBaseException(method + "Invalid input data!");
        }
        SymmetricKey[] keys;

        logger.debug(method + "Searching for sym key: " + name);
        try {
            keys = token.getCryptoStore().getSymmetricKeys();
        } catch (TokenException e) {
            throw new EBaseException(method + "Can't get the list of symmetric keys!");
        }
        int len = keys.length;
        for (int i = 0; i < len; i++) {
            SymmetricKey cur = keys[i];
            if (cur != null) {
                if (name.equals(cur.getNickName())) {
                    logger.debug(method + "Found key: " + name);
                    return cur;
                }
            }
        }

        logger.debug(method + " Sym Key not found.");
        return null;
    }

    public CryptoToken returnTokenByName(String name, CryptoManager manager) throws NoSuchTokenException, NotInitializedException {

        logger.debug("returnTokenByName: requested name: " + name);
        if (name == null || manager == null)
            throw new NoSuchTokenException();

        return CryptoUtil.getKeyStorageToken(name);
    }

    public static byte[] makeDes3FromDes2(byte[] des2) {

        if (des2 == null || des2.length != SecureChannelProtocol.DES2_LENGTH) {
            return null;
        }

        byte[] des3 = new byte[SecureChannelProtocol.DES3_LENGTH];

        System.arraycopy(des2, 0, des3, 0, SecureChannelProtocol.DES2_LENGTH);
        System.arraycopy(des2, 0, des3, DES2_LENGTH, EIGHT_BYTES);

        return des3;
    }

    public static void debugByteArray(byte[] array, String message) {

        logger.debug("About to dump array: " + message);
        System.out.println("About to dump array: " + message);

        if (array == null) {
            logger.debug("Array to dump is empty!");
            return;
        }

        System.out.println("################### ");
        logger.debug("################### ");

        String result = getHexString(array);
        logger.debug(result);
        System.out.println(result);
    }

    public static void
            displayByteArray(byte[] ba, boolean has_check_sum) {
        char mask = 0xff;

        if (has_check_sum == true)
            mask = 0xfe;

        for (int i = 0; i < ba.length; i++) {

            System.out.print(Integer.toHexString(ba[i] & mask) + " ");
            if ((i % 26) == 25) {
                System.out.println("");
            }
        }
        System.out.println("");
    }

    final protected static char[] hex = "0123456789abcdef".toCharArray();

    public static String getHexString(byte[] bytes) {

        char[] hexChars = new char[bytes.length * 3];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 3] = hex[v >>> 4];
            hexChars[j * 3 + 1] = hex[v & 0x0F];
            hexChars[j * 3 + 2] = ':';
        }
        return new String(hexChars);
    }

    public CryptoManager getCryptoManger() throws EBaseException {
        String method = "SecureChannelProtocol.getCryptoManager";
        CryptoManager cm = null;

        if (cryptoManager != null)
            return cryptoManager;

        try {
            cm = CryptoManager.getInstance();
        } catch (NotInitializedException e) {
            logger.debug(method + " " + e);
            throw new EBaseException(e);

        }

        cryptoManager = cm;

        return cryptoManager;

    }

    public static byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(LONG_SIZE);
        buffer.putLong(x);
        return buffer.array();
    }

    /* Generate 24 key, but with a DES2 key converted to DES3
       This needed to appease the server side keygen and the coollkey applet.
    */
    public SymmetricKey generateSymKey(String selectedToken) throws EBaseException {
        String method = "SecureChannelProtocol.generateSymKey:";

        logger.debug(method + " entering , token: " + selectedToken);
        SymmetricKey symKey = null;
        SymmetricKey symKeyFinal = null;

        if (selectedToken == null) {
            throw new EBaseException(method + " Invalid input data!");
        }

        try {
            CryptoManager cm = this.getCryptoManger();
            CryptoToken token = returnTokenByName(selectedToken, cm);

            KeyGenerator kg = token.getKeyGenerator(KeyGenAlgorithm.DES3);

            symKey = kg.generate();

            symKeyFinal = this.makeDes3KeyDerivedFromDes2(symKey, selectedToken);

        } catch (Exception  e) {
            logger.debug(method + " " + e);
            throw new EBaseException(e);
        }

        return symKeyFinal;

    }

    public byte[] ecbEncrypt(SymmetricKey devKey, SymmetricKey symKey, String selectedToken) throws EBaseException {
        byte[] result = null;
        String method = "SecureChannelProtocol.ecbEncrypt:";
        logger.debug(method + " Entering...");

        if (devKey == null || symKey == null || selectedToken == null) {
            throw new EBaseException(method + " Invalid input parameters.");
        }

        String devKeyToken = null;
        try {
            devKeyToken = symKey.getOwningToken().getName();
            logger.debug(method + " symKey token: " + devKeyToken);
            logger.debug(method + " devKey token: " + devKey.getOwningToken().getName());

        } catch (TokenException e) {
        }
        SymmetricKey des2 = this.extractDes2FromDes3(symKey, devKeyToken);

        //SecureChannelProtocol.debugByteArray(des2.getEncoded(), method + " raw des2 key, to be wrapped.");

        result = this.wrapSessionKey(selectedToken, des2, devKey);

        //SecureChannelProtocol.debugByteArray(result, " Wrapped des2 key");

        return result;
    }

    /* Convenience routine to create a 3DES key from a 2DES key.
    This is done by taking the first 8 bytes of the 2DES key and copying it to the end, making
     a faux 3DES key. This is required due to applet requirements.
    */
    public SymmetricKey makeDes3KeyDerivedFromDes2(SymmetricKey des3Key, String selectedToken) throws EBaseException {
        SymmetricKey des3 = null;

        String method = "SecureChannelProtocol.makeDes3KeyDerivedFromDes2:";

        logger.debug(method + " Entering ...");

        if (des3Key == null || selectedToken == null) {
            throw new EBaseException(method + " Invalid input data!");
        }

        try {
            CryptoManager cm = this.getCryptoManger();
            CryptoToken token = returnTokenByName(selectedToken, cm);

            long bitPosition = 0;

            byte[] param = SecureChannelProtocol.longToBytes(bitPosition);

            SymmetricKey extracted16 = this.extractDes2FromDes3(des3Key, selectedToken);

            SymmetricKeyDeriver extract8 = token.getSymmetricKeyDeriver();

            extract8.initDerive(
                    extracted16, PKCS11Constants.CKM_EXTRACT_KEY_FROM_KEY, param, null,
                    PKCS11Constants.CKA_ENCRYPT, PKCS11Constants.CKA_DERIVE, 8);

            SymmetricKey extracted8 = extract8.derive();

            //logger.debug(method + " extracted8 key: " + extracted8);
            logger.debug(method + " extracted8 key");

            SymmetricKeyDeriver concat = token.getSymmetricKeyDeriver();
            concat.initDerive(
                    extracted16, extracted8, PKCS11Constants.CKM_CONCATENATE_BASE_AND_KEY, null, null,
                    PKCS11Constants.CKM_DES3_ECB, PKCS11Constants.CKA_DERIVE, 0);

            des3 = concat.derive();

        } catch (Exception e) {
            logger.debug(method + " " + e);
            throw new EBaseException(e);
        }

        return des3;
    }

    public SymmetricKey extractDes2FromDes3(SymmetricKey baseKey, String selectedToken) throws EBaseException {
        String method = "SecureChannelProtocol.extractDes2FromDes3:";
        logger.debug(method + " Entering: ");

        SymmetricKey extracted16 = null;

        if (baseKey == null || selectedToken == null) {
            throw new EBaseException(method + " Invalid input data.");
        }

        try {
            CryptoManager cm = this.getCryptoManger();
            CryptoToken token = returnTokenByName(selectedToken, cm);

            long bitPosition = 0;

            byte[] param = SecureChannelProtocol.longToBytes(bitPosition);

            SymmetricKeyDeriver extract16 = token.getSymmetricKeyDeriver();
            extract16.initDerive(
                    baseKey, PKCS11Constants.CKM_EXTRACT_KEY_FROM_KEY, param, null,
                    PKCS11Constants.CKA_ENCRYPT, PKCS11Constants.CKA_DERIVE, 16);

            extracted16 = extract16.derive();

        } catch (Exception e) {
            logger.debug(method + " " + e);
            throw new EBaseException(e);
        }

        return extracted16;
    }

    /* If wrappingKey is not null, use it, otherwise use the shared secret key
    */
    public byte[] wrapSessionKey(String tokenName, SymmetricKey sessionKey, SymmetricKey wrappingKey)
            throws EBaseException {
        //Now wrap the key for the trip back to TPS with shared secret transport key

        String method = "SecureChannelProtocol.wrapSessionKey";

        KeyWrapper keyWrap = null;
        byte[] wrappedSessKeyData = null;

        if (tokenName == null || sessionKey == null) {
            throw new EBaseException(method + " Invalid input data.");
        }

        SymmetricKey wrapper = null;

        if (wrappingKey == null) {
            wrapper = transportKey;
        } else {
            wrapper = wrappingKey;
        }

        logger.debug(method + " wrapper key type: " + wrapper.getType());

        if (wrapper.getType() != SymmetricKey.AES) {
            logger.debug(method + "Trying to wrap a key with an DES key!");

            try {
                CryptoManager cm = this.getCryptoManger();
                CryptoToken token = returnTokenByName(tokenName, cm);

                keyWrap = token.getKeyWrapper(KeyWrapAlgorithm.DES3_ECB);
                keyWrap.initWrap(wrapper, null);
                wrappedSessKeyData = keyWrap.wrap(sessionKey);

            } catch (
                    Exception e) {
                logger.debug(method + " " + e);
                throw new EBaseException(e);
            }

        } else if (wrapper.getType() == SymmetricKey.AES) {
            logger.debug(method + "Trying to wrap a key with an AES key!");
            try {
                CryptoManager cm = this.getCryptoManger();
                CryptoToken token = returnTokenByName(tokenName, cm);

                int ivLength = EncryptionAlgorithm.AES_128_CBC.getIVLength();
                //logger.debug(method + " Set iv length to " + ivLength);
                byte[] iv = null;

                if (ivLength > 0) {
                    iv = new byte[ivLength]; // all zeroes
                }

                keyWrap = token.getKeyWrapper(KeyWrapAlgorithm.AES_CBC);
                keyWrap.initWrap(wrapper, new IVParameterSpec(iv));
                wrappedSessKeyData = keyWrap.wrap(sessionKey);

            } catch (Exception e) {
                logger.debug(method + " " + e);
                throw new EBaseException(e);
            }
        }

        //SecureChannelProtocol.debugByteArray(wrappedSessKeyData, "wrappedSessKeyData");
        logger.debug(method + " returning session key");

        return wrappedSessKeyData;

    }

    //128 for now.
    public byte[] computeAES_CBCEncryption(SymmetricKey symKey, String selectedToken, byte[] input, byte[] iv)
            throws EBaseException
    {
        String method = "SecureChannelProtocol.computeAES_CBCEncryption";
        byte[] output = null;
        byte[] finalIv = null;

        if (symKey == null || selectedToken == null) {
            throw new EBaseException(method + " Invalid input data.");
        }

        if (iv == null) {
            // Set iv based on key length
            finalIv = new byte[DEF_AES_KEYLENGTH];
        } else {
            finalIv = iv;
        }

        //logger.debug(method + ": iv length = " + finalIv.length);

        try {
            CryptoManager cm = this.getCryptoManger();
            CryptoToken token = returnTokenByName(selectedToken, cm);
            Cipher encryptor = token.getCipherContext(EncryptionAlgorithm.AES_128_CBC);
            encryptor.initEncrypt(symKey, new IVParameterSpec(finalIv));
            output = encryptor.doFinal(input);
            //SecureChannelProtocol.debugByteArray(output, "AES CBC Encrypted data:");
        } catch (Exception e) {

            logger.debug(method + e);
            throw new EBaseException(method + e);
        }

        return output;
    }

    public byte[] computeDes3EcbEncryption(SymmetricKey desKey, String selectedToken, byte[] input)
            throws EBaseException {

        String method = "SecureChannelProtocol.computeDes3EcbEncryption";
        byte[] output = null;

        if (desKey == null || selectedToken == null) {
            throw new EBaseException(method + " Invalid input data.");
        }

        try {
            CryptoManager cm = this.getCryptoManger();
            CryptoToken token = returnTokenByName(selectedToken, cm);
            logger.debug(method + "desKey: owning token: " + desKey.getOwningToken().getName());
            logger.debug(method + "desKey: current token: " + token.getName());
            Cipher encryptor = token.getCipherContext(EncryptionAlgorithm.DES3_ECB);
            logger.debug(method + "got encryptor");
            encryptor.initEncrypt(desKey);
            logger.debug(method + "done initEncrypt");
            output = encryptor.doFinal(input);
            //logger.debug(method + "done doFinal " + output);
            logger.debug(method + "done doFinal");
            //SecureChannelProtocol.debugByteArray(output, "Encrypted data:");
        } catch (Exception e) {

            logger.debug(method + e);
            throw new EBaseException(method + e);
        }
        logger.debug("returning encrypted output.");
        //SecureChannelProtocol.debugByteArray(output, "Encrypted data before leaving:");

        return output;
    }

    //SCP03 uses aes
    public byte[] computeKeyCheck_SCP03(SymmetricKey symKey, String selectedToken) throws EBaseException {

        String method = "SecureChannelProtocol.computeKeyCheck_SCP03:";

        if (symKey == null || selectedToken == null) {
            throw new EBaseException(method + " invalid input data!");
        }

        byte[] key_check_message = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };
        //zero iv vector
        byte[] key_check_iv = new byte[16];
        byte[] output = null;
        byte[] finalOutput = new byte[3];

        // RedHat :Do the same behavior as computeKeyCheck, use the token where the aes key resides.
        String keysToken = null;
        try {
            keysToken = symKey.getOwningToken().getName();
        } catch (TokenException e1) {
            throw new EBaseException(e1 + " Can't get owning token for key/");
        }

        try {
            output = computeAES_CBCEncryption(symKey, keysToken, key_check_message, key_check_iv);
        } catch (EBaseException e) {
            logger.debug(method + e);
            throw e;

        }

        //Get the 3 bytes needed
        System.arraycopy(output, 0, finalOutput, 0, 3);

        //SecureChannelProtocol.debugByteArray(finalOutput, method + " output: ");

        return finalOutput;
    }

    //AES, uses AES_CMAC alg to do the work.
    public byte[] computeCryptogram_SCP03(SymmetricKey symKey, String selectedToken, byte[] context, byte cryptoType)
            throws EBaseException {
        String method = "SecureChannelProtocol.computeCryptogram_SCP03";

        logger.debug(method + " entering ..");

        if (symKey == null || selectedToken == null || (cryptoType != NistSP800_108KDF.CARD_CRYPTO_KDF_CONSTANT)
                && cryptoType != NistSP800_108KDF.HOST_CRYPTO_KDF_CONSTANT) {
            throw new EBaseException(method + " Invalid input data.");
        }

        NistSP800_108KDF nistKdf = new NistSP800_108KDF(this);
        byte[] crypto = nistKdf.kdf_AES_CMAC_SCP03(symKey, context, cryptoType, 8);

        //SecureChannelProtocol.debugByteArray(crypto, " calculated cryptogram");

        byte[] finalCrypto = new byte[8];

        System.arraycopy(crypto, 0, finalCrypto, 0, 8);

        return finalCrypto;
    }

    public byte[] computeKeyCheck(SymmetricKey desKey, String selectedToken) throws EBaseException {

        String method = "SecureChannelProtocol.computeKeyCheck:";

        logger.debug(method + " Entering...");

        byte[] input = new byte[EIGHT_BYTES];
        byte[] finalOutput = new byte[3];

        if (desKey == null || selectedToken == null) {
            throw new EBaseException(method + " Invalid input data.");
        }

        byte[] output = null;
        String keysToken = null;
        try {
            keysToken = desKey.getOwningToken().getName();
        } catch (TokenException e1) {
            throw new EBaseException(e1 + " Can't get owning token for key/");
        }

        try {
            output = computeDes3EcbEncryption(desKey, keysToken, input);
        } catch (EBaseException e) {
            logger.debug(method + e);
            throw e;

        }

        //Get the 3 bytes needed
        System.arraycopy(output, 0, finalOutput, 0, 3);

        //SecureChannelProtocol.debugByteArray(finalOutput, "Calculated KeyCheck Value:");
        logger.debug(method + " ends");

        return finalOutput;
    }

    public byte[] computeMAC_SCP01(SymmetricKey symKey, byte[] input, byte[] icv, String selectedToken)
            throws EBaseException {
        byte[] output = null;
        byte[] result = null;

        String method = "SecureChannelProtocol.computeMAC_SCP01:";

        logger.debug(method + " Entering...");

        if (symKey == null || input == null || icv == null || icv.length != EIGHT_BYTES) {
            throw new EBaseException(method + " invalid input data!");
        }
        int inputLen = input.length;

        byte[] macPad = new byte[8];
        macPad[0] = (byte) 0x80;

        CryptoToken token = null;

        try {

            CryptoManager cm = this.getCryptoManger();
            token = returnTokenByName(selectedToken, cm);

            Cipher cipher = token.getCipherContext(EncryptionAlgorithm.DES3_ECB);
            cipher.initEncrypt(symKey);

            result = new byte[EIGHT_BYTES];
            System.arraycopy(icv, 0, result, 0, EIGHT_BYTES);

            /* Process whole blocks */
            int inputOffset = 0;
            while (inputLen >= 8)
            {
                for (int i = 0; i < 8; i++)
                {
                    //Xor implicitly converts bytes to ints, we convert answer back to byte.
                    byte a = (byte) (result[i] ^ input[inputOffset + i]);
                    result[i] = a;
                }

                byte[] ciphResult = cipher.update(result);

                if (ciphResult.length != result.length) {
                    throw new EBaseException(method + " Invalid cipher!");
                }

                System.arraycopy(ciphResult, 0, result, 0, EIGHT_BYTES);

                inputLen -= 8;
                inputOffset += 8;
            }

            /*
             * Fold in remaining data (if any)
             * Set i to number of bytes processed
             */
            int i = 0;
            for (i = 0; i < inputLen; i++)
            {
                byte a = (byte) (result[i] ^ input[inputOffset + i]);
                result[i] = a;
            }

            /*
             * Fill remainder of last block. There
             * will be at least one byte handled here.
             */

            //Start at the beginning of macPad
            // Keep going with i in result where we left off.
            int padOffset = 0;
            while (i < 8)
            {
                byte a = (byte) (result[i] ^ macPad[padOffset++]);
                result[i] = a;
                i++;
            }

            output = cipher.doFinal(result);

            if (output.length != result.length) {
                throw new EBaseException(method + " Invalid cipher!");
            }

        } catch (Exception e) {
            throw new EBaseException(method + " Cryptographic problem encountered! " + e.toString());
        }

        // SecureChannelProtocol.debugByteArray(output, method + " output: ");

        return output;
    }

    //Calculates the 3 new card keys to be written to the token for
    //Symmetric key changeover. Supports SCP03 now.
    //Provide all the static developer key arrays should we need them
    public byte[] diversifyKey(String tokenName,
            String newTokenName,
            String oldMasterKeyName,
            String newMasterKeyName,
            byte[] oldKeyInfo,
            byte[] newKeyInfo,
            byte nistSP800_108KdfOnKeyVersion,
            boolean nistSP800_108KdfUseCuidAsKdd,
            byte[] CUIDValue,
            byte[] KDD,
            byte[] kekKeyArray, byte[] encKeyArray, byte[] macKeyArray,
            String useSoftToken, String keySet, byte protocol, GPParams params, 
            GPParams oldParams) throws EBaseException { // ** G&D 256 Key Rollover Support ** add oldParams parameter

        String method = "SecureChannelProtocol.diversifyKey:";

        logger.debug(method + " Entering ... newTokenName: " + newTokenName + " protocol: " + protocol);
        logger.debug(method + " oldMasterKeyName: " + oldMasterKeyName);
        logger.debug(method + " newMasterKeyName: " + newMasterKeyName);
        
        //SecureChannelProtocol.debugByteArray(encKeyArray, " Developer enc key array: ");
        //SecureChannelProtocol.debugByteArray(macKeyArray, " Developer mac key array: ");
        //SecureChannelProtocol.debugByteArray(kekKeyArray, " Developer kek key array: ");

        SymmetricKey masterKey = null;
        SymmetricKey oldMasterKey = null;

        byte[] KDCenc = null;
        byte[] KDCmac = null;
        byte[] KDCkek = null;

        SymmetricKey old_mac_sym_key = null;
        SymmetricKey old_enc_sym_key = null;
        SymmetricKey old_kek_sym_key = null;

        SymmetricKey encKey = null;
        SymmetricKey macKey = null;
        SymmetricKey kekKey = null;

        // The final answer
        byte[] output = null;

        if (oldMasterKeyName == null || oldKeyInfo == null || newKeyInfo == null
                || keySet == null || params == null) {
            throw new EBaseException(method + "Invalid input!");
        }

        if (oldKeyInfo.length < 2 || newKeyInfo.length < 2) {
            throw new EBaseException(method + " Invalid input length for keyinfo versions.");
        }

        String fullNewMasterKeyName = getFullMasterKeyName(newMasterKeyName);
        String fullOldMasterKeyName = getFullMasterKeyName(oldMasterKeyName);

        logger.debug(method + " fullOldMasterKeyName: " + fullOldMasterKeyName);
        logger.debug(method + " fullNewMasterKeyName: " + fullNewMasterKeyName);

        CryptoManager cm = null;
        CryptoToken token = null;
        CryptoToken newToken = null;
        try {
            cm = CryptoManager.getInstance();
            token = returnTokenByName(tokenName, cm);
            if (newTokenName != null) {
                newToken = returnTokenByName(newTokenName, cm);
            }
        } catch (NotInitializedException e) {
            logger.debug(method + " " + e);
            throw new EBaseException(e);

        } catch (NoSuchTokenException e) {
            logger.debug(method + " " + e);
            throw new EBaseException(e);
        }

        try {
            if (newToken != null) {
                masterKey = getSymKeyByName(newToken, fullNewMasterKeyName);
            }
            oldMasterKey = getSymKeyByName(token, fullOldMasterKeyName);
        } catch (EBaseException e) {
            masterKey = null;
            logger.debug(method + " Master key is null, possibly ok in moving from keyset 2 to 1");

            if (oldMasterKey == null) {
                throw new EBaseException(method + " Can't retrieve old master key!");
            }
        }

        //SecureChannelProtocol.debugByteArray(oldKeyInfo, " oldKeyInfo: ");
        //SecureChannelProtocol.debugByteArray(newKeyInfo, " newKeyInfo: ");

        byte oldKeyVersion = oldKeyInfo[0];
        byte newKeyVersion = newKeyInfo[0];

        byte[] context = null;

        if (nistSP800_108KdfUseCuidAsKdd == true) {
            context = CUIDValue;
        } else {
            context = KDD;
        }

        if (context == null) {
            throw new EBaseException(method + "Invalid token id information included!");
        }

        // We may need either or both of these

        StandardKDF standardKDF = new StandardKDF(this);
        NistSP800_108KDF nistKDF = new NistSP800_108KDF(this);

        KDCenc = KDF.getDiversificationData_VISA2(KDD, SecureChannelProtocol.encType);
        KDCmac = KDF.getDiversificationData_VISA2(KDD, SecureChannelProtocol.macType);
        KDCkek = KDF.getDiversificationData_VISA2(KDD, SecureChannelProtocol.kekType);

        //This routine does not even support protocol 2, bail if asked to do so.
        if (protocol == PROTOCOL_TWO) {
            throw new EBaseException(method + " SCP 02 not yet supported here.");
        }

        String transportKeyName = SecureChannelProtocol.getSharedSecretKeyName(null);

        if (checkForDeveloperKeySet(oldMasterKeyName) == true) {
            //Starting with the deve key set, do nothing in this clause
            logger.debug(method + " Developer key set case:  protocol: " + protocol);
        } else {
            //Case where down grading back to the deve key set, or to another master key set
            // This clause does nothing but calculate the kek key of the
            // Current keyset, which will be used to wrap the new keys, to be calculated
            logger.debug(method + " Not Developer key set case: ");

            if (protocol == PROTOCOL_ONE ) {
                if (NistSP800_108KDF.useThisKDF(nistSP800_108KdfOnKeyVersion, oldKeyVersion)) {
                    logger.debug(method + " NistSP800_108KDF code: Using NIST SP800-108 KDF.");

                    Map<String, SymmetricKey> keys = null;
                    try {
                        keys = nistKDF.computeCardKeys(oldMasterKey, context, token);
                    } catch (EBaseException e) {
                        logger.debug(method + "Can't compute card keys! " + e);
                        throw e;
                    }

                    old_enc_sym_key = keys.get(SecureChannelProtocol.encType);
                    old_mac_sym_key = keys.get(SecureChannelProtocol.macType);
                    old_kek_sym_key = keys.get(SecureChannelProtocol.kekType);

                    if (old_enc_sym_key == null || old_mac_sym_key == null || old_kek_sym_key == null) {
                        throw new EBaseException(method + " Can't derive session keys with Nist KDF.");
                    }

                } else {
                    logger.debug(method + " ComputeSessionKey NistSP800_108KDF code: Using original KDF.");

                    old_kek_sym_key = standardKDF.computeCardKey(oldMasterKey, KDCkek, token, PROTOCOL_ONE);
                }

            } else { // Protocol 3
                // ** G&D 256 Key Rollover Support **
                // use the oldParams to compute the old_kek_sym_key
                old_kek_sym_key = this.computeSessionKey_SCP03(tokenName, oldMasterKeyName,
                      oldKeyInfo, SecureChannelProtocol.kekType, kekKeyArray, keySet,
                      CUIDValue, KDD, null, null, transportKeyName, oldParams);
                
                logger.debug(method + " Moving back to the developer key set case, protocol 3");
            }
        }

        // Now compute the new keys to be written to the token.
        /* special case #01#01 */
        if (fullNewMasterKeyName != null
                && (fullNewMasterKeyName.equals("#01#01") || fullNewMasterKeyName.contains("#01#03")))
        {
            //This is the case where we revert to the original developer key set or key set 1
            if (protocol == PROTOCOL_ONE) {
                logger.debug(method + " Special case returning to the dev key set (1) for DiversifyKey, protocol 1!");
                encKey = returnDeveloperSymKey(newToken, SecureChannelProtocol.encType, keySet, null,"DES3");
                macKey = returnDeveloperSymKey(newToken, SecureChannelProtocol.macType, keySet, null,"DES3");
                kekKey = returnDeveloperSymKey(newToken, SecureChannelProtocol.kekType, keySet, null,"DES3");
            } else if (protocol == PROTOCOL_THREE) {
                logger.debug(method + " Special case or returning to the dev key set (or ver 1) for DiversifyKey, protocol 3!");
                encKey = this.computeSessionKey_SCP03(newTokenName, newMasterKeyName, newKeyInfo,
                        SecureChannelProtocol.encType, kekKeyArray,
                        keySet, CUIDValue, KDD, null, null, transportKeyName, params);
                macKey = this.computeSessionKey_SCP03(newTokenName, newMasterKeyName, newKeyInfo,
                        SecureChannelProtocol.macType, kekKeyArray,
                        keySet, CUIDValue, KDD, null, null, transportKeyName, params);
                kekKey = this.computeSessionKey_SCP03(newTokenName, newMasterKeyName, newKeyInfo,
                        SecureChannelProtocol.kekType, kekKeyArray,
                        keySet, CUIDValue, KDD, null, null, transportKeyName, params);
            }
        } else {
            //Compute new card keys for upgraded key set
            logger.debug(method + " Compute card key on token case ! For new key version.");

            if (protocol == PROTOCOL_ONE) {
                if (NistSP800_108KDF.useThisKDF(nistSP800_108KdfOnKeyVersion, newKeyVersion)) {
                    logger.debug(method + " NistSP800_108KDF code: Using NIST SP800-108 KDF. For new key version.");

                    Map<String, SymmetricKey> keys = null;
                    try {
                        keys = nistKDF.computeCardKeys(masterKey, context, newToken);
                    } catch (EBaseException e) {
                        logger.debug(method + "Can't compute card keys! For new key version. " + e);
                        throw e;
                    }

                    encKey = keys.get(SecureChannelProtocol.encType);
                    macKey = keys.get(SecureChannelProtocol.macType);
                    kekKey = keys.get(SecureChannelProtocol.kekType);

                } else {
                    logger.debug(method
                            + " ComputeSessionKey NistSP800_108KDF code: Using original KDF. For new key version.");

                    encKey = standardKDF.computeCardKeyOnToken(masterKey, KDCenc, protocol);
                    macKey = standardKDF.computeCardKeyOnToken(masterKey, KDCmac, protocol);
                    kekKey = standardKDF.computeCardKeyOnToken(masterKey, KDCkek, protocol);
                }

            } else { // protocol 3

                logger.debug(method + " Generating new card keys to upgrade to, protocol 3.");
                logger.debug("tokenName: " + tokenName + " newTokenName: " + newTokenName);
                encKey = this.computeSessionKey_SCP03(newTokenName, newMasterKeyName, oldKeyInfo,
                        SecureChannelProtocol.encType, kekKeyArray,
                        keySet, CUIDValue, KDD, null, null, transportKeyName, params);
                macKey = this.computeSessionKey_SCP03(newTokenName, newMasterKeyName, oldKeyInfo,
                        SecureChannelProtocol.macType, kekKeyArray,
                        keySet, CUIDValue, KDD, null, null, transportKeyName, params);
                kekKey = this.computeSessionKey_SCP03(newTokenName, newMasterKeyName, oldKeyInfo,
                        SecureChannelProtocol.kekType, kekKeyArray,
                        keySet, CUIDValue, KDD, null, null, transportKeyName, params);

                // Generate an old kek key to do the encrypting of the new static keys

                // ** G&D 256 Key Rollover Support **
                // use the oldParams to compute the old_kek_sym_key
                old_kek_sym_key = this.computeSessionKey_SCP03(tokenName, oldMasterKeyName, oldKeyInfo,
                        SecureChannelProtocol.kekType, kekKeyArray,
                        keySet, CUIDValue, KDD, null, null, transportKeyName, oldParams);
            }

            if (encKey == null || macKey == null || kekKey == null) {
                throw new EBaseException(method
                        + " Can't derive session keys with selected KDF. For new key version.");
            }

        }

        boolean showKeysForDebug = checkAllowDebugKeyRollover();

        if (showKeysForDebug == true) {
            byte[] enc = debugAESKeyToBytes(token,encKey);
            byte[] mac = debugAESKeyToBytes(token,macKey);
            byte[] kek = debugAESKeyToBytes(token,kekKey); 

            SecureChannelProtocol.debugByteArray(enc, "DiversifyKey: new encKey: ");
            SecureChannelProtocol.debugByteArray(mac, "DiversifyKey: new macKey:");
            SecureChannelProtocol.debugByteArray(kek, "DiversifyKey: new kekKey");
        }

        if (old_kek_sym_key != null) {

            logger.debug(method + " old kek sym key is not null");
            output = createKeySetDataWithSymKeys(newKeyVersion, (byte[]) null,
                    old_kek_sym_key,
                    encKey,
                    macKey,
                    kekKey,
                    protocol, tokenName);

        } else {

            logger.debug(method + " old kek sym key is null");

            String devKeyType = null;

            if(protocol == PROTOCOL_THREE) {
                devKeyType = params.getDevKeyType();
            } else {
                devKeyType = "DES3";
            }

            old_kek_sym_key = returnDeveloperSymKey(token, SecureChannelProtocol.kekType, keySet, kekKeyArray, devKeyType);

            output = createKeySetDataWithSymKeys(newKeyVersion, (byte[]) null,
                    old_kek_sym_key,
                    encKey,
                    macKey,
                    kekKey,
                    protocol, tokenName);

        }

        return output;
    }

    //Create the actual blob of new keys to be written to the token
    // Suports prot1 and prot3
    private byte[] createKeySetDataWithSymKeys(byte newKeyVersion, byte[] old_kek_key_array,
            SymmetricKey old_kek_sym_key,
            SymmetricKey encKey, SymmetricKey macKey, SymmetricKey kekKey, byte protocol, String tokenName)
            throws EBaseException {

        SymmetricKey wrappingKey = null;

        String method = "SecureChannelProtocol.createKeySetDataWithSymKeys:";

        byte alg = (byte) 0x81;

        byte[] output = null;

        if (encKey == null || macKey == null || kekKey == null || tokenName == null) {
            throw new EBaseException(method + " Invalid input data!");
        }

        CryptoManager cm = null;
        CryptoToken token = null;
        try {
            cm = CryptoManager.getInstance();
            token = returnTokenByName(tokenName, cm);
        } catch (NotInitializedException e) {
            logger.debug(method + " " + e);
            throw new EBaseException(e);

        } catch (NoSuchTokenException e) {
            logger.debug(method + " " + e);
            throw new EBaseException(e);
        }

        SymmetricKey encKey16 = null;
        SymmetricKey macKey16 = null;
        SymmetricKey kekKey16 = null;

        byte[] encrypted_enc_key = null;
        byte[] encrypted_mac_key = null;
        byte[] encrypted_kek_key = null;

        byte[] keycheck_enc_key = null;
        byte[] keycheck_mac_key = null;
        byte[] keycheck_kek_key = null;
        
        if (protocol == PROTOCOL_ONE) {
            if (old_kek_sym_key == null) {
                logger.debug(method + " Using old kek key array.");
                wrappingKey = unwrapSymKeyOnToken(token, old_kek_key_array, false);
            } else {
                logger.debug(method + " Using input old key key sym key.");
                wrappingKey = old_kek_sym_key;
            }

            logger.debug(method + "Wrapping key: length: " + wrappingKey.getLength());

            alg = (byte) 0x81;
            encKey16 = extractDes2FromDes3(encKey, tokenName);
            macKey16 = extractDes2FromDes3(macKey, tokenName);
            kekKey16 = extractDes2FromDes3(kekKey, tokenName);

            encrypted_enc_key = this.wrapSessionKey(tokenName, encKey16, wrappingKey);
            encrypted_mac_key = this.wrapSessionKey(tokenName, macKey16, wrappingKey);
            encrypted_kek_key = this.wrapSessionKey(tokenName, kekKey16, wrappingKey);

            keycheck_enc_key = this.computeKeyCheck(encKey, tokenName);
            keycheck_mac_key = this.computeKeyCheck(macKey, tokenName);
            keycheck_kek_key = this.computeKeyCheck(kekKey, tokenName);

        } else if (protocol == PROTOCOL_TWO) {
            throw new EBaseException(method + " SCP 02 not yet implemented!");
        } else if (protocol == PROTOCOL_THREE) {
            logger.debug(method + " Attempting SCP03");

            if (old_kek_sym_key == null) {
                logger.debug(method + " SCP03: Using old kek key array.");
                wrappingKey = unwrapAESSymKeyOnToken(token, old_kek_key_array, false);
            } else {
                logger.debug(method + "SCP03: Using input old key key sym key.");
                wrappingKey = old_kek_sym_key;
            }

            alg = (byte) 0x88;

            encrypted_enc_key = this.wrapSessionKey(tokenName, encKey, wrappingKey);
            encrypted_mac_key = this.wrapSessionKey(tokenName, macKey, wrappingKey);
            encrypted_kek_key = this.wrapSessionKey(tokenName, kekKey, wrappingKey);

            try {
                keycheck_enc_key = this.computeKeyCheck_SCP03(encKey, encKey.getOwningToken().getName());
                keycheck_mac_key = this.computeKeyCheck_SCP03(macKey, macKey.getOwningToken().getName());
                keycheck_kek_key = this.computeKeyCheck_SCP03(kekKey, kekKey.getOwningToken().getName());
            } catch (TokenException e) {
                throw new EBaseException(method + e);
            }


        } else {
            throw new EBaseException(method + " Invalid SCP version requested!");
        }

        // Compose the final key set data byte array

        byte[] b1 = null;
        byte[] b2 = null;

        if (protocol == PROTOCOL_THREE) 
        {
            //Will be different if the key is bigger than AES 128
            // Support 128 for now
            // Added support for AES 256 keys
            //logger.debug(method + " encrypted_enc_key length = " + encrypted_enc_key.length);
            if (encrypted_enc_key.length == DEF_AES_256_KEYLENGTH)
            {
                b1 = new byte[] { alg, 0x21, (byte) encrypted_enc_key.length };
            }
            else
            {
                b1 = new byte[] { alg, 0x11, (byte) encrypted_enc_key.length };
            }
        } else {
            b1 = new byte[] { alg, 0x10 };
        }

        b2 = new byte[] { 0x3 };

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        try {
            outputStream.write(newKeyVersion);
            outputStream.write(b1);
            outputStream.write(encrypted_enc_key);
            outputStream.write(b2);
            outputStream.write(keycheck_enc_key);

            outputStream.write(b1);
            outputStream.write(encrypted_mac_key);
            outputStream.write(b2);
            outputStream.write(keycheck_mac_key);

            outputStream.write(b1);
            outputStream.write(encrypted_kek_key);
            outputStream.write(b2);
            outputStream.write(keycheck_kek_key);

            output = outputStream.toByteArray();

        } catch (IOException e) {
            throw new EBaseException(method + " Can't compose final output byte array!");
        }

        //SecureChannelProtocol.debugByteArray(output, " Final output to createKeySetData: ");
        logger.debug(method + " returning output");

        return output;
    }

    private String getFullMasterKeyName(String masterKeyName)
    {
        if (masterKeyName == null)
        {
            return null;
        }

        String fullMasterKeyName = null;

        fullMasterKeyName = "";

        if (masterKeyName.length() > 0) {
            fullMasterKeyName += masterKeyName;
        }

        return fullMasterKeyName;
    }

    private boolean checkForDeveloperKeySet(String keyInfo)
    {
        if (keyInfo == null)
            return true;

        //SCP01 or SCP02
        if (keyInfo.equals("#01#01") || keyInfo.equals("#FF#01"))
            return true;

        //SCP02
        if (keyInfo.equals("#01#02") || keyInfo.equals("#FF#02"))
            return true;

        //SCP03
        if (keyInfo.contains("#01#03") || keyInfo.contains("#FF#03"))
            return true;

        return false;
    }

    public static void setDefaultPrefix(String masterkeyPrefix) {
        if (SecureChannelProtocol.masterKeyPrefix == null) {
            SecureChannelProtocol.masterKeyPrefix = masterkeyPrefix;
        }
    }


    //SCP03 wrap a session key with AES kek key.
    public byte[] encryptData_SCP03(String selectedToken, String keyNickName, byte[] data, byte[] keyInfo,
            byte nistSP800_108KdfOnKeyVersion, boolean nistSP800_108KdfUseCuidAsKdd, byte[] xCUID, byte[] xKDD,
            byte[] kekKeyArray, String useSoftToken_s, String keySet, GPParams params) throws EBaseException {

        String method = "SecureChannelProtocol.encryptData_SCP03:";

        logger.debug(method + " Entering ....");

        String transportKeyName = SecureChannelProtocol.getSharedSecretKeyName(null);

        if (keyInfo == null || keySet == null || (keyInfo == null || keyInfo.length < 2) || params == null) {
            throw new EBaseException(method + "Invalid input!");
        }

        if (xCUID == null || xCUID.length <= 0) {
            throw new EBaseException(method + "CUID invalid size!");
        }

        if (xKDD == null || xKDD.length != NistSP800_108KDF.KDD_SIZE_BYTES) {
            throw new EBaseException(method + "KDD invalid size!");
        }

        SymmetricKey kekKey = computeSessionKey_SCP03(selectedToken, keyNickName,
                keyInfo, kekType, kekKeyArray, keySet, xCUID, xKDD,
                null, null, transportKeyName, params);

        byte[] output = null;
        output = computeAES_CBCEncryption(kekKey, selectedToken, data, null);

        //debugByteArray(output, method + " encryptData: Output: ");

        return output;
    }

    public byte[] encryptData(String selectedToken, String keyNickName, byte[] data, byte[] keyInfo,
            byte nistSP800_108KdfOnKeyVersion, boolean nistSP800_108KdfUseCuidAsKdd, byte[] xCUID, byte[] xKDD,
            byte[] kekKeyArray, String useSoftToken_s, String keySet) throws EBaseException {

        String method = "SecureChannelProtocol.encryptData:";

        logger.debug(method + " Entering ....");

        String transportKeyName = SecureChannelProtocol.getSharedSecretKeyName(null);

        if (keyInfo == null || keySet == null || (keyInfo == null || keyInfo.length < 2)) {
            throw new EBaseException(method + "Invalid input!");
        }

        if (xCUID == null || xCUID.length <= 0) {
            throw new EBaseException(method + "CUID invalid size!");
        }

        if (xKDD == null || xKDD.length != NistSP800_108KDF.KDD_SIZE_BYTES) {
            throw new EBaseException(method + "KDD invalid size!");
        }

        SymmetricKey kekKey = computeSessionKey_SCP01(kekType, selectedToken, keyNickName, null,
                null, keyInfo, nistSP800_108KdfOnKeyVersion, nistSP800_108KdfUseCuidAsKdd, xCUID, xKDD,
                kekKeyArray, useSoftToken_s, keySet, transportKeyName);

        byte[] output = computeDes3EcbEncryption(kekKey, selectedToken, data);

        //debugByteArray(output, " encryptData: Output: ");

        return output;
    }

    public SymmetricKey generateAESSymKey(String selectedToken, int keySize) throws EBaseException {
        String method = "SecureChannelProtocol.generateAESSymKey: ";

        logger.debug(method + " entering , token: " + selectedToken + " size: " + keySize);
        SymmetricKey symKey = null;

        if (selectedToken == null) {
            throw new EBaseException(method + " Invalid input data!");
        }

        try {
            CryptoManager cm = this.getCryptoManger();
            CryptoToken token = returnTokenByName(selectedToken, cm);
            symKey =  CryptoUtil.generateKey(token, KeyGenAlgorithm.AES, keySize,
                session_key_usages,true);
        } catch (Exception e) {
            logger.debug(method + " " +  e);
            throw new EBaseException(e);
        }

        return symKey;
    }
    private static byte[] debugAESKeyToBytes(CryptoToken token,SymmetricKey aesKey) {
        KeyGenerator kg;
        SymmetricKey sessionKey;
        byte[] result = null;

        if(token == null || aesKey == null) {
            return result;
        }

        try {
            kg = token.getKeyGenerator(KeyGenAlgorithm.AES);

            SymmetricKey.Usage usages[] = new SymmetricKey.Usage[4];
            usages[0] = SymmetricKey.Usage.WRAP;
            usages[1] = SymmetricKey.Usage.UNWRAP;
            usages[2] = SymmetricKey.Usage.ENCRYPT;
            usages[3] = SymmetricKey.Usage.DECRYPT;

            kg.setKeyUsages(usages);
            kg.temporaryKeys(true);
            // Handle 128 and 256 initialization sizes
            kg.initialize(256);
            SymmetricKey tempKey = kg.generate();

            // Now wrap and unwrap with AES CBC PAD

            KeyWrapper keyWrap = token.getKeyWrapper(KeyWrapAlgorithm.AES_CBC_PAD);
            int ivLen = KeyWrapAlgorithm.AES_CBC_PAD.getBlockSize();
            byte[] iv = new byte[ivLen];

            IVParameterSpec ivsp = new IVParameterSpec(iv);
            keyWrap.initWrap(tempKey, ivsp);
            byte [] wrapped = keyWrap.wrap(aesKey);

            Cipher decryptor = token.getCipherContext(EncryptionAlgorithm.AES_256_CBC_PAD);
            decryptor.initDecrypt(tempKey,ivsp);
            result = decryptor.doFinal(wrapped);

         } catch (Exception e) {
             return result;
         }

         return result;
     }
     
      private boolean checkAllowDebugKeyRollover() {
        boolean allow = false;

        String method = "SecureChannelProtocol.checkAllowDebugKeyRollover: ";

        TKSEngine engine = TKSEngine.getInstance();
        TKSEngineConfig cs = engine.getConfig();
        String allowDebugKeyRollover = "tks.debugKeyRollover";

        //logger.debug(method + " trying config: " + allowDebugKeyRollover);

        try {
            allow = cs.getBoolean("tks.useNewSharedSecretNames", false);
        } catch (EBaseException e) {
            allow = false;
        }

        //logger.debug(method + "returning allow: " + allow);
        return allow;
    }

}

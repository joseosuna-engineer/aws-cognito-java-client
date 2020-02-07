
package com.prottonne.cognito.util;

import com.prottonne.cognito.exception.CognitoException;
import com.amazonaws.util.StringUtils;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Component;

/**
 * Internal class for doing the Hkdf calculations.
 */
@Component
public class Hkdf {

    private static final int MAX_KEY_SIZE = 255;
    private final byte[] emptyArray = new byte[0];
    private final String algorithm = "HmacSHA256";
    private SecretKey prk;

    public Hkdf() {
        super();
    }

    /**
     * @param ikm REQUIRED: The input key material.
     */
    public void init(byte[] ikm) {
        this.init(ikm, (byte[]) null);
    }

    /**
     * @param ikm REQUIRED: The input key material.
     * @param salt REQUIRED: Random bytes for salt.
     */
    public void init(byte[] ikm, byte[] salt) {

        try {
            byte[] realSalt = getRealSalt(salt);
            byte[] rawKeyMaterial;

            final Mac e = Mac.getInstance(this.algorithm);
            if (realSalt.length == 0) {
                realSalt = new byte[e.getMacLength()];
                Arrays.fill(realSalt, (byte) 0);
            }

            e.init(new SecretKeySpec(realSalt, this.algorithm));
            rawKeyMaterial = e.doFinal(ikm);
            final SecretKeySpec key = new SecretKeySpec(rawKeyMaterial,
                    this.algorithm);
            Arrays.fill(rawKeyMaterial, (byte) 0);
            this.unsafeInitWithoutKeyExtraction(key);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new CognitoException(e);
        }

    }

    /**
     * @param rawKey REQUIRED: Current secret key.
     * @throws InvalidKeyException
     */
    private void unsafeInitWithoutKeyExtraction(SecretKey rawKey) {
        if (rawKey.getAlgorithm().equals(this.algorithm)) {
            this.prk = rawKey;
        } else {
            throw new CognitoException();
        }
    }

    public byte[] deriveKey(String info, int length) {

        byte[] toInfo = getToInfo(info);

        try {
            return this.deriveKey(toInfo, length);
        } catch (NoSuchAlgorithmException ex) {
            throw new CognitoException(ex);
        }
    }

    /**
     * @param info REQUIRED
     * @param length REQUIRED
     * @return converted bytes.
     */
    private byte[] deriveKey(byte[] info, int length)
            throws NoSuchAlgorithmException {
        final byte[] result = new byte[length];

        this.deriveKey(info, length, result);
        return result;

    }

    private void deriveKey(byte[] info, int length, byte[] output)
            throws NoSuchAlgorithmException {
        this.assertInitialized();

        final Mac mac = this.createMac();

        if (length > MAX_KEY_SIZE * mac.getMacLength()) {
            throw new IllegalArgumentException(
                    "Requested keys may not be longer than 255 "
                    + "times the underlying HMAC length.");
        }

        byte[] t = emptyArray;

        int loc = 0;

        for (byte i = 1; loc < length; ++i) {
            mac.update(t);
            mac.update(info);
            mac.update(i);
            t = mac.doFinal();

            for (int x = 0; x < t.length && loc < length; ++loc, x++) {
                output[loc] = t[x];
            }
        }

    }

    /**
     * @return the generates message authentication code.
     */
    private Mac createMac() throws NoSuchAlgorithmException {

        final Mac ex = Mac.getInstance(this.algorithm);
        try {
            ex.init(this.prk);
        } catch (InvalidKeyException ike) {
            throw new CognitoException(ike);
        }
        return ex;

    }

    /**
     * Checks for a valid pseudo-random key.
     */
    private void assertInitialized() {
        if (this.prk == null) {
            throw new IllegalStateException("Hkdf has not been"
                    + " initialized");
        }
    }

    private byte[] getRealSalt(byte[] salt) {
        if (salt == null) {
            return emptyArray.clone();
        } else {
            return (byte[]) salt.clone();
        }
    }

    private byte[] getToInfo(String info) {
        if (null == info) {
            return emptyArray.clone();
        } else {
            return info.getBytes(StringUtils.UTF8);
        }
    }

}

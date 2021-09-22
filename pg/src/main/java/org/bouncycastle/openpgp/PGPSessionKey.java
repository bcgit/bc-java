package org.bouncycastle.openpgp;

import org.bouncycastle.util.encoders.Hex;

public class PGPSessionKey {

    private final int algorithm;
    private final byte[] sessionKey;

    public PGPSessionKey(int algorithm, byte[] sessionKey) {
        this.algorithm = algorithm;
        this.sessionKey = sessionKey;
    }

    public static PGPSessionKey fromPBESessionData(byte[] sessionData) {
        int algorithm = sessionData[0] & 0xff;
        byte[] key = new byte[sessionData.length - 1];
        System.arraycopy(sessionData, 1, key, 0, key.length);
        return new PGPSessionKey(algorithm, key);
    }

    public static PGPSessionKey fromPublicKeySessionData(byte[] sessionData) {
        int algorithm = sessionData[0] & 0xff;
        byte[] key = new byte[sessionData.length - 3];
        System.arraycopy(sessionData, 1, key, 0, key.length);
        return new PGPSessionKey(algorithm, key);
    }

    public int getAlgorithm() {
        return algorithm;
    }

    public byte[] getKey() {
        byte[] copy = new byte[sessionKey.length];
        System.arraycopy(sessionKey, 0, copy, 0, sessionKey.length);
        return copy;
    }

    @Override
    public String toString() {
        return algorithm + ":" + Hex.toHexString(sessionKey).toUpperCase();
    }
}

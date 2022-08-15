package org.bouncycastle.pqc.crypto.crystals.dilithium;

import org.bouncycastle.crypto.digests.SHAKEDigest;

class Symmetric
{

    static final int Shake128Rate = 168;
    static final int Shake256Rate = 136;
    static final int Sha3Rate256 = 136;
    static final int Sha3Rate512 = 72;

    static void shakeStreamInit(SHAKEDigest digest, byte[] seed, short nonce)
    {
        // byte[] temp = new byte[seed.length + 2];
        // System.arraycopy(seed, 0, temp, 0, seed.length);

        // temp[seed.length] = (byte) nonce;
        // temp[seed.length] = (byte) (nonce >> 8);
        byte[] temp = new byte[2];
        // System.arraycopy(seed, 0, temp, 0, seed.length);
        temp[0] = (byte)nonce;
        temp[1] = (byte)(nonce >> 8);

        digest.update(seed, 0, seed.length);
        digest.update(temp, 0, temp.length);
    }
}

package org.bouncycastle.pqc.crypto.sdith;

import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;

/**
 * Domain-separated SHA3 / SHAKE wrappers for SDitH, matching the reference
 * hash-sha3.c and rng.c. Each hash absorbs a single one-byte prefix
 * (HASH_COM=0, HASH_H1=1, HASH_H2=2, HASH_TREE=3) before any payload.
 * <p>
 * For category 1 the hash is SHA3-256 and the XOF is SHAKE128 — this matches
 * the cat1 settings used by the shipped KAT vectors. The class wires those in
 * as static factories; the digest sizes are exposed via the SDitHParameters
 * the engine carries.
 */
final class SDitHHash
{
    static final byte HASH_COM = 0;
    static final byte HASH_H1 = 1;
    static final byte HASH_H2 = 2;
    static final byte HASH_TREE = 3;

    private final SHA3Digest digest;

    private SDitHHash(int bitLength, byte prefix)
    {
        this.digest = new SHA3Digest(bitLength);
        this.digest.update(prefix);
    }

    static SDitHHash sha3(int bitLength, byte prefix)
    {
        return new SDitHHash(bitLength, prefix);
    }

    static SHAKEDigest shake(int bitLength)
    {
        return new SHAKEDigest(bitLength);
    }

    void update(byte b)
    {
        digest.update(b);
    }

    void update(byte[] in, int off, int len)
    {
        digest.update(in, off, len);
    }

    void update(byte[] in)
    {
        digest.update(in, 0, in.length);
    }

    int getDigestSize()
    {
        return digest.getDigestSize();
    }

    void doFinal(byte[] out, int off)
    {
        digest.doFinal(out, off);
    }

    static void oneShot(int bitLength, byte prefix, byte[] data, int dataOff, int dataLen, byte[] out, int outOff)
    {
        SDitHHash h = new SDitHHash(bitLength, prefix);
        h.update(data, dataOff, dataLen);
        h.doFinal(out, outOff);
    }

    static void shakeOneShot(int shakeBits, byte[] seed, int seedOff, int seedLen, byte[] out, int outOff, int outLen)
    {
        SHAKEDigest xof = new SHAKEDigest(shakeBits);
        xof.update(seed, seedOff, seedLen);
        xof.doFinal(out, outOff, outLen);
    }
}

package org.bouncycastle.pqc.crypto.newhope;

import java.security.SecureRandom;

import org.bouncycastle.crypto.digests.SHA3Digest;

/**
 * This implementation is based heavily on the C reference implementation from https://cryptojedi.org/crypto/index.shtml.
 */
class NewHope
{
    private static final boolean STATISTICAL_TEST = false;

    public static final int AGREEMENT_SIZE = 32;
    public static final int POLY_SIZE = Params.N;
    public static final int SEND_SIZE = POLY_SIZE * 2;

    public static void keygen(SecureRandom rand, byte[] send, short[] sk)
    {
        byte[] seed = new byte[Params.SEED_BYTES];
        rand.nextBytes(seed);

        short[] a = new short[Params.N];
        generateA(a, seed);

        byte[] noiseSeed = new byte[32];
        rand.nextBytes(noiseSeed);

        Poly.getNoise(sk, noiseSeed, (byte)0);
        Poly.toNTT(sk);

        short[] e = new short[Params.N];
        Poly.getNoise(e, noiseSeed, (byte)1);
        Poly.toNTT(e);

        short[] r = new short[Params.N];
        Poly.pointWise(a, sk, r);

        short[] pk = new short[Params.N];
        Poly.add(r, e, pk);

        encodeA(send, pk, seed);
    }

    public static void sharedB(SecureRandom rand, byte[] sharedKey, byte[] send, byte[] received)
    {
        short[] pkA = new short[Params.N];
        byte[] seed = new byte[Params.SEED_BYTES];
        decodeA(pkA, seed, received);

        short[] a = new short[Params.N];
        generateA(a, seed);

        byte[] noiseSeed = new byte[32];
        rand.nextBytes(noiseSeed);

        short[] sp = new short[Params.N];
        Poly.getNoise(sp, noiseSeed, (byte)0);
        Poly.toNTT(sp);

        short[] ep = new short[Params.N];
        Poly.getNoise(ep, noiseSeed, (byte)1);
        Poly.toNTT(ep);

        short[] bp = new short[Params.N];
        Poly.pointWise(a, sp, bp);
        Poly.add(bp, ep, bp);

        short[] v = new short[Params.N];
        Poly.pointWise(pkA, sp, v);
        Poly.bitReverse(v);
        Poly.fromNTT(v);

        short[] epp = new short[Params.N];
        Poly.getNoise(epp, noiseSeed, (byte)2);
        Poly.add(v, epp, v);

        short[] c = new short[Params.N];
        ErrorCorrection.helpRec(c, v, noiseSeed, (byte)3);

        encodeB(send, bp, c);

        ErrorCorrection.rec(sharedKey, v, c);

        if (!STATISTICAL_TEST)
        {
            sha3(sharedKey);
        }
    }

    public static void sharedA(byte[] sharedKey, short[] sk, byte[] received)
    {
        short[] bp = new short[Params.N];
        short[] c = new short[Params.N];
        decodeB(bp, c, received);

        short[] v = new short[Params.N];
        Poly.pointWise(sk, bp, v);
        Poly.bitReverse(v);
        Poly.fromNTT(v);

        ErrorCorrection.rec(sharedKey, v, c);

        if (!STATISTICAL_TEST)
        {
            sha3(sharedKey);
        }
    }

    static void decodeA(short[] pk, byte[] seed, byte[] r)
    {
        Poly.fromBytes(pk, r);

        for (int i = 0; i < 32; ++i)
        {
            int seedVal = 0;
            for (int j = 0; j < 4; ++j)
            {
                int rVal = r[2 * (4 * i + j) + 1] & 0xFF;
                seedVal |= (rVal >>> 6) << (2 * j);
            }
            seed[i] = (byte)seedVal;
        }
    }

    static void decodeB(short[] b, short[] c, byte[] r)
    {
        Poly.fromBytes(b, r);

        for (int i = 0; i < 1024; ++i)
        {
            int rVal = r[2 * i + 1] & 0xFF;
            c[i] = (short)(rVal >>> 6);
        }
    }

    static void encodeA(byte[] r, short[] pk, byte[] seed)
    {
        Poly.toBytes(r, pk);
        
        for (int i = 0; i < Params.SEED_BYTES; ++i)
        {
            int seedVal = seed[i] & 0xFF;
            for (int j = 0; j < 4; ++j)
            {
                r[2 * (4 * i + j) + 1] |= seedVal << 6;
                seedVal >>>= 2;
            }
        }
    }

    static void encodeB(byte[] r, short[] b, short[] c)
    {
        Poly.toBytes(r, b);
        
        for (int i = 0; i < 1024; ++i)
        {
            r[2 * i + 1] |= c[i] << 6;
        }
    }

    static void generateA(short[] a, byte[] seed)
    {
        Poly.uniform(a, seed);
    }
    
    static void sha3(byte[] sharedKey)
    {
        SHA3Digest d = new SHA3Digest(256);
        d.update(sharedKey, 0, 32);
        d.doFinal(sharedKey, 0);
    }
}

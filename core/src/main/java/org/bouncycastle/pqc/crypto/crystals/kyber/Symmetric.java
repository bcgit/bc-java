package org.bouncycastle.pqc.crypto.crystals.kyber;

import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;

abstract class Symmetric
{

    final int xofBlockBytes;

    abstract void hash_h(byte[] out, byte[] in, int outOffset);
    abstract void hash_g(byte[] out, byte[] in);
    abstract void xofAbsorb(byte[] seed, byte x, byte y);
    abstract void xofSqueezeBlocks(byte[] out, int outOffset, int outLen);
    abstract void prf(byte[] out, byte[] key, byte nonce);
    abstract void kdf(byte[] out, byte[] in);

    Symmetric(int blockBytes)
    {
        this.xofBlockBytes = blockBytes;
    }


    static class ShakeSymmetric
        extends Symmetric
    {
        private final SHAKEDigest xof;
        private final SHAKEDigest prf;
        private final SHA3Digest sha3Digest512;
        private final SHA3Digest sha3Digest256;
        private final SHAKEDigest shakeDigest;



        ShakeSymmetric()
        {
            super(168);
            this.xof = new SHAKEDigest(128);
            this.prf = new SHAKEDigest(256);
            this.sha3Digest256 = new SHA3Digest(256);
            this.sha3Digest512 = new SHA3Digest(512);
            this.shakeDigest = new SHAKEDigest(256);
        }

        @Override
        void hash_h(byte[] out, byte[] in, int outOffset)
        {
            sha3Digest256.update(in, 0, in.length);
            sha3Digest256.doFinal(out, outOffset);
        }

        @Override
        void hash_g(byte[] out, byte[] in)
        {
            sha3Digest512.update(in, 0, in.length);
            sha3Digest512.doFinal(out, 0);
        }

        @Override
        void xofAbsorb(byte[] seed, byte a, byte b)
        {
            xof.reset();
            byte[] buf = new byte[seed.length + 2];
            System.arraycopy(seed, 0, buf, 0, seed.length);
            buf[seed.length] = a;
            buf[seed.length + 1] = b;
            xof.update(buf, 0, seed.length + 2);
        }

        @Override
        void xofSqueezeBlocks(byte[] out, int outOffset, int outLen)
        {
            xof.doOutput(out, outOffset, outLen);
        }

        @Override
        void prf(byte[] out, byte[] seed, byte nonce)
        {
            byte[] extSeed = new byte[seed.length + 1];
            System.arraycopy(seed, 0, extSeed, 0, seed.length);
            extSeed[seed.length] = nonce;
            prf.update(extSeed, 0, extSeed.length);
            prf.doFinal(out, 0, out.length);
        }

        @Override
        void kdf(byte[] out, byte[] in)
        {
            shakeDigest.update(in, 0, in.length);
            shakeDigest.doFinal(out, 0, out.length);
        }
    }
    static class AesSymmetric
        extends Symmetric
    {
        AesSymmetric()
        {
            super(64);
        }

        @Override
        void hash_h(byte[] out, byte[] in, int outOffset)
        {

        }

        @Override
        void hash_g(byte[] out, byte[] in)
        {

        }

        @Override
        void xofAbsorb(byte[] seed, byte x, byte y)
        {

        }

        @Override
        void xofSqueezeBlocks(byte[] out, int outOffset, int outLen)
        {

        }

        @Override
        void prf(byte[] out, byte[] key, byte nonce)
        {

        }

        @Override
        void kdf(byte[] out, byte[] in)
        {

        }
    }
    public static SHAKEDigest KyberXOF(byte[] seed, int a, int b)
    {
        SHAKEDigest xof = new SHAKEDigest(128);
        byte[] buf = new byte[seed.length + 2];
        System.arraycopy(seed, 0, buf, 0, seed.length);
        buf[seed.length] = (byte)a;
        buf[seed.length + 1] = (byte)b;

        xof.update(buf, 0, seed.length + 2);


        return xof;
    }

    public final static int SHAKE128_rate = 168;

    public static SHAKEDigest KyberPRF(byte[] seed, byte nonce)
    {
        SHAKEDigest prf = new SHAKEDigest(256);

        byte[] extSeed = new byte[seed.length + 1];
        System.arraycopy(seed, 0, extSeed, 0, seed.length);
        extSeed[seed.length] = nonce;
        prf.update(extSeed, 0, extSeed.length);
        return prf;
    }
}

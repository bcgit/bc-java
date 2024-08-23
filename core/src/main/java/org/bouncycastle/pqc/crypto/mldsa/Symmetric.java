package org.bouncycastle.pqc.crypto.mldsa;

import org.bouncycastle.crypto.digests.SHAKEDigest;

abstract class Symmetric
{

    final int stream128BlockBytes;
    final int stream256BlockBytes;

    Symmetric(int stream128, int stream256)
    {
        this.stream128BlockBytes = stream128;
        this.stream256BlockBytes = stream256;
    }

    abstract void stream128init(byte[] seed, short nonce);

    abstract void stream256init(byte[] seed, short nonce);

    abstract void stream128squeezeBlocks(byte[] output, int offset, int size);

    abstract void stream256squeezeBlocks(byte[] output, int offset, int size);

    static class ShakeSymmetric
        extends Symmetric
    {
        private final SHAKEDigest digest128;
        private final SHAKEDigest digest256;

        ShakeSymmetric()
        {
            super(168, 136);
            digest128 = new SHAKEDigest(128);
            digest256 = new SHAKEDigest(256);
        }

        private void streamInit(SHAKEDigest digest, byte[] seed, short nonce)
        {
            digest.reset();
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


        @Override
        void stream128init(byte[] seed, short nonce)
        {
            streamInit(digest128, seed, nonce);
        }

        @Override
        void stream256init(byte[] seed, short nonce)
        {
            streamInit(digest256, seed, nonce);
        }

        @Override
        void stream128squeezeBlocks(byte[] output, int offset, int size)
        {
            digest128.doOutput(output, offset, size);
        }

        @Override
        void stream256squeezeBlocks(byte[] output, int offset, int size)
        {
            digest256.doOutput(output, offset, size);
        }
    }
}

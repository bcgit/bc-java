package org.bouncycastle.pqc.crypto.crystals.dilithium;

import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

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


    /**
     * @deprecated
     * obsolete to be removed
     */
    @Deprecated
    static class AesSymmetric
        extends Symmetric
    {

        private final StreamCipher cipher;

        AesSymmetric()
        {
            super(64, 64);
            cipher = SICBlockCipher.newInstance(AESEngine.newInstance());
        }

        private void aes128(byte[] out, int offset, int size)
        {
            byte[] buf = new byte[size];   // TODO: there might be a more efficient way of doing this...
            cipher.processBytes(buf, 0, size, out, offset);
        }

        private void streamInit(byte[] key, short nonce)
        {
            byte[] expnonce = new byte[12];
            expnonce[0] = (byte)nonce;
            expnonce[1] = (byte)(nonce >> 8);

            ParametersWithIV kp = new ParametersWithIV(new KeyParameter(key, 0, 32), expnonce);
            cipher.init(true, kp);
        }

        @Override
        void stream128init(byte[] seed, short nonce)
        {
            streamInit(seed, nonce);
        }

        @Override
        void stream256init(byte[] seed, short nonce)
        {
            streamInit(seed, nonce);
        }

        @Override
        void stream128squeezeBlocks(byte[] output, int offset, int size)
        {
            aes128(output, offset, size);
        }

        @Override
        void stream256squeezeBlocks(byte[] output, int offset, int size)
        {
            aes128(output, offset, size);
        }
    }


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

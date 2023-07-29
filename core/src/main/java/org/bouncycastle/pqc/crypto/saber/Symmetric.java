package org.bouncycastle.pqc.crypto.saber;

import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

abstract class Symmetric
{
    abstract void hash_h(byte[] out, byte[] in, int outOffset);

    abstract void hash_g(byte[] out, byte[] in);

    abstract void prf(byte[] out, byte[] in, int inLen, int outLen);

    static class ShakeSymmetric
        extends Symmetric
    {

        private final SHA3Digest sha3Digest256;
        private final SHA3Digest sha3Digest512;
        private final Xof shakeDigest;
        ShakeSymmetric()
        {
            shakeDigest = new SHAKEDigest(128);
            sha3Digest256 = new SHA3Digest(256);
            sha3Digest512 = new SHA3Digest(512);
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
        void prf(byte[] out, byte[] in, int inLen, int outLen)
        {
            shakeDigest.reset();
            shakeDigest.update(in, 0, inLen);
            shakeDigest.doFinal(out, 0, outLen);
        }
    }
    
    static class AesSymmetric
        extends Symmetric
    {
        private final SHA256Digest sha256Digest;
        private final SHA512Digest sha512Digest;
        private final StreamCipher cipher;

        AesSymmetric()
        {
            sha256Digest = new SHA256Digest();
            sha512Digest = new SHA512Digest();
            this.cipher = SICBlockCipher.newInstance(AESEngine.newInstance());
        }
        @Override
        void hash_h(byte[] out, byte[] in, int outOffset)
        {
            sha256Digest.update(in, 0, in.length);
            sha256Digest.doFinal(out, outOffset);
        }

        @Override
        void hash_g(byte[] out, byte[] in)
        {
            sha512Digest.update(in, 0, in.length);
            sha512Digest.doFinal(out, 0);
        }

        @Override
        void prf(byte[] out, byte[] in, int inLen, int outLen)
        {
            ParametersWithIV kp = new ParametersWithIV(new KeyParameter(in, 0, inLen), new byte[16]);
            cipher.init(true, kp);
            byte[] buf = new byte[outLen];   // TODO: there might be a more efficient way of doing this...
            cipher.processBytes(buf, 0, outLen, out, 0);
        }


    }
}

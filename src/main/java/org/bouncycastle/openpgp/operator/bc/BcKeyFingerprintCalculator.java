package org.bouncycastle.openpgp.operator.bc;

import java.io.IOException;

import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.MPInteger;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;

public class BcKeyFingerprintCalculator
    implements KeyFingerPrintCalculator
{
    public byte[] calculateFingerprint(PublicKeyPacket publicPk)
        throws PGPException
    {
        BCPGKey key = publicPk.getKey();
        Digest digest;

        if (publicPk.getVersion() <= 3)
        {
            RSAPublicBCPGKey rK = (RSAPublicBCPGKey)key;

            try
            {
                digest = new MD5Digest();

                byte[]  bytes = new MPInteger(rK.getModulus()).getEncoded();
                digest.update(bytes, 2, bytes.length - 2);

                bytes = new MPInteger(rK.getPublicExponent()).getEncoded();
                digest.update(bytes, 2, bytes.length - 2);
            }
            catch (IOException e)
            {
                throw new PGPException("can't encode key components: " + e.getMessage(), e);
            }
        }
        else
        {
            try
            {
                byte[]             kBytes = publicPk.getEncodedContents();

                digest = new SHA1Digest();

                digest.update((byte)0x99);
                digest.update((byte)(kBytes.length >> 8));
                digest.update((byte)kBytes.length);
                digest.update(kBytes, 0, kBytes.length);
            }
            catch (IOException e)
            {
                throw new PGPException("can't encode key components: " + e.getMessage(), e);
            }
        }

        byte[] digBuf = new byte[digest.getDigestSize()];

        digest.doFinal(digBuf, 0);

        return digBuf;
    }
}

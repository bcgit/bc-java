package org.bouncycastle.openpgp.operator.jcajce;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.MPInteger;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;

public class JcaKeyFingerprintCalculator
    implements KeyFingerPrintCalculator
{
    public byte[] calculateFingerprint(PublicKeyPacket publicPk)
        throws PGPException
    {
        BCPGKey key = publicPk.getKey();

        if (publicPk.getVersion() <= 3)
        {
            RSAPublicBCPGKey rK = (RSAPublicBCPGKey)key;

            try
            {
                MessageDigest digest = MessageDigest.getInstance("MD5");

                byte[]  bytes = new MPInteger(rK.getModulus()).getEncoded();
                digest.update(bytes, 2, bytes.length - 2);

                bytes = new MPInteger(rK.getPublicExponent()).getEncoded();
                digest.update(bytes, 2, bytes.length - 2);

                return digest.digest();
            }
            catch (NoSuchAlgorithmException e)
            {
                throw new PGPException("can't find MD5", e);
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

                MessageDigest   digest = MessageDigest.getInstance("SHA1");

                digest.update((byte)0x99);
                digest.update((byte)(kBytes.length >> 8));
                digest.update((byte)kBytes.length);
                digest.update(kBytes);

                return digest.digest();
            }
            catch (NoSuchAlgorithmException e)
            {
                throw new PGPException("can't find SHA1", e);
            }
            catch (IOException e)
            {
                throw new PGPException("can't encode key components: " + e.getMessage(), e);
            }
        }
    }
}

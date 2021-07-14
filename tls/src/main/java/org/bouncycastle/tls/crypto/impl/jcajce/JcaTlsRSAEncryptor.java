package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsEncryptor;

final class JcaTlsRSAEncryptor
    implements TlsEncryptor
{
    private final JcaTlsCrypto crypto;
    private final PublicKey pubKeyRSA;

    JcaTlsRSAEncryptor(JcaTlsCrypto crypto, PublicKey pubKeyRSA)
    {
        this.crypto = crypto;
        this.pubKeyRSA = pubKeyRSA;
    }

    public byte[] encrypt(byte[] input, int inOff, int length)
        throws IOException
    {
        try
        {
            Cipher c = crypto.createRSAEncryptionCipher();
            // try wrap mode first - strictly speaking this is the correct one to use.
            try
            {
                c.init(Cipher.WRAP_MODE, pubKeyRSA, crypto.getSecureRandom());
                return c.wrap(new SecretKeySpec(input, inOff, length, "TLS"));
            }
            catch (Exception e)
            {
                try
                {
                    // okay, maybe the provider does not support wrap mode.
                    c.init(Cipher.ENCRYPT_MODE, pubKeyRSA, crypto.getSecureRandom());
                    return c.doFinal(input, inOff, length);
                }
                catch (Exception ex)
                {
                    // okay, if we get here let's rethrow the original one.
                    throw new TlsFatalAlert(AlertDescription.internal_error, e);
                }
            }
        }
        catch (GeneralSecurityException e)
        {
            /*
             * This should never happen, only during decryption.
             */
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }
}

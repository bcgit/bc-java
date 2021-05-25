package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.impl.TlsEncryptor;

final class BcTlsRSAEncryptor
    implements TlsEncryptor
{
    private static RSAKeyParameters checkPublicKey(RSAKeyParameters pubKeyRSA)
    {
        if (null == pubKeyRSA || pubKeyRSA.isPrivate())
            throw new IllegalArgumentException("No public RSA key provided");

        return pubKeyRSA;
    }

    private final BcTlsCrypto crypto;
    private final RSAKeyParameters pubKeyRSA;

    BcTlsRSAEncryptor(BcTlsCrypto crypto, RSAKeyParameters pubKeyRSA)
    {
        this.crypto = crypto;
        this.pubKeyRSA = checkPublicKey(pubKeyRSA);
    }

    public byte[] encrypt(byte[] input, int inOff, int length)
        throws IOException
    {
        try
        {
            PKCS1Encoding encoding = new PKCS1Encoding(new RSABlindedEngine());
            encoding.init(true, new ParametersWithRandom(pubKeyRSA, crypto.getSecureRandom()));
            return encoding.processBlock(input, inOff, length);
        }
        catch (InvalidCipherTextException e)
        {
            /*
             * This should never happen, only during decryption.
             */
            throw new TlsFatalAlert(AlertDescription.internal_error, e);
        }
    }
}

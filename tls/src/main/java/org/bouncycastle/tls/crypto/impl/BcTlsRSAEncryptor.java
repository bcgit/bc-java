package org.bouncycastle.tls.crypto.impl;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;

import java.io.IOException;
import java.security.SecureRandom;

public class BcTlsRSAEncryptor
    implements TlsEncryptor
{

    private final SecureRandom secureRandom;
    private CipherParameters pubKeyRSA;

    public BcTlsRSAEncryptor(RSAKeyParameters pubKeyRSA, SecureRandom secureRandom)
    {
        this.pubKeyRSA = pubKeyRSA;
        this.secureRandom = secureRandom;

    }

    public byte[] encrypt(byte[] input, int inOff, int length)
            throws IOException
    {
        try
        {
            PKCS1Encoding encoding = new PKCS1Encoding(new RSABlindedEngine());
            encoding.init(true, new ParametersWithRandom(pubKeyRSA, secureRandom));
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

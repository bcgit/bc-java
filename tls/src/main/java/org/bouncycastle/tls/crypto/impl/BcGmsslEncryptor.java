package org.bouncycastle.tls.crypto.impl;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.gm.SM2Cipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;

import java.io.IOException;
import java.security.SecureRandom;

/**
 * GMSSL basic chinese GMT 0009-2012
 *
 *
 * @since 2021-03-10 13:56:20
 */
public class BcGmsslEncryptor implements TlsEncryptor
{


    private final ParametersWithRandom keyParameters;

    public BcGmsslEncryptor(ECPublicKeyParameters keyParameters, SecureRandom secureRandom)
    {
        this.keyParameters = new ParametersWithRandom(keyParameters, secureRandom);

    }

    public byte[] encrypt(byte[] input, int inOff, int length) throws IOException
    {
        try
        {
            SM2Engine engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
            engine.init(true, keyParameters);
            byte[] c1c3c2 = engine.processBlock(input, inOff, length);
            return SM2Cipher.fromC1C3C2(c1c3c2).getEncoded();
        } catch (InvalidCipherTextException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }
}

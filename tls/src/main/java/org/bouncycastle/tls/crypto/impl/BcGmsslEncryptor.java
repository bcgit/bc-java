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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * GMSSL basic chinese GMT 0009-2012
 *
 * @author Cliven
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

            /*
             * construct GMT0009-2012 encrypted data struct
             */
            ByteArrayInputStream stream = new ByteArrayInputStream(c1c3c2);
            // read 1 byte for uncompressed point prefix 0x04
            stream.read();
            final byte[] x = new byte[32];
            final byte[] y = new byte[32];
            final byte[] hash = new byte[32];
            final byte[] cipherText = new byte[length];
            stream.read(x);
            stream.read(y);
            stream.read(hash);
            stream.read(cipherText);

            final SM2Cipher sm2Cipher = new SM2Cipher();
            sm2Cipher.setxCoordinate(new ASN1Integer(new BigInteger(1, x)));
            sm2Cipher.setyCoordinate(new ASN1Integer(new BigInteger(1, y)));
            sm2Cipher.setHash(new DEROctetString(hash));
            sm2Cipher.setCipherText(new DEROctetString(cipherText));
            return sm2Cipher.getEncoded();
        } catch (InvalidCipherTextException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }
}

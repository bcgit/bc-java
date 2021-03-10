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
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.util.encoders.Hex;

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
            byte[] x = TlsUtils.readFully(32, stream);
            byte[] y = TlsUtils.readFully(32, stream);
            byte[] hash = TlsUtils.readFully(32, stream);
            final byte[] cipherText = TlsUtils.readFully(length, stream);

            final SM2Cipher sm2Cipher = new SM2Cipher();
            sm2Cipher.setxCoordinate(new ASN1Integer(new BigInteger(x)));
            sm2Cipher.setyCoordinate(new ASN1Integer(new BigInteger(y)));
            sm2Cipher.setHash(new DEROctetString(hash));
            sm2Cipher.setCipherText(new DEROctetString(cipherText));
            final byte[] encoded = sm2Cipher.getEncoded();
            System.out.printf(">> PreMasterSecret Key: %s\n", Hex.toHexString(input).toUpperCase());
            System.out.printf(">> CipherTtext: %s\n", Hex.toHexString(encoded).toUpperCase());
            return encoded;
        }
        catch (InvalidCipherTextException e)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }
}

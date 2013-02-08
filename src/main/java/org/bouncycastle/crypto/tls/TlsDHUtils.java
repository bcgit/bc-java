package org.bouncycastle.crypto.tls;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.generators.DHBasicKeyPairGenerator;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.util.BigIntegers;

public class TlsDHUtils
{
    static final BigInteger ONE = BigInteger.valueOf(1);
    static final BigInteger TWO = BigInteger.valueOf(2);

    public static byte[] calculateDHBasicAgreement(DHPublicKeyParameters publicKey,
        DHPrivateKeyParameters privateKey)
    {
        DHBasicAgreement dhAgree = new DHBasicAgreement();
        dhAgree.init(privateKey);
        BigInteger agreement = dhAgree.calculateAgreement(publicKey);
        return BigIntegers.asUnsignedByteArray(agreement);
    }

    public static AsymmetricCipherKeyPair generateDHKeyPair(SecureRandom random, DHParameters dhParams)
    {
        DHBasicKeyPairGenerator dhGen = new DHBasicKeyPairGenerator();
        dhGen.init(new DHKeyGenerationParameters(random, dhParams));
        return dhGen.generateKeyPair();
    }

    public static DHPrivateKeyParameters generateEphemeralClientKeyExchange(SecureRandom random, DHParameters dhParams, OutputStream os)
        throws IOException
    {
        AsymmetricCipherKeyPair dhAgreeClientKeyPair = generateDHKeyPair(random, dhParams);
        DHPrivateKeyParameters dhAgreeClientPrivateKey = (DHPrivateKeyParameters)dhAgreeClientKeyPair.getPrivate();

        BigInteger Yc = ((DHPublicKeyParameters)dhAgreeClientKeyPair.getPublic()).getY();
        byte[] keData = BigIntegers.asUnsignedByteArray(Yc);
        TlsUtils.writeOpaque16(keData, os);

        return dhAgreeClientPrivateKey;
    }

    public static DHPublicKeyParameters validateDHPublicKey(DHPublicKeyParameters key)
        throws IOException
    {
        BigInteger Y = key.getY();
        DHParameters params = key.getParameters();
        BigInteger p = params.getP();
        BigInteger g = params.getG();

        if (!p.isProbablePrime(2))
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
        if (g.compareTo(TWO) < 0 || g.compareTo(p.subtract(TWO)) > 0)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }
        if (Y.compareTo(TWO) < 0 || Y.compareTo(p.subtract(ONE)) > 0)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        // TODO See RFC 2631 for more discussion of Diffie-Hellman validation

        return key;
    }
}

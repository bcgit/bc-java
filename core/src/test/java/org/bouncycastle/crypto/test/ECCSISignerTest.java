package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECCSIKeyPairGenerator;
import org.bouncycastle.crypto.params.ECCSIKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECCSIPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECCSIPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.ECCSISigner;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;

public class ECCSISignerTest
    extends SimpleTest
{
    public static void main(String[] args)
        throws Exception
    {
        ECCSISignerTest test = new ECCSISignerTest();
        test.performTest();
    }

    @Override
    public String getName()
    {
        return "ECCSISigner Test";
    }

    @Override
    public void performTest()
        throws Exception
    {
        testTestVector();
    }

    private void testTestVector()
        throws Exception
    {
        BigInteger ksak = BigInteger.valueOf(0x12345);
        BigInteger v = BigInteger.valueOf(0x23456);
        BigInteger j = BigInteger.valueOf(0x34567);
        ECCSIKeyPairGenerator generator = new ECCSIKeyPairGenerator();
        SecureRandom random = new FixedSecureRandom(new FixedSecureRandom.Source[]{new FixedSecureRandom.Data(BigIntegers.asUnsignedByteArray(32, ksak)),
            new FixedSecureRandom.Data(BigIntegers.asUnsignedByteArray(32, v)),
            new FixedSecureRandom.Data(BigIntegers.asUnsignedByteArray(32, j))});
        ECCSIKeyGenerationParameters keyGenerationParameters = new ECCSIKeyGenerationParameters(random, "2011-02\0tel:+447700900123\0".getBytes());
        generator.init(keyGenerationParameters);
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
        ECCSIPublicKeyParameters pub = (ECCSIPublicKeyParameters)keyPair.getPublic();
        ECCSIPrivateKeyParameters priv = (ECCSIPrivateKeyParameters)keyPair.getPrivate();
        System.out.println(new String(Hex.encode(pub.getPVT().getXCoord().toBigInteger().toByteArray())));
        System.out.println(new String(Hex.encode(pub.getPVT().getYCoord().toBigInteger().toByteArray())));
        System.out.println(new String(Hex.encode(priv.getSSK().toByteArray())));

        byte[] M = "message\0".getBytes();

        ECCSISigner signer = new ECCSISigner(keyGenerationParameters.getKPAK(), keyGenerationParameters.getId());
        signer.init(true, new ParametersWithRandom(priv, random));
        signer.update(M, 0, M.length);
        byte[] sig = signer.generateSignature();
        System.out.println("sig: " + new String(Hex.encode(sig)));

        signer.init(false, pub);
        signer.update(M, 0, M.length);
        isTrue(signer.verifySignature(sig));
    }
}

package org.bouncycastle.jce.provider.test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

public class DSTU4145Test
    extends SimpleTest
{

    public String getName()
    {
        return "DSTU4145";
    }

    public void performTest()
        throws Exception
    {

        DSTU4145Test();
        generationTest();
        //parametersTest();
        generateFromCurveTest();
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());
        runTest(new DSTU4145Test());
    }
    
    static final BigInteger r = new BigInteger("00f2702989366e9569d5092b83ac17f918bf040c487a", 16);
    static final BigInteger s = new BigInteger("01dd460039db3be70392d7012f2a492d3e59091ab7a6", 16);
    
    private void generationTest() throws Exception
    {
        ECCurve.F2m curve = new ECCurve.F2m(173, 1, 2, 10, BigInteger.ZERO, new BigInteger("108576C80499DB2FC16EDDF6853BBB278F6B6FB437D9", 16));

        ECParameterSpec spec = new ECParameterSpec(
            curve,
            curve.createPoint(new BigInteger("BE6628EC3E67A91A4E470894FBA72B52C515F8AEE9", 16), new BigInteger("D9DEEDF655CF5412313C11CA566CDC71F4DA57DB45C", 16)),
            new BigInteger("800000000000000000000189B4E67606E3825BB2831", 16));
        
        SecureRandom k = new TestRandomBigInteger(Hex.decode("00137449348C1249971759D99C252FFE1E14D8B31F00"));
        SecureRandom keyRand = new TestRandomBigInteger(Hex.decode("0000955CD7E344303D1034E66933DC21C8044D42ADB8"));
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSTU4145", "BC");
        keyGen.initialize(spec, keyRand);
        KeyPair pair = keyGen.generateKeyPair();
        
        Signature sgr = Signature.getInstance("DSTU4145", "BC");

        sgr.initSign(pair.getPrivate(), k);

        byte[] message = new byte[]{(byte)'a', (byte)'b', (byte)'c'};

        sgr.update(message);

        byte[] sigBytes = sgr.sign();

        sgr.initVerify(pair.getPublic());

        sgr.update(message);

        if (!sgr.verify(sigBytes))
        {
            fail("DSTU4145 verification failed");
        }

        BigInteger[] sig = decode(sigBytes);

        if (!r.equals(sig[0]))
        {
            fail(
                ": r component wrong." + Strings.lineSeparator()
                    + " expecting: " + r + Strings.lineSeparator()
                    + " got      : " + sig[0].toString(16));
        }

        if (!s.equals(sig[1]))
        {
            fail(
                ": s component wrong." + Strings.lineSeparator()
                    + " expecting: " + s + Strings.lineSeparator()
                    + " got      : " + sig[1].toString(16));
        }
    }

    private void generateFromCurveTest()
        throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSTU4145", "BC");

        for (int i = 0; i != 10; i++)
        {
            keyGen.initialize(new ECGenParameterSpec("1.2.804.2.1.1.1.1.3.1.1.2." + i));
        }

        try
        {
            keyGen.initialize(new ECGenParameterSpec("1.2.804.2.1.1.1.1.3.1.1.2." + 10));
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            isTrue("unknown curve name: 1.2.804.2.1.1.1.1.3.1.1.2.10".equals(e.getMessage()));
        }
    }

    private void DSTU4145Test()
        throws Exception
    {

        SecureRandom k = new TestRandomBigInteger(Hex.decode("00137449348C1249971759D99C252FFE1E14D8B31F00"));

        ECCurve.F2m curve = new ECCurve.F2m(173, 1, 2, 10, BigInteger.ZERO, new BigInteger("108576C80499DB2FC16EDDF6853BBB278F6B6FB437D9", 16));

        ECParameterSpec spec = new ECParameterSpec(
            curve,
            curve.createPoint(new BigInteger("BE6628EC3E67A91A4E470894FBA72B52C515F8AEE9", 16), new BigInteger("D9DEEDF655CF5412313C11CA566CDC71F4DA57DB45C", 16)),
            new BigInteger("800000000000000000000189B4E67606E3825BB2831", 16));

        ECPrivateKeySpec priKey = new ECPrivateKeySpec(
            new BigInteger("955CD7E344303D1034E66933DC21C8044D42ADB8", 16), // d
            spec);

        ECPublicKeySpec pubKey = new ECPublicKeySpec(
            curve.createPoint(new BigInteger("22de541d48a75c1c3b8c7c107b2551c5093c6c096e1", 16), new BigInteger("1e5b602efc0269d61e64d97c9193d2788fa05c4b7fd5", 16)),
            spec);

        Signature sgr = Signature.getInstance("DSTU4145", "BC");
        KeyFactory f = KeyFactory.getInstance("DSTU4145", "BC");
        PrivateKey sKey = f.generatePrivate(priKey);
        PublicKey vKey = f.generatePublic(pubKey);

        sgr.initSign(sKey, k);

        byte[] message = new byte[]{(byte)'a', (byte)'b', (byte)'c'};

        sgr.update(message);

        byte[] sigBytes = sgr.sign();

        sgr.initVerify(vKey);

        sgr.update(message);

        if (!sgr.verify(sigBytes))
        {
            fail("DSTU4145 verification failed");
        }

        BigInteger[] sig = decode(sigBytes);

        if (!r.equals(sig[0]))
        {
            fail(
                ": r component wrong." + Strings.lineSeparator()
                    + " expecting: " + r + Strings.lineSeparator()
                    + " got      : " + sig[0].toString(16));
        }

        if (!s.equals(sig[1]))
        {
            fail(
                ": s component wrong." + Strings.lineSeparator()
                    + " expecting: " + s + Strings.lineSeparator()
                    + " got      : " + sig[1].toString(16));
        }
    }

    private BigInteger[] decode(
        byte[] encoding)
        throws IOException
    {
        ASN1OctetString octetString = (ASN1OctetString)ASN1OctetString.fromByteArray(encoding);
        encoding = octetString.getOctets();

        byte[] r = new byte[encoding.length / 2];
        byte[] s = new byte[encoding.length / 2];

        System.arraycopy(encoding, 0, s, 0, encoding.length / 2);

        System.arraycopy(encoding, encoding.length / 2, r, 0, encoding.length / 2);

        BigInteger[] sig = new BigInteger[2];

        sig[0] = new BigInteger(1, r);
        sig[1] = new BigInteger(1, s);

        return sig;
    }
}

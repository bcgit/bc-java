package org.bouncycastle.pqc.jcajce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.pqc.jcajce.interfaces.RainbowKey;
import org.bouncycastle.pqc.jcajce.interfaces.RainbowPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.RainbowParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class RainbowTest
    extends TestCase
{
    byte[] msg = Strings.toByteArray("Hello World!");

    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    public void testPrivateKeyRecovery()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Rainbow", "BCPQC");

        kpg.initialize(RainbowParameterSpec.rainbowIIIclassic, new RainbowTest.RiggedRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("Rainbow", "BCPQC");

        RainbowKey privKey = (RainbowKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        assertEquals(kp.getPrivate(), privKey);
        assertEquals(kp.getPrivate().getAlgorithm(), privKey.getAlgorithm());
        assertEquals(kp.getPrivate().hashCode(), privKey.hashCode());

        assertEquals(((RainbowPrivateKey)kp.getPrivate()).getPublicKey(), ((RainbowPrivateKey)privKey).getPublicKey());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(privKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        RainbowKey privKey2 = (RainbowKey)oIn.readObject();

        assertEquals(privKey, privKey2);
        assertEquals(privKey.getAlgorithm(), privKey2.getAlgorithm());
        assertEquals(privKey.hashCode(), privKey2.hashCode());

        assertEquals(kp.getPublic(), ((RainbowPrivateKey)privKey2).getPublicKey());
        assertEquals(((RainbowPrivateKey)privKey).getPublicKey(), ((RainbowPrivateKey)privKey2).getPublicKey());
    }

    public void testPublicKeyRecovery()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Rainbow", "BCPQC");

        kpg.initialize(RainbowParameterSpec.rainbowVclassic, new RainbowTest.RiggedRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("Rainbow", "BCPQC");

        RainbowKey pubKey = (RainbowKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        assertEquals(kp.getPublic(), pubKey);
        assertEquals(kp.getPublic().getAlgorithm(), pubKey.getAlgorithm());
        assertEquals(kp.getPublic().hashCode(), pubKey.hashCode());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(pubKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        RainbowKey pubKey2 = (RainbowKey)oIn.readObject();

        assertEquals(pubKey, pubKey2);
        assertEquals(pubKey.getAlgorithm(), pubKey2.getAlgorithm());
        assertEquals(pubKey.hashCode(), pubKey2.hashCode());
    }

    public void testRainbowIIIclassic()
        throws Exception
    {
        doConfSigTest("Rainbow-III-Classic", RainbowParameterSpec.rainbowIIIclassic, RainbowParameterSpec.rainbowVclassic);
    }

    public void testRainbowIIIcircum()
        throws Exception
    {
        doConfSigTest("Rainbow-III-Circumzenithal", RainbowParameterSpec.rainbowIIIcircumzenithal, RainbowParameterSpec.rainbowVclassic);
    }

    public void testRainbowIIIcomp()
        throws Exception
    {
        doConfSigTest("Rainbow-III-Compressed", RainbowParameterSpec.rainbowIIIcompressed, RainbowParameterSpec.rainbowVclassic);
    }

    public void testRainbowVclassic()
        throws Exception
    {
        doConfSigTest("Rainbow-V-Classic", RainbowParameterSpec.rainbowVclassic, RainbowParameterSpec.rainbowIIIclassic);
    }

    public void testRainbowVcircum()
        throws Exception
    {
        doConfSigTest("Rainbow-V-Circumzenithal", RainbowParameterSpec.rainbowVcircumzenithal, RainbowParameterSpec.rainbowIIIclassic);
    }

    public void testRainbowVcompressed()
        throws Exception
    {
        doConfSigTest("Rainbow-V-Compressed", RainbowParameterSpec.rainbowVcompressed, RainbowParameterSpec.rainbowIIIclassic);
    }

    private void doConfSigTest(String algorithmName, AlgorithmParameterSpec algSpec, AlgorithmParameterSpec altSpec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Rainbow", "BCPQC");

        kpg.initialize(algSpec, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("Rainbow", "BCPQC");

        sig.initSign(kp.getPrivate(), new SecureRandom());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig = Signature.getInstance(algorithmName, "BCPQC");

        assertEquals(Strings.toUpperCase(algorithmName), Strings.toUpperCase(sig.getAlgorithm()));

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));

        kpg = KeyPairGenerator.getInstance("Rainbow", "BCPQC");

        kpg.initialize(altSpec, new SecureRandom());

        kp = kpg.generateKeyPair();

        try
        {
            sig.initVerify(kp.getPublic());
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("signature configured for " + Strings.toUpperCase(algorithmName), e.getMessage());
        }
    }

    public void testRestrictedKeyPairGen()
        throws Exception
    {
        doTestRestrictedKeyPairGen(RainbowParameterSpec.rainbowIIIclassic, RainbowParameterSpec.rainbowVclassic);
        doTestRestrictedKeyPairGen(RainbowParameterSpec.rainbowIIIcircumzenithal, RainbowParameterSpec.rainbowVclassic);
        doTestRestrictedKeyPairGen(RainbowParameterSpec.rainbowIIIcompressed, RainbowParameterSpec.rainbowVclassic);
        doTestRestrictedKeyPairGen(RainbowParameterSpec.rainbowVclassic, RainbowParameterSpec.rainbowIIIclassic);
        doTestRestrictedKeyPairGen(RainbowParameterSpec.rainbowVcircumzenithal, RainbowParameterSpec.rainbowIIIclassic);
        doTestRestrictedKeyPairGen(RainbowParameterSpec.rainbowVcompressed, RainbowParameterSpec.rainbowIIIclassic);
    }

    private void doTestRestrictedKeyPairGen(RainbowParameterSpec spec, RainbowParameterSpec altSpec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.getName(), "BCPQC");

        kpg.initialize(spec, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        assertEquals(spec.getName(), kp.getPublic().getAlgorithm());
        assertEquals(spec.getName(), kp.getPrivate().getAlgorithm());

        kpg = KeyPairGenerator.getInstance(spec.getName(), "BCPQC");

        try
        {
            kpg.initialize(altSpec, new SecureRandom());
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            assertEquals("key pair generator locked to " + spec.getName(), e.getMessage());
        }
    }

    public void testRainbowRandomSig()
            throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Rainbow", "BCPQC");

        kpg.initialize(RainbowParameterSpec.rainbowIIIcompressed, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("Rainbow", "BCPQC");

        sig.initSign(kp.getPrivate(), new SecureRandom());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig = Signature.getInstance("Rainbow", "BCPQC");

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));
    }

    /**
     * count = 0
     * seed = 061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1
     * No public key as it's a bit "big".
     */
    public void testRainbowKATSigCompressedIII()
        throws Exception
    {
        byte[] privK = Hex.decode("8626ED79D451140800E03B59B956F8210E556067407D13DC90FA9E8B872BFB8F7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D");
        byte[] msg = Hex.decode("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8");
        byte[] s = Hex.decode(" 451F524FEF128EDBE93814C041D5EDD2C8A0226E05E13942B5B832C864A96184261745A5B530D09D51773C3E6F3C8297E3A8E6E4DBD23E56BDA10B5C3A491F7A5D9EA819D712FC6565429F965FD7264041E5F2007085DE29930B20B187BB9E5BC4BCAC01C35CABC97F5EC6476C42138C3D18A1DBD23BA22B31B21BDBE5421AC1B837A793123C80E2B5028A0763872E76E45F6AA9D675E2D667E6F68024D5EF1143D21713");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Rainbow", "BCPQC");
        SecureRandom katRandom = new NISTSecureRandom(Hex.decode("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"), null);

        kpg.initialize(RainbowParameterSpec.rainbowIIIcompressed, katRandom);

        KeyPair kp = kpg.generateKeyPair();

        PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());

        ASN1OctetString privEnc = ASN1OctetString.getInstance(privInfo.parsePrivateKey());

        assertTrue(Arrays.areEqual(privK, privEnc.getOctets()));

        doKatTest(kp, msg, s, katRandom);
    }

    public void testRainbowKATSigCompressedV()
        throws Exception
    {
        byte[] privK = Hex.decode("8626ED79D451140800E03B59B956F8210E556067407D13DC90FA9E8B872BFB8F7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D");
        byte[] msg = Hex.decode("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8");
        byte[] s = Hex.decode(" D1F97D1310F57AF3509F66307985B7F341234CE8F7516E4B61F9E53B1282CE66B9526321C66954E1753D1A9C8BA4012B9C5A211F0287C72705141F71A9AAEC350E81F6EC67ED10E1BD61DCDFA4AC87553563E0FEE31927E5877741D5DCDF03C44E50CF80BB3D15856AF49F2C68A7EDAC52FD2957F96A7113DCE51785EDF0AB8538C1EAAD694E8514CDC7872664412BCF9884C185BADE87781016826E32E08C1EC6275C6F8588A11FF6575D704505D4AB794D047BEC1104C00DAD3BCFC2DE42267B3552BD74090543C9478050169FCCFBC0E9BA11");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Rainbow", "BCPQC");
        SecureRandom katRandom = new NISTSecureRandom(Hex.decode("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"), null);

        kpg.initialize(RainbowParameterSpec.rainbowVcompressed, katRandom);

        KeyPair kp = kpg.generateKeyPair();

        PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());

        ASN1OctetString privEnc = ASN1OctetString.getInstance(privInfo.parsePrivateKey());

        assertTrue(Arrays.areEqual(privK, privEnc.getOctets()));

        doKatTest(kp, msg, s, katRandom);
    }

    public void testRainbowKATSigClassicIII()
        throws Exception
    {
        byte[] msg = Hex.decode("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8");
        byte[] s = Hex.decode("6033C99A65042BE545EED707341BD14F73CA178F2A5B244A87E847DCAB29A9086676D7A7A4B35E3904A9EDD7B399B1BD104A19373A415029BCCD4C707B416EED683F13A9189EF0BDC151116CBF6D6A9D4BC019FAA58FD770B6F567A410C700B48C488A375C33866F3FEBB8DEDF239C64FF9A36F092E3D6192B9A0726B06672A540A892FA7BA47DBE7F3E66BF394ED328A107B8EDCEB39AD2E43C6EE441F39ECE871397AC");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Rainbow", "BCPQC");
        SecureRandom katRandom = new NISTSecureRandom(Hex.decode("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"), null);

        kpg.initialize(RainbowParameterSpec.rainbowIIIclassic, katRandom);

        doKatTest(kpg.generateKeyPair(), msg, s, katRandom);
    }

    public void testRainbowKATSigClassicV()
        throws Exception
    {
        byte[] msg = Hex.decode("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8");
        byte[] s = Hex.decode("15040F890F2BF56F8B04B1D8B9BA21D303C490868A0A10C9FFC04A2AF9D1F3122D14F7C6D5E0B1D914CC23D763C061B2FD34DF8CB0D75F12111244241FA7A136C440C2D40782390FE5EF3C15ED5539285B437DA0447E361853E98982E1F16AA0506BABFFBBA8282BAA0A307C50EBA79596AD26EBECE897E7B4DE3B601A515C08775526522915ED03F08BAA23AFED4224C8E50ED67FBCCFAB62C58872CE880C850D3A03F21B2703C5C085FA410A5FCB3559E50D6BBC6A06FABA309962F2922E0D014C5EB074090543C9478050169FCCFBC0E9BA11");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Rainbow", "BCPQC");
        SecureRandom katRandom = new NISTSecureRandom(Hex.decode("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"), null);

        kpg.initialize(RainbowParameterSpec.rainbowVclassic, katRandom);

        doKatTest(kpg.generateKeyPair(), msg, s, katRandom);
    }

    public void testRainbowKATSigCircumIII()
        throws Exception
    {
        byte[] msg = Hex.decode("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8");
        byte[] s = Hex.decode("451F524FEF128EDBE93814C041D5EDD2C8A0226E05E13942B5B832C864A96184261745A5B530D09D51773C3E6F3C8297E3A8E6E4DBD23E56BDA10B5C3A491F7A5D9EA819D712FC6565429F965FD7264041E5F2007085DE29930B20B187BB9E5BC4BCAC01C35CABC97F5EC6476C42138C3D18A1DBD23BA22B31B21BDBE5421AC1B837A793123C80E2B5028A0763872E76E45F6AA9D675E2D667E6F68024D5EF1143D21713");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Rainbow", "BCPQC");
        SecureRandom katRandom = new NISTSecureRandom(Hex.decode("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"), null);

        kpg.initialize(RainbowParameterSpec.rainbowIIIcircumzenithal, katRandom);

        doKatTest(kpg.generateKeyPair(), msg, s, katRandom);
    }

    public void testRainbowKATSigCircumV()
        throws Exception
    {
        byte[] msg = Hex.decode("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8");
        byte[] s = Hex.decode("D1F97D1310F57AF3509F66307985B7F341234CE8F7516E4B61F9E53B1282CE66B9526321C66954E1753D1A9C8BA4012B9C5A211F0287C72705141F71A9AAEC350E81F6EC67ED10E1BD61DCDFA4AC87553563E0FEE31927E5877741D5DCDF03C44E50CF80BB3D15856AF49F2C68A7EDAC52FD2957F96A7113DCE51785EDF0AB8538C1EAAD694E8514CDC7872664412BCF9884C185BADE87781016826E32E08C1EC6275C6F8588A11FF6575D704505D4AB794D047BEC1104C00DAD3BCFC2DE42267B3552BD74090543C9478050169FCCFBC0E9BA11");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Rainbow", "BCPQC");
        SecureRandom katRandom = new NISTSecureRandom(Hex.decode("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"), null);

        kpg.initialize(RainbowParameterSpec.rainbowVcircumzenithal, katRandom);

        doKatTest(kpg.generateKeyPair(), msg, s, katRandom);
    }

    private static void doKatTest(KeyPair kp, byte[] msg, byte[] s, SecureRandom katRandom)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException
    {
        Signature sig = Signature.getInstance("Rainbow", "BCPQC");

        sig.initSign(kp.getPrivate(), katRandom);

        sig.update(msg, 0, msg.length);

        byte[] genS = sig.sign();

        assertTrue(Arrays.areEqual(s, genS));

        sig = Signature.getInstance("Rainbow", "BCPQC");

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));
    }

    private static class RiggedRandom
            extends SecureRandom
    {
        public void nextBytes(byte[] bytes)
        {
            for (int i = 0; i != bytes.length; i++)
            {
                bytes[i] = (byte)(i & 0xff);
            }
        }
    }
}

package org.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECKey;
import java.security.spec.ECFieldFp;
import java.security.spec.EllipticCurve;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;

public class ImplicitlyCaTest
    extends SimpleTest
{
    byte[] k1 = Hex.decode("d5014e4b60ef2ba8b6211b4062ba3224e0427dd3");
    byte[] k2 = Hex.decode("345e8d05c075c3a508df729a1685690e68fcfb8c8117847e89063bca1f85d968fd281540b6e13bd1af989a1fbf17e06462bf511f9d0b140fb48ac1b1baa5bded");

    SecureRandom random = new FixedSecureRandom(
        new FixedSecureRandom.Source[] { new FixedSecureRandom.Data(k1), new FixedSecureRandom.Data(k2) });

    public void performTest()
        throws Exception
    {
        testBCAPI();

        testJDKAPI();

        testKeyFactory();

        testBasicThreadLocal();
    }

    private void testBCAPI()
        throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");

        X9ECParameters x9 = ECNamedCurveTable.getByName("prime239v1");
        ECParameterSpec ecSpec = new ECParameterSpec(x9.getCurve(), x9.getG(), x9.getN(), x9.getH());

        ConfigurableProvider config = (ConfigurableProvider)Security.getProvider("BC");

        config.setParameter(ConfigurableProvider.EC_IMPLICITLY_CA, ecSpec);

        g.initialize(null, new SecureRandom());

        KeyPair p = g.generateKeyPair();

        ECPrivateKey sKey = (ECPrivateKey)p.getPrivate();
        ECPublicKey vKey = (ECPublicKey)p.getPublic();

        testECDSA(sKey, vKey);

        testBCParamsAndQ(sKey, vKey);
        testEC5Params(sKey, vKey);

        testEncoding(sKey, vKey);
    }

    private void testKeyFactory()
        throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");

        X9ECParameters x9 = ECNamedCurveTable.getByName("prime239v1");
        ECParameterSpec ecSpec = new ECParameterSpec(x9.getCurve(), x9.getG(), x9.getN(), x9.getH());

        ConfigurableProvider config = (ConfigurableProvider)Security.getProvider("BC");

        config.setParameter(ConfigurableProvider.EC_IMPLICITLY_CA, ecSpec);

        g.initialize(null, new SecureRandom());

        KeyPair p = g.generateKeyPair();

        ECPrivateKey sKey = (ECPrivateKey)p.getPrivate();
        ECPublicKey vKey = (ECPublicKey)p.getPublic();

        KeyFactory fact = KeyFactory.getInstance("ECDSA", "BC");

        vKey = (ECPublicKey)fact.generatePublic(new ECPublicKeySpec(vKey.getQ(), null));
        sKey = (ECPrivateKey)fact.generatePrivate(new ECPrivateKeySpec(sKey.getD(), null));
        
        testECDSA(sKey, vKey);

        testBCParamsAndQ(sKey, vKey);
        testEC5Params(sKey, vKey);

        testEncoding(sKey, vKey);

        ECPublicKey vKey2 = (ECPublicKey)fact.generatePublic(new ECPublicKeySpec(vKey.getQ(), null));
        ECPrivateKey sKey2 = (ECPrivateKey)fact.generatePrivate(new ECPrivateKeySpec(sKey.getD(), null));

        if (!vKey.equals(vKey2) || vKey.hashCode() != vKey2.hashCode())
        {
            fail("public equals/hashCode failed");
        }

        if (!sKey.equals(sKey2) || sKey.hashCode() != sKey2.hashCode())
        {
            fail("private equals/hashCode failed");
        }

        // check we can get specs.
        fact.getKeySpec(vKey, java.security.spec.ECPublicKeySpec.class);

        fact.getKeySpec(sKey, java.security.spec.ECPrivateKeySpec.class);
    }

    private void testJDKAPI()
        throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");

        EllipticCurve curve = new EllipticCurve(
            new ECFieldFp(new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839")), // q
            new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
            new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

        java.security.spec.ECParameterSpec ecSpec = new java.security.spec.ECParameterSpec(
            curve,
            ECPointUtil.decodePoint(curve, Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
            new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307"), // n
            1); // h


        ConfigurableProvider config = (ConfigurableProvider)Security.getProvider("BC");

        config.setParameter(ConfigurableProvider.EC_IMPLICITLY_CA, ecSpec);

        g.initialize(null, new SecureRandom());

        KeyPair p = g.generateKeyPair();

        ECPrivateKey sKey = (ECPrivateKey)p.getPrivate();
        ECPublicKey vKey = (ECPublicKey)p.getPublic();

        testECDSA(sKey, vKey);

        testBCParamsAndQ(sKey, vKey);
        testEC5Params(sKey, vKey);

        testEncoding(sKey, vKey);
    }

    private void testBasicThreadLocal()
        throws Exception
    {
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");

        EllipticCurve curve = new EllipticCurve(
            new ECFieldFp(new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839")), // q
            new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
            new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b

        java.security.spec.ECParameterSpec ecSpec = new java.security.spec.ECParameterSpec(
            curve,
            ECPointUtil.decodePoint(curve, Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
            new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307"), // n
            1); // h


        ConfigurableProvider config = (ConfigurableProvider)Security.getProvider("BC");

        config.setParameter(ConfigurableProvider.THREAD_LOCAL_EC_IMPLICITLY_CA, ecSpec);

        g.initialize(null, new SecureRandom());

        KeyPair p = g.generateKeyPair();

        ECPrivateKey sKey = (ECPrivateKey)p.getPrivate();
        ECPublicKey vKey = (ECPublicKey)p.getPublic();

        testECDSA(sKey, vKey);

        testBCParamsAndQ(sKey, vKey);
        testEC5Params(sKey, vKey);

        testEncoding(sKey, vKey);
    }

    private void testECDSA(
        ECPrivateKey sKey,
        ECPublicKey vKey)
        throws Exception
    {
        byte[]           data = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 };
        Signature        s = Signature.getInstance("ECDSA", "BC");

        s.initSign(sKey);

        s.update(data);

        byte[] sigBytes = s.sign();

        s = Signature.getInstance("ECDSA", "BC");

        s.initVerify(vKey);

        s.update(data);

        if (!s.verify(sigBytes))
        {
            fail("ECDSA verification failed");
        }
    }

    private void testEncoding(
        ECPrivateKey privKey,
        ECPublicKey pubKey)
        throws Exception
    {
        KeyFactory kFact = KeyFactory.getInstance("ECDSA", "BC");

        byte[] bytes = privKey.getEncoded();

        PrivateKeyInfo sInfo = PrivateKeyInfo.getInstance(new ASN1InputStream(bytes).readObject());
        
        if (!sInfo.getPrivateKeyAlgorithm().getParameters().equals(DERNull.INSTANCE))
        {
            fail("private key parameters wrong");
        }

        ECPrivateKey sKey = (ECPrivateKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(bytes));

        if (!sKey.equals(privKey))
        {
            fail("private equals failed");
        }

        if (sKey.hashCode() != privKey.hashCode())
        {
            fail("private hashCode failed");          
        }

        bytes = pubKey.getEncoded();

        SubjectPublicKeyInfo vInfo = SubjectPublicKeyInfo.getInstance(new ASN1InputStream(bytes).readObject());

        if (!vInfo.getAlgorithm().getParameters().equals(DERNull.INSTANCE))
        {
            fail("public key parameters wrong");
        }
        
        ECPublicKey vKey = (ECPublicKey)kFact.generatePublic(new X509EncodedKeySpec(bytes));

        if (!vKey.equals(pubKey) || vKey.hashCode() != pubKey.hashCode())
        {
            fail("public equals/hashCode failed");
        }

        testBCParamsAndQ(sKey, vKey);
        testEC5Params(sKey, vKey);

        testECDSA(sKey, vKey);
    }

    private void testBCParamsAndQ(
        ECPrivateKey sKey,
        ECPublicKey vKey)
    {
        if (sKey.getParameters() != null)
        {
            fail("parameters exposed in private key");
        }

        if (vKey.getParameters() != null)
        {
            fail("parameters exposed in public key");
        }

        if (vKey.getQ().getCurve() != null)
        {
            fail("curve exposed in public point");
        }
    }

    private void testEC5Params(
        ECPrivateKey sKey,
        ECPublicKey vKey)
    {
        java.security.interfaces.ECKey k = (java.security.interfaces.ECKey)sKey;

        if (k.getParams() != null)
        {
            fail("parameters exposed in private key");
        }

        k = (ECKey)vKey;
        if (k.getParams() != null)
        {
            fail("parameters exposed in public key");
        }
    }

    public String getName()
    {
        return "ImplicitlyCA";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new ImplicitlyCaTest());
    }
}

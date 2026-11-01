package org.bouncycastle.jce.provider.test;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Set;

import javax.crypto.KeyAgreement;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x9.X962NamedCurves;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.spec.GOST3410ParameterSpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.util.test.SimpleTest;

public class NamedCurveTest
    extends SimpleTest
{
    private static Hashtable CURVE_NAMES = new Hashtable();
    private static Hashtable CURVE_ALIASES = new Hashtable();

    static
    {
        CURVE_NAMES.put("prime192v1", "prime192v1"); // X9.62
        CURVE_NAMES.put("sect571r1", "sect571r1"); // sec
        CURVE_NAMES.put("secp224r1", "secp224r1");
        CURVE_NAMES.put("B-409", SECNamedCurves.getName(NISTNamedCurves.getOID("B-409")));   // nist
        CURVE_NAMES.put("P-521", SECNamedCurves.getName(NISTNamedCurves.getOID("P-521")));
        CURVE_NAMES.put("brainpoolP160r1", "brainpoolp160r1");         // TeleTrusT

        CURVE_ALIASES.put("secp192r1", "prime192v1");
        CURVE_ALIASES.put("secp256r1", "prime256v1");
    }
    
    public void testCurve(
        String name)
        throws Exception
    {
        ECGenParameterSpec     ecSpec = new ECGenParameterSpec(name);

        KeyPairGenerator    g = KeyPairGenerator.getInstance("ECDH", "BC");

        g.initialize(ecSpec, new SecureRandom());

        //
        // a side
        //
        KeyPair aKeyPair = g.generateKeyPair();

        KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDHC", "BC");

        aKeyAgree.init(aKeyPair.getPrivate());

        //
        // b side
        //
        KeyPair bKeyPair = g.generateKeyPair();

        KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDHC", "BC");

        bKeyAgree.init(bKeyPair.getPrivate());

        //
        // agreement
        //
        aKeyAgree.doPhase(bKeyPair.getPublic(), true);
        bKeyAgree.doPhase(aKeyPair.getPublic(), true);

        BigInteger  k1 = new BigInteger(aKeyAgree.generateSecret());
        BigInteger  k2 = new BigInteger(bKeyAgree.generateSecret());

        if (!k1.equals(k2))
        {
            fail("2-way test failed");
        }

        //
        // public key encoding test
        //
        byte[]              pubEnc = aKeyPair.getPublic().getEncoded();
        KeyFactory          keyFac = KeyFactory.getInstance("ECDH", "BC");
        X509EncodedKeySpec  pubX509 = new X509EncodedKeySpec(pubEnc);
        ECPublicKey         pubKey = (ECPublicKey)keyFac.generatePublic(pubX509);

        if (!pubKey.getW().equals(((ECPublicKey)aKeyPair.getPublic()).getW()))
        {
            fail("public key encoding (Q test) failed");
        }

        if (!(pubKey.getParams() instanceof ECNamedCurveSpec))
        {
            fail("public key encoding not named curve");
        }

        //
        // private key encoding test
        //
        byte[]              privEnc = aKeyPair.getPrivate().getEncoded();
        PKCS8EncodedKeySpec privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
        ECPrivateKey        privKey = (ECPrivateKey)keyFac.generatePrivate(privPKCS8);

        if (!privKey.getS().equals(((ECPrivateKey)aKeyPair.getPrivate()).getS()))
        {
            fail("private key encoding (S test) failed");
        }

        if (!(privKey.getParams() instanceof ECNamedCurveSpec))
        {
            fail("private key encoding not named curve");
        }

        ECNamedCurveSpec privSpec = (ECNamedCurveSpec)privKey.getParams();
        if (!(privSpec.getName().equals(name) || privSpec.getName().equals(CURVE_NAMES.get(name))))
        {
            fail("private key encoding wrong named curve. Expected: " + CURVE_NAMES.get(name) + " got " + privSpec.getName());
        }
    }

    public void testECDSA(
        String name)
        throws Exception
    {
        ECGenParameterSpec     ecSpec = new ECGenParameterSpec(name);

        KeyPairGenerator    g = KeyPairGenerator.getInstance("ECDSA", "BC");

        g.initialize(ecSpec, new SecureRandom());

        Signature sgr = Signature.getInstance("ECDSA", "BC");
        KeyPair   pair = g.generateKeyPair();
        PrivateKey sKey = pair.getPrivate();
        PublicKey vKey = pair.getPublic();

        sgr.initSign(sKey);

        byte[] message = new byte[] { (byte)'a', (byte)'b', (byte)'c' };

        sgr.update(message);

        byte[]  sigBytes = sgr.sign();

        sgr.initVerify(vKey);

        sgr.update(message);

        if (!sgr.verify(sigBytes))
        {
            fail(name + " verification failed");
        }

        //
        // public key encoding test
        //
        byte[]              pubEnc = vKey.getEncoded();
        KeyFactory          keyFac = KeyFactory.getInstance("ECDH", "BC");
        X509EncodedKeySpec  pubX509 = new X509EncodedKeySpec(pubEnc);
        ECPublicKey         pubKey = (ECPublicKey)keyFac.generatePublic(pubX509);

        if (!pubKey.getW().equals(((ECPublicKey)vKey).getW()))
        {
            fail("public key encoding (Q test) failed");
        }

        if (!(pubKey.getParams() instanceof ECNamedCurveSpec))
        {
            fail("public key encoding not named curve");
        }

        //
        // private key encoding test
        //
        byte[]              privEnc = sKey.getEncoded();
        PKCS8EncodedKeySpec privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
        ECPrivateKey        privKey = (ECPrivateKey)keyFac.generatePrivate(privPKCS8);

        if (!privKey.getS().equals(((ECPrivateKey)sKey).getS()))
        {
            fail("private key encoding (S test) failed");
        }

        if (!(privKey.getParams() instanceof ECNamedCurveSpec))
        {
            fail("private key encoding not named curve");
        }

        ECNamedCurveSpec privSpec = (ECNamedCurveSpec)privKey.getParams();
        if (!privSpec.getName().equalsIgnoreCase(name)
            && !privSpec.getName().equalsIgnoreCase((String)CURVE_ALIASES.get(name)))
        {
            fail("private key encoding wrong named curve. Expected: " + name + " got " + privSpec.getName());
        }
    }

    public void testECGOST(
        String name)
        throws Exception
    {
        ECGenParameterSpec     ecSpec = new ECGenParameterSpec(name);

        KeyPairGenerator    g;
        Signature           sgr;
        String              keyAlgorithm;

        if (name.startsWith("Tc26-Gost-3410"))
        {
            keyAlgorithm = "ECGOST3410-2012";
            if (name.indexOf("256") > 0)
            {
                sgr = Signature.getInstance("ECGOST3410-2012-256", "BC");
            }
            else
            {
                sgr = Signature.getInstance("ECGOST3410-2012-512", "BC");
            }
        }
        else
        {
            keyAlgorithm = "ECGOST3410";

            sgr = Signature.getInstance("ECGOST3410", "BC");
        }

        g = KeyPairGenerator.getInstance(keyAlgorithm, "BC");

        g.initialize(ecSpec, new SecureRandom());

        KeyPair   pair = g.generateKeyPair();
        PrivateKey sKey = pair.getPrivate();
        PublicKey vKey = pair.getPublic();

        sgr.initSign(sKey);

        byte[] message = new byte[] { (byte)'a', (byte)'b', (byte)'c' };

        sgr.update(message);

        byte[]  sigBytes = sgr.sign();

        sgr.initVerify(vKey);

        sgr.update(message);

        if (!sgr.verify(sigBytes))
        {
            fail(name + " verification failed");
        }

        //
        // public key encoding test
        //
        byte[]              pubEnc = vKey.getEncoded();
        KeyFactory          keyFac = KeyFactory.getInstance(keyAlgorithm, "BC");
        X509EncodedKeySpec  pubX509 = new X509EncodedKeySpec(pubEnc);
        ECPublicKey         pubKey = (ECPublicKey)keyFac.generatePublic(pubX509);

        if (!pubKey.getW().equals(((ECPublicKey)vKey).getW()))
        {
            fail("public key encoding (Q test) failed");
        }

        if (!(pubKey.getParams() instanceof ECNamedCurveSpec))
        {
            fail("public key encoding not named curve");
        }

        //
        // private key encoding test
        //
        byte[]              privEnc = sKey.getEncoded();
        PKCS8EncodedKeySpec privPKCS8 = new PKCS8EncodedKeySpec(privEnc);
        ECPrivateKey        privKey = (ECPrivateKey)keyFac.generatePrivate(privPKCS8);

        if (!privKey.getS().equals(((ECPrivateKey)sKey).getS()))
        {
            fail("GOST private key encoding (S test) failed");
        }

        if (!(privKey.getParams() instanceof ECNamedCurveSpec))
        {
            fail("GOST private key encoding not named curve");
        }

        ECNamedCurveSpec privSpec = (ECNamedCurveSpec)privKey.getParams();
        if (!privSpec.getName().equalsIgnoreCase(name)
            && !privSpec.getName().equalsIgnoreCase((String)CURVE_ALIASES.get(name)))
        {
            fail("GOST private key encoding wrong named curve. Expected: " + name + " got " + privSpec.getName());
        }
    }

    public void testAcceptable()
        throws Exception
    {
        ECGenParameterSpec     ecSpec = new ECGenParameterSpec("P-256");
        KeyPairGenerator       kpGen = KeyPairGenerator.getInstance("EC", "BC");

        kpGen.initialize(ecSpec);

        KeyPair kp = kpGen.generateKeyPair();

        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(kp.getPublic().getEncoded());
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded());

        KeyFactory kf = KeyFactory.getInstance("EC", "BC");

        ConfigurableProvider bcProv = ((ConfigurableProvider)Security.getProvider("BC"));

        bcProv.setParameter(ConfigurableProvider.ACCEPTABLE_EC_CURVES, Collections.singleton(NISTNamedCurves.getOID("P-384")));

        try
        {
            kf.generatePrivate(privSpec);
            fail("no exception");
        }
        catch (InvalidKeySpecException e)
        {
            isTrue("wrong message", "encoded key spec not recognized: named curve not acceptable".equals(e.getMessage()));
        }

        try
        {
            kf.generatePublic(pubSpec);
            fail("no exception");
        }
        catch (InvalidKeySpecException e)
        {
            isTrue("wrong message", "encoded key spec not recognized: named curve not acceptable".equals(e.getMessage()));
        }

        bcProv.setParameter(ConfigurableProvider.ACCEPTABLE_EC_CURVES, Collections.singleton(NISTNamedCurves.getOID("P-256")));

        kf.generatePrivate(privSpec);
        kf.generatePublic(pubSpec);

        bcProv.setParameter(ConfigurableProvider.ACCEPTABLE_EC_CURVES, Collections.EMPTY_SET);

        kf.generatePrivate(privSpec);
        kf.generatePublic(pubSpec);
    }

    public void testAdditional()
        throws Exception
    {
        ConfigurableProvider bcProv = ((ConfigurableProvider)Security.getProvider("BC"));
        ASN1ObjectIdentifier bogusCurveID = Extension.auditIdentity;

        bcProv.setParameter(ConfigurableProvider.ADDITIONAL_EC_PARAMETERS, Collections.singletonMap(bogusCurveID, NISTNamedCurves.getByName("P-384")));

        KeyPairGenerator       kpGen = KeyPairGenerator.getInstance("EC", "BC");

        kpGen.initialize(new ECGenParameterSpec(bogusCurveID.getId()));

        KeyPair kp = kpGen.generateKeyPair();

        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(kp.getPublic().getEncoded());
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded());

        KeyFactory kf = KeyFactory.getInstance("EC", "BC");

        kf.generatePrivate(privSpec);
        kf.generatePublic(pubSpec);
    }

    // toString() is what other providers print for BC key parameters, e.g. SunEC's "Curve not supported: ..."
    private void testToString()
        throws Exception
    {
        String brainpool = "brainpoolP256r1 (1.3.36.3.3.2.8.1.1.7)";
        String fp256 = "EC parameters (Fp, 256-bit field)";
        String f2m163 = "EC parameters (F2m, 163-bit field)";

        ECNamedCurveParameterSpec bcSpec = ECNamedCurveTable.getParameterSpec("brainpoolP256r1");
        isEquals(brainpool, bcSpec.toString());
        isEquals(brainpool, namedSpec("brainpoolP256r1", bcSpec).toString());

        // an OID given as the name is shown once, after the table name when there is one
        isEquals(brainpool, namedSpec("1.3.36.3.3.2.8.1.1.7", bcSpec).toString());
        isEquals("1.3.6.1.4.1.99999.1", namedSpec("1.3.6.1.4.1.99999.1", bcSpec).toString());
        isEquals("madeUpCurve", namedSpec("madeUpCurve", bcSpec).toString());

        // no name: describe the curve
        isEquals(fp256, namedSpec(null, bcSpec).toString());
        isEquals(fp256, new ECNamedCurveParameterSpec(null, bcSpec.getCurve(), bcSpec.getG(), bcSpec.getN()).toString());
        isEquals(fp256, new org.bouncycastle.jce.spec.ECParameterSpec(bcSpec.getCurve(), bcSpec.getG(), bcSpec.getN()).toString());

        ECNamedCurveParameterSpec f2mSpec = ECNamedCurveTable.getParameterSpec("sect163k1");
        isEquals("sect163k1 (1.3.132.0.1)", f2mSpec.toString());
        isEquals(f2m163, namedSpec(null, f2mSpec).toString());
        isEquals(f2m163, new org.bouncycastle.jce.spec.ECParameterSpec(f2mSpec.getCurve(), f2mSpec.getG(), f2mSpec.getN()).toString());

        isEquals("secp384r1 (1.3.132.0.34)", new ECNamedCurveGenParameterSpec("secp384r1").toString());

        // the parameters of a BC key, generated and decoded
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");
        kpGen.initialize(new ECGenParameterSpec("brainpoolP256r1"));
        ECPublicKey pub = (ECPublicKey)kpGen.generateKeyPair().getPublic();
        isEquals(brainpool, pub.getParams().toString());

        ECPublicKey decoded = (ECPublicKey)KeyFactory.getInstance("EC", "BC").generatePublic(new X509EncodedKeySpec(pub.getEncoded()));
        isEquals(brainpool, decoded.getParams().toString());

        AlgorithmParameters params = AlgorithmParameters.getInstance("EC", "BC");
        params.init(new ECGenParameterSpec("secp384r1"));
        isEquals("secp384r1 (1.3.132.0.34)", params.toString());

        params = AlgorithmParameters.getInstance("EC", "BC");
        params.init(pub.getParams());
        AlgorithmParameters decodedParams = AlgorithmParameters.getInstance("EC", "BC");
        decodedParams.init(params.getEncoded());
        isEquals(brainpool, decodedParams.toString());

        java.security.spec.ECParameterSpec explicit = new java.security.spec.ECParameterSpec(
            pub.getParams().getCurve(), pub.getParams().getGenerator(), pub.getParams().getOrder(), pub.getParams().getCofactor());
        params = AlgorithmParameters.getInstance("EC", "BC");
        params.init(explicit);
        isEquals(fp256, params.toString());

        isEquals("GOST3410 parameters [publicKeyParamSet=GostR3410-2001-CryptoPro-A (1.2.643.2.2.35.1), digestParamSet=1.2.643.2.2.30.1]",
            new GOST3410ParameterSpec("GostR3410-2001-CryptoPro-A").toString());
        isEquals("GOST3410 parameters [publicKeyParamSet=GostR3410-2001-CryptoPro-A (1.2.643.2.2.35.1), digestParamSet=1.2.643.2.2.30.1, encryptionParamSet=1.2.643.2.2.31.1]",
            new GOST3410ParameterSpec(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_A,
                CryptoProObjectIdentifiers.gostR3411_94_CryptoProParamSet, CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_A_ParamSet).toString());
    }

    private static ECNamedCurveSpec namedSpec(String name, ECNamedCurveParameterSpec spec)
    {
        return new ECNamedCurveSpec(name, spec.getCurve(), spec.getG(), spec.getN(), spec.getH(), spec.getSeed());
    }

    public String getName()
    {
        return "NamedCurve";
    }
    
    public void performTest()
        throws Exception
    {
        testCurve("prime192v1"); // X9.62
        testCurve("sect571r1"); // sec
        testCurve("secp224r1");
        testCurve("B-409");   // nist
        testCurve("P-521");
        testCurve("brainpoolP160r1");    // TeleTrusT

        for (Enumeration en = X962NamedCurves.getNames(); en.hasMoreElements();)
        {
            testECDSA((String)en.nextElement());
        }

        // these curves can't be used under JDK 1.5
        Set  problemCurves = new HashSet();

        problemCurves.add("secp256k1");
        problemCurves.add("secp160k1");
        problemCurves.add("secp224k1");
        problemCurves.add("secp192k1");
        
        for (Enumeration en = SECNamedCurves.getNames(); en.hasMoreElements();)
        {
            String curveName = (String)en.nextElement();

            if (!problemCurves.contains(curveName))
            {
                testECDSA(curveName);
            }
        }

        for (Enumeration en = TeleTrusTNamedCurves.getNames(); en.hasMoreElements();)
        {
            testECDSA((String)en.nextElement());
        }

        for (Enumeration en = ECGOST3410NamedCurves.getNames(); en.hasMoreElements();)
        {
            testECGOST((String)en.nextElement());
        }

        testAcceptable();
        testAdditional();
        testToString();
    }
    
    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());
    
        runTest(new NamedCurveTest());
    }
}

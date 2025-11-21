package org.bouncycastle.pqc.jcajce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.MLDSAProxyPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLDSAKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;

/**
 * MLDSA now in BC provider
 */
public class MLDSATest
    extends TestCase
{
    byte[] msg = Strings.toByteArray("Hello World!");

    static private final String[] names = new String[]{
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
        "ML-DSA-44-WITH-SHA512",
        "ML-DSA-65-WITH-SHA512",
        "ML-DSA-87-WITH-SHA512"
    };

    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        Security.addProvider(new BouncyCastleProvider());
    }

    public void testParametersAndParamSpecs()
        throws Exception
    {
        MLDSAParameters mldsaParameters[] = new MLDSAParameters[]
            {
                MLDSAParameters.ml_dsa_44,
                MLDSAParameters.ml_dsa_65,
                MLDSAParameters.ml_dsa_87,
                MLDSAParameters.ml_dsa_44_with_sha512,
                MLDSAParameters.ml_dsa_65_with_sha512,
                MLDSAParameters.ml_dsa_87_with_sha512
            };

        for (int i = 0; i != names.length; i++)
        {
            assertEquals(names[i], MLDSAParameterSpec.fromName(mldsaParameters[i].getName()).getName());
        }

        for (int i = 0; i != names.length; i++)
        {
            assertEquals(names[i], MLDSAParameterSpec.fromName(names[i]).getName());
        }
    }

    public void testKeyFactory()
        throws Exception
    {
        KeyFactory kFact = KeyFactory.getInstance("ML-DSA", "BC");
        KeyPairGenerator kpGen44 = KeyPairGenerator.getInstance("ML-DSA-44", "BC");
        KeyPair kp44 = kpGen44.generateKeyPair();
        KeyPairGenerator kpGen65 = KeyPairGenerator.getInstance("ML-DSA-65", "BC");
        KeyPair kp65 = kpGen65.generateKeyPair();
        KeyPairGenerator kpGen87 = KeyPairGenerator.getInstance("ML-DSA-87", "BC");
        KeyPair kp87 = kpGen87.generateKeyPair();
        KeyPairGenerator kpGen44withSha512 = KeyPairGenerator.getInstance("ML-DSA-44-WITH-SHA512", "BC");
        KeyPair kp44withSha512 = kpGen44withSha512.generateKeyPair();
        KeyPairGenerator kpGen65withSha512 = KeyPairGenerator.getInstance("ML-DSA-65-WITH-SHA512", "BC");
        KeyPair kp65withSha512 = kpGen65withSha512.generateKeyPair();
        KeyPairGenerator kpGen87withSha512 = KeyPairGenerator.getInstance("ML-DSA-87-WITH-SHA512", "BC");
        KeyPair kp87withSha512 = kpGen87withSha512.generateKeyPair();

        tryKeyFact(KeyFactory.getInstance("ML-DSA-44", "BC"), kp44, kp65, "2.16.840.1.101.3.4.3.18");
        tryKeyFact(KeyFactory.getInstance(NISTObjectIdentifiers.id_ml_dsa_44.toString(), "BC"), kp44, kp65, "2.16.840.1.101.3.4.3.18");
        tryKeyFact(KeyFactory.getInstance("ML-DSA-65", "BC"), kp65, kp44, "2.16.840.1.101.3.4.3.17");
        tryKeyFact(KeyFactory.getInstance(NISTObjectIdentifiers.id_ml_dsa_65.toString(), "BC"), kp65, kp44, "2.16.840.1.101.3.4.3.17");
        tryKeyFact(KeyFactory.getInstance("ML-DSA-87", "BC"), kp87, kp65, "2.16.840.1.101.3.4.3.18");
        tryKeyFact(KeyFactory.getInstance(NISTObjectIdentifiers.id_ml_dsa_87.toString(), "BC"), kp87, kp65, "2.16.840.1.101.3.4.3.18");
        tryKeyFact(KeyFactory.getInstance("ML-DSA-44-WITH-SHA512", "BC"), kp44withSha512, kp65, "2.16.840.1.101.3.4.3.18");
        tryKeyFact(KeyFactory.getInstance(NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512.toString(), "BC"), kp44withSha512, kp65, "2.16.840.1.101.3.4.3.18");
        tryKeyFact(KeyFactory.getInstance("ML-DSA-65-WITH-SHA512", "BC"), kp65withSha512, kp44, "2.16.840.1.101.3.4.3.17");
        tryKeyFact(KeyFactory.getInstance(NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512.toString(), "BC"), kp65withSha512, kp44, "2.16.840.1.101.3.4.3.17");
        tryKeyFact(KeyFactory.getInstance("ML-DSA-87-WITH-SHA512", "BC"), kp87withSha512, kp65, "2.16.840.1.101.3.4.3.18");
        tryKeyFact(KeyFactory.getInstance(NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512.toString(), "BC"), kp87withSha512, kp65, "2.16.840.1.101.3.4.3.18");
    }

    private void tryKeyFact(KeyFactory kFact, KeyPair kpValid, KeyPair kpInvalid, String oid)
        throws Exception
    {
        kFact.generatePrivate(new PKCS8EncodedKeySpec(kpValid.getPrivate().getEncoded()));
        kFact.generatePrivate(new PKCS8EncodedKeySpec(((MLDSAPrivateKey)kpValid.getPrivate()).getPrivateKey(true).getEncoded()));
        kFact.generatePrivate(new PKCS8EncodedKeySpec(((MLDSAPrivateKey)kpValid.getPrivate()).getPrivateKey(false).getEncoded()));
        kFact.generatePublic(new X509EncodedKeySpec(kpValid.getPublic().getEncoded()));

        try
        {
            kFact.generatePrivate(new PKCS8EncodedKeySpec(kpInvalid.getPrivate().getEncoded()));
            fail("no exception");
        }
        catch (InvalidKeySpecException e)
        {
            assertEquals("incorrect algorithm OID for key: " + oid, e.getMessage());
        }
        try
        {
            kFact.generatePublic(new X509EncodedKeySpec(kpInvalid.getPublic().getEncoded()));
            fail("no exception");
        }
        catch (InvalidKeySpecException e)
        {
            assertEquals("incorrect algorithm OID for key: " + oid, e.getMessage());
        }
    }

    public void testPrivateKeyRecovery()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");

        kpg.initialize(MLDSAParameterSpec.ml_dsa_65, new MLDSATest.RiggedRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("ML-DSA", "BC");

        MLDSAKey privKey = (MLDSAKey)kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(privKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        MLDSAKey privKey2 = (MLDSAKey)oIn.readObject();

        assertEquals(privKey, privKey2);

        assertEquals(kp.getPublic(), ((MLDSAPrivateKey)privKey2).getPublicKey());
        assertEquals(((MLDSAPrivateKey)privKey).getPublicKey(), ((MLDSAPrivateKey)privKey2).getPublicKey());
    }

    public void testDefaultPrivateKeyEncoding()
        throws Exception
    {
        KeyPairGenerator kpGen44 = KeyPairGenerator.getInstance("ML-DSA-44", "BC");

        byte[] seed = Hex.decode("000102030405060708090a0b0c0d0e0f" + "100102030405060708090a0b0c0d0e0f");

        kpGen44.initialize(MLDSAParameterSpec.ml_dsa_44, new FixedSecureRandom(seed));
        KeyPair kp44 = kpGen44.generateKeyPair();

        PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(kp44.getPrivate().getEncoded());
        ASN1OctetString seq = ASN1OctetString.getInstance(ASN1Sequence.getInstance(privInfo.getPrivateKey().getOctets()).getObjectAt(0));

        assertTrue(Arrays.areEqual(seq.getOctets(), seed));

        ASN1OctetString privData = ASN1OctetString.getInstance(ASN1Sequence.getInstance(privInfo.getPrivateKey().getOctets()).getObjectAt(1));

        assertTrue(Arrays.areEqual(privData.getOctets(), ((MLDSAPrivateKey)kp44.getPrivate()).getPrivateData()));
    }

    public void testSeedPrivateKeyEncoding()
        throws Exception
    {
        KeyPairGenerator kpGen44 = KeyPairGenerator.getInstance("ML-DSA-44", "BC");

        byte[] seed = Hex.decode("000102030405060708090a0b0c0d0e0f" + "100102030405060708090a0b0c0d0e0f");

        kpGen44.initialize(MLDSAParameterSpec.ml_dsa_44, new FixedSecureRandom(seed));
        KeyPair kp44 = kpGen44.generateKeyPair();

        PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(((MLDSAPrivateKey)kp44.getPrivate()).getPrivateKey(true).getEncoded());

        ASN1OctetString k = privInfo.getPrivateKey();

        assertTrue(Arrays.areEqual(ASN1OctetString.getInstance((ASN1TaggedObject)privInfo.parsePrivateKey(), false).getOctets(), seed));
    }

    public void testExpandedKeyPrivateKeyEncoding()
        throws Exception
    {
        KeyPairGenerator kpGen44 = KeyPairGenerator.getInstance("ML-DSA-44", "BC");

        byte[] seed = Hex.decode("000102030405060708090a0b0c0d0e0f" + "100102030405060708090a0b0c0d0e0f");
        byte[] expandedKey = Base64.decode("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");

        kpGen44.initialize(MLDSAParameterSpec.ml_dsa_44, new FixedSecureRandom(seed));
        KeyPair kp44 = kpGen44.generateKeyPair();
        
        PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(((MLDSAPrivateKey)kp44.getPrivate()).getPrivateKey(false).getEncoded());

        assertTrue(Arrays.areEqual(ASN1OctetString.getInstance(privInfo.parsePrivateKey()).getOctets(), expandedKey));
    }

    public void testPrivateKeyRecoding()
        throws Exception
    {
        // TODO: rebuild with newer encodings.
//        byte[] mldsa44_sequence = Base64.decode("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");
        byte[] mldsa44_seed_only = Base64.decode("MDICAQAwCwYJYIZIAWUDBAMRBCAAAQIDBAUGBwgJCgsMDQ4PEAECAwQFBgcICQoLDA0ODw==");
        byte[] mldsa44_wrap_seed_only = Base64.decode("MDQCAQAwCwYJYIZIAWUDBAMRBCIEIAABAgMEBQYHCAkKCwwNDg8QAQIDBAUGBwgJCgsMDQ4P");
        byte[] mldsa44_expanded_only = Base64.decode("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");
//        byte[] mldsa44_wrap_expanded_only = Base64.decode("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");
//        byte[] mldsa44_seed_with_pub_key = Base64.decode("MIIFVwIBATALBglghkgBZQMEAxEEIAABAgMEBQYHCAkKCwwNDg8QAQIDBAUGBwgJCgsMDQ4PgYIFIQDD8Wh9s95rjkA8Ad5Co15kvgpy8wevxX+Kc2xRuZiUTcEHWDP0MI8enUbboCTOE020U+28L6HkQZZ4JzkhORY54IkHcSKSRcKkiNkLdbm9jWKOEiQAWKuYJyQ3dcbNWa4ogK+E4LsT2jHguWA/rmSJ42Azys2/d+kIMTmmKt3Y2PyiWU5zzj/2TNOQUHaHuJhAmXAT7iCrcEz+6vCsH/dKQrcVjMjIfbibRyRMLZIrLhqXqV4vboYE/yu9jzNRUGQH5rmenF+wDtnvu7YNO/2hWYRZJKrbTgy+nuBEBAkCKorHWVaGJvmXcEPSodB+5cRIQ5+uCCswH1lJT00+SzKsCacs68iBFcte5TkAOwTzq7slL1lAptILPkzwAhNhqKGCVz4B+qRiB6CK8917el2ioTKPxyHBtgHTKPIEoIdRAgi0+uaVBPAQ21VUlYDcILBd0mAH/7rxXsIdfq5PmklvIVD0VNxeDmwIbQH0J/LNr9kKCfmHSAXgZ3Vh/DQa2eVukKv7PZiBGSCyBHukEFK+791XNCydlSNsJkvz+xvp5cEkAseNxGJoUigCW4a5r2FV37JD9FQE6PDeCrKSL428p8vMl4Vpp6I+G90JuVv7+c0ShDh9n/PdnF/hC3v9uHso/COKsYvaKN4CIo9pwiyrm44XLuDSoX+F8DcmmaLYcEqW+o06/mVz5+dTSSrWZgiXqkIkPFI44AgwC/21SI9piGtdXouzcjxmIrgg1n1utPGESQXE2xxd3AkYJtVnPpdvMoEv/MSN2OMl5LGeO0DhPD4rdRYkT1HnT1/dbb5QoKpWHBiUgxTb2xJGzljMMaFooPi9mQiUas1fSjGk/7gNKgfi88nR8HiAPm5me3NGfxcS3plrI1UewwB9ubOOBfAQiRYQI2w5ax12ygyiPSS8ekYLv1HD2TfpfdVzwIQhWYnYWDls6WhW+sJ15Al5QJ3kGe2fIQflEH6196P5Xo/4Kmv1A02jzeN3KSPb/KutI8HM4TXWAgsQX+7XmH+zzS3lXqdjRhhQ0RQ9HK4HFZ2OFw9/2KhsbR0vMIcsc0VB0zsx096ZIgMynAbyQ5rI3mFeKM7n+CD4m5KXMYSupfesNv9e8Of/FROnwR9It9N2BzQVcLWwiMuwYiqgchfUfmZFWcD2if5e23xuSt/t8hYReU/I2SydkhzTUNfwbELIkjcsxwWVkpYFIf7rT2i5Atkl6auBag5Eg/fjEuiR7RsFS1C/AcHx5lxqqbckZ/eXinG7kPDw9ZSpjHki4/PeKTeviCs4aOGtLC9kexDAU++k2cFQe7fqbUHST+eENU2m9HQ1/WfUt1426wDUdYZTqInnvk/PjUbkvE0RNbFzS+0w9Qsnh28YfLXRt/j+IcZhG4buivL2G0N/UqHtwWpyh3Wigic5tqpMaTZ54RN1/jJWmsQS3rvd8rHaZPk2CbH0Iss1PrcROzksogqZBQn4Y1zwDsF6yqdscqaMJXmH5+7REdQACUTCzU2Qj4x59doVByXnKY+Of8fAB1XTjurYgq8DrbKnzfUThC3zEodT/HTcLdP7gEIhPizDQYxNA6LlGUxGzpy7+iMs3j38WiSbToASbB1dCsFtR7Jp0P8qc9LJmX36CW87JON1pEVaTCth/HQS8AXUsGU7HSorD/CkCwehxKlABcRbpPTIZC/dtR9LkrkI5T9AyTWMDS2pPzICo+PUhOOkU3pSKS6o20VnvZtj2uU8M31K6I16H5KbqXMr");

        KeyFactory kFact = KeyFactory.getInstance("ML-DSA", "BC");

//        checkEncodeRecode(kFact, mldsa44_sequence);
        checkEncodeRecode(kFact, mldsa44_seed_only);
        checkEncodeRecode(kFact, mldsa44_wrap_seed_only);
        checkEncodeRecode(kFact, mldsa44_expanded_only);
//        checkEncodeRecode(kFact, mldsa44_wrap_expanded_only);
//        checkEncodeRecode(kFact, mldsa44_seed_with_pub_key);
    }

    private void checkEncodeRecode(KeyFactory kFact, byte[] encoding)
        throws Exception
    {
        PrivateKey key = kFact.generatePrivate(new PKCS8EncodedKeySpec(encoding));

        assertTrue(Arrays.areEqual(encoding, key.getEncoded()));
    }


    public void testPublicKeyRecovery()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");

        kpg.initialize(MLDSAParameterSpec.ml_dsa_87, new MLDSATest.RiggedRandom());

        KeyPair kp = kpg.generateKeyPair();

        KeyFactory kFact = KeyFactory.getInstance("ML-DSA", "BC");

        MLDSAKey pubKey = (MLDSAKey)kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        assertEquals(kp.getPublic().hashCode(), pubKey.hashCode());

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(pubKey);

        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        MLDSAKey pubKey2 = (MLDSAKey)oIn.readObject();

        assertEquals(pubKey, pubKey2);
        assertEquals(pubKey.hashCode(), pubKey2.hashCode());
    }

    public void testRestrictedSignature()
        throws Exception
    {
        doTestRestrictedSignature("ML-DSA-44", MLDSAParameterSpec.ml_dsa_44, MLDSAParameterSpec.ml_dsa_87);
        doTestRestrictedSignature("ML-DSA-65", MLDSAParameterSpec.ml_dsa_65, MLDSAParameterSpec.ml_dsa_87);
        doTestRestrictedSignature("ML-DSA-87", MLDSAParameterSpec.ml_dsa_87, MLDSAParameterSpec.ml_dsa_44);
        doTestRestrictedSignature("ML-DSA-44-WITH-SHA512", MLDSAParameterSpec.ml_dsa_44_with_sha512, MLDSAParameterSpec.ml_dsa_87);
        doTestRestrictedSignature("ML-DSA-65-WITH-SHA512", MLDSAParameterSpec.ml_dsa_65_with_sha512, MLDSAParameterSpec.ml_dsa_87);
        doTestRestrictedSignature("ML-DSA-87-WITH-SHA512", MLDSAParameterSpec.ml_dsa_87_with_sha512, MLDSAParameterSpec.ml_dsa_44);
    }

    private void doTestRestrictedSignature(String sigName, MLDSAParameterSpec spec, MLDSAParameterSpec altSpec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");

        kpg.initialize(spec, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance(sigName, "BC");

        sig.initSign(kp.getPrivate(), new SecureRandom());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig = Signature.getInstance(sigName, "BC");

        assertEquals(sigName, sig.getAlgorithm());

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));

        kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");

        kpg.initialize(altSpec, new SecureRandom());

        kp = kpg.generateKeyPair();

        try
        {
            sig.initVerify(kp.getPublic());
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("signature configured for " + spec.getName(), e.getMessage());
        }
    }

    /*
    public void testMLDSA()
        throws Exception
    {

        KeyPairGenerator kpGen44 = KeyPairGenerator.getInstance("ML-DSA-44");
        KeyPair kp44 = kpGen44.generateKeyPair();
        KeyPairGenerator kpGen65 = KeyPairGenerator.getInstance("ML-DSA-65");
        KeyPair kp65 = kpGen65.generateKeyPair();
        KeyPairGenerator kpGen87 = KeyPairGenerator.getInstance("ML-DSA-87");
        KeyPair kp87 = kpGen87.generateKeyPair();

        outputKeyPair("ml-dsa-44", kp44);
        outputKeyPair("ml-dsa-65", kp65);
        outputKeyPair("ml-dsa-87", kp87);
    }

    private void outputKeyPair(String algorithm, KeyPair kp)
        throws Exception
    {
        KeyFactory kFact = KeyFactory.getInstance("ML-DSA", "BC");

        System.setProperty("seed", "true");
        System.setProperty("expanded", "true");
        FileWriter fWrt = new FileWriter("/tmp/ml-dsa-pems/" + algorithm + "-priv.pem");

        PemWriter pWrt = new PemWriter(fWrt);

        pWrt.writeObject(new PemObject("PRIVATE KEY", kp.getPrivate().getEncoded()));

        pWrt.close();

        PrivateKey priv = kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        System.setProperty("seed", "true");
        System.setProperty("expanded", "false");
        fWrt = new FileWriter("/tmp/ml-dsa-pems/" + algorithm + "-seed-only-priv.pem");

        pWrt = new PemWriter(fWrt);

        pWrt.writeObject(new PemObject("PRIVATE KEY", priv.getEncoded()));

        pWrt.close();

        priv = kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        System.setProperty("seed", "false");
        System.setProperty("expanded", "true");
        fWrt = new FileWriter("/tmp/ml-dsa-pems/" + algorithm + "-expanded-only-priv.pem");

        pWrt = new PemWriter(fWrt);

        pWrt.writeObject(new PemObject("PRIVATE KEY", priv.getEncoded()));

        pWrt.close();

        fWrt = new FileWriter("/tmp/ml-dsa-pems/" + algorithm + "-pub.pem");

        pWrt = new PemWriter(fWrt);

        pWrt.writeObject(new PemObject("PUBLIC KEY", kp.getPublic().getEncoded()));

        pWrt.close();
    }
      */
    
    public void testRestrictedKeyPairGen()
        throws Exception
    {
        doTestRestrictedKeyPairGen(MLDSAParameterSpec.ml_dsa_44, MLDSAParameterSpec.ml_dsa_87);
        doTestRestrictedKeyPairGen(MLDSAParameterSpec.ml_dsa_65, MLDSAParameterSpec.ml_dsa_87);
        doTestRestrictedKeyPairGen(MLDSAParameterSpec.ml_dsa_87, MLDSAParameterSpec.ml_dsa_44);
        doTestRestrictedKeyPairGen(MLDSAParameterSpec.ml_dsa_44_with_sha512, MLDSAParameterSpec.ml_dsa_87);
        doTestRestrictedKeyPairGen(MLDSAParameterSpec.ml_dsa_65_with_sha512, MLDSAParameterSpec.ml_dsa_87);
        doTestRestrictedKeyPairGen(MLDSAParameterSpec.ml_dsa_87_with_sha512, MLDSAParameterSpec.ml_dsa_44);
    }

    private void doTestRestrictedKeyPairGen(MLDSAParameterSpec spec, MLDSAParameterSpec altSpec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.getName(), "BC");

        kpg.initialize(spec, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        assertEquals(spec.getName(), kpg.getAlgorithm());
        assertEquals(spec.getName(), kp.getPublic().getAlgorithm());
        assertEquals(spec.getName(), kp.getPrivate().getAlgorithm());

        kpg = KeyPairGenerator.getInstance(spec.getName(), "BC");

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

    public void testMLDSARandomSig()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");

        kpg.initialize(MLDSAParameterSpec.ml_dsa_44, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("ML-DSA", "BC");

        sig.initSign(kp.getPrivate(), new SecureRandom());

        sig.update(msg, 0, msg.length);

        byte[] s = sig.sign();

        sig = Signature.getInstance("ML-DSA", "BC");

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));
    }

    public void testMLDSARandomMsgAndMuSig()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");

        kpg.initialize(MLDSAParameterSpec.ml_dsa_44, new SecureRandom());

        final KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("ML-DSA-CALCULATE-MU", "BC");

        sig.initSign(kp.getPrivate(), new SecureRandom());

        sig.update(msg, 0, msg.length);

        byte[] mu = sig.sign();

        sig = Signature.getInstance("ML-DSA-EXTERNAL-MU", "BC");

        sig.initSign(kp.getPrivate(), new SecureRandom());

        sig.update(mu, 0, mu.length);

        byte[] s = sig.sign();

        sig = Signature.getInstance("ML-DSA", "BC");

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));

        sig = Signature.getInstance("ML-DSA-EXTERNAL-MU", "BC");

        sig.initVerify(kp.getPublic());

        sig.update(mu, 0, mu.length);

        assertTrue(sig.verify(s));

        sig = Signature.getInstance("ML-DSA-CALCULATE-MU", "BC");

        sig.initSign(new MLDSAProxyPrivateKey(kp.getPublic()));

        sig.update(msg, 0, msg.length);

        byte[] mu2 = sig.sign();

        assertTrue(Arrays.areEqual(mu, mu2));
    }

    public void testMLDSAMuKatTest()
        throws Exception
    {
        byte[] pk = Hex.decode("3BB5567D7049939D8A5911BBE1FEC62843DAD05447BFC37CEF917C431DD20B8EE32A985C4F681DB63186FCB455A9163559301728E6F03F9C915FBF48571CF7DC76B1D1373B1C57B1C479DCAF136EE893D04B8E8C3A86D28483E84CB6814A17DDE3FE4152B69ADFBFD40B1AF8D4CD66101070B9979E6EEEFD4ED21111D129FE959E39E8C00311EA624A54F3340FC6BE06A0A826A3E74DD4161FC9EEF6097562316E62BBAF4D482732BABBB1C5132B86C8D7D733DC9595DDB93EF6BF5D79A860885D3F3BE31908787587A99D84017D00E814E4F697F2688ADF3967AB05F61C0D0F02BD5B8C4EA51010103265F49F90F2D1D5DE55305B59CB3658146F1696F12EE25875136A234E35F10B7BE95FCCDAD326D9CEDCF64F7DA0E9F0697A9A04E4C7237CDFBAAFC6974DA04D158EA2CDC7A3F87CE0E5BE9DCD54ED84ABAFC6C9889C3427A904C2DFF70581E1BF0F544BC1954AAC852DFAB032D140AC94CACE5889DFD43BF9DB490CDF3342C15E4F88EC5F16B789828367A488CFAA6FED1E94322759EAAA211041444D10ACF8E1DF1EF840B68412603DA6BBC4FE69C8D2627C032A266475B1314119D843F54689300EAC933060D0A7106EDF58CC6B1F313B8FDE024C0179E7B67B08CC030B7B3BC610E9C2A60BFDEE54A1D5E0F53E8533456AEB4D0978DA9C7E904AC31B676222C9369D3FC74EDC8642C4F3C19E31B14F1E5EB3FCA413478E5B03DA9FB50755EECD2F0F513502232367A12A02A0B1B86C9FA8FD2990B8A7296818F9DA6E70228AC8BBC55A9374E1719BA180A29147CC1E379CF10FAFDF6FB0FFBB35CD033FBB6660042F9A61AEFBFBF6ECDBB146A3233644D5596AF68CE3C89BB77E75D60D2D044400374179483B3DC65FC029246A9C950D5AA4825C359B45EFB7B24E36C0A0B2592BD50F992484D170F4C3D77F8F7755D86FF1DE21332A7D1F70D069DAD0CFF4B4B3BBBC6A535C48E0262333AA87C22DD70D07610EA105D506BFCA77283B64C262F2A38FAAE68E96B9491A229B0A2FC6BF967F2C2DDDA1A8804F5B6E37C2AEFB768B33DC1D05B0E3C86BD4F799346101B2E44BCA78AF5CB50C8F57B104F054054CF2975DEFB661A8BE18BAA9296D3372B1460338F58E6B9CDCCF25CE371B3BF39E90E9B35037BE4F24BEA1ACF75A643ABD19E7D312DF45F27E04CD3D94E1569029F1EBB806E2617252263BD10EE898B90526675A42B90FB64F4C5B0F18B3446049B2F85BD1DD526E7AC5C41E3DF0F0920EAFAF804B808FF0E5B2E064BB39909AD39FB3BED06D1A97288A1D7F7B8EBBCD257869B736B87E18990E0E7DB4E2EB70FDE0B9B235DB741161C68F71E2C1AE9525AC68569D3AAD61584EE29EE5581C0F67439B9F1DE7EC65073929D08119A45B6C10028CC34132E57F8B969D4195095E891276822C83FA6AD3743B1F3597AE188A0324AF4C198995246338533123092A80F4B40D557B7AEF5CAA6C9F65B03E86A9D580370659F2BD76D1A79468BBE725E07CD67E0094CEB4D8CAC55C76B6AAE7C9DA8B7CD851679105B9934D8F8C5CE2F69124AC41EC8E8F4470AD4CCAA55C7F3533558D366D5A78410B4232927CAACA135166CD0792D9CDD595711633DADC81685939D1107AC085919534747095FD24026031480CC5E16BBA2A7083B0E94D3C67EF3901B30E1BF8645A96EC8DE67999E985EECD714603371C854F90F7545A45C455154E596BB9406769935022133B9195106AD5BB1BEDADF9BC05518E480832F6C961FF35F8B1C6D030CAE8CC9D47C8B573B6F8CD06510D9D9C33505EB9080089F41434E5695759B4641B2F06F33B4C8EAEA86116B7A45422FBB1E1FC0AF4C75CCFB94DEA99");
        byte[] mu = Hex.decode("ACFA27834894431BAA18EB0353DA5383BCFD8585E60F1A4382566E0D85E0519F67084AC615088A85074D901D8DBD36AE487B23281E1172F6C03C8CD31A4B683B");
        byte[] sig = Hex.decode("146E97D0704552E762FBF3B0387C255B381D84A1B98EACAF572E71EB0317133758BBF3631CA6C3412238327AEA511432CCF868841BC7F71E484DDB8158E20687AFA3381DC14B96E045036AF004955CF7C9BC9DBCDD3EE558C73E9E16AAD91603E0D839294684B358559F0B2278B5ABB6224395E02849CD7E4DC52805058809674D9CC79744A25436AFBBEB77784F6F85ABF315E963794270C763128F5EDB8E390E0CD2328B868FF6AEE3BC1DE73DC66DBD9D967E9BD1E0E96008C8678C5C28ED73349C297E86DEFC00653E97D873DD6443E4164A0D5231E8C9EFB4EA2F068FECA57BDAEA4A7989C96ED307A578013F705073E875B045CDDF8D131DC6A72DD4EB63495C0DDF53706EB43E44B7B4FAD7C835CB6E9C0D771894A11289A43D3454E4FC8301C9CEC180EAD4B763D332E4760CFE2DDCA5893D0190E6BB7E36E9B596AE714B5B30C65BA0B0675595BDED190BCEA2450063BA157E4CE7DAC45F66FC270BB0608C82196F5EAC4B53C5E2F8C59C3D18222428F935EB3F4E54C1FE7DE4BFDE305C2AFC36C91894387DDDC957C4D2737E9FCDE5C7CAE453A4C45D4FE10A811C78179D6DDB4E33F5E374245EBC3D3DEA4351C8F55E10CD0F79B70010E897BD3F376F7693937F2DF58A7BAB9A0AF5595E3383C426DEC394EBE410C026A2F3E6B2E8200BDAAF15F33DFA4ADEBD59F386AE6C8F097E1183CA9577FFC008C710705DC73A87B6EDBACC23CC8C4FE652916CF8DDFFBACB92EF6BAA668E5772A0A06A2F4DE1F307ABDF6A028BE7F82ECECDA72A411CFBF377B1B3B2AB731563611F8BC933478913A8C1FFF1BB7C76F7B6E55125A41A4FC12C306349546AEA527FA24C0815AAAF8AA3E5367654A6B2BBC886804F25A57E64EAFC0E1D3F805979500A7EF16AE8F0A6E13A3DB3B72A9A91B9D11D9C1A19A0300663C7E931A4AD5EB503EE6F4F7264B66C43C98AB26A5DC42BEFEBC5CAEDC08F7B328C5556B904AA173867737AB3EAEA09722680DF5CB5EF3A1C0D549731EF800D0C72AE8D90BD6C21BB4F4F0E2F4147181C4054F29EAB4A0AFCA49E7406C1A711F38659A638646E5CB3C142747EF843F6517A905F70BD93818816641A45C894E2D44E6CAB7DA0524C9998AF62EF0047CE1A7C5EDD490938402FB1B7015273FBDEB85E536946F0AB7051062536ACD21BAD2311E4A45AF17714426645293EF0D6266DB59692DD99286ABA0C9C77581ECE32CC4C7FBFABA55D719E35E68FC0A6C7031F999BB08153C2501FD61BEA99198DEF0C514A6A1A8FF6E5D9411BC0B7BD2B66E364AF51D007F49DC9E2A756396B1842BF6FCDDF0A2F9E8AF485AB8AF4653FB1F9570E99633DD4914624177CF3D2027053B0BA0D60FBCFEF92EAD69494C56D2717C427666AA313884FAC83BC42DAF224826E127F4B33A6340DEB52942E2792D90023FEBFC935E5B18C6EC8B2A6861C3F2C929A3FFA38C2DD23A97EBAA2CC694199BE95E93BDA5C4CBD13712D03A0C3CDC1F0A1C9B64A88F0E752A167F8F093077CA73B538A8738EA7F2B878A29FAA7D42266FCE8CF16A9BB413FD50FCF6057F77E16C916704AE7622AF72D666AD06C2596E9CE3A297786C134A430441958484EB058C8DB19D1A6E788336D67D52E877CEB4C9F204E4D995FE2685AAB6EEFCFA6D0FD1D61B0C8F532953B32642A34657BFBAD90B8F0C85A821054770C6A2E27D8CE315618DB82EA24A1D486C12934EBC9133F38B72481748B8C9D432A3D1E1AF85DEFB2BEE0C155006BE17E879811E2FE08A337D54A03E5884384000DE817A3D9BBE94941A52A58ECE851F605B9F69E1C3112CFF92AB332D6E694A65EFD58ED61F57F84947A75A5C9776A9A7FD187C5015425ED708DC242CDAA30BEE759BBD9CBB046DF3F4D54F481208216AF5CA7892150DD9829A3AB540BBFCFC2E303E9205ABB4D65D7287B5BBCC85F8987AD7B182058E36DA5C37FE5658138ED49D65B11B67360A1FEE9E44D2D2C3164BEF63B426DB495540B383AAE5F54283F91B1E543F7F965289CB9F64928E6AC208D9791DE234ABA43FC2B44D89317277136F791C782A773340998C526015C0415211676F53BDCE809974D6450E39CA2C814F644D75CB4F349D28EDF08B1CE58616D16816B4C021C5F16CCD5FB539BEFA6C9F03704FFE1010589350C20AE319545B0E39AE7CAA7FCED9A3D2151ACF6CBAB5FBB0D0E83313A45E6209046BF1A89D5F808969CC62167B014E969EAD6B2088B7738FAB3D277D1CDD6F4C6816B847AD1D30083F77564CABEB55CB4A8BB8C6BD47A59B6772DCCC8431A01C04184965B8F25BF8333281AC7686852FAFD77B374E76D8839CFE1F594E212531325F0CD6F8C2853194B4D668F843776F0E563E00CBBE6F5D6EBE4EBC11A5F70D3872F669939BD4A21A26FCD836DB79EC271CB463A521264DD62CD0A664B1EF3D7B4C84793F2B9C36369BEB651858CA9D5DCA23D6F8137C6C1F96FEE19DD3A4CD08A4FD4CD579F0F994E302A62F37121189B2A61E8591A98E0396766047B77E8D4533E62891B77AD0F7607DC0AF1D7D327E8E7B45991A508B5B22FD3398BEA7F80966EBEF5A1ACF9F5FCCF9C0C6E61A05DBB583EB048CAA41C28E87530820D21E90BFD2CFF29C8FEC2F7F1FC90605F2C84553A709CB9F53C1BDF12DC20524E76870ACB7624AD238B5BB8EEC8D5D37F02F12D1DF2384E7EC70CFDCC25831305682080326E702795ABFC6DF60BE923AB245887A35EB5EC00B7A109F86A8F7DCF2E59DBD8C4C9D645588F4D25C768F499C3FA65C98FEB48B07A4B01C7AF8AF28ADBC5C487A5C1FB059EF91B3A77C8321126978B5EAD648BB96C6210C6EF505B6E40098E415E0324D1CCD0A5B0560455BA894AD84CFA8E9B37706EFC23B00513BA3D6DF77D38E203AAD4E718286BE73A729C7CB2CB2EEC65726EA48E657DA31A548972B21642C01512421A21E2A4151A995CDC2DA9A7602E747CB62C893D555BA4455ACD880282459257622B370F3AEE7C99C2D8CD31050E6F1050340EB287BE92133C2479F07780ED355CC124FBDD2C7ADC2A129DA3A99C964F1BB32B5609C36ABB69AFABC0F1445362DFBE2A381C3D88973EDFF9D98ECD0E5EDA94D394B784ABC97470283FBB87403A5DCD4BCF55F24F4368BDE39E63E3C906FD2EA6C4103EF571FCD269700472C761B2E2C52F9F10C195C7947AE378B40724499C8EB3AE5ED4B3B06DCE02F29424662BF209AA14D39C1EEC5E3E5DE7B7CADFD1D8ED9D0AA552FF54353F0E9BD1CD02965A47D83F1359BE6FE0C0144BC0EA8BD2C37CAB4DFBEEB31833F4146316023C4D556C7C8093C3CAD4E7040B122B375963767893A9B4DEE5EDEEFAFC0409121A326F7072A2ACD5DCEEF1F2F4FD051E26373B3F464B97999A9B9FA4ABC9E2FDFE00000000000000000000000000000C1E2F42");

        KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA-44", "BC");

        SubjectPublicKeyInfo mlDsaInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(NISTObjectIdentifiers.id_ml_dsa_44), pk);

        Signature sigImpl = Signature.getInstance("ML-DSA-EXTERNAL-MU", "BC");

        sigImpl.initVerify(keyFactory.generatePublic(new X509EncodedKeySpec(mlDsaInfo.getEncoded())));

        sigImpl.update(mu, 0, mu.length);

        assertTrue(sigImpl.verify(sig));
    }

    public void testMLDSAMuExceptionTest()
        throws Exception
    {
        // mu shortened by 1 byte
        byte[] mu = Hex.decode("FA27834894431BAA18EB0353DA5383BCFD8585E60F1A4382566E0D85E0519F67084AC615088A85074D901D8DBD36AE487B23281E1172F6C03C8CD31A4B683B");
        byte[] sig = Hex.decode("146E97D0704552E762FBF3B0387C255B381D84A1B98EACAF572E71EB0317133758BBF3631CA6C3412238327AEA511432CCF868841BC7F71E484DDB8158E20687AFA3381DC14B96E045036AF004955CF7C9BC9DBCDD3EE558C73E9E16AAD91603E0D839294684B358559F0B2278B5ABB6224395E02849CD7E4DC52805058809674D9CC79744A25436AFBBEB77784F6F85ABF315E963794270C763128F5EDB8E390E0CD2328B868FF6AEE3BC1DE73DC66DBD9D967E9BD1E0E96008C8678C5C28ED73349C297E86DEFC00653E97D873DD6443E4164A0D5231E8C9EFB4EA2F068FECA57BDAEA4A7989C96ED307A578013F705073E875B045CDDF8D131DC6A72DD4EB63495C0DDF53706EB43E44B7B4FAD7C835CB6E9C0D771894A11289A43D3454E4FC8301C9CEC180EAD4B763D332E4760CFE2DDCA5893D0190E6BB7E36E9B596AE714B5B30C65BA0B0675595BDED190BCEA2450063BA157E4CE7DAC45F66FC270BB0608C82196F5EAC4B53C5E2F8C59C3D18222428F935EB3F4E54C1FE7DE4BFDE305C2AFC36C91894387DDDC957C4D2737E9FCDE5C7CAE453A4C45D4FE10A811C78179D6DDB4E33F5E374245EBC3D3DEA4351C8F55E10CD0F79B70010E897BD3F376F7693937F2DF58A7BAB9A0AF5595E3383C426DEC394EBE410C026A2F3E6B2E8200BDAAF15F33DFA4ADEBD59F386AE6C8F097E1183CA9577FFC008C710705DC73A87B6EDBACC23CC8C4FE652916CF8DDFFBACB92EF6BAA668E5772A0A06A2F4DE1F307ABDF6A028BE7F82ECECDA72A411CFBF377B1B3B2AB731563611F8BC933478913A8C1FFF1BB7C76F7B6E55125A41A4FC12C306349546AEA527FA24C0815AAAF8AA3E5367654A6B2BBC886804F25A57E64EAFC0E1D3F805979500A7EF16AE8F0A6E13A3DB3B72A9A91B9D11D9C1A19A0300663C7E931A4AD5EB503EE6F4F7264B66C43C98AB26A5DC42BEFEBC5CAEDC08F7B328C5556B904AA173867737AB3EAEA09722680DF5CB5EF3A1C0D549731EF800D0C72AE8D90BD6C21BB4F4F0E2F4147181C4054F29EAB4A0AFCA49E7406C1A711F38659A638646E5CB3C142747EF843F6517A905F70BD93818816641A45C894E2D44E6CAB7DA0524C9998AF62EF0047CE1A7C5EDD490938402FB1B7015273FBDEB85E536946F0AB7051062536ACD21BAD2311E4A45AF17714426645293EF0D6266DB59692DD99286ABA0C9C77581ECE32CC4C7FBFABA55D719E35E68FC0A6C7031F999BB08153C2501FD61BEA99198DEF0C514A6A1A8FF6E5D9411BC0B7BD2B66E364AF51D007F49DC9E2A756396B1842BF6FCDDF0A2F9E8AF485AB8AF4653FB1F9570E99633DD4914624177CF3D2027053B0BA0D60FBCFEF92EAD69494C56D2717C427666AA313884FAC83BC42DAF224826E127F4B33A6340DEB52942E2792D90023FEBFC935E5B18C6EC8B2A6861C3F2C929A3FFA38C2DD23A97EBAA2CC694199BE95E93BDA5C4CBD13712D03A0C3CDC1F0A1C9B64A88F0E752A167F8F093077CA73B538A8738EA7F2B878A29FAA7D42266FCE8CF16A9BB413FD50FCF6057F77E16C916704AE7622AF72D666AD06C2596E9CE3A297786C134A430441958484EB058C8DB19D1A6E788336D67D52E877CEB4C9F204E4D995FE2685AAB6EEFCFA6D0FD1D61B0C8F532953B32642A34657BFBAD90B8F0C85A821054770C6A2E27D8CE315618DB82EA24A1D486C12934EBC9133F38B72481748B8C9D432A3D1E1AF85DEFB2BEE0C155006BE17E879811E2FE08A337D54A03E5884384000DE817A3D9BBE94941A52A58ECE851F605B9F69E1C3112CFF92AB332D6E694A65EFD58ED61F57F84947A75A5C9776A9A7FD187C5015425ED708DC242CDAA30BEE759BBD9CBB046DF3F4D54F481208216AF5CA7892150DD9829A3AB540BBFCFC2E303E9205ABB4D65D7287B5BBCC85F8987AD7B182058E36DA5C37FE5658138ED49D65B11B67360A1FEE9E44D2D2C3164BEF63B426DB495540B383AAE5F54283F91B1E543F7F965289CB9F64928E6AC208D9791DE234ABA43FC2B44D89317277136F791C782A773340998C526015C0415211676F53BDCE809974D6450E39CA2C814F644D75CB4F349D28EDF08B1CE58616D16816B4C021C5F16CCD5FB539BEFA6C9F03704FFE1010589350C20AE319545B0E39AE7CAA7FCED9A3D2151ACF6CBAB5FBB0D0E83313A45E6209046BF1A89D5F808969CC62167B014E969EAD6B2088B7738FAB3D277D1CDD6F4C6816B847AD1D30083F77564CABEB55CB4A8BB8C6BD47A59B6772DCCC8431A01C04184965B8F25BF8333281AC7686852FAFD77B374E76D8839CFE1F594E212531325F0CD6F8C2853194B4D668F843776F0E563E00CBBE6F5D6EBE4EBC11A5F70D3872F669939BD4A21A26FCD836DB79EC271CB463A521264DD62CD0A664B1EF3D7B4C84793F2B9C36369BEB651858CA9D5DCA23D6F8137C6C1F96FEE19DD3A4CD08A4FD4CD579F0F994E302A62F37121189B2A61E8591A98E0396766047B77E8D4533E62891B77AD0F7607DC0AF1D7D327E8E7B45991A508B5B22FD3398BEA7F80966EBEF5A1ACF9F5FCCF9C0C6E61A05DBB583EB048CAA41C28E87530820D21E90BFD2CFF29C8FEC2F7F1FC90605F2C84553A709CB9F53C1BDF12DC20524E76870ACB7624AD238B5BB8EEC8D5D37F02F12D1DF2384E7EC70CFDCC25831305682080326E702795ABFC6DF60BE923AB245887A35EB5EC00B7A109F86A8F7DCF2E59DBD8C4C9D645588F4D25C768F499C3FA65C98FEB48B07A4B01C7AF8AF28ADBC5C487A5C1FB059EF91B3A77C8321126978B5EAD648BB96C6210C6EF505B6E40098E415E0324D1CCD0A5B0560455BA894AD84CFA8E9B37706EFC23B00513BA3D6DF77D38E203AAD4E718286BE73A729C7CB2CB2EEC65726EA48E657DA31A548972B21642C01512421A21E2A4151A995CDC2DA9A7602E747CB62C893D555BA4455ACD880282459257622B370F3AEE7C99C2D8CD31050E6F1050340EB287BE92133C2479F07780ED355CC124FBDD2C7ADC2A129DA3A99C964F1BB32B5609C36ABB69AFABC0F1445362DFBE2A381C3D88973EDFF9D98ECD0E5EDA94D394B784ABC97470283FBB87403A5DCD4BCF55F24F4368BDE39E63E3C906FD2EA6C4103EF571FCD269700472C761B2E2C52F9F10C195C7947AE378B40724499C8EB3AE5ED4B3B06DCE02F29424662BF209AA14D39C1EEC5E3E5DE7B7CADFD1D8ED9D0AA552FF54353F0E9BD1CD02965A47D83F1359BE6FE0C0144BC0EA8BD2C37CAB4DFBEEB31833F4146316023C4D556C7C8093C3CAD4E7040B122B375963767893A9B4DEE5EDEEFAFC0409121A326F7072A2ACD5DCEEF1F2F4FD051E26373B3F464B97999A9B9FA4ABC9E2FDFE00000000000000000000000000000C1E2F42");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");

        kpg.initialize(MLDSAParameterSpec.ml_dsa_44, new SecureRandom());

        final KeyPair kp = kpg.generateKeyPair();

        Signature sigImpl = Signature.getInstance("ML-DSA-EXTERNAL-MU", "BC");

        sigImpl.initVerify(kp.getPublic());

        sigImpl.update(mu, 0, mu.length);
        try
        {
            sigImpl.verify(sig);
            fail("no exception");
        }
        catch (SignatureException e)
        {
            assertEquals("mu value must be 64 bytes", e.getMessage());
        }

        sigImpl.initSign(kp.getPrivate());

        sigImpl.update(mu, 0, mu.length);

        try
        {
            sigImpl.sign();
            fail("no exception");
        }
        catch (Exception e)
        {
            assertEquals("mu value must be 64 bytes", e.getMessage());
        }

    }

    public void testMLDSAKATSig()
        throws Exception
    {
        byte[] pubK = Hex.decode("dc7bc9a2e0b6dc66823ae4fbde971c0cfc46f9d96bbfbeebb3470ae0a5a0139fdd6a6ce5bc76e94faa9e9250abd4cee02cf1ee46a8e99ce12d7395781fa7519021273da3365519724efbe279add6c35f92c9d42b032832f1bf29ebbecd3ec87a3af3da33c611f7f35fa35acab174024f118979e23bf2fe069269a2ec45fbc1b9c1fb0e1f05486a6a833eb48adc2960641d9af6eb8b7381b1ec55d889f26b084ddfa1c9ed9b962d342694cede83825309d9db6bd6ba7582132534861e44a04388a694242411761d34e7c085d282b723c65948a2ac764d9702bd8ed7fe9931d7d8704a39e6508844f3f84843c305594fe6e5404e08f18ed039ac6563cbaa34b0ca38320299d6256ec0f78d421f088159d49dc439cbc539a55884a3eb4efc9cf190b42f713441cb97004245d41437a39b7b77fc602fbbfd619a42363714b265173cae68fd8a1b3ca2bd30ae60c53e5604577a4a3b1f1506e697c37432dbd883553aac8d382a3d250cf5b29e4d1be2cbcd531ff0e07e89c1f7dbc8d4529aeebe55b5ce4d0214bfdec69e080bd3ef36cca6a54933f1ef2f37867c0d38fd5865b87929115808c7e2595458e993bacc6c5a3b9f5025001e9b41447708bfbaa0462efa63876c42f769908b432f5485508a393224960551d77eadfaf4411cbc49fdff46f2f155ddd6ec30867905b709888ca0f30f935fb8d7f4803cfc7a5f7790ca181d99ca21f2621d69a5c6d49c76b4969da62740a378470332b30947ab31ccdb9ba0c7b625879eec4bd81f0200ba23504a7dc3b118bc2ab1145df13af3c8cc39f577873b84911b3d85fbbf4cb19e4d36b10a938eeb78b599dc86615fd6cec6eb7b8f7afa5f6d6be19ea81630d36ccfb2f487de50d0cf46da8d3fe3512812043c0e3ef2d7231fb0b0a35a0fb283be30a1247780f30ae0294e8b6f5897383edb895595f577524df54593cdf927b4967616ee3913e4d6b29b0dbd7c33a2a45e4ef1b1954ea5d91ce37efc1302e7ce02a97395565da2a5c5d3fdb0d87684e9b1c0ad07ec33df2dfad528e2ea0966d2a47dd5ee88e77d653c0d004fab0165f0757c4da40af327e7192536c79947a80a827aa2107dacfae3debfc8fad3d6e08076d938c510a276bdf6721a1f087cb169515028ad5ce27a1047abd92809934ca63b893f71f9a34a99c0fd30310c47e9aa37394d0ab73b254d3ca69d9c5549c9479aae24264ac5ea64d3fd821c3962ec77e709f9d30bc7b65a52e48c16e80603558caca1811411c3155d1f949fc9cf9aa9385a7199e99be77a66fad7eed91258de55b2c4c83f9a050adebea5f09758f40dac4a1c394ee8d687879150d26426895ab1938e14ae11b376254c91fc6130436996f8ed43bd27be20ec9067111c116ec94cc2b06cc91a13c5d10bbd7eecea4792f17b2b77631ef145e9fb41a83eaa11c2b72a48fb90fdbd88644c4edf8ab20dce3118364b276ac1237b36c8926e346aab5a111aa0bf341c518b7bff9e9dbb8bcb4728601b3760663e67650331e6fb54ac82fc414cb8ddfc160a25311ec5272de46217fef8b992ff89754fbee351f21bb90b6c97078b510c983350681266c8fed1f0583c5151e7b8fe3b7292319699687cc6b641fdbd689428543bc0fa1facc109de65b62784c2d985ab15d77d3af12af6d03e8d1859a553688584d75ef673a1de74093ee108c761fff32c217c231b0e2953daf521429264c0963bc8a5cdeddc617a7285b934ea51ddb5cdab23bcede86be36e001bc65c65e9a1c94baff4fab8eb5f8ed42ec377423633fe00049142467c47c5d58a7202c8e9104841c1f7f380145a6a0a828c570235e507ae5868a6062f722bb98ff6be");
        byte[] privK = Hex.decode("dc7bc9a2e0b6dc66823ae4fbde971c0cfc46f9d96bbfbeebb3470ae0a5a0139ff037b84e75537e0a1cf02a517acfe323ffffe11df72e4f38430e0e66a2654b2f2ef757da47649d9f63fa03f1bf6fe6bc7c62971a98a2bd9d36eb0ec43ad4e9d940df3bb5874f5c92192aa31e0535d3cf70950bba858d11a688eaf854f63ecfc520c50d624891434265d8b0680c03061040299a104082c0910c8508d1100d44a6509408292211125b90508a2688e1302dc4021280028ac302611820851237808a000ae2040421b4910bb80550a08051b2511c28428a3672a494504910201bb45161424424a75001328181942d62a850023449ca94200b296213156408924c48122100b605030208e0060200a311e1802021116483a62898029291480801083041066613200e5b360951400c53000aa08851944842e316704ab2089b92440025121b0309418209c2a0800b290a819851c4340da4424500a0105b048e603400138928a4422648002c90202d194068e2146d19278a083746e4146914006422c660d3a03013242844965014166da0284dcc462e94367100232e1c114909a2040131060a2172c2142ada000c5a260d13228a62c444e3142d013445980224d33841c0308121a621e348720b1984d2c89108b8690887714a2884d496451a9301ca2285da30859ac851dcc00820106060465262302aa224251044640b2842988011540692144251d236719bb4900b082890188e41c469e1a469032160e01409d3020c20c88c1cb23164086218476920228ccb8470089528029550533270013405888424541041d202881aa84ccac88181008d0392899ab809d9900c9a1290614065c9322d89860c123521cc4266c8360010062411028ea3b44d44023043a0285a002ed1980c4882658922441c010212907084226e12134d011902519064113364c91806c2c04589262908b63024308cda022e0c27250b367058162c5116420b4946c1208841246c99466a04434e18a86c821661922028639409c30211029520211782d43868003460c84688e0160000a32dc0a82824b640831464c81022a2086503234ac8122ea098418c2072cc308a62c665093408412682da429089328514967081226001176d5948428ab88d592051d80892e2c0889044700ac0245a020904218a59c45094441094140820460209270c441020dcc8209212015038250c456e4a1666223770dc808ca426412222441ba3618a343099844099c42952046d88146ccb242a7cd129a8d333115c62d033b6a8357cf7cd10268ab12f16fceb7975d0a28a6c4822213c9a772df084ad91a669e2040550fc5e8d0aeb10fab2375fc9625ef9cd48c19631997a1cb6455d2c6286c569c9637add0317ce990996b28e51c3f3f717fb5907bbdd53961ad3497f2c3c473cce170906ac4c624a89aa8fbe624d99385e9c9548bf05e8cafd47d2476e41b73001f813726499e88b2b3b6f596ca311657850346598994c40e34747161e4e76264deef2a3019389d1594c942301af47b7544c23ecda2df2dece81e487d8f3f58ea89cd811d7275807ff1b0369ba86470088c174a3099fdafbe5fbb4d158801053b2b435d54059e26dee76d10a7a372f06b0b88b985b32f52052387438be8dc8bc6ae7369e2da9aa5e2585f8de403d091ccb7f790d54ddb34c608b0876f2825e9113be20a2b85867a01bda53287ac780bcd8b606d2e6d7712c56ce0142d22fe6b786de544963e134fecedfafb83d763061d799096a59e30d4472e440ae1faaabdf42640ce69740ceb9cae1a9612c21931b74af3f780236123321b205b6efd6cbb134f4c73d63c0c13e660b59d5920bc33197c355853d8d1cddc7959f7bc500ac81d985016f5b89a0eec79b0d9364ead8e38577c2a6549f2d067cb09438fdb21220aec80f6e22a476f332a2a4a0b7acbeb9e078d2b5a92ae84c924f7cb19fc7df377beb6546af97aa985c747cd111a127a674b4c26d89c14485b82e3a498a12d05406febd6c4d4b8bc051ab2cb91224b078538374b794b7dd9ddf3ac2b4a671fb7b9cf5acb78622ae2709eb2db16943aa24a9c97a81077bc784d25c0ea5991d2de883798a1f0e78f3361ed6a10dded81b1d683658331534fd7c01bc0eb00dfc4c3c84f0693046ff806bb200dd7bd4c0e6abca3f2934b4814fc0e1f8be615a2dda7c8a8d06cf9ce8566b40f4a6543b25bacddc926863fc0fa2007d6d7bf6d18dc98df696bd0865bf0be4c492b8043a32def8e3595ba7da345252f38f95be10fd7fb899b498fa01b09de5d5608eabc44a721aa04c4ef1dcb86102ac5f5f79c9708dcf5c5e896edd8c2c7bde3fa83e6ffce22d66174e31657a0b6361585e669d3031952f08631ae1f16ff90b90d0aad3c6d7e1dd0a9c41ab00a6e1c4f96af9ac5b79fcf821ffc016cb059245fb78dbe6c633d965aaab5333be07195c4b74b18e4600ce783c0a914ef4281016e80a7c9aa92d0fd789879c5e6751125ecb154432311e41cebd4fab3a31e4d2ce22d0f8c67737bf8a0dd85fe1349d5079a4d5feb3fee9378ca47ae46cc58a3f02038cfd53c4cee9cc4270cebc3d115a39c831e8ed41c4dbe4051b51d7872ba0c2bb163e0085201188eaa624a6bea9400a3a1fcc355a57f15704e61fda55a5dbaea8448fa5cb2d377a07f58305ad107e844ab4806e5bf99c1f513ee1d0a2acc04549f0801742169a77971d0adbfbfe0dd2ee5d16bc461e35748d1f3f6f4598321e8c49e79e740f990359858d2729dde007fcb26fdda9aa6e2ec4bd736f2836e7e4c83440191c849f6a53c72a4f8f830d001ea3b18f3cb4a5bd3cf066032b4932cfd2e62a9b55723fa61c688c935518af6860cd649bfbf1bf5fdc1f36dcaefaa157438d1cc8d56a150161511df82631f5e88e773e4ce263f276b7b3678d4c6fc75311d411c0d01bfdb595bb70552838e1b86517c837d909e772b428599e1fe569f77ce61531fde6fd31cdce1bdee4ba467fcbfbb9feeaad99fef67d4906e036c73662ddce158d4e5d4635e5d366f79f31a19d1b3dc4a591b0df194bb06c18147f41d88d1a409becdfb67eb063d16312266fd51b521ba9115e2e5e2aeae6ec511cede13ed4132ffbe0273f6c7039b3874f058804a54809af60557a21d9b4b831d04156a7c22dcbcdfe14f62437f449cb5ef12bf4251d485496cd835c0c2bc58bd845963dfa76ecd68519c4bdaf110be7ab052876dc3407591568c956ea3bf107c90fd5853a292f59a8d4b58b5d3fddf29bdbeac36852e3c69766fe460176a801831292b8e88a74a01ecbbe09a7b4d74cfd7fd628841944d9d556dbd60c76f96f07dc53443805ee9aa09365de4fb8179252c6b099b5dd351fdefc23dbd8090596c5d208ffd2c5661d8e5612dd574fc69045c769a969e600d77cfe192f1d3ae911289355c585811491b0ccd73692ab158824ab9edf8ac8193f0b33e6138b72c6dcd5d344f807b3da92425037de5ea4eead1c795effaa145e2ecdd327606eb2609929b9474b2bb04653602555c068385e92f06f29ca613ce5b4404f01ab1805db0acaa890330d291f40692df382509302b6dc8668f2c8f2d3a44fd58dca26e9802794f73d25b3149e6d576441");
        byte[] msg = Hex.decode("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8");
        byte[] s = Hex.decode("237c7b8820733d2cf35345f8a851996061675570ce42923ee2cd437e41b4a9b391481f71ece9e0b64c584a73710d8d688a930ac0bf02abf57c6e4709e724a9e4178c629018bc0b73b37a087dd3e7ea8da65b1145bcfeed1a7c1223607eaf0aef04ab2b60d47460945c621a4f9356130bcb5e94f00c710d1cfe99c05ea0cf9e0779577f3671560316bf24ec9cf2572b13e9a50d5fbcca4ddce481f740db1d7e200268459629d66eb5a0b5603ad6468a4a04498d84df62ee394d6fc5a3a7b1ef9de0cebe88168e5d6f771efc1ea315e78b83cb2c0ef88f167ee170dffddb9acaa5df380af1f80353746b6a5530c9fde8458eec99b478dcc6673236b277c41cde9eba586b9808146ccfae6fd8bea1d0654f65cac7583ab7050711b1a322d8da6c6aad16608a9053a655580d66016fc9cefaa17fe0fed5080dbd4daa9692f96794243a2813677ad542e1e164efa9341bd0fdba956a1b4b594f1a70fb3c14aed1217b861dcb749a56b281205d7df5d472a08fb376955524dda1017bcc8be85768191d0e18570fa8f263bd592a8d5358cf7f6ac28e0c664776acf51b689cf2e96603cb7de14978cc56f00819a217b5ae5e3c083c487f5a23c07939737c9ed6b2a51e04f39ddc69da569b88054fc64769098056d83539759d0cc487a711125bf73de1f6671695f5633645534e6cb2d374645c3c9fd39c5347c4b82fb1a452fbb6137f3c470eb1fc7240a5c2a281a1dd45670807552bcc0d160a6775b6dfebbc68500eb76e1e96db1ca0f31413c96f87354ab7071c7786c9e67d0d6476282bd676af23feeb7127b7864daca72f994a85bd10f1f66ea1240882f9b62895f19c0aaad1cf35cda81b311993194d977337d9a10728a7f3d82c8d7fe35cd7047d233c8efe1d9b66b2828c9b582dc2e4605683ace6be76ba351b6d7a1db23a81854d17e9601e7dc69beaae6426ef307300508d204b433026e0534dd0f0123b06252524769f2f86771c8cf5ee82f0b3b3010828a300578871af9b6031f34342cb2d5ea4093c50b621b10248d0a32c1cd5684ca50b5f9886e2df6deca3213bd5cd79d63b5dc8266beb4d80beeed82c9ee801ed35c6a9f69947e806e791173b5b883e20192573e85e7003f99c5ab417e72f03563eb93b163f4c2300675e8c1ab9f80cf62c88b1876fd0bd4258e0e083da712e341fbbceef37d59e090f6eca0cb3e8e6b7fe1c7f35c3a9db958cd273fcc581b285e30e3c35714f01d2eda306a6e66d9609d4ae88248bf76a991acb8b833255aaafcb27498d009eff0aa5264e1874b17eb646dfce4707e8bfb946babfa4f7affe388c0656b9dc4a8bbc670e64d42676db5b3cd017ce6d52e2547d43745e66ed9b1ca2228594546b4c2c636f524edec65d9ade60a9fd3b2586af169ada64574d85594cbaac5f3827d3c4317e51722c497f09dcaa4b7c4f03bd4fef3ba847d38d252fccecd7e207830fe4d60733b49527b5d29e71d2b736a97d9d34475fb081d0bc8810507f672ae03232bc32a33c711a3f12826fe1801f40962061e3d3fdeb3368e91eab892cdac18f0e06a4312e67f445578dbeaf54f5c3cbdbae0ab2dd84525a32253b3720d83c9b3e50ecf0554c89d15bd352b0636b40b79d38fc5cca5e696c1ff0cd2f0934fb3eaadccc1b6d5fac5544b6fe5c6e0a317c4fcfff2b1f70718b7e4e7cf3db3bf1c002031ef50c049bdffc3b78358e0be20eb57ed41bae04cdd09091afefa457a8aebb3376370ee04a7f48d444b7f1170edab68e0b970e8fc2850976536ce3bb14586af06baeac171278a5e949e00af7cdb0d4b841244ccccc797ff3fd4187077d4c9d33873cab0bf6e690591b9021f80c52d47494051ac1ff75554b6b1907903dc530ec6b42d025f723d7d4e539222e683e47532541f25f14b0c007b093b7ccbfc0172e78e543517f632149d842821a2b414d0db9aac1398b5e99c269ef4e303e1373f9bcdf8211b55c65ec19f93a0422a7148cabd4c311f11a49efc757534d00cae3c84cb849e975193145538917f81225cc96457bc1a2ab8fa72afa8563dc314766ffd19a10db92dabf9a0656066728d384f598229fa94e906b8a3222b0dfe164afd9c116f31c315ee53ffb0b0d582ee0abfad259f1b4095c00a347673fd4e17ea7d8f974dbf2ed90311cb167d61aebea7b0b17a34f5b721fecafcfbc3feac7091b81851f8a5b051add8e724a503386a53b70d106d86a99813d579ef75a065cf70cc1ab9d80c39a01d3c5946049efed8d4e383b5ca65827a9cee08cba792a903347f7547a64745f8e17d71a0d40d71d15484b9a6814c86230aa05539e907cddda5efb3162c356f35829bc32a28bc80ec9454e5bfec24a6dd74675e3b913647f3d176a6773c1a0e40edd17ecd13aee3493710b1154f855f2591e62cc7073c608bbaa77104e8d4993b67cf81f65af89c8c91d695f7560daa68ad14160cb7df4e7a61b1860255320dbb813676df1285c015aec994d7bc0ce29751416b31ed15b69172968ddaa515692b8febccb4e3298e8bf169c20b965903b80f26f20a6a3bd5facd1bc38c6c817e23bf35187ff75f982ae9ed65a43f6199b61ae84683e1befcf9c0178b8ea2890f96a6e08d33d44c3ce50d9ccbd1cdf96df6b2f5e8f1c6cb04300f7f6d483108390aea8ed31b07b32c87c542ab475946d525e24c16b2d0afb86687e47cce7abb5b7fc41d6a9953a59a8b221d057b793845cfab414726b3753d87c020253fb93722263ceee93a66acf163c86eb7bd62136f70ec414b5562862f1202deeb9feaf7981416be2a09c0e7c1f18ee95314b54d0497bac2986d90e9ed3990220e96ae1622e11f2ee91c1b16128e7384a87fabc6731c7b0b00bb707fd1abe0392c95e4c435460b47d2199829b076b4ef6b11ad32825cad85794a674eefdd6173dca39dcbf397c1b9531380a72d142b7d4005d884fcbd59211827820fc5b2bc605e5c717c31e124cd1f57180d4ba598833f097056f809b71214fbee25f7fe7f14e3df8cb6bbf6c3f3de82885f71bfd874e6b7ad11db7210fd73c0ccbaa60f008a86a59a9860c0c851672da17b077d35977c52cf35bf06d450f3ec061977f627324c55aada361c6abb3de77e828a63aef6dc37cdf0caf3b98c3a409e3cdbdd2edd0dc4feb1a6ede8df7252cb658413f22728142304d7d02b06e438b10814f7731a489e79b6b8a6b0fca6b63fe9a61ff2994704bdff918e1ae6a99df07d3e18a216890465397b6eda5f47ad2f216817544b8840c6af1704d9a71a02c73b6a29fb6fb17787d97a8984790a34736050607093d3f557d9ba5afb8ced3d4dee1e8eef1f8fc0117474f558c96b2b4c2d6d9f8439198aac0cad2d3eaed0d1a243d44456486cfdce4e6f1000000000000000000000000000000000000000000000015222c39");
        byte[] seed = Hex.decode("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");
        SecureRandom katRandom = new NISTSecureRandom(Hex.decode("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"), null);

        kpg.initialize(MLDSAParameterSpec.ml_dsa_44, katRandom);

        KeyPair kp = kpg.generateKeyPair();

        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());

        ASN1BitString pubSeq = pubInfo.getPublicKeyData();

        assertTrue(Arrays.areEqual(pubSeq.getOctets(), pubK));

        PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());
        ASN1OctetString seq = privInfo.getPrivateKey();

        assertTrue(Arrays.areEqual(ASN1OctetString.getInstance(ASN1Sequence.getInstance(seq.getOctets()).getObjectAt(0)).getOctets(), seed));

        Signature sig = Signature.getInstance("ML-DSA", "BC");

        sig.initSign(kp.getPrivate());

        sig.update(msg, 0, msg.length);

        byte[] genS = sig.sign();

        assertTrue(Arrays.areEqual(s, genS));

        sig = Signature.getInstance("ML-DSA", "BC");

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));

        // check randomisation

        sig.initSign(kp.getPrivate(), new SecureRandom());

        sig.update(msg, 0, msg.length);

        genS = sig.sign();

        assertFalse(Arrays.areEqual(s, genS));

        sig = Signature.getInstance("ML-DSA", "BC");

        sig.initVerify(kp.getPublic());

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));
    }

    public void testMLDSAKATSigWithContext()
        throws Exception
    {
        byte[] pubK = Hex.decode("dc7bc9a2e0b6dc66823ae4fbde971c0cfc46f9d96bbfbeebb3470ae0a5a0139fdd6a6ce5bc76e94faa9e9250abd4cee02cf1ee46a8e99ce12d7395781fa7519021273da3365519724efbe279add6c35f92c9d42b032832f1bf29ebbecd3ec87a3af3da33c611f7f35fa35acab174024f118979e23bf2fe069269a2ec45fbc1b9c1fb0e1f05486a6a833eb48adc2960641d9af6eb8b7381b1ec55d889f26b084ddfa1c9ed9b962d342694cede83825309d9db6bd6ba7582132534861e44a04388a694242411761d34e7c085d282b723c65948a2ac764d9702bd8ed7fe9931d7d8704a39e6508844f3f84843c305594fe6e5404e08f18ed039ac6563cbaa34b0ca38320299d6256ec0f78d421f088159d49dc439cbc539a55884a3eb4efc9cf190b42f713441cb97004245d41437a39b7b77fc602fbbfd619a42363714b265173cae68fd8a1b3ca2bd30ae60c53e5604577a4a3b1f1506e697c37432dbd883553aac8d382a3d250cf5b29e4d1be2cbcd531ff0e07e89c1f7dbc8d4529aeebe55b5ce4d0214bfdec69e080bd3ef36cca6a54933f1ef2f37867c0d38fd5865b87929115808c7e2595458e993bacc6c5a3b9f5025001e9b41447708bfbaa0462efa63876c42f769908b432f5485508a393224960551d77eadfaf4411cbc49fdff46f2f155ddd6ec30867905b709888ca0f30f935fb8d7f4803cfc7a5f7790ca181d99ca21f2621d69a5c6d49c76b4969da62740a378470332b30947ab31ccdb9ba0c7b625879eec4bd81f0200ba23504a7dc3b118bc2ab1145df13af3c8cc39f577873b84911b3d85fbbf4cb19e4d36b10a938eeb78b599dc86615fd6cec6eb7b8f7afa5f6d6be19ea81630d36ccfb2f487de50d0cf46da8d3fe3512812043c0e3ef2d7231fb0b0a35a0fb283be30a1247780f30ae0294e8b6f5897383edb895595f577524df54593cdf927b4967616ee3913e4d6b29b0dbd7c33a2a45e4ef1b1954ea5d91ce37efc1302e7ce02a97395565da2a5c5d3fdb0d87684e9b1c0ad07ec33df2dfad528e2ea0966d2a47dd5ee88e77d653c0d004fab0165f0757c4da40af327e7192536c79947a80a827aa2107dacfae3debfc8fad3d6e08076d938c510a276bdf6721a1f087cb169515028ad5ce27a1047abd92809934ca63b893f71f9a34a99c0fd30310c47e9aa37394d0ab73b254d3ca69d9c5549c9479aae24264ac5ea64d3fd821c3962ec77e709f9d30bc7b65a52e48c16e80603558caca1811411c3155d1f949fc9cf9aa9385a7199e99be77a66fad7eed91258de55b2c4c83f9a050adebea5f09758f40dac4a1c394ee8d687879150d26426895ab1938e14ae11b376254c91fc6130436996f8ed43bd27be20ec9067111c116ec94cc2b06cc91a13c5d10bbd7eecea4792f17b2b77631ef145e9fb41a83eaa11c2b72a48fb90fdbd88644c4edf8ab20dce3118364b276ac1237b36c8926e346aab5a111aa0bf341c518b7bff9e9dbb8bcb4728601b3760663e67650331e6fb54ac82fc414cb8ddfc160a25311ec5272de46217fef8b992ff89754fbee351f21bb90b6c97078b510c983350681266c8fed1f0583c5151e7b8fe3b7292319699687cc6b641fdbd689428543bc0fa1facc109de65b62784c2d985ab15d77d3af12af6d03e8d1859a553688584d75ef673a1de74093ee108c761fff32c217c231b0e2953daf521429264c0963bc8a5cdeddc617a7285b934ea51ddb5cdab23bcede86be36e001bc65c65e9a1c94baff4fab8eb5f8ed42ec377423633fe00049142467c47c5d58a7202c8e9104841c1f7f380145a6a0a828c570235e507ae5868a6062f722bb98ff6be");
        byte[] privK = Hex.decode("dc7bc9a2e0b6dc66823ae4fbde971c0cfc46f9d96bbfbeebb3470ae0a5a0139ff037b84e75537e0a1cf02a517acfe323ffffe11df72e4f38430e0e66a2654b2f2ef757da47649d9f63fa03f1bf6fe6bc7c62971a98a2bd9d36eb0ec43ad4e9d940df3bb5874f5c92192aa31e0535d3cf70950bba858d11a688eaf854f63ecfc520c50d624891434265d8b0680c03061040299a104082c0910c8508d1100d44a6509408292211125b90508a2688e1302dc4021280028ac302611820851237808a000ae2040421b4910bb80550a08051b2511c28428a3672a494504910201bb45161424424a75001328181942d62a850023449ca94200b296213156408924c48122100b605030208e0060200a311e1802021116483a62898029291480801083041066613200e5b360951400c53000aa08851944842e316704ab2089b92440025121b0309418209c2a0800b290a819851c4340da4424500a0105b048e603400138928a4422648002c90202d194068e2146d19278a083746e4146914006422c660d3a03013242844965014166da0284dcc462e94367100232e1c114909a2040131060a2172c2142ada000c5a260d13228a62c444e3142d013445980224d33841c0308121a621e348720b1984d2c89108b8690887714a2884d496451a9301ca2285da30859ac851dcc00820106060465262302aa224251044640b2842988011540692144251d236719bb4900b082890188e41c469e1a469032160e01409d3020c20c88c1cb23164086218476920228ccb8470089528029550533270013405888424541041d202881aa84ccac88181008d0392899ab809d9900c9a1290614065c9322d89860c123521cc4266c8360010062411028ea3b44d44023043a0285a002ed1980c4882658922441c010212907084226e12134d011902519064113364c91806c2c04589262908b63024308cda022e0c27250b367058162c5116420b4946c1208841246c99466a04434e18a86c821661922028639409c30211029520211782d43868003460c84688e0160000a32dc0a82824b640831464c81022a2086503234ac8122ea098418c2072cc308a62c665093408412682da429089328514967081226001176d5948428ab88d592051d80892e2c0889044700ac0245a020904218a59c45094441094140820460209270c441020dcc8209212015038250c456e4a1666223770dc808ca426412222441ba3618a343099844099c42952046d88146ccb242a7cd129a8d333115c62d033b6a8357cf7cd10268ab12f16fceb7975d0a28a6c4822213c9a772df084ad91a669e2040550fc5e8d0aeb10fab2375fc9625ef9cd48c19631997a1cb6455d2c6286c569c9637add0317ce990996b28e51c3f3f717fb5907bbdd53961ad3497f2c3c473cce170906ac4c624a89aa8fbe624d99385e9c9548bf05e8cafd47d2476e41b73001f813726499e88b2b3b6f596ca311657850346598994c40e34747161e4e76264deef2a3019389d1594c942301af47b7544c23ecda2df2dece81e487d8f3f58ea89cd811d7275807ff1b0369ba86470088c174a3099fdafbe5fbb4d158801053b2b435d54059e26dee76d10a7a372f06b0b88b985b32f52052387438be8dc8bc6ae7369e2da9aa5e2585f8de403d091ccb7f790d54ddb34c608b0876f2825e9113be20a2b85867a01bda53287ac780bcd8b606d2e6d7712c56ce0142d22fe6b786de544963e134fecedfafb83d763061d799096a59e30d4472e440ae1faaabdf42640ce69740ceb9cae1a9612c21931b74af3f780236123321b205b6efd6cbb134f4c73d63c0c13e660b59d5920bc33197c355853d8d1cddc7959f7bc500ac81d985016f5b89a0eec79b0d9364ead8e38577c2a6549f2d067cb09438fdb21220aec80f6e22a476f332a2a4a0b7acbeb9e078d2b5a92ae84c924f7cb19fc7df377beb6546af97aa985c747cd111a127a674b4c26d89c14485b82e3a498a12d05406febd6c4d4b8bc051ab2cb91224b078538374b794b7dd9ddf3ac2b4a671fb7b9cf5acb78622ae2709eb2db16943aa24a9c97a81077bc784d25c0ea5991d2de883798a1f0e78f3361ed6a10dded81b1d683658331534fd7c01bc0eb00dfc4c3c84f0693046ff806bb200dd7bd4c0e6abca3f2934b4814fc0e1f8be615a2dda7c8a8d06cf9ce8566b40f4a6543b25bacddc926863fc0fa2007d6d7bf6d18dc98df696bd0865bf0be4c492b8043a32def8e3595ba7da345252f38f95be10fd7fb899b498fa01b09de5d5608eabc44a721aa04c4ef1dcb86102ac5f5f79c9708dcf5c5e896edd8c2c7bde3fa83e6ffce22d66174e31657a0b6361585e669d3031952f08631ae1f16ff90b90d0aad3c6d7e1dd0a9c41ab00a6e1c4f96af9ac5b79fcf821ffc016cb059245fb78dbe6c633d965aaab5333be07195c4b74b18e4600ce783c0a914ef4281016e80a7c9aa92d0fd789879c5e6751125ecb154432311e41cebd4fab3a31e4d2ce22d0f8c67737bf8a0dd85fe1349d5079a4d5feb3fee9378ca47ae46cc58a3f02038cfd53c4cee9cc4270cebc3d115a39c831e8ed41c4dbe4051b51d7872ba0c2bb163e0085201188eaa624a6bea9400a3a1fcc355a57f15704e61fda55a5dbaea8448fa5cb2d377a07f58305ad107e844ab4806e5bf99c1f513ee1d0a2acc04549f0801742169a77971d0adbfbfe0dd2ee5d16bc461e35748d1f3f6f4598321e8c49e79e740f990359858d2729dde007fcb26fdda9aa6e2ec4bd736f2836e7e4c83440191c849f6a53c72a4f8f830d001ea3b18f3cb4a5bd3cf066032b4932cfd2e62a9b55723fa61c688c935518af6860cd649bfbf1bf5fdc1f36dcaefaa157438d1cc8d56a150161511df82631f5e88e773e4ce263f276b7b3678d4c6fc75311d411c0d01bfdb595bb70552838e1b86517c837d909e772b428599e1fe569f77ce61531fde6fd31cdce1bdee4ba467fcbfbb9feeaad99fef67d4906e036c73662ddce158d4e5d4635e5d366f79f31a19d1b3dc4a591b0df194bb06c18147f41d88d1a409becdfb67eb063d16312266fd51b521ba9115e2e5e2aeae6ec511cede13ed4132ffbe0273f6c7039b3874f058804a54809af60557a21d9b4b831d04156a7c22dcbcdfe14f62437f449cb5ef12bf4251d485496cd835c0c2bc58bd845963dfa76ecd68519c4bdaf110be7ab052876dc3407591568c956ea3bf107c90fd5853a292f59a8d4b58b5d3fddf29bdbeac36852e3c69766fe460176a801831292b8e88a74a01ecbbe09a7b4d74cfd7fd628841944d9d556dbd60c76f96f07dc53443805ee9aa09365de4fb8179252c6b099b5dd351fdefc23dbd8090596c5d208ffd2c5661d8e5612dd574fc69045c769a969e600d77cfe192f1d3ae911289355c585811491b0ccd73692ab158824ab9edf8ac8193f0b33e6138b72c6dcd5d344f807b3da92425037de5ea4eead1c795effaa145e2ecdd327606eb2609929b9474b2bb04653602555c068385e92f06f29ca613ce5b4404f01ab1805db0acaa890330d291f40692df382509302b6dc8668f2c8f2d3a44fd58dca26e9802794f73d25b3149e6d576441");
        byte[] msg = Hex.decode("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8");
        byte[] s = Hex.decode("098d5709482f9975b8c5c2e04f2dd8b54b4cf14fab51794948e88ab469656e1989a76c1a67bb93f8e8ae33f691773da3a86876c850e77ae2a4f58189f0f98d4fd5c748c9f760cd75f7c1912ad06df232c6ac38d49ceb8f648bfdd5998797812d8d2326cf5a07292a9c0d8fb87ae33cf85723c2e6383f1072d0c2b96aa4f00c981fb2e0c619344fa5ebb9761b8d2f2011639724b6a66cf502a9795da237776bc5da3a0ce35da57a2f36edf365d138c013582a21c8e4e26a43b259240c2af48504fa298ca816bfe1620dedfa72ea338da2a81e03b207bda413d2bbe38f9a4939f877bdfe2ed80261ea2293e4f9ad5fd8c5a94311d1564e18b58239de393750c5b2f7b579f47eb748a7c0635adc63a2396b4d1fda5071936eed5a3b3a3dbdd31eaf40ae09371ac7a910e056c0f84c1729cff8cc53f35aa68cbe97c4649e8d7c52381b3e1b5899c08bf758556149fb37bff2db4056741188036ae4e64190b843d213a090db1f0a338d0e9ace2b6b9caac158a6ba27092ff0ca082dc64aeaf748f2ae35597d184e7b5c03dcd2da11aff5ffe98f5075cc355d1214314ed256c637b762c54d038ca3f4a85d583f4bb68ea705a40481c35a0ae4de8c8ea7c417f2d1e1a101d6aec6aac87aef3dd4ace3a86a2b205ab9e98a9cf579f61c6a683820aa3c8b8eaa492800398f196e40300cc1e155d8e81344a07af407438a71c30bf4b936037312829020f4648899c9eff03f37d48373d462ce419e9dfe638437ea0e6871c4a78a93388000a759468eb8ad25bd60fa8363efe0ba826349598228402a286a1d7f95122b23cc051d325a539b5179afe1c0b049060d072ddc1635c4228ba13d768e704aadb5692e0eec1ffed5a9ea4ffbf45725b924afe2362bbf592d7b8ffcccb558374471ebd69ab9712c366b8f503e4aaf6ab9cb7c4124fa5767757f6b66bbbda7457e2bd35bc8927167e5520d81ff05d89e15891d6e8cf8b91cc8af0c02e2c82c93095504f61e8cb0e62dcde96c3ee0558921946cf7d20c9485e93269e9c44c6a6a8c5a266f1fe1610ae24a73897e05e69cfc1fef396e38d66119115dc6dd6d965eb053a5b6d7dbe8ae40b99f853ccdb7f569bf9b18d394abf2496bddd77801d4a9530c871c24b2b7a3ae4d335c7be3522aeeb7bb4ace52b7d213ccb086eb031aad103020413fb21b44dfabae7e1d95845dff10cd434c357b3b9f6f2a6c4e5c9c0f8d8490f31fe1faaa2f860c7f54453923e57d80ec26ebcacb3e79375ae7b0900f1f1eefe7bb491d079a0b561bb4a280ac1bc3daae702b2ca9e9cf7ff2804f5b98861d900f047d415e8911cd177cd691dfd079f6a439b4dfd407d3b3d78a33aa818f8948815c14e311d0fb6f32006863bd2a538177d1d9d9283ba7ec43932534900ab745cd54a6a115ee2786bfe1c3f8bb085f30c58cefceccb95f5d3388151df1af838e6711739d1a0d543b42e6d7948a5d8ce55fefd5ebe5d616cfa6d386c611f781b12d04eba65a3a57780b851daee6f038fe393d8bbdcd2d0bb706881d82ac55d0faa22e0c8756c676048f48fa8de39a2e8a5f1581ecc03045a3c90e1f5584a2db606c7d2ee0b724f7a84b0b21202b68729f4850da6723454536d43afce781198049f3dbbec600dbafa18fcbed25aef8095349595fe9ebdf75d951353b8cc6898a5bd4e7c0595920d9cdd1db426c694c119539a987888eaa9ca0767a3719eb967547636a24d1d8b0ae7006466b8b968476d7dd70fe5fd5c678bf37eff54da49f135db340448960d64bf097bc120660a27ca8d0f1fe28e9758ae7b171427a19bda0133a176c8d75b82b6b33f03a68013233ef124b8c56ac181f09563c5e07d445b383ddf275f3390ed27903bb1b58bee5d53b7fe871b8480e024caa1a2693681a8192ae992ba2578177dd9a9153d42d6fd1c952c840711d46e96ce4f0ec089d460347cef11cbee0eaabbeee8454552d404a3acf2d99c763ad9c000a4aa7e31cd61061741561ffd60b79c4a1881abe794db591de66837092ff93d4aa49deb083cdbd2b70de2edeb99b4f0b52dab10e5b5eab3e5bd12a8c1b042614266aa1bfe8511e7769a20510ed5e393144a9b72c0ec93a95f35d4f38a50253f3e244044ed24f69b149b5e7d887a5c2ca6c80e60aaef2667a63d49601e73ab9c5e2e09ca29aaf666719ff3b5ba32299749445e8e3f9563af2b95578f1995cf2814707e42640cd65f87518f1007aedc202cd401ba51efb0b1256ef43bdfc63d1bc46481c85ca1f1d938b5e0c802859efde08f3dfd27bee7d0f004b4abfd019165422f4b7fccd7ca4952850ca5c6c6079b8bed3bfc876923bb5e19dce7e672721486f496187d2928336c5f7ab6b4a32d7eb196b05795d55c8665645e9673c6f2a792a6f319cee59bf152a1482feb2ef325128bc8c22be9f47feb6693ff51c278a19d8256dfaa3b14ad4e299e8cda06bb9aa103a77c6062debaa42fab40d7b602343e74949d1f35c9fdfa0af0c86fcfc740e385e08bb30d37ad8d4d818bf4588fb0ef3cccf2133f7cd6501848f69e833d3988b9d627f693cb9ad4724427afa9efffd249fad1473074366e3e777ea67655264e1e3502b41ac628e0a6cc7577886b061643f2c61540497e04c81ec6db1bb33dfa53574b2e4a10c968b8d2d13dbe374159a189056ca052bd0cb8f95dac9aad2dc90b43831ea973b14fb642c4772005940fa5e41136660b588526684d7a62bfefb6d1549b5bedf3b262d5c27a85cd52f79c51e668c80a18ca543e4963a2970b7ddddd3297cabf1d51ed24fc3c55ee5c83dac281cfcef06a4e24fee98f0a84ed7ddbfaaccf2b2e7ef3abc0abd21fa2f0f24a494dd70d4b4ce685b31ca337393943a8db71011901d1061f08c56a672201b7726b158dca828ac9217629c66fac9adec98851412421d22caeadc7483c407566fcee45044e7aea3639fd0534c9d242d129dc4b0f1aa056f597bd3972852815d10bcdcd4149caf4eb8e29d61fda97a137b81d2d2800fd9a9cbcb2ab8d6351faf7d67e6385f98be98ea1f97fad8ba928338ccf0b249354991947b47b00196e51d6af3ec3d49b21e4b053147284e391d5beefcc92544752cff02fe03f5bf9276ed6b313d210aa55bfee3b2f72aed7eaaf03c7cb471b5f67d7fe13b8679e418807c8e82559489f3121268febe301b1361b929f8c3805e1f5909133ec381fecfc225ceb1c46ef9f2ab271900999a5ad596c79ce7f43e7d0ba82a177134c7b2e37c58e0fdc20a60055a4d0223320ffbed994cb26698722f8299f5600d069bab541819636ab6112a395152565b5e636e78858da6acb0b5b6cd373e45485b96a0b7bae1e8fc2d56658d98a1afb6b7b8d7dde8e9424c768a8e8fabc1d2e0e4f00000000000000000000000000000000000000000000000131f2d39");
        byte[] seed = Hex.decode("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");
        SecureRandom katRandom = new NISTSecureRandom(Hex.decode("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"), null);

        kpg.initialize(MLDSAParameterSpec.ml_dsa_44, katRandom);

        KeyPair kp = kpg.generateKeyPair();

        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());

        ASN1BitString pubSeq = pubInfo.getPublicKeyData();

        assertTrue(Arrays.areEqual(pubSeq.getOctets(), pubK));

        PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());
        ASN1OctetString seq = privInfo.getPrivateKey();

        assertTrue(Arrays.areEqual(ASN1OctetString.getInstance(ASN1Sequence.getInstance(seq.getOctets()).getObjectAt(0)).getOctets(), seed));

        Signature sig = Signature.getInstance("ML-DSA", "BC");

        sig.initSign(kp.getPrivate());

        sig.setParameter(new ContextParameterSpec(Strings.toByteArray("Hello, world!")));

        sig.update(msg, 0, msg.length);

        byte[] genS = sig.sign();

        assertTrue(Hex.toHexString(genS), Arrays.areEqual(s, genS));

        sig = Signature.getInstance("ML-DSA", "BC");

        sig.initVerify(kp.getPublic());

        sig.setParameter(new ContextParameterSpec(Strings.toByteArray("Hello, world!")));

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));

        // check reflection based context.

        sig = Signature.getInstance("ML-DSA", "BC");

        sig.initVerify(kp.getPublic());

        sig.setParameter(new MyContextParameterSpec(Strings.toByteArray("Hello, world!")));

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(s));

        // check randomisation

        sig.initSign(kp.getPrivate(), new SecureRandom());

        sig.setParameter(new ContextParameterSpec(Strings.toByteArray("Hello, world!")));

        sig.update(msg, 0, msg.length);

        genS = sig.sign();

        AlgorithmParameters sp = sig.getParameters();

        ContextParameterSpec sspec = sp.getParameterSpec(ContextParameterSpec.class);

        assertTrue(Arrays.areEqual(Strings.toByteArray("Hello, world!"), sspec.getContext()));

        assertFalse(Arrays.areEqual(s, genS));

        sig = Signature.getInstance("ML-DSA", "BC");

        sig.initVerify(kp.getPublic());

        sig.setParameter(new ContextParameterSpec(Strings.toByteArray("Hello, world!")));

        sig.update(msg, 0, msg.length);

        assertTrue(sig.verify(genS));

        AlgorithmParameters vp = sig.getParameters();

        ContextParameterSpec vspec = vp.getParameterSpec(ContextParameterSpec.class);

        assertTrue(Arrays.areEqual(Strings.toByteArray("Hello, world!"), vspec.getContext()));
    }

//    public void testHashMLDSAKATSig()
//        throws Exception
//    {
//        byte[] pubK = Hex.decode("dc7bc9a2e0b6dc66823ae4fbde971c0cfc46f9d96bbfbeebb3470ae0a5a0139fdd6a6ce5bc76e94faa9e9250abd4cee02cf1ee46a8e99ce12d7395781fa7519021273da3365519724efbe279add6c35f92c9d42b032832f1bf29ebbecd3ec87a3af3da33c611f7f35fa35acab174024f118979e23bf2fe069269a2ec45fbc1b9c1fb0e1f05486a6a833eb48adc2960641d9af6eb8b7381b1ec55d889f26b084ddfa1c9ed9b962d342694cede83825309d9db6bd6ba7582132534861e44a04388a694242411761d34e7c085d282b723c65948a2ac764d9702bd8ed7fe9931d7d8704a39e6508844f3f84843c305594fe6e5404e08f18ed039ac6563cbaa34b0ca38320299d6256ec0f78d421f088159d49dc439cbc539a55884a3eb4efc9cf190b42f713441cb97004245d41437a39b7b77fc602fbbfd619a42363714b265173cae68fd8a1b3ca2bd30ae60c53e5604577a4a3b1f1506e697c37432dbd883553aac8d382a3d250cf5b29e4d1be2cbcd531ff0e07e89c1f7dbc8d4529aeebe55b5ce4d0214bfdec69e080bd3ef36cca6a54933f1ef2f37867c0d38fd5865b87929115808c7e2595458e993bacc6c5a3b9f5025001e9b41447708bfbaa0462efa63876c42f769908b432f5485508a393224960551d77eadfaf4411cbc49fdff46f2f155ddd6ec30867905b709888ca0f30f935fb8d7f4803cfc7a5f7790ca181d99ca21f2621d69a5c6d49c76b4969da62740a378470332b30947ab31ccdb9ba0c7b625879eec4bd81f0200ba23504a7dc3b118bc2ab1145df13af3c8cc39f577873b84911b3d85fbbf4cb19e4d36b10a938eeb78b599dc86615fd6cec6eb7b8f7afa5f6d6be19ea81630d36ccfb2f487de50d0cf46da8d3fe3512812043c0e3ef2d7231fb0b0a35a0fb283be30a1247780f30ae0294e8b6f5897383edb895595f577524df54593cdf927b4967616ee3913e4d6b29b0dbd7c33a2a45e4ef1b1954ea5d91ce37efc1302e7ce02a97395565da2a5c5d3fdb0d87684e9b1c0ad07ec33df2dfad528e2ea0966d2a47dd5ee88e77d653c0d004fab0165f0757c4da40af327e7192536c79947a80a827aa2107dacfae3debfc8fad3d6e08076d938c510a276bdf6721a1f087cb169515028ad5ce27a1047abd92809934ca63b893f71f9a34a99c0fd30310c47e9aa37394d0ab73b254d3ca69d9c5549c9479aae24264ac5ea64d3fd821c3962ec77e709f9d30bc7b65a52e48c16e80603558caca1811411c3155d1f949fc9cf9aa9385a7199e99be77a66fad7eed91258de55b2c4c83f9a050adebea5f09758f40dac4a1c394ee8d687879150d26426895ab1938e14ae11b376254c91fc6130436996f8ed43bd27be20ec9067111c116ec94cc2b06cc91a13c5d10bbd7eecea4792f17b2b77631ef145e9fb41a83eaa11c2b72a48fb90fdbd88644c4edf8ab20dce3118364b276ac1237b36c8926e346aab5a111aa0bf341c518b7bff9e9dbb8bcb4728601b3760663e67650331e6fb54ac82fc414cb8ddfc160a25311ec5272de46217fef8b992ff89754fbee351f21bb90b6c97078b510c983350681266c8fed1f0583c5151e7b8fe3b7292319699687cc6b641fdbd689428543bc0fa1facc109de65b62784c2d985ab15d77d3af12af6d03e8d1859a553688584d75ef673a1de74093ee108c761fff32c217c231b0e2953daf521429264c0963bc8a5cdeddc617a7285b934ea51ddb5cdab23bcede86be36e001bc65c65e9a1c94baff4fab8eb5f8ed42ec377423633fe00049142467c47c5d58a7202c8e9104841c1f7f380145a6a0a828c570235e507ae5868a6062f722bb98ff6be");
//        byte[] privK = Hex.decode("dc7bc9a2e0b6dc66823ae4fbde971c0cfc46f9d96bbfbeebb3470ae0a5a0139ff037b84e75537e0a1cf02a517acfe323ffffe11df72e4f38430e0e66a2654b2f2ef757da47649d9f63fa03f1bf6fe6bc7c62971a98a2bd9d36eb0ec43ad4e9d940df3bb5874f5c92192aa31e0535d3cf70950bba858d11a688eaf854f63ecfc520c50d624891434265d8b0680c03061040299a104082c0910c8508d1100d44a6509408292211125b90508a2688e1302dc4021280028ac302611820851237808a000ae2040421b4910bb80550a08051b2511c28428a3672a494504910201bb45161424424a75001328181942d62a850023449ca94200b296213156408924c48122100b605030208e0060200a311e1802021116483a62898029291480801083041066613200e5b360951400c53000aa08851944842e316704ab2089b92440025121b0309418209c2a0800b290a819851c4340da4424500a0105b048e603400138928a4422648002c90202d194068e2146d19278a083746e4146914006422c660d3a03013242844965014166da0284dcc462e94367100232e1c114909a2040131060a2172c2142ada000c5a260d13228a62c444e3142d013445980224d33841c0308121a621e348720b1984d2c89108b8690887714a2884d496451a9301ca2285da30859ac851dcc00820106060465262302aa224251044640b2842988011540692144251d236719bb4900b082890188e41c469e1a469032160e01409d3020c20c88c1cb23164086218476920228ccb8470089528029550533270013405888424541041d202881aa84ccac88181008d0392899ab809d9900c9a1290614065c9322d89860c123521cc4266c8360010062411028ea3b44d44023043a0285a002ed1980c4882658922441c010212907084226e12134d011902519064113364c91806c2c04589262908b63024308cda022e0c27250b367058162c5116420b4946c1208841246c99466a04434e18a86c821661922028639409c30211029520211782d43868003460c84688e0160000a32dc0a82824b640831464c81022a2086503234ac8122ea098418c2072cc308a62c665093408412682da429089328514967081226001176d5948428ab88d592051d80892e2c0889044700ac0245a020904218a59c45094441094140820460209270c441020dcc8209212015038250c456e4a1666223770dc808ca426412222441ba3618a343099844099c42952046d88146ccb242a7cd129a8d333115c62d033b6a8357cf7cd10268ab12f16fceb7975d0a28a6c4822213c9a772df084ad91a669e2040550fc5e8d0aeb10fab2375fc9625ef9cd48c19631997a1cb6455d2c6286c569c9637add0317ce990996b28e51c3f3f717fb5907bbdd53961ad3497f2c3c473cce170906ac4c624a89aa8fbe624d99385e9c9548bf05e8cafd47d2476e41b73001f813726499e88b2b3b6f596ca311657850346598994c40e34747161e4e76264deef2a3019389d1594c942301af47b7544c23ecda2df2dece81e487d8f3f58ea89cd811d7275807ff1b0369ba86470088c174a3099fdafbe5fbb4d158801053b2b435d54059e26dee76d10a7a372f06b0b88b985b32f52052387438be8dc8bc6ae7369e2da9aa5e2585f8de403d091ccb7f790d54ddb34c608b0876f2825e9113be20a2b85867a01bda53287ac780bcd8b606d2e6d7712c56ce0142d22fe6b786de544963e134fecedfafb83d763061d799096a59e30d4472e440ae1faaabdf42640ce69740ceb9cae1a9612c21931b74af3f780236123321b205b6efd6cbb134f4c73d63c0c13e660b59d5920bc33197c355853d8d1cddc7959f7bc500ac81d985016f5b89a0eec79b0d9364ead8e38577c2a6549f2d067cb09438fdb21220aec80f6e22a476f332a2a4a0b7acbeb9e078d2b5a92ae84c924f7cb19fc7df377beb6546af97aa985c747cd111a127a674b4c26d89c14485b82e3a498a12d05406febd6c4d4b8bc051ab2cb91224b078538374b794b7dd9ddf3ac2b4a671fb7b9cf5acb78622ae2709eb2db16943aa24a9c97a81077bc784d25c0ea5991d2de883798a1f0e78f3361ed6a10dded81b1d683658331534fd7c01bc0eb00dfc4c3c84f0693046ff806bb200dd7bd4c0e6abca3f2934b4814fc0e1f8be615a2dda7c8a8d06cf9ce8566b40f4a6543b25bacddc926863fc0fa2007d6d7bf6d18dc98df696bd0865bf0be4c492b8043a32def8e3595ba7da345252f38f95be10fd7fb899b498fa01b09de5d5608eabc44a721aa04c4ef1dcb86102ac5f5f79c9708dcf5c5e896edd8c2c7bde3fa83e6ffce22d66174e31657a0b6361585e669d3031952f08631ae1f16ff90b90d0aad3c6d7e1dd0a9c41ab00a6e1c4f96af9ac5b79fcf821ffc016cb059245fb78dbe6c633d965aaab5333be07195c4b74b18e4600ce783c0a914ef4281016e80a7c9aa92d0fd789879c5e6751125ecb154432311e41cebd4fab3a31e4d2ce22d0f8c67737bf8a0dd85fe1349d5079a4d5feb3fee9378ca47ae46cc58a3f02038cfd53c4cee9cc4270cebc3d115a39c831e8ed41c4dbe4051b51d7872ba0c2bb163e0085201188eaa624a6bea9400a3a1fcc355a57f15704e61fda55a5dbaea8448fa5cb2d377a07f58305ad107e844ab4806e5bf99c1f513ee1d0a2acc04549f0801742169a77971d0adbfbfe0dd2ee5d16bc461e35748d1f3f6f4598321e8c49e79e740f990359858d2729dde007fcb26fdda9aa6e2ec4bd736f2836e7e4c83440191c849f6a53c72a4f8f830d001ea3b18f3cb4a5bd3cf066032b4932cfd2e62a9b55723fa61c688c935518af6860cd649bfbf1bf5fdc1f36dcaefaa157438d1cc8d56a150161511df82631f5e88e773e4ce263f276b7b3678d4c6fc75311d411c0d01bfdb595bb70552838e1b86517c837d909e772b428599e1fe569f77ce61531fde6fd31cdce1bdee4ba467fcbfbb9feeaad99fef67d4906e036c73662ddce158d4e5d4635e5d366f79f31a19d1b3dc4a591b0df194bb06c18147f41d88d1a409becdfb67eb063d16312266fd51b521ba9115e2e5e2aeae6ec511cede13ed4132ffbe0273f6c7039b3874f058804a54809af60557a21d9b4b831d04156a7c22dcbcdfe14f62437f449cb5ef12bf4251d485496cd835c0c2bc58bd845963dfa76ecd68519c4bdaf110be7ab052876dc3407591568c956ea3bf107c90fd5853a292f59a8d4b58b5d3fddf29bdbeac36852e3c69766fe460176a801831292b8e88a74a01ecbbe09a7b4d74cfd7fd628841944d9d556dbd60c76f96f07dc53443805ee9aa09365de4fb8179252c6b099b5dd351fdefc23dbd8090596c5d208ffd2c5661d8e5612dd574fc69045c769a969e600d77cfe192f1d3ae911289355c585811491b0ccd73692ab158824ab9edf8ac8193f0b33e6138b72c6dcd5d344f807b3da92425037de5ea4eead1c795effaa145e2ecdd327606eb2609929b9474b2bb04653602555c068385e92f06f29ca613ce5b4404f01ab1805db0acaa890330d291f40692df382509302b6dc8668f2c8f2d3a44fd58dca26e9802794f73d25b3149e6d576441");
//        byte[] msg = Hex.decode("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8");
//        byte[] s = Hex.decode("eea01acc8fe6631c9260996def0c75d84998cf4512c7b67bc4246bbfbff165a404d02bca30da1c2b61d91d7986a467fd4b3a1131077ac138b4011ef07fc1f3ca6237e7fc6550c7e071c939f4554f265362eb26158ee1a2e57c72d20beb78168d9e2d7faf54763755a44bdc29e575884133062453a9e3e761a13a82143d7db7215ab0b8628c096e0f298491a8d67517ab8a90be7db5d311eddc7e883d50eb873decd9b3e420155008c0a3632d51f93a9c67ea336273c8f26617c7cfa2a3aa6d9aa075e75fc60fb587fb5522cb6bac4ef1979a069a15aed3171660ce5da2c27af188e9d3bc62eebdbd798f1a650c7d46411e3cabeb27be3ae787b5f4d82a2e2cf4eee84b4fc82edea4533a47bf7d3791933d1c5ce19c1792a6420c9dcd540dc3a494d9b518ce5f4f85d7747c2fa45d812d16f089682c57a96061210c942dbaca8dbde509f56f498d68f0b4e6f4a51373c9f5a5db2e20ec8254ea9d59f69d732fd1b1149fbd0b608368086a3b6acbe5de156fc508390ddc9ca28d201fdc67140a767b2d99d08051255e73d423750e91b1aa31982cc7014e46c75b69ec972f15745bafbe4878f73d8800d80ad22716f15f4d964f0468e8583add1a4ba8f544e9b83dd6c5ebf744436e254bd699e8909e712d9f6e69fbda39be69a4e0bb58cdd0ddbd369cf5a6475b1ad5fe2849c439611516bd13de14b34b26a731c5a5bde4fae538782a6daeb6fbdaf4cf1af40f3b9c7896e87ac71b3fc95eea02f2f28bf62b9d613998ad973added64515a699fc89304b8fe4d4c97759662b720835c2b28585648e54dedfbfa40fd1455e8a945a390765e3b1a2588286bd4f2995eca39ce9eca6d2e32d92e18c930e4b99109f148db96f1763703aeb431c3c815d577c2b0282181932bb182325bf45e1355d91c8ec669ccd94429dc4ea0abc562988bd2b27b39f2dd0e4ace6fc9148cd064005e9cf0f8105a6534261942774c2a02f150f8d250822745b1cc40e1d57c68dea152c0f5088712266e5a37eb7760204c2747561688990d3cf7c76660e5671727c7ebde56420c91549a48b3763062ff92a4679e7d3e8569303eeff650c0ae606234d70a350aa9862b912825b13c1ec7bd6bf346717b0f30c45c1925873f04d469fd28f82f19375531ffb83851c471ebf623c86130d929e739bd8721d97ca9a83676f26c0a75493b5b02f0921aea91baae2da96532ab9db04dc997d5f800f58a891f6ef26e5478de1ce9b4da04eccac4cee81de5c3b1010ef28242217ec737beb36815c4af1de9a4160180ea896120ce96869bf551bb6be079482f4ab5c0f7f234c50bb4139ff9fba1b594c85cc3780434fc00f7d0492cfc86c0d1889784b113650e3c29bb2e9ed6f94df5ea42afac8060856fb90fab5f4c6fb6875fd67e0438335bcd5199b72706cf358492e5f4945bf2a686aa2861908d6a71ba4e760c87e75a7ff31169993cf048817512aeac4e960771879be541b1adcd6c2da9f9d2153e728d4ee1e91acd7f704e0b472856cfd8f85e2f30b0f6e427f190dbc1079343fdc71f9ac0b8aa5e6fdfd60fe9c90e4bebd4a91dbf16378bcc2a330aeed5b7e8dd617fbf3c6ed9b2c2ac82f2e9d03c975b2a832a667864090da9ca91ad1af97278f6cfebeaf2cc681957f3d75d17a5710de85444b636cf7e0dbac06852fe669f87bc7c430ff548ee0b34f1a68e86f1b26290f8a056c0bccd18a540ce04ee7fdee47f5176b811021a89d170e71250a040e10f8f900236617c6be92217b77aa00854d6376739d5a63d32a377da20c368092367fc6afb62e0b898c01462a399aa3dba4beb0d03d7f8a2e84b499a41e7a6e50cd5e09b4d6d8cb3e8ee3a2d1b50775f9caf7335f1ea15b2312352831418ce2529542011a19c6ece5c1e6dfe7e37821933594ca6f55ca6c799b32f88b21d59744c10538ea7208eb61a04d24476c326068ac9ad4199080e02b95766f6a18738c7e4506d18e9c5c526ef4f28ef14662667dc865ffd446026cefca1b39be77cdfd7773aac0bf570647c21979b9f0ff0d67f2a9940e1e1c27e9e3296c7d890c5627e9126fa09bed1f242aa23112d828529ce431939c9ecc0d4311742a1fa5f9f283eb0135093d3e6aa9e89d4641415678f0b2ecb1210a611d062c5e17f01521aa45d778e2a0770cfda540ce1b5bbb3fabfc783601480b080f4e7275e69705b6cff043a3b503da77fbdc05702b790b1cf4dccfb6b2df00bf0ee896420175e1293a6b8fbc96cf9759a6c0e56067dc9e2522621af2cf830e2bb648f0ca3560bdf9c2c0c01bb23806455bc40889472398f9daf71f0ab9e1aab2fe8d6c8c504a1a45d99229828a9588a559a7172b041b2bbcdbe2e59b749b3e1219abf51a39164c9fac17bd8c83eab1e0e04e029550b689134194d486083b956706a6706274324d63ff79c35f37cf8c2932910e60e1da7cc6c4d9b966fb11437f7d4e94221e4b9ce51ea04325e4b75e45dbbbaadeeadd432e776c9b14cff55529c24b43211b52d1f27de0d86c0f253ec3c2262fdfb1ecb18442174321bbed4c1454522d747be4f53f9ea445d4db360c5c0ddbac51179c7f6016249bcadcce47d4abaf0604047d806f556d11aba411239a32a80d4403c72198036917b6c3b9c5fefcbb73b4d11cea0cc09b419ab8bb0a093131b4c32280fac586bee305e14a18432bbaf1ad6ffc67863edd564df4f9518c6363b80d83c59440bde98c2eeed939bfa1d8f720a805088e2090ab1af71ad5190978b2e23a7d58fc28ab2ed623f2cc65d67629a2fbbe84309a3e0447f3805728155cca522217f9e66b5b2d794fec7131b091f7f77df37e8d726f150d416018941a7b48617fe291a3a3594df80bb1927d87d8f8d5cb945c39c977e7a4f9882e3facd6f26e42390a1f7d14e55797bd22ae78ac11208084be07399d2f9cd2fa331784c5e65de766d87c3d19aad2c7993485e65f11b2c03533f265d9268f8d7f9ce14f97a76891e2b764d2e0a7baf2f81c6fcfd15c78552bba4952fe375c9872a25fddfa19a29695320858fa8a910c29d0739edff01da6d80f757906f7103984c4910c44220ce83fb5b46527c918d186b5c096ea4d1c85df71b4e7d625bb2df5a898880a18238eb4388f66f0d5daf074bdfc6e3b4695ef5faaf754ed764b80463d724d1fc41b598861207d1971cfe1e857cf2bf8dcc4afae1e44c622d96194d3f85fa5a37aed9a154074fbc54d50724658678dfba30bce2fc853bf87f7379d80865f08f0a772afedd8f45808b49605ff3d2875a6ce7b90f4a61fc55734f791bf2e6ed554309111a385158627d7e828491a2b7c6d1f00315162c42435b62656f89bbbcbfe1e6e8f0f7f9000711123b5b6ea7b0b7b8c9d2e5e9f5fc09727a9b9e9fb3d3d6e9ebf4000000000000000000000000000011253642");
//        byte[] seed = Hex.decode("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d");
//
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("HASH-ML-DSA", "BC");
//        SecureRandom katRandom = new NISTSecureRandom(Hex.decode("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"), null);
//
//        kpg.initialize(MLDSAParameterSpec.ml_dsa_44, katRandom);
//
//        KeyPair kp = kpg.generateKeyPair();
//
//        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
//
//        ASN1BitString pubSeq = pubInfo.getPublicKeyData();
//
//        assertTrue(Arrays.areEqual(pubSeq.getOctets(), pubK));
//
//        PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());
//        ASN1OctetString seq = privInfo.getPrivateKey();
//
//        assertTrue(Arrays.areEqual(ASN1OctetString.getInstance(ASN1Sequence.getInstance(seq.getOctets()).getObjectAt(0)).getOctets(), seed));
//
//        Signature sig = Signature.getInstance("HASH-ML-DSA", "BC");
//
//        sig.initSign(kp.getPrivate());
//
//        sig.update(msg, 0, msg.length);
//
//        byte[] genS = sig.sign();
//
//        assertTrue(Arrays.areEqual(s, genS));
//
//        sig = Signature.getInstance("HASH-ML-DSA", "BC");
//
//        sig.initVerify(kp.getPublic());
//
//        sig.update(msg, 0, msg.length);
//
//        assertTrue(sig.verify(s));
//
//        // check randomisation
//
//        sig.initSign(kp.getPrivate(), new SecureRandom());
//
//        sig.update(msg, 0, msg.length);
//
//        genS = sig.sign();
//
//        assertFalse(Arrays.areEqual(s, genS));
//
//        sig = Signature.getInstance("HASH-ML-DSA", "BC");
//
//        sig.initVerify(kp.getPublic());
//
//        sig.update(msg, 0, msg.length);
//
//        assertTrue(sig.verify(genS));
//
//        AlgorithmParameters algP = sig.getParameters();
//
//        assertTrue(null == algP);
//
//        // test using ml-dsa-44 for the key, should be the same.
//
//        kpg = KeyPairGenerator.getInstance("ML-DSA", "BC");
//        katRandom = new NISTSecureRandom(Hex.decode("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"), null);
//
//        kpg.initialize(MLDSAParameterSpec.ml_dsa_44_with_sha512, katRandom);
//
//        kp = kpg.generateKeyPair();
//
//        sig = Signature.getInstance("HASH-ML-DSA", "BC");
//
//        sig.initSign(kp.getPrivate());
//
//        sig.update(msg, 0, msg.length);
//
//        genS = sig.sign();
//
//        assertTrue(Arrays.areEqual(s, genS));
//
//        sig = Signature.getInstance("HASH-ML-DSA", "BC");
//
//        sig.initVerify(kp.getPublic());
//
//        sig.update(msg, 0, msg.length);
//
//        assertTrue(sig.verify(s));
//    }

//    public void testHashMLDSAKATSigWithContext()
//        throws Exception
//    {
//        byte[] pubK = Hex.decode("dc7bc9a2e0b6dc66823ae4fbde971c0cfc46f9d96bbfbeebb3470ae0a5a0139fdd6a6ce5bc76e94faa9e9250abd4cee02cf1ee46a8e99ce12d7395781fa7519021273da3365519724efbe279add6c35f92c9d42b032832f1bf29ebbecd3ec87a3af3da33c611f7f35fa35acab174024f118979e23bf2fe069269a2ec45fbc1b9c1fb0e1f05486a6a833eb48adc2960641d9af6eb8b7381b1ec55d889f26b084ddfa1c9ed9b962d342694cede83825309d9db6bd6ba7582132534861e44a04388a694242411761d34e7c085d282b723c65948a2ac764d9702bd8ed7fe9931d7d8704a39e6508844f3f84843c305594fe6e5404e08f18ed039ac6563cbaa34b0ca38320299d6256ec0f78d421f088159d49dc439cbc539a55884a3eb4efc9cf190b42f713441cb97004245d41437a39b7b77fc602fbbfd619a42363714b265173cae68fd8a1b3ca2bd30ae60c53e5604577a4a3b1f1506e697c37432dbd883553aac8d382a3d250cf5b29e4d1be2cbcd531ff0e07e89c1f7dbc8d4529aeebe55b5ce4d0214bfdec69e080bd3ef36cca6a54933f1ef2f37867c0d38fd5865b87929115808c7e2595458e993bacc6c5a3b9f5025001e9b41447708bfbaa0462efa63876c42f769908b432f5485508a393224960551d77eadfaf4411cbc49fdff46f2f155ddd6ec30867905b709888ca0f30f935fb8d7f4803cfc7a5f7790ca181d99ca21f2621d69a5c6d49c76b4969da62740a378470332b30947ab31ccdb9ba0c7b625879eec4bd81f0200ba23504a7dc3b118bc2ab1145df13af3c8cc39f577873b84911b3d85fbbf4cb19e4d36b10a938eeb78b599dc86615fd6cec6eb7b8f7afa5f6d6be19ea81630d36ccfb2f487de50d0cf46da8d3fe3512812043c0e3ef2d7231fb0b0a35a0fb283be30a1247780f30ae0294e8b6f5897383edb895595f577524df54593cdf927b4967616ee3913e4d6b29b0dbd7c33a2a45e4ef1b1954ea5d91ce37efc1302e7ce02a97395565da2a5c5d3fdb0d87684e9b1c0ad07ec33df2dfad528e2ea0966d2a47dd5ee88e77d653c0d004fab0165f0757c4da40af327e7192536c79947a80a827aa2107dacfae3debfc8fad3d6e08076d938c510a276bdf6721a1f087cb169515028ad5ce27a1047abd92809934ca63b893f71f9a34a99c0fd30310c47e9aa37394d0ab73b254d3ca69d9c5549c9479aae24264ac5ea64d3fd821c3962ec77e709f9d30bc7b65a52e48c16e80603558caca1811411c3155d1f949fc9cf9aa9385a7199e99be77a66fad7eed91258de55b2c4c83f9a050adebea5f09758f40dac4a1c394ee8d687879150d26426895ab1938e14ae11b376254c91fc6130436996f8ed43bd27be20ec9067111c116ec94cc2b06cc91a13c5d10bbd7eecea4792f17b2b77631ef145e9fb41a83eaa11c2b72a48fb90fdbd88644c4edf8ab20dce3118364b276ac1237b36c8926e346aab5a111aa0bf341c518b7bff9e9dbb8bcb4728601b3760663e67650331e6fb54ac82fc414cb8ddfc160a25311ec5272de46217fef8b992ff89754fbee351f21bb90b6c97078b510c983350681266c8fed1f0583c5151e7b8fe3b7292319699687cc6b641fdbd689428543bc0fa1facc109de65b62784c2d985ab15d77d3af12af6d03e8d1859a553688584d75ef673a1de74093ee108c761fff32c217c231b0e2953daf521429264c0963bc8a5cdeddc617a7285b934ea51ddb5cdab23bcede86be36e001bc65c65e9a1c94baff4fab8eb5f8ed42ec377423633fe00049142467c47c5d58a7202c8e9104841c1f7f380145a6a0a828c570235e507ae5868a6062f722bb98ff6be");
//        byte[] privK = Hex.decode("dc7bc9a2e0b6dc66823ae4fbde971c0cfc46f9d96bbfbeebb3470ae0a5a0139ff037b84e75537e0a1cf02a517acfe323ffffe11df72e4f38430e0e66a2654b2f2ef757da47649d9f63fa03f1bf6fe6bc7c62971a98a2bd9d36eb0ec43ad4e9d940df3bb5874f5c92192aa31e0535d3cf70950bba858d11a688eaf854f63ecfc520c50d624891434265d8b0680c03061040299a104082c0910c8508d1100d44a6509408292211125b90508a2688e1302dc4021280028ac302611820851237808a000ae2040421b4910bb80550a08051b2511c28428a3672a494504910201bb45161424424a75001328181942d62a850023449ca94200b296213156408924c48122100b605030208e0060200a311e1802021116483a62898029291480801083041066613200e5b360951400c53000aa08851944842e316704ab2089b92440025121b0309418209c2a0800b290a819851c4340da4424500a0105b048e603400138928a4422648002c90202d194068e2146d19278a083746e4146914006422c660d3a03013242844965014166da0284dcc462e94367100232e1c114909a2040131060a2172c2142ada000c5a260d13228a62c444e3142d013445980224d33841c0308121a621e348720b1984d2c89108b8690887714a2884d496451a9301ca2285da30859ac851dcc00820106060465262302aa224251044640b2842988011540692144251d236719bb4900b082890188e41c469e1a469032160e01409d3020c20c88c1cb23164086218476920228ccb8470089528029550533270013405888424541041d202881aa84ccac88181008d0392899ab809d9900c9a1290614065c9322d89860c123521cc4266c8360010062411028ea3b44d44023043a0285a002ed1980c4882658922441c010212907084226e12134d011902519064113364c91806c2c04589262908b63024308cda022e0c27250b367058162c5116420b4946c1208841246c99466a04434e18a86c821661922028639409c30211029520211782d43868003460c84688e0160000a32dc0a82824b640831464c81022a2086503234ac8122ea098418c2072cc308a62c665093408412682da429089328514967081226001176d5948428ab88d592051d80892e2c0889044700ac0245a020904218a59c45094441094140820460209270c441020dcc8209212015038250c456e4a1666223770dc808ca426412222441ba3618a343099844099c42952046d88146ccb242a7cd129a8d333115c62d033b6a8357cf7cd10268ab12f16fceb7975d0a28a6c4822213c9a772df084ad91a669e2040550fc5e8d0aeb10fab2375fc9625ef9cd48c19631997a1cb6455d2c6286c569c9637add0317ce990996b28e51c3f3f717fb5907bbdd53961ad3497f2c3c473cce170906ac4c624a89aa8fbe624d99385e9c9548bf05e8cafd47d2476e41b73001f813726499e88b2b3b6f596ca311657850346598994c40e34747161e4e76264deef2a3019389d1594c942301af47b7544c23ecda2df2dece81e487d8f3f58ea89cd811d7275807ff1b0369ba86470088c174a3099fdafbe5fbb4d158801053b2b435d54059e26dee76d10a7a372f06b0b88b985b32f52052387438be8dc8bc6ae7369e2da9aa5e2585f8de403d091ccb7f790d54ddb34c608b0876f2825e9113be20a2b85867a01bda53287ac780bcd8b606d2e6d7712c56ce0142d22fe6b786de544963e134fecedfafb83d763061d799096a59e30d4472e440ae1faaabdf42640ce69740ceb9cae1a9612c21931b74af3f780236123321b205b6efd6cbb134f4c73d63c0c13e660b59d5920bc33197c355853d8d1cddc7959f7bc500ac81d985016f5b89a0eec79b0d9364ead8e38577c2a6549f2d067cb09438fdb21220aec80f6e22a476f332a2a4a0b7acbeb9e078d2b5a92ae84c924f7cb19fc7df377beb6546af97aa985c747cd111a127a674b4c26d89c14485b82e3a498a12d05406febd6c4d4b8bc051ab2cb91224b078538374b794b7dd9ddf3ac2b4a671fb7b9cf5acb78622ae2709eb2db16943aa24a9c97a81077bc784d25c0ea5991d2de883798a1f0e78f3361ed6a10dded81b1d683658331534fd7c01bc0eb00dfc4c3c84f0693046ff806bb200dd7bd4c0e6abca3f2934b4814fc0e1f8be615a2dda7c8a8d06cf9ce8566b40f4a6543b25bacddc926863fc0fa2007d6d7bf6d18dc98df696bd0865bf0be4c492b8043a32def8e3595ba7da345252f38f95be10fd7fb899b498fa01b09de5d5608eabc44a721aa04c4ef1dcb86102ac5f5f79c9708dcf5c5e896edd8c2c7bde3fa83e6ffce22d66174e31657a0b6361585e669d3031952f08631ae1f16ff90b90d0aad3c6d7e1dd0a9c41ab00a6e1c4f96af9ac5b79fcf821ffc016cb059245fb78dbe6c633d965aaab5333be07195c4b74b18e4600ce783c0a914ef4281016e80a7c9aa92d0fd789879c5e6751125ecb154432311e41cebd4fab3a31e4d2ce22d0f8c67737bf8a0dd85fe1349d5079a4d5feb3fee9378ca47ae46cc58a3f02038cfd53c4cee9cc4270cebc3d115a39c831e8ed41c4dbe4051b51d7872ba0c2bb163e0085201188eaa624a6bea9400a3a1fcc355a57f15704e61fda55a5dbaea8448fa5cb2d377a07f58305ad107e844ab4806e5bf99c1f513ee1d0a2acc04549f0801742169a77971d0adbfbfe0dd2ee5d16bc461e35748d1f3f6f4598321e8c49e79e740f990359858d2729dde007fcb26fdda9aa6e2ec4bd736f2836e7e4c83440191c849f6a53c72a4f8f830d001ea3b18f3cb4a5bd3cf066032b4932cfd2e62a9b55723fa61c688c935518af6860cd649bfbf1bf5fdc1f36dcaefaa157438d1cc8d56a150161511df82631f5e88e773e4ce263f276b7b3678d4c6fc75311d411c0d01bfdb595bb70552838e1b86517c837d909e772b428599e1fe569f77ce61531fde6fd31cdce1bdee4ba467fcbfbb9feeaad99fef67d4906e036c73662ddce158d4e5d4635e5d366f79f31a19d1b3dc4a591b0df194bb06c18147f41d88d1a409becdfb67eb063d16312266fd51b521ba9115e2e5e2aeae6ec511cede13ed4132ffbe0273f6c7039b3874f058804a54809af60557a21d9b4b831d04156a7c22dcbcdfe14f62437f449cb5ef12bf4251d485496cd835c0c2bc58bd845963dfa76ecd68519c4bdaf110be7ab052876dc3407591568c956ea3bf107c90fd5853a292f59a8d4b58b5d3fddf29bdbeac36852e3c69766fe460176a801831292b8e88a74a01ecbbe09a7b4d74cfd7fd628841944d9d556dbd60c76f96f07dc53443805ee9aa09365de4fb8179252c6b099b5dd351fdefc23dbd8090596c5d208ffd2c5661d8e5612dd574fc69045c769a969e600d77cfe192f1d3ae911289355c585811491b0ccd73692ab158824ab9edf8ac8193f0b33e6138b72c6dcd5d344f807b3da92425037de5ea4eead1c795effaa145e2ecdd327606eb2609929b9474b2bb04653602555c068385e92f06f29ca613ce5b4404f01ab1805db0acaa890330d291f40692df382509302b6dc8668f2c8f2d3a44fd58dca26e9802794f73d25b3149e6d576441");
//        byte[] msg = Hex.decode("D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC8");
//        byte[] s = Hex.decode("42a2ad149a7f35856ed92005232a2d33dc4a1ad0cb0fb7b772f56956082fb9a630fd7284bca55b5cef3a55ad73c2225d7c2d143d0023cd988890b81c271b97e6ed99250bd141550e4eb0276d4a59f19023d0bd725fe2c4f3301655ae91089851db6ecd24bc448ac06c1bbad4254bb1370678858586d55ffa4a9112dd48fd14c224d35d9c2987dc8bff84578d9a5fd0a1e34f7fb34523a305f623cef1766ac8b336c6c1a062f8d273e4f5636969c8c5afb3102436f9549a68ceb5393065944f0a231eb53ef7c6d3bca1fdf2544e3637f5efa96752455e4816d8747c5af14d3996eb241b2dc28fff9a9d93d148193195a87d6763dd94a5d9dfcd8623baf73ecebf545291bd236f44a3b9c5b8d231b7d7e991f6fbd67bbf3740611ef64c66765e25dc0e968900c407565097adf82f7b2387d03f93757a88c1a7590fdca09e19579ecc124629a26e80851b1ca5f29bff6ed37fc779bfc304e93169004b7c742ff4ab9ead2e96e313f1ddd8f6f94d58298ecd2393e119f5536d46e934ff11323f06df447685fbc1f8017a1a98ed717c8c7e4aa9be3b9f0c9f4e43c802c9542a26c013a07f5dcf2cfac584e8a998712cb6f00d4e51f9a3d65bac5197b49bd5291db44fbb90160a364818548b0bb59d34f48fbfc86b7f9d765a427074bee154dacce37f2bae727e99ec55bf7b5d618eebabc73cb015d18c6ba4c45a4c5f8c8802beceb9fd183989f4ccd3964a995a19a4a4492ca043c4be3ff76505d97174db15e15d56acf3e78147c0136373e784d627360e1ad41decdbb5a92cf271cba3a969f366ef53fa1150a1514b18b8c6835a44c9139456c162dfa59e525892e38ad6864097f5108752b4b8d3f847bdc0c185f6da216da8ee00c06ee8b54d66adfa85d2f8851ecbafea5d063604d6abf28a0df4042d788cc539cbfce523f1183dd7c955990ef9709d9db2d28a0ac55382b92b3869ae40072119278e005be9acd8b30507d55a065815db29fe5ad0ded3094d9e92762b1d52a7790e146d4b4b7e81389af5e1bff9485ba72ffebf902aa343e5ad737f57bee177ed8514f0549083407f6a645234be6ece678c59f905e3af7190602e4c1d8815a28e791d476c10ecfbcfc9539e995e72c8cad9f7b515a53e0c912be7071c13c2d350b1965627ec610e17bc52c13108dd3f2e2fd703edf13d76ee62d904f45d6f89b5814a6570ab5e041b14186c63bc0b93de643aa4828ae4747c964474102cfb77aed3412248c67a8fbd2971072058ddda17df2b152449c63b164dd1ca152c893e38afd042d9f186e677969dc3caa6d2105b54d7e8dc47bda7f63606e8670f3f671b0e43d1cf0884cdde011743a9748e50b66cebacfd4595c346a8229883fd92945e65fab2c9a1dad85d6ae11ed3dcd07dbe1bf031fce1c23f5d1fc61dd970b40dec577abd5b2bb697f6b24406ef7d623b45b0a96a79a8171805d599ea99fab55682eba390c0dbd7f53999ca7cd5e4e471139b5e877be6fdcab79ba7cc7693a07bf537f4e05669a977610d2f526e7ed6edf75164b09e6ed608ec755744571694218a36ad96362381fbfb967ec0e0180fb8efd4972c8614f82e262e0628a083f360ed927dc85b9b95d5c53eb371848f3ee1c7dd069918f74e7a1f25fc6f955e72be0202a401e28c7fc20c8378469b6bc370700b6fce04224a3f3815598f15f44ad95972208c215126753db78fa84fac87b62da8b1249360ff2171643cb100c07f8caffbd9aa4d94b0b192eb49af6c9d3b68357d708d597004a178c116efe72f5ec80d2269c592e65eb12b5968f3c153bb900ea3d49a91e155dc38383844bb849f8f78c9038d30ab7b6719830a7667a725f67b6318615b37f0d0a2dedf7e2f741d1807abd4614087449ce789ff10deee23befcac04de3376245143f24df1a1f95d7442439b2e6f983959598c95577e2d262e96f8fa4cc4a1fd59e2b4d9c4394071630c2e0569c4fa3784bfb0d39f42e366c8fee583412be0c6d4c67fff9d570926210fe632fa125245496af25cd084d723994c94e2ff659637784c31e9a555a788c8fc7410839ee1c6e80544d825b79fcf238afd1c0d6be0fa32ecb8b93463d98b9f2b3495c81f25877a613227bdaf8b94342da81c0f2995872a5a75341503bfaec2bb7f95db0f340f4732a832f4effab9bf4da476528a15fbfc5104fe3dae3a5fdd05ebc42989d96f1eb056c3ffc79de35d229a55e301c33975b92c4a7de50962a2fcb83912441189ac1a4e4ad38e30ecc3df084f0ecd8745750323debdea86ab87e725d41fd044fd507f279e7dfbb6a04b34cb150ed9fda95d7393cf8e611589ec56a5dc9a9de4dc80c36e7cbcfb77501bc69b93437ce3642ee35da9a0d71b76a641847fb9798e18b1d073a7b832958f65079648b47370bfc175869dfc412b0b3074fc43d608acd2b602f7b9d2fb831c3a37de56600a34135a1d029bb5f582732b2dc45f992c4a6dcc2c3b1cad807ad4e741490b5cad74a6e7a416fe91b1ad216c428558c3f8d0797d4acca85ca864a5194cf1273622ffeed9624f702b4725a93057a90d155ee081183d87517123647fbd31216b664107a124adef5e1dbedb7e714f6b49696fa21a4a3c2c822cc675b2a171949cd64d10fa188913a9e3318dc9829aa3e6bdeac781afd2b20211c6aeda61deedc8ef7d1426f7cf464af6a700bfce3e0df99f417b1440807870ca0af461cec38cde60e6861f817901a56db98af64e9be3648585513f833a3e5c6fedc613dfff720e76a0800139d53957b1f91e7efcd0e6308613740705e589d48934f5e9a193af901b3335e767310830ebc6662ef8d33e7c87e242b65595c61212f9ac459c09995cf4a996584bf473d4c58db901c2c994f62e6022720987e653d1e3100a84db6e077b9e4387b9df33048d201969b5fb215cb142000bb21e7e5cc3e74b934cfb80e9d117fcecb1c68479390f173cb8e33853f66a51d157287324b3f8a590e40646877c5435e3251fdd5c19791471b51f07c5265dd79aeb2997545e7a3c7b6484f34734871145260d019b28692be1357ff27b9361ff90c1e5f308a1832a900dc915c3771cb83e964e99667e5e46a713c152ce2e33d45ef4050d34671391ec20f93fcb9b9597781e1ca4d4ba1762fced1f9a06311905c6bdda492f72ce9a1c9f20cc26d020aa0a3cede4bf35a7735fe41d1ae0e0ecbb5da8ccd68f37c7acaebc1f8fc764db3bed1dbf4053911b9105e09605de322fb8750717c756330856835ed2c713ff7957f8a99f7ed485e480949b2a9b9d1d8acc0eafeee71977a56a07132c495067aeb7b9dae1e7132036424b7993949cbfd2dedff91b42494a555d6a72757aa2aebfd0f0fb161a617c8890a4a5afc0d1d9dadef300000000000000000000000000000000000000000000000c1a2a39");
//        byte[] seed = Hex.decode("7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2d");
//
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("HASH-ML-DSA", "BC");
//        SecureRandom katRandom = new NISTSecureRandom(Hex.decode("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1"), null);
//
//        kpg.initialize(MLDSAParameterSpec.ml_dsa_44, katRandom);
//
//        KeyPair kp = kpg.generateKeyPair();
//
//        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
//
//        ASN1BitString pubSeq = pubInfo.getPublicKeyData();
//
//        assertTrue(Arrays.areEqual(pubSeq.getOctets(), pubK));
//
//        PrivateKeyInfo privInfo = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());
//        ASN1OctetString seq = privInfo.getPrivateKey();
//
//        assertTrue(Arrays.areEqual(ASN1OctetString.getInstance(ASN1Sequence.getInstance(seq.getOctets()).getObjectAt(0)).getOctets(), seed));
//
//        Signature sig = Signature.getInstance("HASH-ML-DSA", "BC");
//
//        sig.initSign(kp.getPrivate());
//
//        sig.setParameter(new ContextParameterSpec(Strings.toByteArray("Hello, world!")));
//
//        sig.update(msg, 0, msg.length);
//
//        byte[] genS = sig.sign();
//
//        assertTrue(Hex.toHexString(genS), Arrays.areEqual(s, genS));
//
//        sig = Signature.getInstance("HASH-ML-DSA", "BC");
//
//        sig.initVerify(kp.getPublic());
//
//        sig.setParameter(new ContextParameterSpec(Strings.toByteArray("Hello, world!")));
//
//        sig.update(msg, 0, msg.length);
//
//        assertTrue(sig.verify(s));
//
//        // check randomisation
//
//        sig.initSign(kp.getPrivate(), new SecureRandom());
//
//        sig.setParameter(new ContextParameterSpec(Strings.toByteArray("Hello, world!")));
//
//        sig.update(msg, 0, msg.length);
//
//        genS = sig.sign();
//
//        assertFalse(Arrays.areEqual(s, genS));
//
//        sig = Signature.getInstance("HASH-ML-DSA", "BC");
//
//        sig.initVerify(kp.getPublic());
//
//        sig.setParameter(new ContextParameterSpec(Strings.toByteArray("Hello, world!")));
//
//        sig.update(msg, 0, msg.length);
//
//        assertTrue(sig.verify(genS));
//    }

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

    public static class MyContextParameterSpec
        implements AlgorithmParameterSpec
    {
        private final byte[] context;

        MyContextParameterSpec(byte[] context)
        {
            this.context = context;
        }

        public byte[] getContext()
        {
            return context;
        }
    }
}

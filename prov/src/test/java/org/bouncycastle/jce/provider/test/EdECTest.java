package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.crypto.KeyAgreement;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.jcajce.spec.DHUParameterSpec;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.jcajce.spec.XDHParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class EdECTest
    extends SimpleTest
{
    private static final byte[] pubEnc = Base64.decode(
        "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=");

    private static final byte[] privEnc = Base64.decode(
        "MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC");

    private static final byte[] privWithPubEnc = Base64.decode(
        "MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC" +
            "oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB" +
            "Z9w7lshQhqowtrbLDFw4rXAxZuE=");

    public static final byte[] x25519Cert = Base64.decode(
        "MIIBLDCB36ADAgECAghWAUdKKo3DMDAFBgMrZXAwGTEXMBUGA1UEAwwOSUVURiBUZX" +
            "N0IERlbW8wHhcNMTYwODAxMTIxOTI0WhcNNDAxMjMxMjM1OTU5WjAZMRcwFQYDVQQD" +
            "DA5JRVRGIFRlc3QgRGVtbzAqMAUGAytlbgMhAIUg8AmJMKdUdIt93LQ+91oNvzoNJj" +
            "ga9OukqY6qm05qo0UwQzAPBgNVHRMBAf8EBTADAQEAMA4GA1UdDwEBAAQEAwIDCDAg" +
            "BgNVHQ4BAQAEFgQUmx9e7e0EM4Xk97xiPFl1uQvIuzswBQYDK2VwA0EAryMB/t3J5v" +
            "/BzKc9dNZIpDmAgs3babFOTQbs+BolzlDUwsPrdGxO3YNGhW7Ibz3OGhhlxXrCe1Cg" +
            "w1AH9efZBw==");

    public String getName()
    {
        return "EdEC";
    }

    public void performTest()
        throws Exception
    {
        KeyFactory kFact = KeyFactory.getInstance("EdDSA", "BC");

        PublicKey pub = kFact.generatePublic(new X509EncodedKeySpec(pubEnc));

        isTrue("pub failed", areEqual(pubEnc, pub.getEncoded()));

        serializationTest("ref pub", pub);

        PrivateKey priv = kFact.generatePrivate(new PKCS8EncodedKeySpec(privEnc));

        isTrue("priv failed", areEqual(privEnc, priv.getEncoded()));

        isEquals(((EdDSAPrivateKey)priv).getPublicKey(), pub);

        priv = kFact.generatePrivate(new PKCS8EncodedKeySpec(privWithPubEnc));

        isTrue("priv with pub failed", areEqual(privWithPubEnc, priv.getEncoded()));

        isEquals(((EdDSAPrivateKey)priv).getPublicKey(), pub);
        
        serializationTest("ref priv", priv);

        Signature sig = Signature.getInstance("EDDSA", "BC");

        ASN1Sequence x25519Seq = ASN1Sequence.getInstance(EdECTest.x25519Cert);
        Certificate x25519Cert = Certificate.getInstance(x25519Seq);

        sig.initVerify(pub);

        // yes, the demo certificate is invalid...
        sig.update(x25519Seq.getObjectAt(0).toASN1Primitive().getEncoded(ASN1Encoding.DL));

        isTrue(sig.verify(x25519Cert.getSignature().getBytes()));

        CertificateFactory certFact = CertificateFactory.getInstance("X.509", "BC");

        X509Certificate c = (X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(EdECTest.x25519Cert));

        isTrue("Ed25519".equals(c.getSigAlgName()));

        // this may look abit strange but it turn's out the Oracle CertificateFactory tampers
        // with public key parameters on building the public key. If the keyfactory doesn't
        // take things into account the generate throws an exception!
        certFact = CertificateFactory.getInstance("X.509", "SUN");

        c = (X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(EdECTest.x25519Cert));

        testPKCS8Override();
        
        x448AgreementTest();
        x25519AgreementTest();
        ed448SignatureTest();
        ed25519SignatureTest();
        x448withCKDFTest();
        x25519withCKDFTest();
        x448withKDFTest();
        x25519withKDFTest();
        x448UwithKDFTest();
        x25519UwithKDFTest();

        xdhGeneratorTest();
        eddsaGeneratorTest();

        keyTest("X448");
        keyTest("X25519");
        keyTest("Ed448");
        keyTest("Ed25519");

        keyFactoryTest("X448", EdECObjectIdentifiers.id_X448);
        keyFactoryTest("X25519", EdECObjectIdentifiers.id_X25519);
        keyFactoryTest("Ed448", EdECObjectIdentifiers.id_Ed448);
        keyFactoryTest("Ed25519", EdECObjectIdentifiers.id_Ed25519);
    }

    private void keyFactoryTest(String algorithm, ASN1ObjectIdentifier algOid)
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance(algorithm, "BC");
        KeyFactory kFact = KeyFactory.getInstance((algorithm.startsWith("X") ? "XDH" : "EdDSA"), "BC");

        KeyPair kp = kpGen.generateKeyPair();

        Set<String> alts = new HashSet<String>();

        alts.add("X448");
        alts.add("X25519");
        alts.add("Ed448");
        alts.add("Ed25519");

        alts.remove(algorithm);

        PrivateKey k1 = kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        checkEquals(algorithm, kp.getPrivate(), k1);

        PublicKey k2 = kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        checkEquals(algorithm, kp.getPublic(), k2);

        for (Iterator<String> it = alts.iterator(); it.hasNext(); )
        {
            String altAlg = (String)it.next();

            kFact = KeyFactory.getInstance(altAlg, "BC");

            try
            {
                k1 = kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
                fail("no exception");
            }
            catch (InvalidKeySpecException e)
            {
                isEquals("encoded key spec not recognized: algorithm identifier " + algOid.getId() + " in key not recognized", e.getMessage());
            }

            try
            {
                k2 = kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
                fail("no exception");
            }
            catch (InvalidKeySpecException e)
            {
                isEquals("encoded key spec not recognized: algorithm identifier " + algOid.getId() + " in key not recognized", e.getMessage());
            }
        }
    }

    private void keyTest(String algorithm)
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance(algorithm, "BC");

        KeyFactory kFact = KeyFactory.getInstance(algorithm, "BC");

        KeyPair kp = kpGen.generateKeyPair();

        PrivateKey k1 = kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

        checkEquals(algorithm, kp.getPrivate(), k1);

        PublicKey k2 = kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));

        checkEquals(algorithm, kp.getPublic(), k2);

        serializationTest(algorithm, kp.getPublic());
        serializationTest(algorithm, kp.getPrivate());

        String pubString = kp.getPublic().toString();
        String privString = kp.getPrivate().toString();

        isTrue(pubString.startsWith(algorithm + " Public Key ["));
        isTrue(privString.startsWith(algorithm + " Private Key ["));
        isTrue(privString.substring((algorithm + " Private Key [").length())
            .equals(pubString.substring((algorithm + " Public Key [").length())));
    }

    private void xdhGeneratorTest()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("XDH", "BC");

        kpGen.initialize(new XDHParameterSpec(XDHParameterSpec.X448));

        KeyPair kp = kpGen.generateKeyPair();

        isTrue("X448".equals(kp.getPublic().getAlgorithm()));

        kpGen.initialize(new ECGenParameterSpec(XDHParameterSpec.X448));

        kp = kpGen.generateKeyPair();

        isTrue("X448".equals(kp.getPublic().getAlgorithm()));

        kpGen.initialize(448);

        kp = kpGen.generateKeyPair();

        isTrue("X448".equals(kp.getPublic().getAlgorithm()));

        kpGen = KeyPairGenerator.getInstance("XDH", "BC");
        
        kpGen.initialize(new XDHParameterSpec(XDHParameterSpec.X25519));

        kp = kpGen.generateKeyPair();

        isTrue("X25519".equals(kp.getPublic().getAlgorithm()));

        kpGen.initialize(new ECGenParameterSpec(XDHParameterSpec.X25519));

        kp = kpGen.generateKeyPair();

        isTrue("X25519".equals(kp.getPublic().getAlgorithm()));

        kpGen.initialize(256);

        kp = kpGen.generateKeyPair();

        isTrue("X25519".equals(kp.getPublic().getAlgorithm()));

        kpGen.initialize(255);

        kp = kpGen.generateKeyPair();

        isTrue("X25519".equals(kp.getPublic().getAlgorithm()));

        kpGen = KeyPairGenerator.getInstance("XDH", "BC");

        try
        {
            kpGen.generateKeyPair();
            fail("no exception");
        }
        catch (IllegalStateException e)
        {
            isEquals("generator not correctly initialized", e.getMessage());
        }

        try
        {
            kpGen.initialize(new EdDSAParameterSpec(EdDSAParameterSpec.Ed448));
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            isEquals("parameterSpec for wrong curve type", e.getMessage());
        }

        try
        {
            kpGen.initialize(1024);
            fail("no exception");
        }
        catch (InvalidParameterException e)
        {
            isEquals("unknown key size", e.getMessage());
        }
        
        try
        {
            kpGen.initialize(new EdDSAParameterSpec(EdDSAParameterSpec.Ed448));
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            isEquals("parameterSpec for wrong curve type", e.getMessage());
        }

        try
        {
            new XDHParameterSpec(EdDSAParameterSpec.Ed448);
        }
        catch (IllegalArgumentException e)
        {
            isEquals("unrecognized curve name: Ed448", e.getMessage());
        }
    }

    private void eddsaGeneratorTest()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EdDSA", "BC");

        kpGen.initialize(new EdDSAParameterSpec(EdDSAParameterSpec.Ed448));

        KeyPair kp = kpGen.generateKeyPair();

        isTrue("Ed448".equals(kp.getPublic().getAlgorithm()));

        kpGen.initialize(new EdDSAParameterSpec(EdDSAParameterSpec.Ed448));

        kp = kpGen.generateKeyPair();

        isTrue("Ed448".equals(kp.getPublic().getAlgorithm()));

        kpGen.initialize(448);

        kp = kpGen.generateKeyPair();

        isTrue("Ed448".equals(kp.getPublic().getAlgorithm()));

        kpGen = KeyPairGenerator.getInstance("EdDSA", "BC");

        kpGen.initialize(new EdDSAParameterSpec(EdDSAParameterSpec.Ed25519));

        kp = kpGen.generateKeyPair();

        isTrue("Ed25519".equals(kp.getPublic().getAlgorithm()));

        kpGen.initialize(new ECGenParameterSpec(EdDSAParameterSpec.Ed25519));

        kp = kpGen.generateKeyPair();

        isTrue("Ed25519".equals(kp.getPublic().getAlgorithm()));

        kpGen.initialize(256);

        kp = kpGen.generateKeyPair();

        isTrue("Ed25519".equals(kp.getPublic().getAlgorithm()));

        kpGen.initialize(255);

        kp = kpGen.generateKeyPair();

        isTrue("Ed25519".equals(kp.getPublic().getAlgorithm()));

        kpGen = KeyPairGenerator.getInstance("EdDSA", "BC");

        try
        {
            kpGen.generateKeyPair();
            fail("no exception");
        }
        catch (IllegalStateException e)
        {
            isEquals("generator not correctly initialized", e.getMessage());
        }

        try
        {
            kpGen.initialize(new XDHParameterSpec(XDHParameterSpec.X448));
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            isEquals("parameterSpec for wrong curve type", e.getMessage());
        }

        try
        {
            kpGen.initialize(new XDHParameterSpec(XDHParameterSpec.X25519));
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            isEquals("parameterSpec for wrong curve type", e.getMessage());
        }

        try
        {
            kpGen.initialize(1024);
            fail("no exception");
        }
        catch (InvalidParameterException e)
        {
            isEquals("unknown key size", e.getMessage());
        }

        try
        {
            new EdDSAParameterSpec(XDHParameterSpec.X448);
        }
        catch (IllegalArgumentException e)
        {
            isEquals("unrecognized curve name: X448", e.getMessage());
        }
    }

    private void checkEquals(String algorithm, Key ka, Key kb)
    {
        isEquals(algorithm + " check equals", ka, kb);
        isEquals(algorithm + " check hashCode", ka.hashCode(), kb.hashCode());
    }

    private void serializationTest(String algorithm, Key key)
        throws IOException, ClassNotFoundException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ObjectOutputStream oOut = new ObjectOutputStream(bOut);

        oOut.writeObject(key);
        oOut.close();

        ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));

        Key rk = (Key)oIn.readObject();

        checkEquals(algorithm, key, rk);
    }

    private void x448AgreementTest()
        throws Exception
    {
        agreementTest("X448");
    }

    private void x25519AgreementTest()
        throws Exception
    {
        agreementTest("X25519");
    }

    private void x448withCKDFTest()
        throws Exception
    {
        agreementTest("X448withSHA256CKDF", new UserKeyingMaterialSpec(Hex.decode("beeffeed")));
        agreementTest("X448withSHA384CKDF", new UserKeyingMaterialSpec(Hex.decode("beeffeed")));
        agreementTest("X448withSHA512CKDF", new UserKeyingMaterialSpec(Hex.decode("beeffeed")));
    }

    private void x25519withCKDFTest()
        throws Exception
    {
        agreementTest("X25519withSHA256CKDF", new UserKeyingMaterialSpec(Hex.decode("beeffeed")));
        agreementTest("X25519withSHA384CKDF", new UserKeyingMaterialSpec(Hex.decode("beeffeed")));
        agreementTest("X25519withSHA512CKDF", new UserKeyingMaterialSpec(Hex.decode("beeffeed")));
    }

    private void x448withKDFTest()
        throws Exception
    {
        agreementTest("X448withSHA512KDF", new UserKeyingMaterialSpec(Hex.decode("beeffeed")));
    }

    private void x25519withKDFTest()
        throws Exception
    {
        agreementTest("X25519withSHA256KDF", new UserKeyingMaterialSpec(Hex.decode("beeffeed")));
    }

    private void ed448SignatureTest()
        throws Exception
    {
        signatureTest("Ed448");
    }

    private void ed25519SignatureTest()
        throws Exception
    {
        signatureTest("Ed25519");
    }

    private void agreementTest(String algorithm)
        throws Exception
    {
        agreementTest(algorithm, null);
    }

    private void agreementTest(String algorithm, AlgorithmParameterSpec spec)
        throws Exception
    {
        KeyAgreement keyAgreement = KeyAgreement.getInstance(algorithm, "BC");

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance(
            algorithm.startsWith("X448") ? "X448" : "X25519", "BC");

        KeyPair kp1 = kpGen.generateKeyPair();
        KeyPair kp2 = kpGen.generateKeyPair();

        keyAgreement.init(kp1.getPrivate());

        keyAgreement.doPhase(kp2.getPublic(), true);

        byte[] sec1 = keyAgreement.generateSecret();

        keyAgreement.init(kp2.getPrivate());

        keyAgreement.doPhase(kp1.getPublic(), true);

        byte[] sec2 = keyAgreement.generateSecret();

        isTrue(areEqual(sec1, sec2));

        if (spec != null)
        {
            keyAgreement.init(kp1.getPrivate(), spec);

            keyAgreement.doPhase(kp2.getPublic(), true);

            byte[] sec3 = keyAgreement.generateSecret();

            keyAgreement.init(kp2.getPrivate(), spec);

            keyAgreement.doPhase(kp1.getPublic(), true);

            byte[] sec4 = keyAgreement.generateSecret();

            isTrue(areEqual(sec3, sec4));
            isTrue(!areEqual(sec1, sec4));
        }
    }

    private void x448UwithKDFTest()
        throws Exception
    {
        unifiedAgreementTest("X448UwithSHA512KDF");
    }

    private void x25519UwithKDFTest()
        throws Exception
    {
        unifiedAgreementTest("X25519UwithSHA256KDF");
    }

    private void unifiedAgreementTest(String algorithm)
        throws Exception
    {
        KeyAgreement keyAgreement = KeyAgreement.getInstance(algorithm, "BC");

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance(
            algorithm.startsWith("X448") ? "X448" : "X25519", "BC");

        KeyPair aKp1 = kpGen.generateKeyPair();
        KeyPair aKp2 = kpGen.generateKeyPair();

        KeyPair bKp1 = kpGen.generateKeyPair();
        KeyPair bKp2 = kpGen.generateKeyPair();

        keyAgreement.init(aKp1.getPrivate(), new DHUParameterSpec(aKp2, bKp2.getPublic(), Hex.decode("beeffeed")));

        keyAgreement.doPhase(bKp1.getPublic(), true);

        byte[] sec1 = keyAgreement.generateSecret();

        keyAgreement.init(bKp1.getPrivate(), new DHUParameterSpec(aKp2, bKp2.getPublic(), Hex.decode("beeffeed")));

        keyAgreement.doPhase(aKp1.getPublic(), true);

        byte[] sec2 = keyAgreement.generateSecret();

        isTrue(areEqual(sec1, sec2));

        keyAgreement.init(bKp1.getPrivate(), new DHUParameterSpec(aKp2, bKp2.getPublic(), Hex.decode("feed")));

        keyAgreement.doPhase(aKp1.getPublic(), true);

        byte[] sec3 = keyAgreement.generateSecret();

        isTrue(!areEqual(sec1, sec3));
    }

    private void signatureTest(String algorithm)
        throws Exception
    {
        byte[] msg = Strings.toByteArray("Hello, world!");
        Signature signature = Signature.getInstance(algorithm, "BC");

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance(algorithm, "BC");

        KeyPair kp = kpGen.generateKeyPair();

        signature.initSign(kp.getPrivate());

        signature.update(msg);

        byte[] sig = signature.sign();

        signature.initVerify(kp.getPublic());

        signature.update(msg);

        isTrue(signature.verify(sig));

        // try with random - should be ignored

        signature.initSign(kp.getPrivate(), new SecureRandom());

        signature.update(msg);

        sig = signature.sign();

        signature.initVerify(kp.getPublic());

        signature.update(msg);

        isTrue(signature.verify(sig));
    }

    private void testPKCS8Override()
        throws Exception
    {
        System.setProperty("org.bouncycastle.pkcs8.v1_info_only", "true");

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EdDSA", "BC");

        kpGen.initialize(448);

        KeyPair kp = kpGen.generateKeyPair();

        PrivateKeyInfo info = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());

        isTrue(info.getPublicKeyData() == null);
        isTrue(info.getVersion().equals(new ASN1Integer(0)));

        kpGen = KeyPairGenerator.getInstance("XDH", "BC");

        kpGen.initialize(448);

        kp = kpGen.generateKeyPair();

        info = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());

        isTrue(info.getPublicKeyData() == null);
        isTrue(info.getVersion().equals(new ASN1Integer(0)));

        System.setProperty("org.bouncycastle.pkcs8.v1_info_only", "false");

        kpGen = KeyPairGenerator.getInstance("EdDSA", "BC");

        kpGen.initialize(448);

        kp = kpGen.generateKeyPair();

        info = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());

        isTrue(info.getPublicKeyData() != null);
        isTrue(info.getVersion().equals(new ASN1Integer(1)));

        kpGen = KeyPairGenerator.getInstance("XDH", "BC");

        kpGen.initialize(448);

        kp = kpGen.generateKeyPair();

        info = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());

        isTrue(info.getPublicKeyData() != null);
        isTrue(info.getVersion().equals(new ASN1Integer(1)));
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new EdECTest());
    }
}

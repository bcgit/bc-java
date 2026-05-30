package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.interfaces.SDitHKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.SDitHParameterSpec;
import org.bouncycastle.util.Strings;

public class SDitHTest
    extends TestCase
{
    private final byte[] msg = Strings.toByteArray("Hello SDitH!");

    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        // BC provider is needed for the BC→BCPQC bridge tests below
        // (KeyFactory.getInstance(..., "BC") for the SDitH OID).
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testParameterSpec()
    {
        assertEquals("SDITH-HYPERCUBE-CAT1-GF256",
            SDitHParameterSpec.fromName("sdith-hypercube-cat1-gf256").getName());
        try
        {
            SDitHParameterSpec.fromName("not-a-thing");
            fail("expected IllegalArgumentException");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("unknown parameter name: not-a-thing", e.getMessage());
        }
    }

    public void testKeyPair()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SDitH", "BCPQC");
        kpg.initialize(SDitHParameterSpec.sdith_hypercube_cat1_gf256, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();
        assertTrue(kp.getPublic() instanceof SDitHKey);
        assertTrue(kp.getPrivate() instanceof SDitHKey);
        assertEquals("SDITH-HYPERCUBE-CAT1-GF256", kp.getPublic().getAlgorithm());

        // Encoding round-trip via BCPQC.
        KeyFactory kFact = KeyFactory.getInstance("SDitH", "BCPQC");
        java.security.PublicKey pub = kFact.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        java.security.PrivateKey priv = kFact.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
        assertEquals(kp.getPublic(), pub);
        assertEquals(kp.getPrivate(), priv);

        Signature sig = Signature.getInstance("SDitH", "BCPQC");
        sig.initSign(kp.getPrivate(), new SecureRandom());
        sig.update(msg, 0, msg.length);
        byte[] s = sig.sign();

        sig = Signature.getInstance("SDitH", "BCPQC");
        sig.initVerify(kp.getPublic());
        sig.update(msg, 0, msg.length);
        assertTrue(sig.verify(s));
    }

    public void testRestrictedSignature()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SDITH-HYPERCUBE-CAT1-GF256", "BCPQC");
        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SDITH-HYPERCUBE-CAT1-GF256", "BCPQC");
        sig.initSign(kp.getPrivate(), new SecureRandom());
        sig.update(msg, 0, msg.length);
        byte[] s = sig.sign();

        sig.initVerify(kp.getPublic());
        sig.update(msg, 0, msg.length);
        assertTrue(sig.verify(s));
    }

    public void testForeignKeyRejected()
        throws Exception
    {
        Signature sig = Signature.getInstance("SDITH-HYPERCUBE-CAT1-GF256", "BCPQC");
        KeyPair rsaKp = KeyPairGenerator.getInstance("RSA", "BC").generateKeyPair();
        try
        {
            sig.initSign(rsaKp.getPrivate(), new SecureRandom());
            fail("expected InvalidKeyException");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("unknown private key passed to SDitH", e.getMessage());
        }
    }

    public void testThresholdKeyPair()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SDitH", "BCPQC");
        kpg.initialize(SDitHParameterSpec.sdith_threshold_cat1_gf256, new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();
        assertTrue(kp.getPublic() instanceof SDitHKey);
        assertTrue(kp.getPrivate() instanceof SDitHKey);
        assertEquals("SDITH-THRESHOLD-CAT1-GF256", kp.getPublic().getAlgorithm());

        Signature sig = Signature.getInstance("SDitH", "BCPQC");
        sig.initSign(kp.getPrivate(), new SecureRandom());
        sig.update(msg, 0, msg.length);
        byte[] s = sig.sign();

        sig = Signature.getInstance("SDitH", "BCPQC");
        sig.initVerify(kp.getPublic());
        sig.update(msg, 0, msg.length);
        assertTrue(sig.verify(s));
    }

    public void testThresholdKeyFactory()
        throws Exception
    {
        // Regression for github #2312: SDitHKeyFactorySpi only registered the hypercube OIDs in
        // its keyOids set, so KeyFactory.generatePublic / generatePrivate from an encoded spec
        // rejected every threshold variant with "incorrect algorithm OID for key: ...". Exercise
        // the KeyFactory + EncodedKeySpec round-trip (the path the BC->BCPQC converter bridge does
        // not cover) for all six threshold parameter sets.
        SDitHParameterSpec[] thresholdSpecs =
        {
            SDitHParameterSpec.sdith_threshold_cat1_gf256,
            SDitHParameterSpec.sdith_threshold_cat3_gf256,
            SDitHParameterSpec.sdith_threshold_cat5_gf256,
            SDitHParameterSpec.sdith_threshold_cat1_p251,
            SDitHParameterSpec.sdith_threshold_cat3_p251,
            SDitHParameterSpec.sdith_threshold_cat5_p251,
        };

        KeyFactory kFact = KeyFactory.getInstance("SDitH", "BCPQC");

        for (int i = 0; i != thresholdSpecs.length; i++)
        {
            SDitHParameterSpec spec = thresholdSpecs[i];

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("SDitH", "BCPQC");
            kpg.initialize(spec, new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();

            java.security.PublicKey pub = kFact.generatePublic(
                new X509EncodedKeySpec(kp.getPublic().getEncoded()));
            java.security.PrivateKey priv = kFact.generatePrivate(
                new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));

            assertEquals(spec.getName(), kp.getPublic(), pub);
            assertEquals(spec.getName(), kp.getPrivate(), priv);
        }
    }

    public void testThresholdBCBridge()
        throws Exception
    {
        // BC→BCPQC bridge for the threshold OIDs.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SDitH", "BCPQC");
        kpg.initialize(SDitHParameterSpec.sdith_threshold_cat1_p251, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        org.bouncycastle.asn1.x509.SubjectPublicKeyInfo spki =
            org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
        org.bouncycastle.asn1.pkcs.PrivateKeyInfo pki =
            org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());

        java.security.PublicKey pub = BouncyCastleProvider.getPublicKey(spki);
        java.security.PrivateKey priv = BouncyCastleProvider.getPrivateKey(pki);
        assertNotNull(pub);
        assertNotNull(priv);
        assertEquals(kp.getPublic(), pub);
        assertEquals(kp.getPrivate(), priv);
    }

    public void testBCBridge()
        throws Exception
    {
        // BC→BCPQC bridge: BouncyCastleProvider.loadPQCKeys() registers an
        // AsymmetricKeyInfoConverter for the SDitH OID, so the BC provider's
        // SubjectPublicKeyInfo / PrivateKeyInfo decoding paths (e.g. the X.509
        // CertificateFactory's internal key extraction) can resolve the OID
        // even though BCPQC owns the implementation.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("SDitH", "BCPQC");
        kpg.initialize(SDitHParameterSpec.sdith_hypercube_cat1_gf256, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        org.bouncycastle.asn1.x509.SubjectPublicKeyInfo spki =
            org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
        org.bouncycastle.asn1.pkcs.PrivateKeyInfo pki =
            org.bouncycastle.asn1.pkcs.PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());

        java.security.PublicKey pub = BouncyCastleProvider.getPublicKey(spki);
        java.security.PrivateKey priv = BouncyCastleProvider.getPrivateKey(pki);
        assertNotNull("BC bridge should resolve SDitH public key", pub);
        assertNotNull("BC bridge should resolve SDitH private key", priv);
        assertEquals(kp.getPublic(), pub);
        assertEquals(kp.getPrivate(), priv);
    }
}

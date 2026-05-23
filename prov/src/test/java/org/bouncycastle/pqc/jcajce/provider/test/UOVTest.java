package org.bouncycastle.pqc.jcajce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.interfaces.UOVKey;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.UOVParameterSpec;
import org.bouncycastle.util.Strings;

/**
 * JCA-level test for the UOV BCPQC provider wrapper. Covers all twelve
 * parameter sets (4 security levels × 3 encoding variants) via
 * Signature.getInstance / KeyPairGenerator.getInstance / KeyFactory.getInstance
 * against the BCPQC provider. testBcProviderKeyInfoConverter verifies the
 * BC↔BCPQC bridge (BouncyCastleProvider.loadPQCKeys()).
 */
public class UOVTest
    extends TestCase
{
    private static final UOVParameterSpec[] SPECS = new UOVParameterSpec[]{
        UOVParameterSpec.uov_Is,
        UOVParameterSpec.uov_Is_pkc,
        UOVParameterSpec.uov_Is_pkc_skc,
        UOVParameterSpec.uov_Ip,
        UOVParameterSpec.uov_Ip_pkc,
        UOVParameterSpec.uov_Ip_pkc_skc,
        UOVParameterSpec.uov_III,
        UOVParameterSpec.uov_III_pkc,
        UOVParameterSpec.uov_III_pkc_skc,
        UOVParameterSpec.uov_V,
        UOVParameterSpec.uov_V_pkc,
        UOVParameterSpec.uov_V_pkc_skc,
    };

    private final byte[] msg = Strings.toByteArray("Hello World!");

    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testParameterSpecRoundTrip()
    {
        for (UOVParameterSpec spec : SPECS)
        {
            assertEquals(spec, UOVParameterSpec.fromName(spec.getName()));
            assertEquals(spec, UOVParameterSpec.fromName(spec.getName().toLowerCase()));
        }
    }

    public void testPrivateKeyRecovery()
        throws Exception
    {
        for (UOVParameterSpec spec : SPECS)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("UOV", "BCPQC");
            kpg.initialize(spec, new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();

            KeyFactory kFact = KeyFactory.getInstance("UOV", "BCPQC");
            UOVKey priv = (UOVKey)kFact.generatePrivate(
                new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
            assertEquals(spec.getName(), kp.getPrivate(), priv);
            assertEquals(spec.getName(), kp.getPrivate().hashCode(), priv.hashCode());
            assertEquals(spec.getName(), spec, priv.getParameterSpec());

            // Java serialization round-trip
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            ObjectOutputStream oOut = new ObjectOutputStream(bOut);
            oOut.writeObject(priv);
            oOut.close();
            ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
            UOVKey priv2 = (UOVKey)oIn.readObject();
            assertEquals(spec.getName(), priv, priv2);
            assertEquals(spec.getName(), priv.hashCode(), priv2.hashCode());
        }
    }

    public void testPublicKeyRecovery()
        throws Exception
    {
        for (UOVParameterSpec spec : SPECS)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("UOV", "BCPQC");
            kpg.initialize(spec, new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();

            KeyFactory kFact = KeyFactory.getInstance("UOV", "BCPQC");
            UOVKey pub = (UOVKey)kFact.generatePublic(
                new X509EncodedKeySpec(kp.getPublic().getEncoded()));
            assertEquals(spec.getName(), kp.getPublic(), pub);
            assertEquals(spec.getName(), kp.getPublic().hashCode(), pub.hashCode());

            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            ObjectOutputStream oOut = new ObjectOutputStream(bOut);
            oOut.writeObject(pub);
            oOut.close();
            ObjectInputStream oIn = new ObjectInputStream(new ByteArrayInputStream(bOut.toByteArray()));
            UOVKey pub2 = (UOVKey)oIn.readObject();
            assertEquals(spec.getName(), pub, pub2);
        }
    }

    public void testSignVerifyRoundTrip()
        throws Exception
    {
        for (UOVParameterSpec spec : SPECS)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("UOV", "BCPQC");
            kpg.initialize(spec, new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();

            // Sign with the generic "UOV" Signature alias.
            Signature sig = Signature.getInstance("UOV", "BCPQC");
            sig.initSign(kp.getPrivate(), new SecureRandom());
            sig.update(msg);
            byte[] s = sig.sign();

            Signature ver = Signature.getInstance("UOV", "BCPQC");
            ver.initVerify(kp.getPublic());
            ver.update(msg);
            assertTrue(spec.getName() + ": verify own sig", ver.verify(s));

            // Per-variant signature alias.
            Signature spec2 = Signature.getInstance(spec.getName(), "BCPQC");
            spec2.initVerify(kp.getPublic());
            spec2.update(msg);
            assertTrue(spec.getName() + ": verify via spec name", spec2.verify(s));
        }
    }

    public void testRestrictedSignature()
        throws Exception
    {
        doRestricted(UOVParameterSpec.uov_Ip, UOVParameterSpec.uov_V);
        doRestricted(UOVParameterSpec.uov_Ip_pkc, UOVParameterSpec.uov_Ip);
        doRestricted(UOVParameterSpec.uov_III_pkc_skc, UOVParameterSpec.uov_III_pkc);
    }

    private void doRestricted(UOVParameterSpec spec, UOVParameterSpec wrongSpec)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("UOV", "BCPQC");
        kpg.initialize(spec, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance(spec.getName(), "BCPQC");
        sig.initSign(kp.getPrivate(), new SecureRandom());
        sig.update(msg);
        byte[] s = sig.sign();

        Signature ver = Signature.getInstance(spec.getName(), "BCPQC");
        ver.initVerify(kp.getPublic());
        ver.update(msg);
        assertTrue(spec.getName() + ": correct-variant verify", ver.verify(s));

        KeyPairGenerator kpg2 = KeyPairGenerator.getInstance("UOV", "BCPQC");
        kpg2.initialize(wrongSpec, new SecureRandom());
        KeyPair wrong = kpg2.generateKeyPair();

        try
        {
            ver = Signature.getInstance(spec.getName(), "BCPQC");
            ver.initVerify(wrong.getPublic());
            fail(spec.getName() + ": expected InvalidKeyException for wrong variant");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("signature configured for " + Strings.toUpperCase(spec.getName()), e.getMessage());
        }
    }

    public void testTamperedSignature()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("UOV", "BCPQC");
        kpg.initialize(UOVParameterSpec.uov_Ip, new SecureRandom());
        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("UOV", "BCPQC");
        sig.initSign(kp.getPrivate(), new SecureRandom());
        sig.update(msg);
        byte[] s = sig.sign();
        s[0] ^= 0x01;

        Signature ver = Signature.getInstance("UOV", "BCPQC");
        ver.initVerify(kp.getPublic());
        ver.update(msg);
        assertFalse(ver.verify(s));
    }

    /**
     * The BC↔BCPQC bridge regression test (skill step 11 / pitfall 1).
     * For every parameter set, generate a keypair via BCPQC, then decode both
     * key encodings through BouncyCastleProvider — exercising the
     * AsymmetricKeyInfoConverter entries registered in
     * BouncyCastleProvider.loadPQCKeys(). If this fails but the other tests
     * pass, the loadPQCKeys() wiring was missed.
     */
    public void testBcProviderKeyInfoConverter()
        throws Exception
    {
        BouncyCastleProvider bc = new BouncyCastleProvider();
        for (UOVParameterSpec spec : SPECS)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("UOV", "BCPQC");
            kpg.initialize(spec, new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();

            PublicKey pub = bc.getPublicKey(SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded()));
            assertNotNull(spec.getName() + ": BC failed to decode SubjectPublicKeyInfo", pub);
            assertTrue(spec.getName() + ": decoded pub not UOVKey", pub instanceof UOVKey);
            assertEquals(spec.getName(), spec, ((UOVKey)pub).getParameterSpec());
            assertEquals(spec.getName(), kp.getPublic(), pub);

            PrivateKey priv = bc.getPrivateKey(PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded()));
            assertNotNull(spec.getName() + ": BC failed to decode PrivateKeyInfo", priv);
            assertTrue(spec.getName() + ": decoded priv not UOVKey", priv instanceof UOVKey);
            assertEquals(spec.getName(), spec, ((UOVKey)priv).getParameterSpec());
            assertEquals(spec.getName(), kp.getPrivate(), priv);
        }
    }
}

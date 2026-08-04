package org.bouncycastle.jcajce.provider.test;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;

import javax.crypto.KeyAgreement;

import junit.framework.TestCase;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.encoders.Hex;

/**
 * Exercise the XDH KeyAgreement against the multi-release jar on JDK 11+, covering behaviour
 * that historically drifted between the base tree and the (since removed) jdk1.11 overlay
 * copy of KeyAgreementSpi: the UserKeyingMaterialSpec salt, the EMULATE_ORACLE property, the
 * RFC 8418 XDHwith*HKDF registrations, and the getEncoded() fallback for third-party keys.
 */
public class XDHKeyAgreementMRTest
    extends TestCase
{
    private static final String BC = "BC";

    public void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }

    public void testUkmSaltIsApplied()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("X25519", BC);

        KeyPair kp1 = kpGen.generateKeyPair();
        KeyPair kp2 = kpGen.generateKeyPair();

        byte[] ukm = Hex.decode("beeffeed");
        byte[] salt = Hex.decode("000102030405060708090a0b0c0d0e0f");

        byte[] noSalt = agree("X25519withSHA256HKDF", kp1.getPrivate(), kp2.getPublic(), new UserKeyingMaterialSpec(ukm));
        byte[] salted1 = agree("X25519withSHA256HKDF", kp1.getPrivate(), kp2.getPublic(), new UserKeyingMaterialSpec(ukm, salt));
        byte[] salted2 = agree("X25519withSHA256HKDF", kp2.getPrivate(), kp1.getPublic(), new UserKeyingMaterialSpec(ukm, salt));

        assertTrue("salted agreement mismatch", Arrays.areEqual(salted1, salted2));
        assertFalse("salt ignored in HKDF agreement", Arrays.areEqual(noSalt, salted1));
    }

    public void testRFC8418HKDFAgreements()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("X448", BC);

        KeyPair kp1 = kpGen.generateKeyPair();
        KeyPair kp2 = kpGen.generateKeyPair();

        String[] algorithms = new String[]{ "XDHwithSHA256HKDF", "XDHwithSHA384HKDF", "XDHwithSHA512HKDF" };
        UserKeyingMaterialSpec ukmSpec = new UserKeyingMaterialSpec(Hex.decode("beeffeed"));

        for (int i = 0; i != algorithms.length; i++)
        {
            byte[] sec1 = agree(algorithms[i], kp1.getPrivate(), kp2.getPublic(), ukmSpec);
            byte[] sec2 = agree(algorithms[i], kp2.getPrivate(), kp1.getPublic(), ukmSpec);

            assertTrue(algorithms[i] + " mismatch", Arrays.areEqual(sec1, sec2));
        }
    }

    public void testEmulateOracleProperty()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("X448", BC);

        KeyPair x448Kp = kpGen.generateKeyPair();

        // without the property a named agreement rejects the other curve...
        try
        {
            KeyAgreement.getInstance("X25519", BC).init(x448Kp.getPrivate());
            fail("X448 key accepted by X25519 agreement");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("inappropriate key for X25519", e.getMessage());
        }

        // ...with it the agreement behaves as Oracle's XDH and accepts either.
        System.setProperty(Properties.EMULATE_ORACLE, "true");
        try
        {
            KeyAgreement.getInstance("X25519", BC).init(x448Kp.getPrivate());
        }
        finally
        {
            System.clearProperty(Properties.EMULATE_ORACLE);
        }
    }

    public void testForeignProviderKeyFallback()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("X25519", BC);

        KeyPair kp1 = kpGen.generateKeyPair();
        KeyPair kp2 = kpGen.generateKeyPair();

        // a key from another provider exposes nothing but its encoding - the agreement must
        // fall back to decoding it, as it does on JDK 8.
        byte[] direct = agree("X25519", kp1.getPrivate(), kp2.getPublic(), null);
        byte[] viaForeign = agree("X25519", new ForeignPrivateKey(kp1.getPrivate()), new ForeignPublicKey(kp2.getPublic()), null);

        assertTrue("foreign key agreement mismatch", Arrays.areEqual(direct, viaForeign));
    }

    public void testXECKeysFromSystemProvider()
        throws Exception
    {
        if (Security.getProvider("SunEC") == null)
        {
            return;
        }

        KeyPairGenerator sunKpGen = KeyPairGenerator.getInstance("XDH", "SunEC");
        sunKpGen.initialize(new NamedParameterSpec("X25519"));
        KeyPair sunKp = sunKpGen.generateKeyPair();

        KeyPair bcKp = KeyPairGenerator.getInstance("X25519", BC).generateKeyPair();

        byte[] sec1 = agree("X25519", bcKp.getPrivate(), sunKp.getPublic(), null);
        byte[] sec2 = agree("X25519", sunKp.getPrivate(), bcKp.getPublic(), null);

        assertTrue("SunEC interop mismatch", Arrays.areEqual(sec1, sec2));
    }

    private byte[] agree(String algorithm, PrivateKey priv, PublicKey pub, AlgorithmParameterSpec spec)
        throws Exception
    {
        KeyAgreement keyAgreement = KeyAgreement.getInstance(algorithm, BC);

        if (spec != null)
        {
            keyAgreement.init(priv, spec);
        }
        else
        {
            keyAgreement.init(priv);
        }

        keyAgreement.doPhase(pub, true);

        return keyAgreement.generateSecret();
    }

    private static class ForeignPrivateKey
        implements PrivateKey
    {
        private final PrivateKey delegate;

        ForeignPrivateKey(PrivateKey delegate)
        {
            this.delegate = delegate;
        }

        public String getAlgorithm()
        {
            return delegate.getAlgorithm();
        }

        public String getFormat()
        {
            return delegate.getFormat();
        }

        public byte[] getEncoded()
        {
            return delegate.getEncoded();
        }
    }

    private static class ForeignPublicKey
        implements PublicKey
    {
        private final PublicKey delegate;

        ForeignPublicKey(PublicKey delegate)
        {
            this.delegate = delegate;
        }

        public String getAlgorithm()
        {
            return delegate.getAlgorithm();
        }

        public String getFormat()
        {
            return delegate.getFormat();
        }

        public byte[] getEncoded()
        {
            return delegate.getEncoded();
        }
    }
}

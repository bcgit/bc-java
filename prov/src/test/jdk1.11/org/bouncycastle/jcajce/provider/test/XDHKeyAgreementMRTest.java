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
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

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

    /**
     * The RFC 8418 XDHwith*HKDF agreements on both curves, without a UKM, with one, and with one
     * plus a salt. Each result is checked against HKDF (RFC 5869) computed independently from the
     * raw agreement with the SunJCE HMAC, and the UKM is checked to be the HKDF info, not the salt.
     */
    public void testRFC8418HKDFAgreements()
        throws Exception
    {
        String[] algorithms = new String[]{ "XDHwithSHA256HKDF", "XDHwithSHA384HKDF", "XDHwithSHA512HKDF" };
        String[] macs = new String[]{ "HmacSHA256", "HmacSHA384", "HmacSHA512" };
        String[] curves = new String[]{ "X25519", "X448" };

        byte[] ukm = Hex.decode("beeffeed");
        byte[] salt = Hex.decode("000102030405060708090a0b0c0d0e0f");

        for (int c = 0; c != curves.length; c++)
        {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance(curves[c], BC);

            KeyPair kp1 = kpGen.generateKeyPair();
            KeyPair kp2 = kpGen.generateKeyPair();

            byte[] z = agree(curves[c], kp1.getPrivate(), kp2.getPublic(), null);

            for (int i = 0; i != algorithms.length; i++)
            {
                String label = algorithms[i] + "/" + curves[c];

                byte[] noUkm = checkHKDFAgreement(label + " no ukm", algorithms[i], kp1, kp2, null,
                    hkdf(macs[i], null, z, new byte[0], z.length));
                byte[] withUkm = checkHKDFAgreement(label + " ukm", algorithms[i], kp1, kp2, new UserKeyingMaterialSpec(ukm),
                    hkdf(macs[i], null, z, ukm, z.length));
                checkHKDFAgreement(label + " ukm+salt", algorithms[i], kp1, kp2, new UserKeyingMaterialSpec(ukm, salt),
                    hkdf(macs[i], salt, z, ukm, z.length));

                assertFalse(label + " ukm ignored", Arrays.areEqual(noUkm, withUkm));
                assertFalse(label + " ukm used as salt", Arrays.areEqual(withUkm, hkdf(macs[i], ukm, z, new byte[0], z.length)));
            }
        }
    }

    private byte[] checkHKDFAgreement(String label, String algorithm, KeyPair kp1, KeyPair kp2, AlgorithmParameterSpec spec, byte[] expected)
        throws Exception
    {
        byte[] sec1 = agree(algorithm, kp1.getPrivate(), kp2.getPublic(), spec);
        byte[] sec2 = agree(algorithm, kp2.getPrivate(), kp1.getPublic(), spec);

        assertTrue(label + " mismatch", Arrays.areEqual(sec1, sec2));
        assertTrue(label + " known answer", Arrays.areEqual(expected, sec1));

        return sec1;
    }

    // RFC 5869 using the SunJCE HMAC, so the expected value does not come from BC's HKDF.
    private static byte[] hkdf(String macAlg, byte[] salt, byte[] ikm, byte[] info, int length)
        throws Exception
    {
        Mac mac = Mac.getInstance(macAlg, "SunJCE");

        mac.init(new SecretKeySpec(salt != null ? salt : new byte[mac.getMacLength()], macAlg));
        byte[] prk = mac.doFinal(ikm);

        mac.init(new SecretKeySpec(prk, macAlg));

        byte[] okm = new byte[length];
        byte[] t = new byte[0];
        for (int off = 0, counter = 1; off < length; counter++)
        {
            mac.update(t);
            mac.update(info);
            mac.update((byte)counter);
            t = mac.doFinal();

            int len = Math.min(t.length, length - off);
            System.arraycopy(t, 0, okm, off, len);
            off += len;
        }

        return okm;
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

        // ...with it the agreement reports itself as Oracle's XDH, but stays bound to its curve.
        Properties.setThreadOverride(Properties.EMULATE_ORACLE, true);
        try
        {
            try
            {
                KeyAgreement.getInstance("X25519", BC).init(x448Kp.getPrivate());
                fail("X448 key accepted by X25519 agreement under emulate oracle");
            }
            catch (InvalidKeyException e)
            {
                assertEquals("inappropriate key for XDH", e.getMessage());
            }

            // the XDH name itself is not tied to a curve
            KeyAgreement.getInstance("XDH", BC).init(x448Kp.getPrivate());
        }
        finally
        {
            Properties.removeThreadOverride(Properties.EMULATE_ORACLE);
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

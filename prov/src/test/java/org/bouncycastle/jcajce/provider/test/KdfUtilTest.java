package org.bouncycastle.jcajce.provider.test;

import java.security.InvalidAlgorithmParameterException;

import javax.crypto.SecretKey;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.spec.KEMParameterSpec;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.util.Arrays;

/**
 * Direct coverage of the public KEM helpers on KdfUtil - resolveKemSpec, resolveAlgorithm and
 * makeSecretKey. The provider's own KEM services pre-validate everything they pass in, so the
 * guards here are reachable only by an outside caller, and a provider-driven test can never
 * exercise them; the erase-on-every-exit contract in particular is asserted here for each failure
 * path, since a caller who hits one must not be left holding a live secret the javadoc says was
 * erased.
 */
public class KdfUtilTest
    extends TestCase
{
    private static byte[] secret()
    {
        byte[] secret = new byte[32];
        Arrays.fill(secret, (byte)0x5a);
        return secret;
    }

    private static boolean isErased(byte[] secret)
    {
        return Arrays.areAllZeroes(secret, 0, secret.length);
    }

    public void testMakeSecretKeyHappyPath()
    {
        KTSParameterSpec spec = new KTSParameterSpec.Builder("AES", 256).build();
        byte[] secret = secret();

        SecretKey key = KdfUtil.makeSecretKey(spec, secret, 0, 16, "AES");

        assertEquals("AES", key.getAlgorithm());
        assertEquals(16, key.getEncoded().length);
        assertTrue("input secret not erased", isErased(secret));

        // the same derivation over the same secret bytes gives the same key, and a later window
        // of it differs from the leading one
        SecretKey again = KdfUtil.makeSecretKey(spec, secret(), 0, 16, "AES");
        assertTrue(Arrays.areEqual(key.getEncoded(), again.getEncoded()));
        SecretKey tail = KdfUtil.makeSecretKey(spec, secret(), 16, 32, "AES");
        assertFalse(Arrays.areEqual(key.getEncoded(), tail.getEncoded()));
    }

    /**
     * The erase happens on every exit, the failure paths included - a caller who hits an exception
     * must not be left holding a live secret.
     */
    public void testMakeSecretKeyErasesOnEveryExit()
    {
        KTSParameterSpec spec = new KTSParameterSpec.Builder("AES", 256).build();

        // null algorithm name
        byte[] secret = secret();
        try
        {
            KdfUtil.makeSecretKey(spec, secret, 0, 16, null);
            fail("null algorithm accepted");
        }
        catch (NullPointerException expected)
        {
            assertTrue("secret not erased on the null-algorithm path", isErased(secret));
        }

        // out-of-range request, refused before deriving
        secret = secret();
        try
        {
            KdfUtil.makeSecretKey(spec, secret, 0, 999, "AES");
            fail("out-of-range request accepted");
        }
        catch (IllegalArgumentException expected)
        {
            assertTrue("secret not erased on the range path", isErased(secret));
        }

        // a KDF the derivation itself refuses
        KTSParameterSpec badKdf = new KTSParameterSpec.Builder("AES", 256)
            .withKdfAlgorithm(new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.4"))).build();
        secret = secret();
        try
        {
            KdfUtil.makeSecretKey(badKdf, secret, 0, 16, "AES");
            fail("unknown KDF accepted");
        }
        catch (IllegalArgumentException expected)
        {
            assertTrue("secret not erased on the derivation path", isErased(secret));
        }
    }

    public void testResolveKemSpecGuards()
        throws Exception
    {
        // a bad session key size is the caller's own error, not a spec failure
        try
        {
            KdfUtil.resolveKemSpec(null, "TEST", "test-set", 100);
            fail("non-whole-byte session key size accepted");
        }
        catch (IllegalArgumentException expected)
        {
        }

        // null spec resolves to the mechanism's own secret, no KDF
        KTSParameterSpec resolved = KdfUtil.resolveKemSpec(null, "TEST", "test-set", 192);
        assertEquals("Generic", resolved.getKeyAlgorithmName());
        assertEquals(192, resolved.getKeySize());
        assertNull(resolved.getKdfAlgorithm());

        // a KDF-less request above the session key is refused, naming the set and both sizes
        try
        {
            KdfUtil.resolveKemSpec(new KTSParameterSpec.Builder("AES", 256).withNoKdf().build(),
                "TEST", "test-set", 192);
            fail("unsatisfiable KDF-less spec accepted");
        }
        catch (InvalidAlgorithmParameterException expected)
        {
            assertEquals("no KDF specified and test-set produces a 192 bit secret, 256 requested",
                expected.getMessage());
        }
    }

    public void testResolveAlgorithm()
    {
        KTSParameterSpec generic = new KTSParameterSpec.Builder("Generic", 256).build();
        KTSParameterSpec aes = new KTSParameterSpec.Builder("AES", 256).build();

        assertEquals("AES", KdfUtil.resolveAlgorithm(generic, "AES"));
        assertEquals("AES", KdfUtil.resolveAlgorithm(aes, "Generic"));
        assertEquals("AES", KdfUtil.resolveAlgorithm(aes, "AES"));

        try
        {
            KdfUtil.resolveAlgorithm(aes, "AES-KWP");
            fail("algorithm mismatch accepted");
        }
        catch (UnsupportedOperationException expected)
        {
            assertEquals("AES does not match AES-KWP", expected.getMessage());
        }
    }

    /**
     * A spec built through a Builder never carries a null otherInfo, but the KEMKDFSpec
     * constructor is protected and reachable by a subclass - the deprecated KEMParameterSpec passes
     * null itself - and three of makeKeyBytes' KDF branches read the otherInfo length without a
     * guard. So the normalisation belongs in the constructor: kdf2/kdf3 and HKDF happen to tolerate
     * a null through KDFParameters/HKDFParameters, but KMAC-128, KMAC-256 and SHAKE-256 threw
     * NullPointerException out of the KEM operation before this.
     */
    public void testNullOtherInfoIsNormalised()
    {
        AlgorithmIdentifier[] kdfs = new AlgorithmIdentifier[]
        {
            // the branches that were null-tolerant already, kept as the compatibility assertion
            new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf2,
                new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)),
            new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf3,
                new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)),
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_hkdf_with_sha256),
            // and the three that read otherInfo.length directly
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_Kmac128),
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_Kmac256),
            new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256)
        };

        for (int i = 0; i != kdfs.length; i++)
        {
            AlgorithmIdentifier kdf = kdfs[i];
            String name = kdf.getAlgorithm().toString();

            assertEquals("otherInfo must be normalised for " + name,
                0, new NullOtherInfoSpec(kdf).getOtherInfo().length);

            byte[] secret = secret();
            byte[] keyBytes = KdfUtil.makeKeyBytes(new NullOtherInfoSpec(kdf), secret);

            assertEquals(name + ": derived key size", 32, keyBytes.length);
            assertTrue(name + ": the secret must still be erased", isErased(secret));

            // and the derived bytes must match what an explicitly empty otherInfo gives, so the
            // normalisation is not quietly changing anyone's key material
            byte[] explicit = KdfUtil.makeKeyBytes(new EmptyOtherInfoSpec(kdf), secret());
            assertTrue(name + ": null and empty otherInfo must derive the same key",
                Arrays.areEqual(keyBytes, explicit));
        }

        // the in-tree subclass that passes null itself
        assertNotNull("KEMParameterSpec must not report a null otherInfo",
            new KEMParameterSpec("AES", 256).getOtherInfo());
        assertEquals(0, new KEMParameterSpec("AES", 256).getOtherInfo().length);
    }

    /**
     * An out-of-provider subclass reaching the protected constructor with a null otherInfo - the
     * shape KdfUtil's javadoc invites when it says the helpers are public for callers building
     * their own KEM integration.
     */
    private static class NullOtherInfoSpec
        extends KTSParameterSpec
    {
        NullOtherInfoSpec(AlgorithmIdentifier kdfAlgorithm)
        {
            super("AES", 256, null, kdfAlgorithm, null);
        }
    }

    private static class EmptyOtherInfoSpec
        extends KTSParameterSpec
    {
        EmptyOtherInfoSpec(AlgorithmIdentifier kdfAlgorithm)
        {
            super("AES", 256, null, kdfAlgorithm, new byte[0]);
        }
    }
}

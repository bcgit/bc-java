package org.bouncycastle.jcajce.provider.test;

import java.security.InvalidAlgorithmParameterException;

import javax.crypto.SecretKey;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
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
}

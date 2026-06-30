package org.bouncycastle.openpgp.test;

import junit.framework.TestCase;

import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPBEDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;

/**
 * CVD ANT-2026-34BYJSBV: an OpenPGP Argon2 S2K specifier carries attacker-chosen passes, parallelism
 * and memory-size fields that are honoured (Argon2 is run) before the message can be authenticated.
 * Key derivation must clamp all three so a single decrypt attempt cannot be driven into a huge
 * allocation (~1 TiB) or unbounded CPU work; legitimate, in-range parameters must still derive a key.
 */
public class PGPArgon2S2KLimitTest
    extends TestCase
{
    private static final byte[] SALT = new byte[16];

    private static PBEDataDecryptorFactory factory()
        throws Exception
    {
        return new BcPBEDataDecryptorFactory("password".toCharArray(), new BcPGPDigestCalculatorProvider());
    }

    private static S2K argon2(int passes, int parallelism, int memExp)
    {
        return new S2K(new S2K.Argon2Params(SALT, passes, parallelism, memExp));
    }

    private void assertRejected(S2K s2k, String fragment)
        throws Exception
    {
        try
        {
            factory().makeKeyFromPassPhrase(SymmetricKeyAlgorithmTags.AES_256, s2k);
            fail("excessive Argon2 cost accepted (" + fragment + ")");
        }
        catch (PGPException e)
        {
            assertTrue("unexpected message: " + e.getMessage(), e.getMessage().indexOf(fragment) >= 0);
        }
    }

    public void testExcessiveArgon2CostRejected()
        throws Exception
    {
        // memExp 30 -> memory = 2^30 KiB = 2^40 bytes = 1 TiB of Argon2 working memory
        assertRejected(argon2(1, 1, 30), "memory size exponent out of range");
        assertRejected(argon2(255, 1, 16), "passes out of range");
        assertRejected(argon2(1, 255, 16), "parallelism out of range");
    }

    public void testInRangeArgon2Accepted()
        throws Exception
    {
        // memExp 16 -> memory = 2^16 KiB = 64 MiB, 1 pass, 1 lane: within the caps, key derived normally
        byte[] key = factory().makeKeyFromPassPhrase(SymmetricKeyAlgorithmTags.AES_256, argon2(1, 1, 16));
        assertEquals(32, key.length);
    }
}

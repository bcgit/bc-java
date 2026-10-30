package org.bouncycastle.jcajce.provider.test;

import java.security.Key;
import java.security.Provider;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.jcajce.provider.symmetric.util.ChaCha20SpecUtil;
import org.bouncycastle.jcajce.spec.BCChaCha20ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * The JDK's ChaCha20ParameterSpec in the BC provider's ChaCha20 cipher, converted by the jdk1.11 copy of
 * ChaCha20SpecUtil, exercised against the multi-release jar and checked against SunJCE.
 */
public class ChaCha20ParameterSpecMRTest
    extends TestCase
{
    private static final String BC = "BC";

    private static final byte[] KEY = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    private static final byte[] NONCE = Hex.decode("000000000000004a00000000");

    public void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // the overlay, not the reflection copy, is what the multi-release jar gives a Java 11 runtime
    public void testOverlayInUse()
    {
        assertEquals("reflection copy of ChaCha20SpecUtil loaded", 0, ChaCha20SpecUtil.class.getDeclaredFields().length);
    }

    public void testConversion()
        throws Exception
    {
        BCChaCha20ParameterSpec converted = ChaCha20SpecUtil.toBCChaCha20Spec(new ChaCha20ParameterSpec(NONCE, -1));

        assertNotNull(converted);
        assertTrue(Arrays.areEqual(NONCE, converted.getNonce()));
        assertEquals(-1, converted.getCounter());
        assertNull(ChaCha20SpecUtil.toBCChaCha20Spec(null));
    }

    // Across the unsigned counter range, including the negative ints QUIC and DTLS 1.3 produce from their sample.
    // Only 16 bytes are taken at 2^32 - 1, as SunJCE allows the counter to wrap there and BC does not.
    public void testAgainstSunJCE()
        throws Exception
    {
        int[] counters = new int[]{ 0, 1, 2, 0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff };
        Key key = new SecretKeySpec(KEY, "ChaCha20");

        for (int i = 0; i != counters.length; i++)
        {
            int length = (counters[i] == 0xffffffff) ? 16 : 80;
            byte[] input = new byte[length];
            for (int j = 0; j != length; j++)
            {
                input[j] = (byte)j;
            }

            ChaCha20ParameterSpec spec = new ChaCha20ParameterSpec(NONCE, counters[i]);

            Cipher sun = Cipher.getInstance("ChaCha20", "SunJCE");
            sun.init(Cipher.DECRYPT_MODE, key, spec);
            byte[] expected = sun.doFinal(input);

            Cipher bc = Cipher.getInstance("ChaCha20", BC);
            bc.init(Cipher.ENCRYPT_MODE, key, spec);
            assertTrue("counter " + Integer.toHexString(counters[i]), Arrays.areEqual(expected, bc.doFinal(input)));
            assertTrue("counter " + Integer.toHexString(counters[i]) + ", second doFinal",
                Arrays.areEqual(expected, bc.doFinal(input)));

            bc.init(Cipher.ENCRYPT_MODE, key, new BCChaCha20ParameterSpec(NONCE, counters[i]));
            assertTrue("counter " + Integer.toHexString(counters[i]) + ", BC spec",
                Arrays.areEqual(expected, bc.doFinal(input)));
        }
    }

    // RFC 9001 sec. A.5, driven the way the JDK's own QUIC header protection drives it: one Cipher, initialised
    // in DECRYPT_MODE for every packet, with whatever provider the JCA selects.
    public void testQuicHeaderProtectionWithBCPreferred()
        throws Exception
    {
        byte[] hp = Hex.decode("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
        byte[] sample = Hex.decode("5e5cd55c41f69080575d7999c25a5bfb");
        int counter = (sample[0] & 0xff) | (sample[1] & 0xff) << 8 | (sample[2] & 0xff) << 16 | (sample[3] & 0xff) << 24;
        ChaCha20ParameterSpec spec = new ChaCha20ParameterSpec(Arrays.copyOfRange(sample, 4, 16), counter);
        Key key = new SecretKeySpec(hp, "ChaCha20");

        Provider bc = Security.getProvider(BC);
        Security.removeProvider(BC);
        try
        {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);

            Cipher cipher = Cipher.getInstance("ChaCha20");
            for (int i = 0; i != 2; i++)
            {
                cipher.init(Cipher.DECRYPT_MODE, key, spec);
                assertTrue("mask " + i, Arrays.areEqual(Hex.decode("aefefe7d03"), cipher.doFinal(new byte[5])));
            }
            assertEquals(BC, cipher.getProvider().getName());
        }
        finally
        {
            Security.removeProvider(BC);
            Security.addProvider(bc);
        }
    }
}

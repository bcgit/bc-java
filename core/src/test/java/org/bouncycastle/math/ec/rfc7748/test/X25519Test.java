package org.bouncycastle.math.ec.rfc7748.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class X25519Test
    extends TestCase
{
    private static final SecureRandom RANDOM = new SecureRandom();

//    @BeforeClass
//    public static void init()
    public void setUp()
    {
        X25519.precompute();
    }

//    @Test
    public void testConsistency()
    {
        byte[] u = new byte[X25519.POINT_SIZE];     u[0] = 9;
        byte[] k = new byte[X25519.SCALAR_SIZE];
        byte[] rF = new byte[X25519.POINT_SIZE];
        byte[] rV = new byte[X25519.POINT_SIZE];

        for (int i = 1; i <= 100; ++i)
        {
            RANDOM.nextBytes(k);
            X25519.scalarMultBase(k, 0, rF, 0);
            X25519.scalarMult(k, 0, u, 0, rV, 0);
            assertTrue("Consistency #" + i, Arrays.areEqual(rF, rV));
        }
    }

//    @Test
    public void testECDH()
    {
        byte[] kA = new byte[X25519.SCALAR_SIZE];
        byte[] kB = new byte[X25519.SCALAR_SIZE];
        byte[] qA = new byte[X25519.POINT_SIZE];
        byte[] qB = new byte[X25519.POINT_SIZE];
        byte[] sA = new byte[X25519.POINT_SIZE];
        byte[] sB = new byte[X25519.POINT_SIZE];

        for (int i = 1; i <= 100; ++i)
        {
            // Each party generates an ephemeral private key, ...
            RANDOM.nextBytes(kA);
            RANDOM.nextBytes(kB);

            // ... publishes their public key, ...
            X25519.scalarMultBase(kA, 0, qA, 0);
            X25519.scalarMultBase(kB, 0, qB, 0);

            // ... computes the shared secret, ...
            X25519.scalarMult(kA, 0, qB, 0, sA, 0);
            X25519.scalarMult(kB, 0, qA, 0, sB, 0);

            // ... which is the same for both parties.
            assertTrue("ECDH #" + i, Arrays.areEqual(sA, sB));
        }
    }

//    @Test
    public void testECDHVector1()
    {
        checkECDHVector(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
            "ECDH Vector #1");
    }

//    @Test
    public void testX25519Iterated()
    {
        checkIterated(1000);
    }

//    @Ignore
//    @Test
//    public void testX25519IteratedFull()
//    {
//        checkIterated(1000000);
//    }

//    @Test
    public void testX25519Vector1()
    {
        checkX25519Vector(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
            "Vector #1");
    }

//    @Test
    public void testX25519Vector2()
    {
        checkX25519Vector(
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
            "Vector #2");
    }

    private static void checkECDHVector(String sA, String sAPub, String sB, String sBPub, String sK, String text)
    {
        byte[] a = Hex.decode(sA);
        assertEquals(X25519.SCALAR_SIZE, a.length);

        byte[] b = Hex.decode(sB);
        assertEquals(X25519.SCALAR_SIZE, b.length);

        byte[] aPub = new byte[X25519.POINT_SIZE];
        X25519.scalarMultBase(a, 0, aPub, 0);
        checkValue(aPub, text, sAPub);

        byte[] bPub = new byte[X25519.POINT_SIZE];
        X25519.scalarMultBase(b, 0, bPub, 0);
        checkValue(bPub, text, sBPub);

        byte[] aK = new byte[X25519.POINT_SIZE];
        X25519.scalarMult(a, 0, bPub, 0, aK, 0);
        checkValue(aK, text, sK);

        byte[] bK = new byte[X25519.POINT_SIZE];
        X25519.scalarMult(b, 0, aPub, 0, bK, 0);
        checkValue(bK, text, sK);
    }

    private static void checkIterated(int count)
    {
        assertEquals(X25519.POINT_SIZE, X25519.SCALAR_SIZE);

        byte[] k = new byte[X25519.POINT_SIZE];     k[0] = 9;
        byte[] u = new byte[X25519.POINT_SIZE];     u[0] = 9;
        byte[] r = new byte[X25519.POINT_SIZE];

        int iterations = 0;
        while (iterations < count)
        {
            X25519.scalarMult(k, 0, u, 0, r, 0);

            System.arraycopy(k, 0, u, 0, X25519.POINT_SIZE);
            System.arraycopy(r, 0, k, 0, X25519.POINT_SIZE);

            switch (++iterations)
            {
            case 1:
                checkValue(k, "Iterated @1", "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
                break;
            case 1000:
                checkValue(k, "Iterated @1000", "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
                break;
            case 1000000:
                checkValue(k, "Iterated @1000000", "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424");
                break;
            default:
                break;
            }
        }
    }

    private static void checkValue(byte[] n, String text, String se)
    {
        byte[] e = Hex.decode(se);
        assertTrue(text, Arrays.areEqual(e, n));
    }

    private static void checkX25519Vector(String sk, String su, String se, String text)
    {
        byte[] k = Hex.decode(sk);
        assertEquals(X25519.SCALAR_SIZE, k.length);

        byte[] u = Hex.decode(su);
        assertEquals(X25519.POINT_SIZE, u.length);

        byte[] r = new byte[X25519.POINT_SIZE];
        X25519.scalarMult(k, 0, u, 0, r, 0);
        checkValue(r, text, se);
    }
}

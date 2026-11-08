package org.bouncycastle.crypto.threshold;

import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class ShamirSplitSecretTest
    extends TestCase
{
    public void testRecoveryUsesOverriddenDivision()
        throws IOException
    {
        ShamirSecretSplitter.Algorithm[] algorithms = ShamirSecretSplitter.Algorithm.values();
        for (int i = 0; i != algorithms.length; i++)
        {
            TrackingPolynomial poly = new TrackingPolynomial(algorithms[i]);
            ShamirSplitSecret split = new ShamirSplitSecret(poly, createShares());

            assertTrue(Arrays.areEqual(Hex.decode("20fdca"), split.getSecret()));
            assertEquals(6, poly.divisions);
        }
    }

    public void testDivideUsesOverriddenDivision()
        throws IOException
    {
        ShamirSecretSplitter.Algorithm[] algorithms = ShamirSecretSplitter.Algorithm.values();
        for (int i = 0; i != algorithms.length; i++)
        {
            TrackingPolynomial poly = new TrackingPolynomial(algorithms[i]);
            ShamirSplitSecretShare[] shares = createShares();
            ShamirSplitSecret split = new ShamirSplitSecret(poly, shares);

            split.divide(17);

            assertTrue(Arrays.areEqual(Hex.decode("171415"), shares[0].getEncoded()));
            assertTrue(Arrays.areEqual(Hex.decode("121310"), shares[1].getEncoded()));
            assertTrue(Arrays.areEqual(Hex.decode("111e1f"), shares[2].getEncoded()));
            assertEquals(9, poly.divisions);
        }
    }

    private static ShamirSplitSecretShare[] createShares()
    {
        return new ShamirSplitSecretShare[]
        {
            new ShamirSplitSecretShare(new byte[]{1, 2, 3}, 1),
            new ShamirSplitSecretShare(new byte[]{4, 5, 6}, 2),
            new ShamirSplitSecretShare(new byte[]{7, 8, 9}, 3)
        };
    }

    private static class TrackingPolynomial
        extends Polynomial
    {
        private int divisions;

        TrackingPolynomial(ShamirSecretSplitter.Algorithm algorithm)
        {
            super(algorithm);
        }

        protected byte gfDiv(int x, int y)
        {
            ++divisions;
            return (byte)(x ^ y ^ 7);
        }
    }
}

package org.bouncycastle.pqc.crypto.mldsa;

class Rounding
{
    static void power2RoundAll(int[] c0, int[] c1)
    {
        int d = MLDSAEngine.DilithiumD, n = MLDSAEngine.DilithiumN;
        int u = (1 << (d - 1)) - 1, v = -1 << d;

        for (int i = 0; i < n; ++i)
        {
            int a = c0[i];

            int t = a + u;
            int r1 = a - (t & v);

            c0[i] = t >> d;
            c1[i] = r1;
        }
    }
    
    public static int[] decompose(int a, int gamma2)
    {
        int a1, a0;

        a1 = (a + 127) >> 7;
        if (gamma2 == (MLDSAEngine.DilithiumQ - 1) / 32)
        {
            a1 = (a1 * 1025 + (1 << 21)) >> 22;
            a1 &= 15;
        }
        else if (gamma2 == (MLDSAEngine.DilithiumQ - 1) / 88)
        {
            a1 = (a1 * 11275 + (1 << 23)) >> 24;
            a1 ^= ((43 - a1) >> 31) & a1;
        }
        else
        {
            throw new RuntimeException("Wrong Gamma2!");
        }

        a0 = a - a1 * 2 * gamma2;
        a0 -= (((MLDSAEngine.DilithiumQ - 1) / 2 - a0) >> 31) & MLDSAEngine.DilithiumQ;
        return new int[]{a0, a1};
    }

    public static int makeHint(int a0, int a1, MLDSAEngine engine)
    {
        int g2 = engine.getDilithiumGamma2(), q = MLDSAEngine.DilithiumQ;
        if (a0 <= g2 || a0 > q - g2 || (a0 == q - g2 && a1 == 0))
        {
            return 0;
        }
        return 1;
    }

    public static int useHint(int a, int hint, int gamma2)
    {
        int a0, a1;

        int[] intArray = decompose(a, gamma2);
        a0 = intArray[0];
        a1 = intArray[1];
        // System.out.printf("a0: %d, a1: %d\n", a0, a1);

        if (hint == 0)
        {
            return a1;
        }

        if (gamma2 == (MLDSAEngine.DilithiumQ - 1) / 32)
        {
            if (a0 > 0)
            {
                return (a1 + 1) & 15;
            }
            else
            {
                return (a1 - 1) & 15;
            }
        }
        else if (gamma2 == (MLDSAEngine.DilithiumQ - 1) / 88)
        {
            if (a0 > 0)
            {
                return (a1 == 43) ? 0 : a1 + 1;
            }
            else
            {
                return (a1 == 0) ? 43 : a1 - 1;
            }
        }
        else
        {
            throw new RuntimeException("Wrong Gamma2!");
        }
    }
}

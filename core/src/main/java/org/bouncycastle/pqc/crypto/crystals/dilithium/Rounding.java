package org.bouncycastle.pqc.crypto.crystals.dilithium;

class Rounding
{
    public static int[] power2Round(int a)
    {
        int[] out = new int[2];

        out[0] = (a + (1 << (DilithiumEngine.DilithiumD - 1)) - 1) >> DilithiumEngine.DilithiumD;
        out[1] = a - (out[0] << DilithiumEngine.DilithiumD);
        return out;
    }

    public static int[] decompose(int a, int gamma2)
    {
        int a1, a0;

        a1 = (a + 127) >> 7;
        if (gamma2 == (DilithiumEngine.DilithiumQ - 1) / 32)
        {
            a1 = (a1 * 1025 + (1 << 21)) >> 22;
            a1 &= 15;
        }
        else if (gamma2 == (DilithiumEngine.DilithiumQ - 1) / 88)
        {
            a1 = (a1 * 11275 + (1 << 23)) >> 24;
            a1 ^= ((43 - a1) >> 31) & a1;
        }
        else
        {
            throw new RuntimeException("Wrong Gamma2!");
        }

        a0 = a - a1 * 2 * gamma2;
        a0 -= (((DilithiumEngine.DilithiumQ - 1) / 2 - a0) >> 31) & DilithiumEngine.DilithiumQ;
        return new int[]{a0, a1};
    }

    public static int makeHint(int a0, int a1, DilithiumEngine engine)
    {
        int g2 = engine.getDilithiumGamma2(), q = DilithiumEngine.DilithiumQ;
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

        if (gamma2 == (DilithiumEngine.DilithiumQ - 1) / 32)
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
        else if (gamma2 == (DilithiumEngine.DilithiumQ - 1) / 88)
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

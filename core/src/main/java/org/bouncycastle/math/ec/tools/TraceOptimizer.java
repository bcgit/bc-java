package org.bouncycastle.math.ec.tools;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.SortedSet;
import java.util.TreeSet;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.util.Integers;

public class TraceOptimizer
{
    private static final BigInteger ONE = BigInteger.valueOf(1);

    private static final SecureRandom R = new SecureRandom();

    public static void main(String[] args)
    {
        SortedSet names = new TreeSet(enumToList(ECNamedCurveTable.getNames()));
        names.addAll(enumToList(CustomNamedCurves.getNames()));

        Iterator it = names.iterator();
        while (it.hasNext())
        {
            String name = (String)it.next();
            X9ECParameters x9 = CustomNamedCurves.getByName(name);
            if (x9 == null)
            {
                x9 = ECNamedCurveTable.getByName(name);
            }
            if (x9 != null && ECAlgorithms.isF2mCurve(x9.getCurve()))
            {
                System.out.print(name + ":");
                implPrintNonZeroTraceBits(x9);
            }
        }
    }

    public static void printNonZeroTraceBits(X9ECParameters x9)
    {
        if (!ECAlgorithms.isF2mCurve(x9.getCurve()))
        {
            throw new IllegalArgumentException("Trace only defined over characteristic-2 fields");
        }

        implPrintNonZeroTraceBits(x9);
    }

    public static void implPrintNonZeroTraceBits(X9ECParameters x9)
    {
        ECCurve c = x9.getCurve();
        int m = c.getFieldSize();

        ArrayList nonZeroTraceBits = new ArrayList();

        /*
         * Determine which of the bits contribute to the trace.
         * 
         * See section 3.6.2 of "Guide to Elliptic Curve Cryptography" (Hankerson, Menezes, Vanstone)
         */
        {
            for (int i = 0; i < m; ++i)
            {
                if (0 == (i & 1) && 0 != i)
                {
                    if (nonZeroTraceBits.contains(Integers.valueOf(i >>> 1)))
                    {
                        nonZeroTraceBits.add(Integers.valueOf(i));
                        System.out.print(" " + i);
                    }
                }
                else
                {
                    BigInteger zi = ONE.shiftLeft(i);
                    ECFieldElement fe = c.fromBigInteger(zi);
                    int tr = calculateTrace(fe);
                    if (tr != 0)
                    {
                        nonZeroTraceBits.add(Integers.valueOf(i));
                        System.out.print(" " + i);
                    }
                }
            }
            System.out.println();
        }

        /*
         *  Check calculation based on the non-zero-trace bits against explicit calculation, for random field elements
         */
        {
            for (int i = 0; i < 1000; ++i)
            {
                BigInteger x = new BigInteger(m, R);
                ECFieldElement fe = c.fromBigInteger(x);
                int check = calculateTrace(fe);

                int tr = 0;
                for (int j = 0; j < nonZeroTraceBits.size(); ++j)
                {
                    int bit = ((Integer)nonZeroTraceBits.get(j)).intValue();
                    if (x.testBit(bit))
                    {
                        tr ^= 1;
                    }
                }
                
                if (check != tr)
                {
                    throw new IllegalStateException("Optimized-trace sanity check failed");
                }
            }
        }
    }

    private static int calculateTrace(ECFieldElement fe)
    {
//        int m = fe.getFieldSize();
//        ECFieldElement tr = fe;
//        for (int i = 1; i < m; ++i)
//        {
//            tr = tr.square().add(fe);
//        }

        int m = fe.getFieldSize();
        int k = 31 - Integers.numberOfLeadingZeros(m);
        int mk = 1;

        ECFieldElement tr = fe;
        while (k > 0)
        {
            tr = tr.squarePow(mk).add(tr);
            mk = m >>> --k;
            if (0 != (mk & 1))
            {
                tr = tr.square().add(fe);
            }
        }

        if (tr.isZero())
        {
            return 0;
        }
        if (tr.isOne())
        {
            return 1;
        }
        throw new IllegalStateException("Internal error in trace calculation");
    }

    private static ArrayList enumToList(Enumeration en)
    {
        ArrayList rv = new ArrayList();
        while (en.hasMoreElements())
        {
            rv.add(en.nextElement());
        }
        return rv;
    }
}

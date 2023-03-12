package org.bouncycastle.pqc.math.ntru.test;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import junit.framework.TestCase;
import org.bouncycastle.pqc.math.ntru.HPSPolynomial;
import org.bouncycastle.pqc.math.ntru.Polynomial;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHPS2048509;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHPS4096821;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHPSParameterSet;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHRSS701;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUParameterSet;
import org.bouncycastle.test.TestResourceFinder;

public class PolynomialTest
    extends TestCase
{
    private final SecureRandom random = new SecureRandom();
    private final int TEST_COUNT = 100;

    private static List<Map<String, List<Integer>>> getTestCases(InputStream src)
    {
        List<Map<String, List<Integer>>> testCases = new ArrayList<Map<String, List<Integer>>>();
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));
        Map<String, List<Integer>> buf = new HashMap<String, List<Integer>>();
        try
        {
            for (String line = bin.readLine(); line != null; line = bin.readLine())
            {
                if (line.startsWith("#"))
                {
                    continue;
                }
                if (line.length() == 0)
                {
                    if (buf.size() > 0)
                    {
                        testCases.add(buf);
                    }
                    buf = new HashMap<String, List<Integer>>(); // ensures that each test case starts with a fresh map
                    continue;
                }
                // append fields
                int a = line.indexOf("=");
                if (a > -1)
                {
                    List<Integer> values = new ArrayList<Integer>();
                    for (String str : line.substring(a + 1).trim().split(" "))
                    {
                        values.add(Integer.parseInt(str));
                    }
                    buf.put(line.substring(0, a).trim(), values);
                }
            }
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }
        return testCases;
    }

    private short randShort()
    {
        return (short)(random.nextInt(Short.MAX_VALUE - Short.MIN_VALUE) + Short.MAX_VALUE);
    }

//    public void testBothNegativeMask()
//    {
//        for (int i = 0; i < TEST_COUNT; i++)
//        {
//            short x = randShort();
//            short y = randShort();
//            assertEquals(String.format("x = %d, y = %d", x, y), (x < 0) && (y < 0) ? -1 : 0, Polynomial.bothNegativeMask(x, y));
//        }
//    }

    public void testMod3PhiN()
        throws FileNotFoundException
    {
        NTRUParameterSet params = new NTRUHPS2048509();
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/ntru/ntruhps2048509", "poly_mod_3_Phi_n.txt");
        List<Map<String, List<Integer>>> testCases = getTestCases(src);
        for (Map<String, List<Integer>> testCase : testCases)
        {
            Polynomial poly = new HPSPolynomial((NTRUHPSParameterSet)params);
            int i = 0;
            for (Integer value : testCase.get("r"))
            {
                poly.coeffs[i++] = value.shortValue();
            }

            poly.mod3PhiN();
            i = 0;
            for (Integer value : testCase.get("res"))
            {
                assertEquals(String.format("i = %d", i), value.shortValue(), poly.coeffs[i++]);
            }
        }
    }

    public void testModQPhiN()
        throws FileNotFoundException
    {
        NTRUParameterSet params = new NTRUHPS2048509();
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/ntru/ntruhps2048509", "poly_mod_q_Phi_n.txt");
        List<Map<String, List<Integer>>> testCases = getTestCases(src);
        for (Map<String, List<Integer>> testCase : testCases)
        {
            Polynomial poly = new HPSPolynomial((NTRUHPSParameterSet)params);
            int i = 0;
            for (Integer value : testCase.get("r"))
            {
                poly.coeffs[i++] = value.shortValue();
            }

            poly.modQPhiN();
            i = 0;
            for (Integer value : testCase.get("res"))
            {
                assertEquals(String.format("i = %d", i), value.shortValue(), poly.coeffs[i++]);
            }
        }
    }

    public void testSqToBytes()
        throws FileNotFoundException
    {
        NTRUParameterSet[] params = {
            new NTRUHPS2048509(),
            new NTRUHPS4096821(),
            new NTRUHRSS701()
        };
        String[] katBase = {
            "ntruhps2048509",
            "ntruhps4096821",
            "ntruhrss701"
        };
        int[] len = {
            699,
            1230,
            1138
        };
        for (int i = 0; i < params.length; i++)
        {
            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/ntru/" + katBase[i], "poly_Sq_tobytes.txt");
            List<Map<String, List<Integer>>> testCases = getTestCases(src);
            int count = 0;
            for (Map<String, List<Integer>> testCase : testCases)
            {
                Polynomial poly = params[i].createPolynomial();
                int j = 0;
                for (Integer value : testCase.get("a"))
                {
                    poly.coeffs[j++] = value.shortValue();
                }

                byte[] packed = poly.sqToBytes(len[i]);
                j = 0;
                for (Integer value : testCase.get("r"))
                {
                    assertEquals(String.format("count = %d, i = %d", count, j), value.byteValue(), packed[j++]);
                }
                count++;
            }
        }
    }

    public void testSqFromBytes()
        throws FileNotFoundException
    {
        NTRUParameterSet params = new NTRUHPS2048509();
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/ntru/ntruhps2048509", "poly_Sq_frombytes.txt");
        List<Map<String, List<Integer>>> testCases = getTestCases(src);
        for (Map<String, List<Integer>> testCase : testCases)
        {
            int i = 0;
            byte[] packed = new byte[testCase.get("r").size()];
            for (Integer num : testCase.get("r"))
            {
                packed[i++] = num.byteValue();
            }
            Polynomial unpacked = new HPSPolynomial((NTRUHPSParameterSet)params);
            unpacked.sqFromBytes(packed);

            i = 0;
            for (Integer value : testCase.get("a"))
            {
                assertEquals(String.format("i = %d", i), value.shortValue(), unpacked.coeffs[i++]);
            }
        }
    }

    public void testRqSumZeroToBytes()
        throws FileNotFoundException
    {
        NTRUParameterSet params = new NTRUHPS2048509();
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/ntru/ntruhps2048509", "poly_Rq_sum_zero_tobytes.txt");
        List<Map<String, List<Integer>>> testCases = getTestCases(src);
        for (Map<String, List<Integer>> testCase : testCases)
        {
            Polynomial poly = new HPSPolynomial((NTRUHPSParameterSet)params);
            int i = 0;
            for (Integer value : testCase.get("a"))
            {
                poly.coeffs[i++] = value.shortValue();
            }

            byte[] packed = poly.rqSumZeroToBytes(699);
            i = 0;
            for (Integer value : testCase.get("r"))
            {
                assertEquals(String.format("i = %d", i), value.byteValue(), packed[i++]);
            }
        }
    }

    public void testRqSumZeroFromBytes()
        throws FileNotFoundException
    {
        NTRUParameterSet params = new NTRUHPS2048509();
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/ntru/ntruhps2048509", "poly_Rq_sum_zero_frombytes.txt");
        List<Map<String, List<Integer>>> testCases = getTestCases(src);
        for (Map<String, List<Integer>> testCase : testCases)
        {
            int i = 0;
            byte[] packed = new byte[testCase.get("r").size()];
            for (Integer num : testCase.get("r"))
            {
                packed[i++] = num.byteValue();
            }
            Polynomial unpacked = new HPSPolynomial((NTRUHPSParameterSet)params);
            unpacked.rqSumZeroFromBytes(packed);

            i = 0;
            for (Integer value : testCase.get("a"))
            {
                assertEquals(String.format("i = %d", i), value.shortValue(), unpacked.coeffs[i++]);
            }
        }
    }

    public void testS3ToBytes()
        throws FileNotFoundException
    {
        NTRUParameterSet params = new NTRUHPS2048509();
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/ntru/ntruhps2048509","poly_S3_tobytes.txt");
        List<Map<String, List<Integer>>> testCases = getTestCases(src);
        for (Map<String, List<Integer>> testCase : testCases)
        {
            Polynomial poly = new HPSPolynomial((NTRUHPSParameterSet)params);
            int i = 0;
            for (Integer value : testCase.get("a"))
            {
                poly.coeffs[i++] = value.shortValue();
            }

            byte[] packed = poly.s3ToBytes(params.packTrinaryBytes());
            i = 0;
            for (Integer value : testCase.get("msg"))
            {
                assertEquals(String.format("i = %d", i), value.byteValue(), packed[i++]);
            }
        }
    }

    public void testS3FromBytes()
        throws FileNotFoundException
    {
        NTRUParameterSet params = new NTRUHPS2048509();
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/ntru/ntruhps2048509", "poly_S3_frombytes.txt");
        List<Map<String, List<Integer>>> testCases = getTestCases(src);
        for (Map<String, List<Integer>> testCase : testCases)
        {
            int i = 0;
            byte[] packed = new byte[params.packTrinaryBytes()];
            for (Integer num : testCase.get("msg"))
            {
                packed[i++] = num.byteValue();
            }
            Polynomial unpacked = new HPSPolynomial((NTRUHPSParameterSet)params);
            unpacked.s3FromBytes(packed);

            i = 0;
            for (Integer value : testCase.get("a"))
            {
                assertEquals(String.format("i = %d", i), value.shortValue(), unpacked.coeffs[i++]);
            }
        }
    }

    public void testSqMul()
        throws FileNotFoundException
    {
        NTRUParameterSet params = new NTRUHPS2048509();
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/ntru/ntruhps2048509","poly_Sq_mul.txt");
        List<Map<String, List<Integer>>> testCases = getTestCases(src);
        for (Map<String, List<Integer>> testCase : testCases)
        {
            Polynomial a = new HPSPolynomial((NTRUHPSParameterSet)params);
            int i = 0;
            for (Integer value : testCase.get("a"))
            {
                a.coeffs[i++] = value.shortValue();
            }
            Polynomial b = new HPSPolynomial((NTRUHPSParameterSet)params);
            i = 0;
            for (Integer value : testCase.get("b"))
            {
                b.coeffs[i++] = value.shortValue();
            }

            Polynomial r = new HPSPolynomial((NTRUHPSParameterSet)params);
            r.sqMul(a, b);
            i = 0;
            for (Integer value : testCase.get("r"))
            {
                assertEquals(String.format("i = %d", i), value.shortValue(), r.coeffs[i++]);
            }
        }
    }

    public void testRqMul()
        throws FileNotFoundException
    {
        NTRUParameterSet params = new NTRUHPS2048509();
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/ntru/ntruhps2048509", "poly_Rq_mul.txt");
        List<Map<String, List<Integer>>> testCases = getTestCases(src);
        for (Map<String, List<Integer>> testCase : testCases)
        {
            Polynomial a = new HPSPolynomial((NTRUHPSParameterSet)params);
            int i = 0;
            for (Integer value : testCase.get("a"))
            {
                a.coeffs[i++] = value.shortValue();
            }
            Polynomial b = new HPSPolynomial((NTRUHPSParameterSet)params);
            i = 0;
            for (Integer value : testCase.get("b"))
            {
                b.coeffs[i++] = value.shortValue();
            }

            Polynomial r = new HPSPolynomial((NTRUHPSParameterSet)params);
            r.rqMul(a, b);
            i = 0;
            for (Integer value : testCase.get("r"))
            {
                assertEquals(String.format("i = %d", i), value.shortValue(), r.coeffs[i++]);
            }
        }
    }

    public void testS3Mul()
        throws FileNotFoundException
    {
        NTRUParameterSet params = new NTRUHPS2048509();
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/ntru/ntruhps2048509", "poly_S3_mul.txt");
        List<Map<String, List<Integer>>> testCases = getTestCases(src);
        for (Map<String, List<Integer>> testCase : testCases)
        {
            Polynomial a = new HPSPolynomial((NTRUHPSParameterSet)params);
            int i = 0;
            for (Integer value : testCase.get("a"))
            {
                a.coeffs[i++] = value.shortValue();
            }
            Polynomial b = new HPSPolynomial((NTRUHPSParameterSet)params);
            i = 0;
            for (Integer value : testCase.get("b"))
            {
                b.coeffs[i++] = value.shortValue();
            }

            Polynomial r = new HPSPolynomial((NTRUHPSParameterSet)params);
            r.s3Mul(a, b);
            i = 0;
            for (Integer value : testCase.get("r"))
            {
                assertEquals(String.format("i = %d", i), value.shortValue(), r.coeffs[i++]);
            }
        }
    }

    public void testRqToS3()
        throws FileNotFoundException
    {
        NTRUParameterSet params = new NTRUHPS2048509();
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/ntru/ntruhps2048509","poly_Rq_to_S3.txt");
        List<Map<String, List<Integer>>> testCases = getTestCases(src);
        for (Map<String, List<Integer>> testCase : testCases)
        {
            Polynomial a = new HPSPolynomial((NTRUHPSParameterSet)params);
            int i = 0;
            for (Integer value : testCase.get("a"))
            {
                a.coeffs[i++] = value.shortValue();
            }

            Polynomial r = new HPSPolynomial((NTRUHPSParameterSet)params);
            r.rqToS3(a);
            i = 0;
            for (Integer value : testCase.get("r"))
            {
                assertEquals(String.format("i = %d", i), value.shortValue(), r.coeffs[i++]);
            }
        }
    }

    public void testZ3ToZq()
        throws FileNotFoundException
    {
        NTRUParameterSet params = new NTRUHPS2048509();
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/ntru/ntruhps2048509", "poly_Z3_to_Zq.txt");
        List<Map<String, List<Integer>>> testCases = getTestCases(src);
        for (Map<String, List<Integer>> testCase : testCases)
        {
            Polynomial poly = new HPSPolynomial((NTRUHPSParameterSet)params);
            int i = 0;
            for (Integer value : testCase.get("r"))
            {
                poly.coeffs[i++] = value.shortValue();
            }

            poly.z3ToZq();
            i = 0;
            for (Integer value : testCase.get("res"))
            {
                assertEquals(String.format("i = %d", i), value.shortValue(), poly.coeffs[i++]);
            }
        }
    }

    public void testTrinaryZqToZ3()
        throws FileNotFoundException
    {
        NTRUParameterSet params = new NTRUHPS2048509();
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/ntru/ntruhps2048509", "poly_trinary_Zq_to_Z3.txt");
        List<Map<String, List<Integer>>> testCases = getTestCases(src);
        for (Map<String, List<Integer>> testCase : testCases)
        {
            Polynomial poly = new HPSPolynomial((NTRUHPSParameterSet)params);
            int i = 0;
            for (Integer value : testCase.get("r"))
            {
                poly.coeffs[i++] = value.shortValue();
            }

            poly.trinaryZqToZ3();
            i = 0;
            for (Integer value : testCase.get("res"))
            {
                assertEquals(String.format("i = %d", i), value.shortValue(), poly.coeffs[i++]);
            }
        }
    }
}
package org.bouncycastle.pqc.math.ntru.test;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import junit.framework.TestCase;
import org.bouncycastle.pqc.math.ntru.HPSPolynomial;
import org.bouncycastle.pqc.math.ntru.Polynomial;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHPS2048509;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHPSParameterSet;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUParameterSet;
import org.bouncycastle.test.TestResourceFinder;

public class HPSPolynomialTest
    extends TestCase
{
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

    public void testLift()
        throws FileNotFoundException
    {
        NTRUParameterSet params = new NTRUHPS2048509();
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/ntru/ntruhps2048509", "poly_lift.txt");
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
            r.lift(a);
            i = 0;
            for (Integer value : testCase.get("r"))
            {
                assertEquals(String.format("i = %d", i), value.shortValue(), r.coeffs[i++]);
            }
        }
    }

    public void testR2Inv()
        throws FileNotFoundException
    {
        NTRUParameterSet params = new NTRUHPS2048509();
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/ntru/ntruhps2048509", "poly_R2_inv.txt");
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
            r.r2Inv(a);
            i = 0;
            for (Integer value : testCase.get("r"))
            {
                assertEquals(String.format("i = %d", i), value.shortValue(), r.coeffs[i++]);
            }
        }
    }

    public void testRqInv()
        throws FileNotFoundException
    {
        NTRUParameterSet params = new NTRUHPS2048509();
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/ntru/ntruhps2048509", "poly_Rq_inv.txt");
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
            r.rqInv(a);
            i = 0;
            for (Integer value : testCase.get("r"))
            {
                assertEquals(String.format("i = %d", i), value.shortValue(), r.coeffs[i++]);
            }
        }
    }

    public void testS3Inv()
        throws FileNotFoundException
    {
        NTRUParameterSet params = new NTRUHPS2048509();
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/ntru/ntruhps2048509", "poly_S3_inv.txt");
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
            r.s3Inv(a);
            i = 0;
            for (Integer value : testCase.get("r"))
            {
                assertEquals(String.format("i = %d", i), value.shortValue(), r.coeffs[i++]);
            }
        }
    }
}

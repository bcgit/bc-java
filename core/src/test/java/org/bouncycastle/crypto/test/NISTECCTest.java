package org.bouncycastle.crypto.test;

import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.test.SimpleTest;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class NISTECCTest
        extends SimpleTest
{

    public String getName()
    {
        return "NISTECC";
    }

    public void performTest()
            throws Exception
    {
        testVectors();
    }

    public void testVectors()
    {
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(getClass().getResourceAsStream("nist_ecc.txt")))) {
            String line = br.readLine();
            X9ECParameters curve = null;
            BigInteger k = null;
            BigInteger x = null;
            BigInteger y = null;

            while (line != null) {
                while (null != (line = br.readLine())) {
                    Matcher matcher = Pattern.compile("^ ?(\\w+):? =? ?(\\w+)").matcher(line);
                    if (!matcher.matches()) continue;

                    String nistKey = matcher.group(1);
                    String nistValue = matcher.group(2);

                    switch (nistKey) {
                        case "Curve":
                            // Change curve name from LNNN to L-NNN ie: P256 to P-256
                            String curveName = nistValue.charAt(0) + "-" + nistValue.substring(1);
                            curve = NISTNamedCurves.getByName(curveName);
                            break;
                        case "k":
                            k = new BigInteger(nistValue, 10);
                            break;
                        case "x":
                            x = new BigInteger(nistValue, 16);
                            break;
                        case "y":
                            y = new BigInteger(nistValue,  16);
                            break;
                    }

                    if (curve == null || k == null || x == null || y == null) continue;

                    TestMultiply(curve, k, x, y);
                    k = null;
                    x = null;
                    y = null;
                }
            }
        } catch (IOException exception) {
            fail("Failed to load resources.", exception);
        }
    }

    private void TestMultiply(X9ECParameters curve, BigInteger k, BigInteger x, BigInteger y) {
        // Act
        ECPoint ecPoint = curve.getG().multiply(k).normalize();
        BigInteger affineXCoord = ecPoint.getAffineXCoord().toBigInteger();
        BigInteger affineYCoord = ecPoint.getAffineYCoord().toBigInteger();

        // Assert
        isEquals("Unexpected X Coordinate", x, affineXCoord);
        isEquals("Unexpected Y Coordinate", y, affineYCoord);
    }

    public static void main(String[] args)
    {
        runTest(new NISTECCTest());
    }
}

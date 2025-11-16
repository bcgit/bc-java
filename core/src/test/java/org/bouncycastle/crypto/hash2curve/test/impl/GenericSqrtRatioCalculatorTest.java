package org.bouncycastle.crypto.hash2curve.test.impl;

import junit.framework.TestCase;
import org.bouncycastle.crypto.hash2curve.impl.GenericSqrtRatioCalculator;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;

import java.math.BigInteger;

/**
 * Test class for the GenericSqrtRatioCalculator
 */
public class GenericSqrtRatioCalculatorTest extends TestCase {

  public void testCalculateC1_IsCorrect() {
    ECCurve curve = new SecP256R1Curve();
    BigInteger z = BigInteger.valueOf(-10);
    GenericSqrtRatioCalculator calc = new GenericSqrtRatioCalculator(curve, z);
    calc.sqrtRatio(BigInteger.ONE, BigInteger.valueOf(2));
  }

}

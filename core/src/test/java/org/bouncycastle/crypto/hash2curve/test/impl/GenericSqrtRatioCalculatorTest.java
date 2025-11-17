package org.bouncycastle.crypto.hash2curve.test.impl;

import junit.framework.TestCase;
import org.bouncycastle.crypto.hash2curve.data.SqrtRatio;
import org.bouncycastle.crypto.hash2curve.impl.GenericSqrtRatioCalculator;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;

import java.math.BigInteger;

/**
 * Test class for the GenericSqrtRatioCalculator
 */
public class GenericSqrtRatioCalculatorTest extends TestCase {

  public void testCalculate1() {
    ECCurve curve = new SecP256R1Curve();
    BigInteger z = BigInteger.valueOf(-10);
    GenericSqrtRatioCalculator calc = new GenericSqrtRatioCalculator(curve, z);
    final SqrtRatio sqrtRatio = calc.sqrtRatio(BigInteger.ONE, BigInteger.valueOf(2));
    final BigInteger ratio = sqrtRatio.getRatio();
    assertEquals("39700825768398291280648376089930606243808550255319087055409208967646307233425", ratio.toString(10));
    final boolean qr = sqrtRatio.isQR();
    assertTrue(qr);
  }

  public void testCalculate2() {
    ECCurve curve = new SecP256R1Curve();
    BigInteger z = BigInteger.valueOf(-10);
    GenericSqrtRatioCalculator calc = new GenericSqrtRatioCalculator(curve, z);
    final SqrtRatio sqrtRatio = calc.sqrtRatio(BigInteger.valueOf(10), BigInteger.valueOf(2));
    final BigInteger ratio = sqrtRatio.getRatio();
    assertEquals("3785950496672887136307850542143953904054772247473037052005622114270127172924", ratio.toString(10));
    final boolean qr = sqrtRatio.isQR();
    assertTrue(qr);
  }

  public void testCalculate3() {
    ECCurve curve = new SecP256R1Curve();
    BigInteger z = BigInteger.valueOf(-10);
    GenericSqrtRatioCalculator calc = new GenericSqrtRatioCalculator(curve, z);
    final SqrtRatio sqrtRatio = calc.sqrtRatio(BigInteger.valueOf(1431), BigInteger.valueOf(2));
    final boolean qr = sqrtRatio.isQR();
    assertFalse(qr);
    final BigInteger ratio = sqrtRatio.getRatio();
    assertEquals("20381299611311062807197803046173075660787338796491438136509906084127806899192", ratio.toString(10));
  }

}

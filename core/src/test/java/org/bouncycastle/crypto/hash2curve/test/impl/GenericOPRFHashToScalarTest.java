package org.bouncycastle.crypto.hash2curve.test.impl;

import junit.framework.TestCase;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.hash2curve.MessageExpansion;
import org.bouncycastle.crypto.hash2curve.impl.GenericOPRFHashToScalar;
import org.bouncycastle.crypto.hash2curve.impl.XmdMessageExpansion;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.Security;


/**
 * Test HashToScalar
 */
public class GenericOPRFHashToScalarTest extends TestCase {

  static ECCurve p256Curve = new SecP256R1Curve();
  static GenericOPRFHashToScalar hashToScalar = new GenericOPRFHashToScalar(p256Curve, new SHA256Digest(), 128);



  public void testHashToScalar() {

    BigInteger scalar = hashToScalar.process("Hej".getBytes(), "DST".getBytes());
    //log.info("Scalar value: {}", scalar.toString(16));

  }


  public void testMessageExpansion() {

    MessageExpansion messageExpansion = new XmdMessageExpansion(new SHA256Digest(), 48);
    byte[] expandMessage = messageExpansion.expandMessage("Hej".getBytes(), "DST".getBytes(), 48);

    //log.info("Expanded message: {}", Hex.toHexString(expandMessage));



  }



}

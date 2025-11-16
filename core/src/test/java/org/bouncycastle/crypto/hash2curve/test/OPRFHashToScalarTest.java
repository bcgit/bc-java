package org.bouncycastle.crypto.hash2curve.test;

import junit.framework.TestCase;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.hash2curve.MessageExpansion;
import org.bouncycastle.crypto.hash2curve.OPRFHashToScalar;
import org.bouncycastle.crypto.hash2curve.impl.XmdMessageExpansion;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;

import java.math.BigInteger;

/**
 * Test HashToScalar
 */
public class OPRFHashToScalarTest extends TestCase {

  static ECCurve p256Curve = new SecP256R1Curve();
  static OPRFHashToScalar hashToScalar = new OPRFHashToScalar(p256Curve, new SHA256Digest(), 128);



  public void testHashToScalar() {
    BigInteger scalar = hashToScalar.process("Hej".getBytes(), "DST".getBytes());
    String scalarHex = scalar.toString(16);
    assertEquals("a46a5dedfc6254dd60375be2a7e88393de67fbfc1e49d6817c862d18f176409a", scalarHex);
  }

  public void testMessageExpansion() {
    MessageExpansion messageExpansion = new XmdMessageExpansion(new SHA256Digest(), 48);
    byte[] expandMessage = messageExpansion.expandMessage("Hej".getBytes(), "DST".getBytes(), 48);
    String emHex = new BigInteger(1, expandMessage).toString(16);
    assertEquals("eecb2fbaa0d63c284f61462ab0ee60294486e55b860bf619c9dcb69aa49f72d436bc2a2a862a2f777ab53fc01e4bbeb2", emHex);
  }

}

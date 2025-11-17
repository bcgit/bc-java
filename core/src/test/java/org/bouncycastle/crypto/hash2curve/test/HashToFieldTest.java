package org.bouncycastle.crypto.hash2curve.test;

import junit.framework.TestCase;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.hash2curve.MessageExpansion;
import org.bouncycastle.crypto.hash2curve.HashToField;
import org.bouncycastle.crypto.hash2curve.impl.XmdMessageExpansion;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class HashToFieldTest extends TestCase {

  private static final ECCurve curve;
  private static final MessageExpansion messageExpansion;

  static {
    curve = new SecP256R1Curve();
    messageExpansion = new XmdMessageExpansion(new SHA256Digest(), 128);
  }

  public void testGenericHashToField() {
    byte[] message = new byte[] {};
    byte[] dst = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_".getBytes(StandardCharsets.UTF_8);
    HashToField testInstance = new HashToField(dst, curve, messageExpansion, 48);
    BigInteger[][] result = testInstance.process(message);
    assertEquals("78397231975818298121002851560982570386422970797899025056634496834376049971209", result[0][0].toString(10));
    assertEquals("63350503467990645741152390718511296452551165224812381424345334365447080831578", result[1][0].toString(10));
  }
}

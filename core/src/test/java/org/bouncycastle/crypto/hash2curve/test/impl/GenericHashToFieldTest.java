package org.bouncycastle.crypto.hash2curve.test.impl;

import junit.framework.TestCase;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.hash2curve.MessageExpansion;
import org.bouncycastle.crypto.hash2curve.impl.GenericHashToField;
import org.bouncycastle.crypto.hash2curve.impl.XmdMessageExpansion;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class GenericHashToFieldTest extends TestCase {

  private static final ECCurve curve;
  private static final MessageExpansion messageExpansion;

  static {
    curve = new SecP256R1Curve();
    messageExpansion = new XmdMessageExpansion(new SHA256Digest(), 128);
  }

  public void testGenericHashToField() {
    byte[] message = new byte[] {};
    byte[] dst = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_".getBytes(StandardCharsets.UTF_8);
    GenericHashToField testInstance = new GenericHashToField(dst, curve, messageExpansion, 48);
    BigInteger[][] result = testInstance.process(message);

    //("U0 : {}", Hex.toHexString(result[0][0].toByteArray()));
    //log.info("U1 : {}", Hex.toHexString(result[1][0].toByteArray()));

  }
}

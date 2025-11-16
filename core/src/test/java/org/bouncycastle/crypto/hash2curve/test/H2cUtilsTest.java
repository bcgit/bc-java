package org.bouncycastle.crypto.hash2curve.test;

import junit.framework.TestCase;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.hash2curve.H2cUtils;
import org.bouncycastle.crypto.hash2curve.impl.GenericOPRFHashToScalar;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;


/**
 * Testing hash 2 curve utility functions
 */
public class H2cUtilsTest extends TestCase {

  static ECCurve p256Curve = new SecP256R1Curve();
  static GenericOPRFHashToScalar hashToScalar = new GenericOPRFHashToScalar(p256Curve, new SHA256Digest(), 48);

  public void testIsSquare() throws Exception {

    List<String> smallerXValues = new ArrayList<>();
    smallerXValues.add("4fe14bb3946e9c23a1cacb43de358e45a9931786067278f6ae3315c216e39a0");
    smallerXValues.add("d1d12dd2a682259a5dc0da4b79734d4ab6d435c85c8c980e03f8297611e18937");
    smallerXValues.add("497e89c30c3ed11d291aafcefc02be894f4d87cb29467fa0457b9c02366239d8");
    smallerXValues.add("d1359226395e08d382cc7528b4ff8ed7f7ed991783fe0eb0f9a3ef2449fb1079");
    smallerXValues.add("26d12894c6600f99a3ee553a2c339c33058c09f2b7ed184ae9577a0423a9cdf3");
    smallerXValues.add("5f4edc4e4f1f5dc6eb218bf0791cb80dc264e1d0c2dfcd1cbd00f3b969bcaa56");
    smallerXValues.add("e87cfbe1079f777ff54c82b3bef8edb4dba40762c4c12715952195bc4c146030");
    smallerXValues.add("ed1c985837abfb9317126e52849880155a3e70316ac7c4d7ce343024e975b3f5");
    smallerXValues.add("d7e6c6967d58188bf24bd7aaa04747ab1237725f23eaa47c0e3206f8b4a3c5f5");
    smallerXValues.add("163f11e2d45d62ed5d4f4503f8fd095a2c292e27554cf859f436332bc3ce6bbe");

    boolean[] expectedValues = new boolean[] { true, false, false, true, true, false, false, false, true, false };

    //log.info("P256 curve order: {}", p256Spec.getCurve().getOrder().toString(16));

    for (int i = 0; i < 10; i++) {
      BigInteger x = hashToScalar.process(String.valueOf(i).getBytes(), "DST".getBytes());
      boolean square = H2cUtils.isSquare(x, p256Curve.getOrder());
      //log.info("Integer {} square in p256 order: {}", x.toString(16), square);
      assertEquals(expectedValues[i], square);
    }
  }

  public void testSqrt() throws Exception {

    String[] expectedValues = {
        "323f7ed2e7c1bd98c010e4f7682e424fd7434feeca6a39ad7f80f3dea00eb18d",
        "1e5f775dc6b369930f58df140498358437461c96cb2857c489c346e3927b6a83",
        "56af41b8f8b6f29f556d1d4471f763a7429d5032fde2156d93d50273858453da",
        "2e1d7226dfcd493860543685107d79a684c11c635cec44b0ed1db566cb3c48d2",
        "92bbc6e0dc62c4f3488cb336c911c75108bddbcd60ad7a2ad7f62f07ecf5ddd8",
        "3f32018e0754b2e744ecd06c9b77e7de171f07e6ad6daf6e914e94108db91073",
        "82353b2f3c9505d15429d6a4d5dd4231c3d116e7300efb39f1deca18164bddf6",
        "3afc13643cc49fb989bd18bde7c2ac2332a99381f3f6081293346e1595fca93d",
        "e4244d900f35a71f23ed02dff6c2bc22f11ca4ebb8dd51e0fcaefd0bd7caeed4",
        "b3ed944452119b21901b25b211c0a5d2f9b40384269c77f488064c9503296bd0"
    };

    for (int i = 0; i < 10; i++) {
      BigInteger x = hashToScalar.process(String.valueOf(i).getBytes(), "DST".getBytes());
      BigInteger sqrt = H2cUtils.sqrt(x, p256Curve.getOrder());
      //log.info("Integer {} sqrt in p256 order: {}", x.toString(16), sqrt.toString(16));
      assertEquals(expectedValues[i], sqrt.toString(16));
    }

  }

}

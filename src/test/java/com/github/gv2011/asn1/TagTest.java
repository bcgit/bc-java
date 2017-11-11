package com.github.gv2011.asn1;

import static com.github.gv2011.util.bytes.ByteUtils.asUtf8;
import static com.github.gv2011.util.bytes.ByteUtils.newBytes;
import static com.github.gv2011.util.bytes.ByteUtils.parseHex;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.SecureRandom;

import org.junit.Test;

import com.github.gv2011.util.bytes.Bytes;

/**
 * X.690 test example
 */
public class TagTest {

  Bytes longTagged         =
      asUtf8(
          "ZSRzIp8gEEZFRENCQTk4NzY1NDMyMTCfIQwyMDA2MDQwMTEyMzSUCCAFERVz"
              + "A4kCAHEXGBkalAggBRcYGRqUCCAFZS6QAkRFkQlURUNITklLRVKSBQECAwQF"
              + "kxAREhMUFRYXGBkalAggBREVcwOJAgBxFxgZGpQIIAUXGBkalAggBWUukAJE"
              + "RZEJVEVDSE5JS0VSkgUBAgMEBZMQERITFBUWFxgZGpQIIAURFXMDiQIAcRcY"
              + "GRqUCCAFFxgZGpQIIAVlLpACREWRCVRFQ0hOSUtFUpIFAQIDBAWTEBESExQV"
              + "FhcYGRqUCCAFERVzA4kCAHEXGBkalAggBRcYGRqUCCAFFxgZGpQIIAUXGBka"
              + "lAg=").decodeBase64();

  Bytes longAppSpecificTag = parseHex("5F610101");

  @Test
  public void test() throws IOException {
    DERApplicationSpecific app;
    try (final ASN1InputStream aIn = new ASN1InputStream(longTagged)) {
      app = (DERApplicationSpecific) aIn.readObject();
    }
    try (final ASN1InputStream aIn = new ASN1InputStream(app.getContents())) {
      app = (DERApplicationSpecific) aIn.readObject();
    }
    try (final ASN1InputStream aIn = new ASN1InputStream(app.getContents())) {
      ASN1TaggedObject tagged = (ASN1TaggedObject) aIn.readObject();

      if (tagged.getTagNo() != 32) {
        fail("unexpected tag value found - not 32");
      }

      tagged = (ASN1TaggedObject) ASN1Primitive.fromBytes(tagged.getEncoded());

      if (tagged.getTagNo() != 32) {
        fail("unexpected tag value found on recode - not 32");
      }

      tagged = (ASN1TaggedObject) aIn.readObject();

      if (tagged.getTagNo() != 33) {
        fail("unexpected tag value found - not 33");
      }

      tagged = (ASN1TaggedObject) ASN1Primitive.fromBytes(tagged.getEncoded());

      if (tagged.getTagNo() != 33) {
        fail("unexpected tag value found on recode - not 33");
      }

    }
    try (final ASN1InputStream aIn = new ASN1InputStream(longAppSpecificTag)) {

      app = (DERApplicationSpecific) aIn.readObject();

      if (app.getApplicationTag() != 97) {
        fail("incorrect tag number read");
      }

      app = (DERApplicationSpecific) ASN1Primitive.fromBytes(app.getEncoded());

      if (app.getApplicationTag() != 97) {
        fail("incorrect tag number read on recode");
      }

      final SecureRandom sr = new SecureRandom();
      for (int i = 0; i < 100; ++i) {
        final int testTag = sr.nextInt() >>> (1 + (sr.nextInt() >>> 1) % 26);
        app = new DERApplicationSpecific(testTag, newBytes((byte) 1));
        app = (DERApplicationSpecific) ASN1Primitive.fromBytes(app.getEncoded());

        if (app.getApplicationTag() != testTag) {
          fail("incorrect tag number read on recode (random test value: " + testTag + ")");
        }
      }
    }
  }

}

package com.github.gv2011.asn1;

/*-
 * #%L
 * Vinz ASN.1
 * %%
 * Copyright (C) 2016 - 2017 Vinz (https://github.com/gv2011)
 * %%
 * Please note this should be read in the same way as the MIT license. (https://www.bouncycastle.org/licence.html)
 * 
 * Copyright (c) 2000-2015 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
 * and associated documentation files (the "Software"), to deal in the Software without restriction, 
 * including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 * #L%
 */


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

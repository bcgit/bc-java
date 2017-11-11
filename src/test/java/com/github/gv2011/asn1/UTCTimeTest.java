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


import static org.junit.Assert.fail;

import java.text.SimpleDateFormat;
import java.util.SimpleTimeZone;

import org.junit.Test;

/**
 * X.690 test example
 */
public class UTCTimeTest {
  String[] input    =
      {
          "020122122220Z",
          "020122122220-1000",
          "020122122220+1000",
          "020122122220+00",
          "0201221222Z",
          "0201221222-1000",
          "0201221222+1000",
          "0201221222+00",
          "550122122220Z",
          "5501221222Z"
      };

  String[] output   = {
      "20020122122220GMT+00:00",
      "20020122122220GMT-10:00",
      "20020122122220GMT+10:00",
      "20020122122220GMT+00:00",
      "20020122122200GMT+00:00",
      "20020122122200GMT-10:00",
      "20020122122200GMT+10:00",
      "20020122122200GMT+00:00",
      "19550122122220GMT+00:00",
      "19550122122200GMT+00:00"
  };

  String[] zOutput1 = {
      "20020122122220Z",
      "20020122222220Z",
      "20020122022220Z",
      "20020122122220Z",
      "20020122122200Z",
      "20020122222200Z",
      "20020122022200Z",
      "20020122122200Z",
      "19550122122220Z",
      "19550122122200Z"
  };

  String[] zOutput2 = {
      "20020122122220Z",
      "20020122222220Z",
      "20020122022220Z",
      "20020122122220Z",
      "20020122122200Z",
      "20020122222200Z",
      "20020122022200Z",
      "20020122122200Z",
      "19550122122220Z",
      "19550122122200Z"
  };

  public String getName() {
    return "UTCTime";
  }

  @Test
  public void performTest() throws Exception {
    final SimpleDateFormat yyyyF = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
    final SimpleDateFormat yyF = new SimpleDateFormat("yyyyMMddHHmmss'Z'");

    yyyyF.setTimeZone(new SimpleTimeZone(0, "Z"));
    yyF.setTimeZone(new SimpleTimeZone(0, "Z"));

    for (int i = 0; i != input.length; i++) {
      final ASN1UTCTime t = new ASN1UTCTime(input[i]);

      if (!t.getAdjustedTime().equals(output[i])) {
        fail("failed conversion test " + i);
      }

      if (!yyyyF.format(t.getAdjustedDate()).equals(zOutput1[i])) {
        fail("failed date conversion test " + i);
      }

      if (!yyF.format(t.getDate()).equals(zOutput2[i])) {
        fail("failed date shortened conversion test " + i);
      }
    }
  }

}

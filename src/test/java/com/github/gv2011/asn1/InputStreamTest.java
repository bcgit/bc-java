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


import static com.github.gv2011.util.bytes.ByteUtils.parseHex;

import org.junit.Test;

import com.github.gv2011.asn1.util.test.SimpleTest;
import com.github.gv2011.util.bytes.Bytes;

public class InputStreamTest
    extends SimpleTest
{
    private static final Bytes outOfBoundsLength = parseHex("30 ff ff ff ff ff");
    private static final Bytes negativeLength = parseHex("30 84 ff ff ff ff");
    private static final Bytes outsideLimitLength = parseHex("30 83 0f ff ff");


    @Override
    public String getName()
    {
        return "InputStream";
    }

    @Test
    @Override
    public void performTest()
        throws Exception
    {
        try(final ASN1InputStream aIn = new ASN1InputStream(outOfBoundsLength)){
          try
          {
              aIn.readObject();
              fail("out of bounds length not detected.");
          }
          catch (final ASN1ParsingException e)
          {
              if (!e.getMessage().startsWith("DER length more than 4 bytes"))
              {
                  fail("wrong exception: " + e.getMessage());
              }
          }
        }
        
        try(final ASN1InputStream aIn = new ASN1InputStream(negativeLength)){
          try
          {
              aIn.readObject();
              fail("negative length not detected.");
          }
          catch (final ASN1ParsingException e)
          {
              if (!e.getMessage().equals("corrupted stream - negative length found"))
              {
                  fail("wrong exception: " + e.getMessage());
              }
          }
        }

        try(final ASN1InputStream aIn = new ASN1InputStream(outsideLimitLength)){
          try
          {
              aIn.readObject();
              fail("outside limit length not detected.");
          }
          catch (final ASN1ParsingException e)
          {
              if (!e.getMessage().equals("corrupted stream - out of bounds length found"))
              {
                  fail("wrong exception: " + e.getMessage());
              }
          }
        }
    }
}

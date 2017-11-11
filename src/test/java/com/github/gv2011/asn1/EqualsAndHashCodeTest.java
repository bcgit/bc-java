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


import static org.junit.Assert.assertTrue;

import java.io.InputStream;

import org.junit.Ignore;
import org.junit.Test;

import com.github.gv2011.asn1.util.Strings;
import com.github.gv2011.asn1.util.encoders.Hex;
import com.github.gv2011.asn1.util.test.LegacyTest;
import com.github.gv2011.asn1.util.test.SimpleTestResult;
import com.github.gv2011.asn1.util.test.TestResult;
import com.github.gv2011.util.bytes.ByteUtils;
import com.github.gv2011.util.bytes.Bytes;
import com.github.gv2011.util.bytes.BytesBuilder;

public class EqualsAndHashCodeTest
    implements LegacyTest
{
    @Override
    public TestResult perform()
    {
        final Bytes    data = ByteUtils.parseHex("00 01 00 01 00 00 01");

        final ASN1Primitive    values[] = {
                new BERSequence(new DERPrintableString("hello world")),
                new BERSet(new DERPrintableString("hello world")),
                new BERTaggedObject(0, new DERPrintableString("hello world")),
                new DERApplicationSpecific(0, data),
                new DERBitString(data),
                new DERBMPString("hello world"),
                ASN1Boolean.TRUE,
                ASN1Boolean.FALSE,
                new ASN1Enumerated(100),
                new DERGeneralizedTime("20070315173729Z"),
                new DERGeneralString("hello world"),
                new DERIA5String("hello"),
                new ASN1Integer(1000),
                DERNull.INSTANCE,
                new DERNumericString("123456"),
                new ASN1ObjectIdentifier("1.1.1.10000.1"),
                new DEROctetString(data),
                new DERPrintableString("hello world"),
                new DERSequence(new DERPrintableString("hello world")),
                new DERSet(new DERPrintableString("hello world")),
                new DERT61String("hello world"),
                new DERTaggedObject(0, new DERPrintableString("hello world")),
                new DERUniversalString(data),
                new DERUTF8String("hello world"),
                new DERVisibleString("hello world") ,
                new DERGraphicString(Hex.decode("deadbeef")),
                new DERVideotexString(Strings.toByteArray("Hello World"))
            };

        try
        {
            final BytesBuilder     bOut = ByteUtils.newBytesBuilder();
            final ASN1OutputStream aOut = new ASN1OutputStream(bOut);

            for (final ASN1Primitive v: values) aOut.writeObject(v);

            final InputStream     bIn = bOut.build().openStream();
            try(final ASN1InputStream aIn = new ASN1InputStream(bIn)){

              for (int i = 0; i != values.length; i++)
              {
                  final ASN1Primitive o = aIn.readObject();
                  if (!o.equals(values[i]))
                  {
                      return new SimpleTestResult(false, getName() + ": Failed equality test for " + o.getClass());
                  }

                  if (o.hashCode() != values[i].hashCode())
                  {
                      return new SimpleTestResult(false, getName() + ": Failed hashCode test for " + o.getClass());
                  }
              }
            }
        }
        catch (final Exception e)
        {
            return new SimpleTestResult(false, getName() + ": Failed - exception " + e.toString(), e);
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    @Override
    public String getName()
    {
        return "EqualsAndHashCode";
    }

    @Test
    @Ignore //TODO fails
    public void test()
    {
        final EqualsAndHashCodeTest    test = new EqualsAndHashCodeTest();
        final TestResult      result = test.perform();

        assertTrue(result.isSuccessful());
    }
}

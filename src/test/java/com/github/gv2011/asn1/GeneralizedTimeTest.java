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


import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;
import java.util.TimeZone;

import org.junit.Test;

import com.github.gv2011.asn1.DERGeneralizedTime;
import com.github.gv2011.asn1.util.test.SimpleTest;

/**
 * X.690 test example
 */
public class GeneralizedTimeTest
    extends SimpleTest
{
    String[] input =
        {
            "20020122122220",
            "20020122122220Z",
            "20020122122220-1000",
            "20020122122220+00",
            "20020122122220.1",
            "20020122122220.1Z",
            "20020122122220.1-1000",
            "20020122122220.1+00",
            "20020122122220.01",
            "20020122122220.01Z",
            "20020122122220.01-1000",
            "20020122122220.01+00",
            "20020122122220.001",
            "20020122122220.001Z",
            "20020122122220.001-1000",
            "20020122122220.001+00",
            "20020122122220.0001",
            "20020122122220.0001Z",
            "20020122122220.0001-1000",
            "20020122122220.0001+00",
            "20020122122220.0001+1000"
        };

    String[] output = {
            "20020122122220",
            "20020122122220GMT+00:00",
            "20020122122220GMT-10:00",
            "20020122122220GMT+00:00",
            "20020122122220.1",
            "20020122122220.1GMT+00:00",
            "20020122122220.1GMT-10:00",
            "20020122122220.1GMT+00:00",
            "20020122122220.01",
            "20020122122220.01GMT+00:00",
            "20020122122220.01GMT-10:00",
            "20020122122220.01GMT+00:00",
            "20020122122220.001",
            "20020122122220.001GMT+00:00",
            "20020122122220.001GMT-10:00",
            "20020122122220.001GMT+00:00",
            "20020122122220.0001",
            "20020122122220.0001GMT+00:00",
            "20020122122220.0001GMT-10:00",
            "20020122122220.0001GMT+00:00",
            "20020122122220.0001GMT+10:00" };

    String[] zOutput = {
            "20020122122220Z",
            "20020122122220Z",
            "20020122222220Z",
            "20020122122220Z",
            "20020122122220Z",
            "20020122122220Z",
            "20020122222220Z",
            "20020122122220Z",
            "20020122122220Z",
            "20020122122220Z",
            "20020122222220Z",
            "20020122122220Z",
            "20020122122220Z",
            "20020122122220Z",
            "20020122222220Z",
            "20020122122220Z",
            "20020122122220Z",
            "20020122122220Z",
            "20020122222220Z",
            "20020122122220Z",
            "20020122022220Z"
    };

    String[] mzOutput = {
        "20020122122220.000Z",
        "20020122122220.000Z",
        "20020122222220.000Z",
        "20020122122220.000Z",
        "20020122122220.100Z",
        "20020122122220.100Z",
        "20020122222220.100Z",
        "20020122122220.100Z",
        "20020122122220.010Z",
        "20020122122220.010Z",
        "20020122222220.010Z",
        "20020122122220.010Z",
        "20020122122220.001Z",
        "20020122122220.001Z",
        "20020122222220.001Z",
        "20020122122220.001Z",
        "20020122122220.000Z",
        "20020122122220.000Z",
        "20020122222220.000Z",
        "20020122122220.000Z",
        "20020122022220.000Z"
    };

    @Override
    public String getName()
    {
        return "GeneralizedTime";
    }
    
    @Test
    @Override
    public void performTest()
        throws Exception
    {
        SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmss'Z'");

        dateF.setTimeZone(new SimpleTimeZone(0,"Z"));

        for (int i = 0; i != input.length; i++)
        {
            DERGeneralizedTime    t = new DERGeneralizedTime(input[i]);

            if (output[i].indexOf('G') > 0)   // don't check local time the same way
            {
                if (!t.getTime().equals(output[i]))
                {
                    fail("failed conversion test");
                }
                if (!dateF.format(t.getDate()).equals(zOutput[i]))
                {
                    fail("failed date conversion test");
                }
            }
            else
            {
                String offset = calculateGMTOffset(t.getDate());
                if (!t.getTime().equals(output[i] + offset))
                {
                    fail("failed conversion test");
                }
            }
        }

        dateF = new SimpleDateFormat("yyyyMMddHHmmss.SSS'Z'");

        dateF.setTimeZone(new SimpleTimeZone(0,"Z"));

        for (int i = 0; i != input.length; i++)
        {
            DERGeneralizedTime    t = new DERGeneralizedTime(input[i]);

            if (!dateF.format(t.getDate()).equals(mzOutput[i]))
            {
                fail("failed long date conversion test");
            }
        }
    }

    private String calculateGMTOffset(Date date)
    {
        String sign = "+";
        TimeZone timeZone = TimeZone.getDefault();
        int offset = timeZone.getRawOffset();
        if (offset < 0)
        {
            sign = "-";
            offset = -offset;
        }
        int hours = offset / (60 * 60 * 1000);
        int minutes = (offset - (hours * 60 * 60 * 1000)) / (60 * 1000);

        if (timeZone.useDaylightTime() && timeZone.inDaylightTime(date))
        {
            hours += sign.equals("+") ? 1 : -1;
        }

        return "GMT" + sign + convert(hours) + ":" + convert(minutes);
    }

    private String convert(int time)
    {
        if (time < 10)
        {
            return "0" + time;
        }

        return Integer.toString(time);
    }

}

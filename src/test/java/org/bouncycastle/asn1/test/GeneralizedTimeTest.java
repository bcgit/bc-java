package org.bouncycastle.asn1.test;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;
import java.util.TimeZone;

import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.util.test.SimpleTest;

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

    public String getName()
    {
        return "GeneralizedTime";
    }
    
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

    public static void main(
        String[]    args)
    {
        runTest(new GeneralizedTimeTest());
    }
}

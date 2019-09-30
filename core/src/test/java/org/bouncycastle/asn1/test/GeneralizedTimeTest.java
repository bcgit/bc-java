package org.bouncycastle.asn1.test;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;
import java.util.TimeZone;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
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

    String[] derMzOutput = {
        "20020122122220Z",
        "20020122122220Z",
        "20020122222220Z",
        "20020122122220Z",
        "20020122122220.1Z",
        "20020122122220.1Z",
        "20020122222220.1Z",
        "20020122122220.1Z",
        "20020122122220.01Z",
        "20020122122220.01Z",
        "20020122222220.01Z",
        "20020122122220.01Z",
        "20020122122220.001Z",
        "20020122122220.001Z",
        "20020122222220.001Z",
        "20020122122220.001Z",
        "20020122122220Z",
        "20020122122220Z",
        "20020122222220Z",
        "20020122122220Z",
        "20020122022220Z"
    };

    String[] truncOutput = {
         "200201221222Z",
         "2002012212Z"
     };

     String[] derTruncOutput = {
         "20020122122200Z",
         "20020122120000Z"
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
            ASN1GeneralizedTime    t = new ASN1GeneralizedTime(input[i]);
            if (output[i].indexOf('G') > 0)   // don't check local time the same way
            {
                if (!t.getTime().equals(output[i]))
                {
                    fail("failed GMT conversion test got " + t.getTime() + " expected " + output[i]);
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
                    fail("failed conversion test got " + t.getTime() + " expected " + output[i] + offset);
                }
            }
        }

        dateF = new SimpleDateFormat("yyyyMMddHHmmss.SSS'Z'");

        dateF.setTimeZone(new SimpleTimeZone(0,"Z"));

        for (int i = 0; i != input.length; i++)
        {
            ASN1GeneralizedTime    t = new ASN1GeneralizedTime(input[i]);

            if (!dateF.format(t.getDate()).equals(mzOutput[i]))
            {
                fail("failed long date conversion test");
            }
        }

        for (int i = 0; i != mzOutput.length; i++)
        {
            ASN1GeneralizedTime    t = new DERGeneralizedTime(mzOutput[i]);

            if (!areEqual(t.getEncoded(), new ASN1GeneralizedTime(derMzOutput[i]).getEncoded()))
            {
                fail("der encoding wrong");
            }
        }

        for (int i = 0; i != truncOutput.length; i++)
        {
            DERGeneralizedTime    t = new DERGeneralizedTime(truncOutput[i]);

            if (!areEqual(t.getEncoded(), new ASN1GeneralizedTime(derTruncOutput[i]).getEncoded()))
            {
                fail("trunc der encoding wrong");
            }
        }

        // check an actual GMT string comes back untampered
        ASN1GeneralizedTime time = new ASN1GeneralizedTime("20190704031318GMT+00:00");

        isTrue("20190704031318GMT+00:00".equals(time.getTime()));

        try
        {
            new DERGeneralizedTime(new byte[0]);
        }
        catch (IllegalArgumentException e)
        {
            isTrue(e.getMessage().equals("GeneralizedTime string too short"));
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

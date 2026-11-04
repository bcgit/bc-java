package org.bouncycastle.asn1.test;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.SimpleTimeZone;
import java.util.TimeZone;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
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
    
    /**
     * X.680 lets a GeneralizedTime leave out the minutes and seconds and give a fraction of whichever unit
     * comes last, with '.' or ',' before it; DER (X.690 sec. 11.7) wants the seconds and a fraction of a
     * second only. The DER form carries the fraction down - it used to append the missing digits after it,
     * giving a value that was not DER and grew each time it was re-encoded.
     */
    private void derFractionTest()
        throws Exception
    {
        String[][] cases = {
            { "9050010112.100Z", "90500101120600Z" },          // a tenth of an hour is six minutes
            { "2026010112.123Z", "20260101120722.8Z" },        // 0.123 h is 442.8 s
            { "202601011230.5Z", "20260101123030Z" },          // half a minute
            { "202601011230.25Z", "20260101123015Z" },
            { "2026010112Z", "20260101120000Z" },
            { "202601011230Z", "20260101123000Z" },
            { "20260101123015,500Z", "20260101123015.5Z" },    // ',' becomes '.'
            { "20260101123015.000Z", "20260101123015Z" },
            { "20260101123015.120Z", "20260101123015.12Z" },
        };
        for (int i = 0; i != cases.length; i++)
        {
            // read as the decoder reads a GeneralizedTime off the wire
            byte[] text = Strings.toByteArray(cases[i][0]);
            byte[] lenient = Arrays.concatenate(new byte[]{ 0x18, (byte)text.length }, text);
            byte[] der = ASN1Primitive.fromByteArray(lenient).getEncoded(ASN1Encoding.DER);
            ASN1GeneralizedTime decoded = ASN1GeneralizedTime.getInstance(der);
            isEquals(cases[i][0], cases[i][1], decoded.getTimeString());
            isTrue(cases[i][0] + " DER not stable",
                Arrays.areEqual(der, ASN1Primitive.fromByteArray(der).getEncoded(ASN1Encoding.DER)));
        }
    }

    public void performTest()
        throws Exception
    {
        derFractionTest();

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

        {
            // check BER encoding is still "as given"
            ASN1GeneralizedTime ber = new ASN1GeneralizedTime("202208091215Z");

            isTrue(Arrays.areEqual(Hex.decode("180d3230323230383039313231355a"), ber.getEncoded(ASN1Encoding.DL)));
            isTrue(Arrays.areEqual(Hex.decode("180d3230323230383039313231355a"), ber.getEncoded(ASN1Encoding.BER)));
            isTrue(Arrays.areEqual(Hex.decode("180f32303232303830393132313530305a"), ber.getEncoded(ASN1Encoding.DER)));

            // check always uses DER encoding
            DERGeneralizedTime der = new DERGeneralizedTime("202208091215Z");

            isTrue(Arrays.areEqual(Hex.decode("180f32303232303830393132313530305a"), der.getEncoded(ASN1Encoding.DL)));
            isTrue(Arrays.areEqual(Hex.decode("180f32303232303830393132313530305a"), der.getEncoded(ASN1Encoding.BER)));
            isTrue(Arrays.areEqual(Hex.decode("180f32303232303830393132313530305a"), der.getEncoded(ASN1Encoding.DER)));
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

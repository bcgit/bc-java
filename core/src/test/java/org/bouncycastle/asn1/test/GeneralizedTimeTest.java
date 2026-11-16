package org.bouncycastle.asn1.test;

import java.math.BigInteger;
import java.security.SecureRandom;
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

    /**
     * The DER form of a long fraction must cost time linear in its length, as the encoding does not
     * bound the length of the fraction.
     */
    private void longFractionTest()
        throws Exception
    {
        int digits = 1000000;
        StringBuffer sb = new StringBuffer("20261116120000.");
        for (int i = 0; i != digits; i++)
        {
            sb.append((char)('1' + i % 9));
        }
        sb.append("000Z");
        byte[] text = Strings.toByteArray(sb.toString());
        // read as the decoder reads a GeneralizedTime off the wire (3-byte long-form length)
        byte[] header = { 0x18, (byte)0x83, (byte)(text.length >> 16), (byte)(text.length >> 8), (byte)text.length };
        ASN1Primitive lenient = ASN1Primitive.fromByteArray(Arrays.concatenate(header, text));

        long start = System.currentTimeMillis();
        byte[] der = lenient.getEncoded(ASN1Encoding.DER);
        long elapsed = System.currentTimeMillis() - start;

        isTrue("long fraction took " + elapsed + "ms", elapsed < 1000);
        String expected = sb.toString().substring(0, sb.length() - 4) + "Z";
        isEquals("long fraction", expected, ASN1GeneralizedTime.getInstance(der).getTimeString());
    }

    /**
     * Compare the DER fraction carry against the exact BigInteger arithmetic for random fractions of an
     * hour, a minute and a second.
     */
    private void randomFractionTest()
        throws Exception
    {
        SecureRandom random = new SecureRandom();
        String[] prefixes = { "2026010112", "202601011230", "20260101123015" };
        int[] units = { 3600, 60, 1 };
        for (int t = 0; t != 300; t++)
        {
            int kind = t % 3;
            int len = 1 + random.nextInt(40);
            StringBuffer fraction = new StringBuffer();
            for (int i = 0; i != len; i++)
            {
                fraction.append((char)('0' + random.nextInt(10)));
            }
            String text = prefixes[kind] + "." + fraction + "Z";

            BigInteger[] carried = new BigInteger(fraction.toString()).multiply(BigInteger.valueOf(units[kind]))
                .divideAndRemainder(BigInteger.valueOf(10).pow(len));
            int seconds = carried[0].intValue();
            String rem = carried[1].toString();
            while (rem.length() < len)
            {
                rem = "0" + rem;
            }
            int last = rem.length();
            while (last > 0 && rem.charAt(last - 1) == '0')
            {
                last--;
            }
            rem = rem.substring(0, last);

            StringBuffer expected = new StringBuffer("20260101");
            if (kind == 0)
            {
                expected.append("12").append(twoDigits(seconds / 60)).append(twoDigits(seconds % 60));
            }
            else if (kind == 1)
            {
                expected.append("1230").append(twoDigits(seconds));
            }
            else
            {
                expected.append("123015");
            }
            if (rem.length() != 0)
            {
                expected.append('.').append(rem);
            }
            expected.append('Z');

            byte[] der = new DERGeneralizedTime(Strings.toByteArray(text)).getEncoded();
            isEquals(text, expected.toString(), ASN1GeneralizedTime.getInstance(der).getTimeString());
        }
    }

    private static String twoDigits(int value)
    {
        return value < 10 ? "0" + value : Integer.toString(value);
    }

    public void performTest()
        throws Exception
    {
        derFractionTest();
        longFractionTest();
        randomFractionTest();

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

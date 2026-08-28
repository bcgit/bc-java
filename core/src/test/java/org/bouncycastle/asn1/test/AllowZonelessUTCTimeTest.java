package org.bouncycastle.asn1.test;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Exercises the read-side structural validation of ASN.1 UTCTime / GeneralizedTime content and the
 * one exception to it, the org.bouncycastle.asn1.allow_zoneless_utctime property
 * (Properties.ASN1_ALLOW_ZONELESS_UTCTIME). Since 1.85 structurally malformed content - non-digit
 * or out-of-range fields, an illegal length, a missing or garbage zone terminator - is rejected
 * when it is decoded, which fails the parse of whatever structure carries it.
 * <p>
 * Setting the property admits the zone-less UTCTime "YYMMDDHHMMSS" (github #2411) and nothing
 * else, as its name says: the value is not a legal UTCTime, X.680 sec. 47.3 making the zone
 * mandatory, but getTime() has always read it as GMT so it denotes a real instant. Every other
 * malformed value is still rejected with the property set, and the value itself does not decode
 * at all without it.
 */
public class AllowZonelessUTCTimeTest
    extends SimpleTest
{
    // github #2411: the signing-time attribute of a CMS SignedData in circulation.
    private static final String UTC_NO_ZONE = "150612153520";

    private static final String[] MALFORMED_UTC =
    {
        "1506121535",           // zone-less and without seconds - getTime() cannot index it
        "150612153520X",        // garbage in place of the zone terminator
        "151312153520Z",        // month 13
        "150632153520Z",        // day 32
        "150612243520Z",        // hour 24
        "150612156020Z",        // minute 60
        "150612153560Z",        // second 60
        "150612153520Z0",       // trailing byte past a complete value
        "1506121535\001\002Z",  // control characters
        "1506121535\00120",     // control character where the zone-less value has a second digit
        "150612153520+2500",    // offset hours 25
        "150612153520+0060",    // offset minutes 60
        "151312153520",         // zone-less, but month 13
        "150612153560",         // zone-less, but second 60
    };

    private static final String[] MALFORMED_GENERALIZED =
    {
        "2015",                     // too short to carry YYYYMMDDHH
        "20151312153520Z",          // month 13
        "20150612153520X",          // garbage in place of the zone terminator
        "20150612153520.Z",         // decimal mark with no fraction
        "20150612153520Z0",         // trailing byte past a complete value
        "201506121535\001\002Z",    // control characters
    };

    public String getName()
    {
        return "AllowZonelessUTCTime";
    }

    public void performTest()
        throws Exception
    {
        checkRejectedByDefault();
        checkPropertyAdmitsZoneLessUTCTimeOnly();
        checkPropertyDidNotLeak();
    }

    /**
     * Without the property nothing malformed decodes - the zone-less form included.
     */
    private void checkRejectedByDefault()
        throws Exception
    {
        shouldRejectParse("zone-less UTCTime", utcTime(UTC_NO_ZONE), "invalid UTCTime format");

        for (int i = 0; i != MALFORMED_UTC.length; i++)
        {
            shouldRejectParse("UTCTime " + MALFORMED_UTC[i], utcTime(MALFORMED_UTC[i]), "invalid UTCTime format");
        }
        for (int i = 0; i != MALFORMED_GENERALIZED.length; i++)
        {
            shouldRejectParse("GeneralizedTime " + MALFORMED_GENERALIZED[i], generalizedTime(MALFORMED_GENERALIZED[i]),
                "invalid GeneralizedTime format");
        }
    }

    /**
     * With the property set the zone-less form decodes, denotes the instant it looks like and
     * round-trips unchanged - but it is the only thing the property admits, and it is still not DER.
     */
    private void checkPropertyAdmitsZoneLessUTCTimeOnly()
        throws Exception
    {
        System.setProperty(Properties.ASN1_ALLOW_ZONELESS_UTCTIME, "true");
        try
        {
            byte[] encoding = utcTime(UTC_NO_ZONE);

            ASN1UTCTime time = (ASN1UTCTime)ASN1Primitive.fromByteArray(encoding);

            isEquals("zone-less UTCTime contents altered", UTC_NO_ZONE, time.toString());
            isEquals("zone-less UTCTime not read as GMT", UTC_NO_ZONE + "GMT+00:00", time.getTime());
            isEquals("zone-less UTCTime adjusted time", "20" + UTC_NO_ZONE + "GMT+00:00", time.getAdjustedTime());
            isEquals("zone-less UTCTime date", gmtDate("20150612153520"), time.getDate());
            isEquals("zone-less UTCTime adjusted date", gmtDate("20150612153520"), time.getAdjustedDate());
            isTrue("zone-less UTCTime not re-encoded verbatim", Arrays.areEqual(encoding, time.getEncoded()));

            // nothing else is admitted, whichever primitive it belongs to
            for (int i = 0; i != MALFORMED_UTC.length; i++)
            {
                shouldRejectParse("UTCTime " + MALFORMED_UTC[i] + " with the property set",
                    utcTime(MALFORMED_UTC[i]), "invalid UTCTime format");
            }
            for (int i = 0; i != MALFORMED_GENERALIZED.length; i++)
            {
                shouldRejectParse("GeneralizedTime " + MALFORMED_GENERALIZED[i] + " with the property set",
                    generalizedTime(MALFORMED_GENERALIZED[i]), "invalid GeneralizedTime format");
            }

            // admitted on read, but still not DER - the write-side gate is unaffected.
            System.setProperty(Properties.ASN1_ALLOW_NON_DER_TIME, "false");
            try
            {
                time.getEncoded(ASN1Encoding.DER);
                fail("zone-less UTCTime written as DER");
            }
            catch (IOException e)
            {
                isTrue("unexpected message rejecting DER write: " + e.getMessage(),
                    e.getMessage() != null && e.getMessage().indexOf("not in DER format") >= 0);
            }
            finally
            {
                System.getProperties().remove(Properties.ASN1_ALLOW_NON_DER_TIME);
            }
        }
        finally
        {
            System.getProperties().remove(Properties.ASN1_ALLOW_ZONELESS_UTCTIME);
        }
    }

    private void checkPropertyDidNotLeak()
        throws Exception
    {
        shouldRejectParse("zone-less UTCTime after the property was cleared", utcTime(UTC_NO_ZONE),
            "invalid UTCTime format");
    }

    private void shouldRejectParse(String label, byte[] encoding, String expectedMessage)
    {
        try
        {
            ASN1Primitive.fromByteArray(encoding);
            fail("read did not reject " + label);
        }
        catch (IOException e)
        {
            isTrue("unexpected message rejecting " + label + ": " + e.getMessage(),
                e.getMessage() != null && e.getMessage().indexOf(expectedMessage) >= 0);
        }
    }

    private static Date gmtDate(String value)
        throws Exception
    {
        SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmss");

        dateF.setTimeZone(TimeZone.getTimeZone("GMT"));

        return dateF.parse(value);
    }

    private static byte[] utcTime(String value)
    {
        return tlv(0x17, value);
    }

    private static byte[] generalizedTime(String value)
    {
        return tlv(0x18, value);
    }

    private static byte[] tlv(int tag, String value)
    {
        byte[] v = Strings.toByteArray(value);
        byte[] enc = new byte[2 + v.length];
        enc[0] = (byte)tag;
        enc[1] = (byte)v.length;    // all values used here are short form (< 128 bytes)
        System.arraycopy(v, 0, enc, 2, v.length);
        return enc;
    }

    public static void main(String[] args)
    {
        runTest(new AllowZonelessUTCTimeTest());
    }
}

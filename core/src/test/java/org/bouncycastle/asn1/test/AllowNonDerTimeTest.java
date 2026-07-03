package org.bouncycastle.asn1.test;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DEREncodingException;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Exercises the org.bouncycastle.asn1.allow_non_der_time property
 * (Properties.ASN1_ALLOW_NON_DER_TIME). Reading is always lenient: a non-DER UTCTime or
 * GeneralizedTime on the wire is always parseable. The property only governs DER
 * serialization: default ("true"/unset) preserves the historical pass-through, while
 * "false" makes any attempt to write a non-DER time to a DEROutputStream fail per
 * X.690 sec. 11.7 / 11.8 (github #1973 / #1986).
 */
public class AllowNonDerTimeTest
    extends SimpleTest
{
    public String getName()
    {
        return "AllowNonDerTime";
    }

    public void performTest()
        throws Exception
    {
        byte[] utcDer = utcTime("010301010000Z");                // YYMMDDHHMMSSZ - valid DER
        byte[] utcNoSeconds = utcTime("0103010100Z");             // YYMMDDHHMMZ   - no seconds
        byte[] utcOffset = utcTime("010301010000-0500");          // offset, not 'Z'

        byte[] genDer = generalizedTime("20020122122220Z");           // valid DER
        byte[] genNoSeconds = generalizedTime("200201221222Z");       // no seconds
        byte[] genTrailingZero = generalizedTime("20020122122220.50Z"); // trailing zero in fraction
        byte[] genIssue2040 = generalizedTime("240123000000Z");       // github #2040: 13-char (2-digit year) GeneralizedTime

        // reading is always lenient, regardless of the property
        ASN1UTCTime utcDerObj = (ASN1UTCTime)ASN1Primitive.fromByteArray(utcDer);
        ASN1UTCTime utcNoSecondsObj = (ASN1UTCTime)ASN1Primitive.fromByteArray(utcNoSeconds);
        ASN1UTCTime utcOffsetObj = (ASN1UTCTime)ASN1Primitive.fromByteArray(utcOffset);
        ASN1GeneralizedTime genDerObj = (ASN1GeneralizedTime)ASN1Primitive.fromByteArray(genDer);
        ASN1GeneralizedTime genNoSecondsObj = (ASN1GeneralizedTime)ASN1Primitive.fromByteArray(genNoSeconds);
        ASN1GeneralizedTime genTrailingZeroObj = (ASN1GeneralizedTime)ASN1Primitive.fromByteArray(genTrailingZero);

        // github #2040: a GeneralizedTime carrying a 2-digit-year (UTCTime-shaped) value decodes
        // to an out-of-range month and is now rejected on read by the strict structural validation
        // in ASN1GeneralizedTime.createPrimitive - earlier than, and independent of, the DER write
        // gate below. (Legal-but-non-DER forms - missing seconds, offset, trailing-zero fraction -
        // still parse leniently, as asserted above.)
        shouldRejectParse("GeneralizedTime 2-digit year (github #2040)", genIssue2040);

        // default (property unset / "true"): non-DER may still be re-emitted as DER (lenient pass-through)
        isTrue("default: DER UTCTime round-trip", utcDerObj.getEncoded(ASN1Encoding.DER).length > 0);
        isTrue("default: non-DER UTCTime serialises as DER", utcNoSecondsObj.getEncoded(ASN1Encoding.DER).length > 0);
        isTrue("default: DER GeneralizedTime round-trip", genDerObj.getEncoded(ASN1Encoding.DER).length > 0);
        isTrue("default: non-DER GeneralizedTime serialises as DER", genNoSecondsObj.getEncoded(ASN1Encoding.DER).length > 0);

        // strict mode: only DER content may be written via DEROutputStream; reading still works
        System.setProperty(Properties.ASN1_ALLOW_NON_DER_TIME, "false");
        try
        {
            // reading non-DER still succeeds
            isTrue("strict: still parses non-DER UTCTime", ASN1Primitive.fromByteArray(utcNoSeconds) instanceof ASN1UTCTime);
            isTrue("strict: still parses non-DER GeneralizedTime", ASN1Primitive.fromByteArray(genNoSeconds) instanceof ASN1GeneralizedTime);

            // DER round-trip of conformant content still succeeds
            isTrue("strict: DER UTCTime round-trip", utcDerObj.getEncoded(ASN1Encoding.DER).length > 0);
            isTrue("strict: DER GeneralizedTime round-trip", genDerObj.getEncoded(ASN1Encoding.DER).length > 0);

            // DER write of non-conformant content fails
            shouldRejectDER("UTCTime missing seconds", utcNoSecondsObj);
            shouldRejectDER("UTCTime offset not Z", utcOffsetObj);
            shouldRejectDER("GeneralizedTime missing seconds", genNoSecondsObj);
            shouldRejectDER("GeneralizedTime trailing-zero fraction", genTrailingZeroObj);

            // BER serialization is unaffected by the property
            isTrue("strict: BER write of non-DER UTCTime", utcNoSecondsObj.getEncoded(ASN1Encoding.BER).length > 0);
            isTrue("strict: BER write of non-DER GeneralizedTime", genNoSecondsObj.getEncoded(ASN1Encoding.BER).length > 0);
        }
        finally
        {
            System.getProperties().remove(Properties.ASN1_ALLOW_NON_DER_TIME);
        }

        // property cleared: lenient pass-through again (and the override did not leak to other tests)
        isTrue("restored: non-DER UTCTime DER write", utcNoSecondsObj.getEncoded(ASN1Encoding.DER).length > 0);
    }

    private void shouldRejectParse(String label, byte[] encoding)
    {
        try
        {
            ASN1Primitive.fromByteArray(encoding);
            fail("strict read did not reject " + label);
        }
        catch (IOException e)
        {
            isTrue("unexpected message rejecting " + label,
                e.getMessage() != null && e.getMessage().indexOf("invalid GeneralizedTime format") >= 0);
        }
    }

    private void shouldRejectDER(String label, ASN1Primitive prim)
    {
        try
        {
            prim.getEncoded(ASN1Encoding.DER);
            fail("strict mode did not reject DER write of " + label);
        }
        catch (IOException e)
        {
            isTrue("expected DEREncodingException as cause for " + label,
                e.getCause() instanceof DEREncodingException);
            isTrue("unexpected message rejecting " + label,
                e.getMessage() != null && e.getMessage().indexOf("not in DER format") >= 0);
        }
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
        runTest(new AllowNonDerTimeTest());
    }
}

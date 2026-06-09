package org.bouncycastle.asn1;

import junit.framework.TestCase;
import org.bouncycastle.util.Strings;

/**
 * White-box tests for {@link ASN1TimeFormat}, the strict structural validator
 * for UTCTime / GeneralizedTime content. Lives in {@code org.bouncycastle.asn1}
 * to reach the package-private helper.
 * <p>
 * The "currently accepted but bogus" cases use the exact content bytes from the
 * fuzzing report (github ASN.1 TIME parsing): values BC parses today and either
 * turns into a nonsensical Date or fails on {@code getDate()}. The validator
 * must reject all of them while still accepting the legal lenient forms BC is
 * expected to read.
 */
public class ASN1TimeFormatTest
    extends TestCase
{
    private static byte[] b(String s)
    {
        return Strings.toByteArray(s);
    }

    public void testValidUTCTime()
    {
        // X.680 sec. 47: minutes mandatory, seconds optional, zone (Z or offset) mandatory.
        assertTrue(ASN1TimeFormat.isValidUTCTime(b("5001010000Z")));        // no seconds, Z
        assertTrue(ASN1TimeFormat.isValidUTCTime(b("500101000000Z")));      // seconds, Z
        assertTrue(ASN1TimeFormat.isValidUTCTime(b("5001010000+0500")));    // no seconds, offset
        assertTrue(ASN1TimeFormat.isValidUTCTime(b("5001010000+0530")));    // no seconds, offset
        assertTrue(ASN1TimeFormat.isValidUTCTime(b("500101000000-0830")));  // seconds, offset
        assertTrue(ASN1TimeFormat.isValidUTCTime(b("991231235959Z")));      // boundary fields
        assertTrue(ASN1TimeFormat.isValidUTCTime(b("000101120000Z")));      // year 00 is fine
    }

    public void testInvalidUTCTimeFieldRanges()
    {
        assertFalse(ASN1TimeFormat.isValidUTCTime(b("000000000000Z")));     // month 00, day 00
        assertFalse(ASN1TimeFormat.isValidUTCTime(b("000200000000Z")));     // day 00
        assertFalse(ASN1TimeFormat.isValidUTCTime(b("241300000000Z")));     // month 13 (and day/... irrelevant)
        assertFalse(ASN1TimeFormat.isValidUTCTime(b("240132000000Z")));     // day 32
        assertFalse(ASN1TimeFormat.isValidUTCTime(b("240101240000Z")));     // hour 24
        assertFalse(ASN1TimeFormat.isValidUTCTime(b("240101006000Z")));     // minute 60
        assertFalse(ASN1TimeFormat.isValidUTCTime(b("240101000060Z")));     // second 60
        assertFalse(ASN1TimeFormat.isValidUTCTime(b("240101000000+2460"))); // offset minute 60
        assertFalse(ASN1TimeFormat.isValidUTCTime(b("5001010000+05")));     // no seconds, offset (no minutes)
        assertFalse(ASN1TimeFormat.isValidUTCTime(b("500101000000+05")));   // seconds, offset (no minutes)
    }

    public void testInvalidUTCTimeStructure()
    {
        assertFalse(ASN1TimeFormat.isValidUTCTime(b("240101000000")));      // no zone
        assertFalse(ASN1TimeFormat.isValidUTCTime(b("24010100000Z")));      // illegal length 12
        assertFalse(ASN1TimeFormat.isValidUTCTime(b("2401010000X")));       // bad terminator
        assertFalse(ASN1TimeFormat.isValidUTCTime(b("2401010000+99XX")));   // non-digit offset
        assertFalse(ASN1TimeFormat.isValidUTCTime(b("")));                  // empty

        // embedded control byte where seconds digits are expected
        byte[] ctrl = b("240101000000Z");
        ctrl[10] = 0x07;
        assertFalse(ASN1TimeFormat.isValidUTCTime(ctrl));

        // high (negative) byte where a digit is expected
        byte[] high = b("240101000000Z");
        high[5] = (byte)0xFF;
        assertFalse(ASN1TimeFormat.isValidUTCTime(high));
    }

    public void testValidGeneralizedTime()
    {
        assertTrue(ASN1TimeFormat.isValidGeneralizedTime(b("2024010100Z")));          // hour only, Z
        assertTrue(ASN1TimeFormat.isValidGeneralizedTime(b("202401010000Z")));        // minute, Z
        assertTrue(ASN1TimeFormat.isValidGeneralizedTime(b("20240101000000Z")));      // second, Z
        assertTrue(ASN1TimeFormat.isValidGeneralizedTime(b("20240101000000.5Z")));    // fractional '.'
        assertTrue(ASN1TimeFormat.isValidGeneralizedTime(b("20240101000000,123Z")));  // fractional ','
        assertTrue(ASN1TimeFormat.isValidGeneralizedTime(b("20240101000000+05")));    // numeric offset (no minutes)
        assertTrue(ASN1TimeFormat.isValidGeneralizedTime(b("20240101000000+0500")));  // numeric offset
        assertTrue(ASN1TimeFormat.isValidGeneralizedTime(b("20240101000000+0530")));  // numeric offset
        assertTrue(ASN1TimeFormat.isValidGeneralizedTime(b("20240101000000")));       // local, full
        assertTrue(ASN1TimeFormat.isValidGeneralizedTime(b("2024010100")));           // local, hour only
        assertTrue(ASN1TimeFormat.isValidGeneralizedTime(b("19500101000000Z")));
    }

    public void testInvalidGeneralizedTimeFieldRanges()
    {
        assertFalse(ASN1TimeFormat.isValidGeneralizedTime(b("20240001000000Z")));     // month 00
        assertFalse(ASN1TimeFormat.isValidGeneralizedTime(b("20241301000000Z")));     // month 13
        assertFalse(ASN1TimeFormat.isValidGeneralizedTime(b("20240132000000Z")));     // day 32
        assertFalse(ASN1TimeFormat.isValidGeneralizedTime(b("2024010124Z")));         // hour 24
        assertFalse(ASN1TimeFormat.isValidGeneralizedTime(b("202401010060Z")));       // minute 60
        assertFalse(ASN1TimeFormat.isValidGeneralizedTime(b("20240101000060Z")));     // second 60
    }

    public void testInvalidGeneralizedTimeStructure()
    {
        assertFalse(ASN1TimeFormat.isValidGeneralizedTime(b("202401010")));           // length 9 < 10
        assertFalse(ASN1TimeFormat.isValidGeneralizedTime(b("20240101000000.")));     // decimal mark, no digits
        assertFalse(ASN1TimeFormat.isValidGeneralizedTime(b("2024010100ZZ")));        // trailing junk after Z
        assertFalse(ASN1TimeFormat.isValidGeneralizedTime(b("20240101000000X")));     // bad trailing
        assertFalse(ASN1TimeFormat.isValidGeneralizedTime(b("20240101000000+1")));    // truncated offset (no minutes)
        assertFalse(ASN1TimeFormat.isValidGeneralizedTime(b("20240101000000+123")));  // truncated offset

        byte[] ctrl = b("20240101000000Z");
        ctrl[6] = 0x00;
        assertFalse(ASN1TimeFormat.isValidGeneralizedTime(ctrl));
    }

    /**
     * Exact content octets (tag/length stripped) of inputs from the fuzzing
     * report that BC parses today; every one must now be rejected.
     */
    public void testRejectsReportedCorpusContent()
    {
        // 170d 3030303030303030303030305a  -> "000000000000Z" -> today: Date 1999-11-30
        assertFalse(ASN1TimeFormat.isValidUTCTime(b("000000000000Z")));
        // 170d 3030303230303030303030305a  -> "000200000000Z" -> today: Date 2000-01-31
        assertFalse(ASN1TimeFormat.isValidUTCTime(b("000200000000Z")));
        // 180f 303430303031303030303030303030 -> "040001000000000" -> today: Date 399
        assertFalse(ASN1TimeFormat.isValidGeneralizedTime(b("040001000000000")));
        // 180f 30343030303130303030303030302e -> "04000100000000." -> today: getDate() throws
        assertFalse(ASN1TimeFormat.isValidGeneralizedTime(b("04000100000000.")));
        // 180f 3034303030313030303030303030302a-derived "04000100000000*" (control/punct tail)
        assertFalse(ASN1TimeFormat.isValidGeneralizedTime(b("04000100000000*")));
    }
}

package org.bouncycastle.asn1;

import org.bouncycastle.util.Properties;

/**
 * Strict well-formedness checks for the character content of ASN.1
 * {@link ASN1UTCTime} ({@code UTCTime}) and {@link ASN1GeneralizedTime}
 * ({@code GeneralizedTime}) values.
 * <p>
 * BC parses time values leniently (see {@code ASN1UTCTime(byte[])} /
 * {@code ASN1GeneralizedTime(byte[])}, which only check that the leading
 * year digits are present): any byte sequence whose first two/four bytes are
 * digits is accepted, so control characters, out-of-range fields and stray
 * trailing bytes survive into a parsed object, and {@code getDate()} then
 * either yields a nonsensical {@link java.util.Date} (via the lenient
 * {@code SimpleDateFormat}/{@code Calendar} rollover) or throws.
 * <p>
 * These helpers validate the <i>structure</i> of the content against the legal
 * forms of X.680 sec. 46 (GeneralizedTime) / sec. 47 (UTCTime) — i.e. the full
 * set of encodings BC reads, not just the DER-restricted form checked by
 * {@code ASN1UTCTime.isDERUTCTime}. A value rejected here could never denote a
 * real instant; a value accepted here is well-formed but is not guaranteed to
 * be DER (use the {@code Properties.ASN1_ALLOW_NON_DER_TIME} write-side gate for
 * that). The day is checked against the length of the month it names, February
 * included, so the 30th of February is refused rather than read back as the 2nd
 * of March; setting {@code Properties.ASN1_ALLOW_NON_DER_TIME} admits such a day
 * for a caller that has to read what the JDK's own CertificateFactory accepts.
 * <p>
 * Field ranges enforced: month 01-12, day 01 to the length of the month, hour 00-23, minute 00-59,
 * second 00-59 (ASN.1 time does not represent leap seconds), and, for a numeric
 * zone offset, offset-hours 00-23 and offset-minutes 00-59 (a loose structural
 * bound, not a UTC-offset policy). The year is range-unrestricted.
 * <p>
 * This class is a JCA-free, lightweight helper; it performs no parsing or
 * allocation and does not change any existing parse behaviour.
 */
class ASN1TimeFormat
{
    private ASN1TimeFormat()
    {
    }

    /**
     * Validate the content bytes of a {@code UTCTime}.
     * <p>
     * Legal forms (X.680 sec. 47.3): {@code YYMMDDHHMMZ},
     * {@code YYMMDDHHMMSSZ}, {@code YYMMDDHHMM(+|-)HHMM},
     * {@code YYMMDDHHMMSS(+|-)HHMM}. A zone (either {@code Z} or a numeric
     * offset) is mandatory - item c) of the clause - unlike GeneralizedTime,
     * where a zone-less local time is legal. The one zone-less UTCTime BC will
     * decode, and only on request, is covered by {@link #isZoneLessUTCTime(byte[])}.
     *
     * @param contents the raw content octets (ASCII), as held by {@link ASN1UTCTime}.
     * @return true iff {@code contents} is a structurally valid UTCTime value.
     */
    static boolean isValidUTCTime(byte[] contents)
    {
        int len = contents.length;
        if (len != 11 && len != 13 && len != 15 && len != 17)
        {
            return false;
        }
        // YYMMDDHHMM is always the first ten characters (month at offset 2), and
        // for UTCTime the minute at offset 8 is always present.
        if (!isDigits(contents, 0, 10)
            || !validMonthDayHour(contents, 2)
            || twoDigit(contents, 8) > 59)
        {
            return false;
        }

        switch (len)
        {
        case 11:
            return contents[10] == 'Z';
        case 13:
            return validSeconds(contents, 10) && contents[12] == 'Z';
        case 15:
            return isZoneOffsetHHMM(contents, 10);
        case 17:
            return validSeconds(contents, 10) && isZoneOffsetHHMM(contents, 12);
        default:
            return false;
        }
    }

    /**
     * Is this the zone-less {@code YYMMDDHHMMSS} UTCTime?
     * <p>
     * The value is <b>not</b> a legal UTCTime - X.680 sec. 47.3 makes the zone
     * mandatory - so {@link #isValidUTCTime(byte[])} rejects it and BC does not
     * decode it by default. It is singled out here because it is the one
     * zone-less form BC can make sense of and the one found in the field, in CMS
     * signing-time attributes among others (github #2411):
     * {@link ASN1UTCTime#getTime()} carries an explicit branch that reads a
     * zone-less value as GMT, so twelve digits denote a real instant and
     * re-encode unchanged. Setting {@code Properties.ASN1_ALLOW_ZONELESS_UTCTIME}
     * admits exactly this form, and nothing else.
     * <p>
     * The zone-less {@code YYMMDDHHMM} (no seconds) is deliberately not included:
     * {@code getTime()}'s branch indexes twelve characters unconditionally, so a
     * ten-character value has never yielded a date, only a
     * {@code StringIndexOutOfBoundsException}.
     *
     * @param contents the raw content octets (ASCII), as held by {@link ASN1UTCTime}.
     * @return true iff {@code contents} is a well-formed zone-less UTCTime.
     */
    static boolean isZoneLessUTCTime(byte[] contents)
    {
        return contents.length == 12
            && isDigits(contents, 0, 10)
            && validMonthDayHour(contents, 2)
            && twoDigit(contents, 8) <= 59
            && validSeconds(contents, 10);
    }

    /**
     * Validate the content bytes of a {@code GeneralizedTime}.
     * <p>
     * Legal forms (X.680 sec. 46): {@code YYYYMMDDHH} followed by an optional
     * {@code MM} and optional {@code SS}, an optional fractional part
     * ({@code .} or {@code ,} then one or more digits), and an optional zone
     * (nothing for local time, {@code Z}, or a numeric {@code (+|-)HHMM} offset).
     *
     * @param contents the raw content octets (ASCII), as held by {@link ASN1GeneralizedTime}.
     * @return true iff {@code contents} is a structurally valid GeneralizedTime value.
     */
    static boolean isValidGeneralizedTime(byte[] contents)
    {
        int len = contents.length;
        // Minimum is YYYYMMDDHH.
        if (len < 10)
        {
            return false;
        }
        // YYYYMMDDHH is the first ten characters (month at offset 4); minute and
        // second are optional and validated by the scan below.
        if (!isDigits(contents, 0, 10) || !validMonthDayHour(contents, 4))
        {
            return false;
        }

        int idx = 10;

        // Optional minutes, and (only if minutes present) optional seconds.
        if (twoDigitsAt(contents, idx))
        {
            if (twoDigit(contents, idx) > 59)
            {
                return false;
            }
            idx += 2;
            if (twoDigitsAt(contents, idx))
            {
                if (twoDigit(contents, idx) > 59)
                {
                    return false;
                }
                idx += 2;
            }
        }

        // Optional fractional part on the least significant element present.
        if (idx < len && (contents[idx] == '.' || contents[idx] == ','))
        {
            int frac = idx + 1;
            idx = frac;
            while (idx < len && isDigit(contents[idx]))
            {
                idx++;
            }
            if (idx == frac)
            {
                return false;   // the decimal mark must be followed by at least one digit
            }
        }

        // Optional zone: end-of-string (local time), 'Z', or a numeric offset.
        if (idx == len)
        {
            return true;
        }
        if (contents[idx] == 'Z')
        {
            return idx + 1 == len;
        }
        return isZoneOffsetHHMM(contents, idx)
            || isZoneOffsetHH(contents, idx);
    }

    /**
     * Validate the mandatory month/day/hour fields. {@code monthOff} is the
     * absolute offset of the first month digit: 2 for UTCTime (two-digit year),
     * 4 for GeneralizedTime (four-digit year). The minute field is mandatory for
     * UTCTime but optional for GeneralizedTime, so it is checked by the callers
     * rather than here.
     */
    private static boolean validMonthDayHour(byte[] c, int monthOff)
    {
        int month = twoDigit(c, monthOff);
        int day = twoDigit(c, monthOff + 2);
        int hour = twoDigit(c, monthOff + 4);

        if (month < 1 || month > 12 || day < 1 || hour > 23)
        {
            return false;
        }

        if (day > daysInMonth(month, yearAt(c, monthOff)))
        {
            // the property admits the day the lenient calendar behind getDate() would roll away
            return Properties.isOverrideSet(Properties.ASN1_ALLOW_NON_DER_TIME);
        }

        return true;
    }

    /**
     * The year this value names, a UTCTime's two digits read through the RFC 5280 sec. 4.1.2.5.1
     * window (50-99 are 19xx, 00-49 are 20xx) as ASN1UTCTime reads them.
     */
    private static int yearAt(byte[] c, int monthOff)
    {
        if (monthOff == 2)
        {
            int year = twoDigit(c, 0);

            return (year >= 50) ? 1900 + year : 2000 + year;
        }

        return twoDigit(c, 0) * 100 + twoDigit(c, 2);
    }

    /**
     * Length of the month, February taking the Gregorian leap rule proleptically as ISO 8601 does,
     * so the 29th of February 1500 - a Julian date GregorianCalendar still accepts - is not a day.
     */
    private static int daysInMonth(int month, int year)
    {
        switch (month)
        {
        case 2:
            return isLeapYear(year) ? 29 : 28;
        case 4:
        case 6:
        case 9:
        case 11:
            return 30;
        default:
            return 31;
        }
    }

    private static boolean isLeapYear(int year)
    {
        return (year % 4) == 0 && ((year % 100) != 0 || (year % 400) == 0);
    }

    private static boolean validSeconds(byte[] c, int off)
    {
        return twoDigitsAt(c, off) && twoDigit(c, off) <= 59;
    }

    /**
     * A {@code Z}-less numeric zone offset {@code (+|-)HH} occupying exactly the remainder of the content.
     */
    private static boolean isZoneOffsetHH(byte[] c, int off)
    {
        if (off + 3 == c.length)
        {
            if (c[off] != '+' && c[off] != '-')
            {
                return false;
            }
            if (!twoDigitsAt(c, off + 1))
            {
                return false;
            }
            return twoDigit(c, off + 1) <= 14;
        }

        return false;
    }

    /**
     * A {@code Z}-less numeric zone offset {@code {@code (+|-)HHMM} occupying exactly the remainder of the content.
     */
    private static boolean isZoneOffsetHHMM(byte[] c, int off)
    {
        if (off + 5 == c.length)
        {
            if (c[off] != '+' && c[off] != '-')
            {
                return false;
            }
            if (!isDigits(c, off + 1, 4))
            {
                return false;
            }
            return twoDigit(c, off + 1) <= 14 && twoDigit(c, off + 3) <= 59;
        }

        return false;
    }

    private static boolean twoDigitsAt(byte[] c, int off)
    {
        return off + 2 <= c.length && isDigit(c[off]) && isDigit(c[off + 1]);
    }

    private static boolean isDigits(byte[] c, int off, int count)
    {
        if (off + count > c.length)
        {
            return false;
        }
        for (int i = 0; i < count; i++)
        {
            if (!isDigit(c[off + i]))
            {
                return false;
            }
        }
        return true;
    }

    private static boolean isDigit(byte b)
    {
        return b >= '0' && b <= '9';
    }

    private static int twoDigit(byte[] c, int off)
    {
        // Callers guarantee c[off] and c[off+1] are ASCII digits.
        return (c[off] - '0') * 10 + (c[off + 1] - '0');
    }
}

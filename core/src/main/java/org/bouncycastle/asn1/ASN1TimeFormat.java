package org.bouncycastle.asn1;

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
 * that) and is not calendar-checked beyond per-field ranges (e.g. day 01-31 is
 * accepted without regard to the month, matching the granularity of a
 * structural check rather than a full date validation).
 * <p>
 * Field ranges enforced: month 01-12, day 01-31, hour 00-23, minute 00-59,
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
     * offset) is mandatory.
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
        return month >= 1 && month <= 12
            && day >= 1 && day <= 31
            && hour <= 23;
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

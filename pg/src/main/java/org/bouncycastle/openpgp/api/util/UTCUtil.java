package org.bouncycastle.openpgp.api.util;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

public class UTCUtil
{
    private static SimpleDateFormat utc()
    {
        // Java's SimpleDateFormat is not thread-safe, therefore we return a new instance on every invocation.
        // See https://stackoverflow.com/a/6840856/11150851
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        return format;
    }

    /**
     * Format a {@link Date} as UTC timestamp.
     *
     * @param timestamp date
     * @return formatted timestamp
     */
    public static String format(Date timestamp)
    {
        return utc().format(timestamp);
    }

    /**
     * Parse a UTC timestamp.
     * The timestamp needs to be provided in the form 'yyyy-MM-dd HH:mm:ss z'.
     *
     * @param utcTimestamp timestamp
     * @return date
     */
    public static Date parse(String utcTimestamp)
    {
        try
        {
            return utc().parse(utcTimestamp);
        }
        catch (ParseException e)
        {
            throw new IllegalArgumentException("Malformed UTC timestamp: " + utcTimestamp, e);
        }
    }
}

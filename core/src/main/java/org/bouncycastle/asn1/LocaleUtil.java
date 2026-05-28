package org.bouncycastle.asn1;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import org.bouncycastle.util.Longs;

/**
 * ASN.1 uses an EN locale for its internal formatting. This class finds the nearest equivalent in the
 * current JVM to ensure date formats are always respected.
 */
public class LocaleUtil
{
    private static final Map localeCache = new HashMap();

    public static Locale EN_Locale = forEN();

    private static Locale forEN()
    {
        if ("en".equalsIgnoreCase(Locale.getDefault().getLanguage()))
        {
            return Locale.getDefault();
        }
        
        Locale[] locales = Locale.getAvailableLocales();
        for (int i = 0; i != locales.length; i++)
        {
            if ("en".equalsIgnoreCase(locales[i].getLanguage()))
            {
                return locales[i];
            }
        }

        return Locale.getDefault();
    }

    static Date epochAdjust(Date date)
        throws ParseException
    {
        Locale locale = Locale.getDefault();
        if (locale == null)
        {
            return date;
        }

        synchronized (localeCache)
        {
            Long adj = (Long)localeCache.get(locale);

            if (adj == null)
            {
                // The SimpleDateFormat is intentionally constructed without an explicit
                // Locale: this method's job is to detect a per-locale calendar offset
                // (e.g. Thai Buddhist year + 543, Japanese Imperial era) and the only way
                // to do that is to parse "1970-01-01" under the default locale's calendar.
                // Forcing LocaleUtil.EN_Locale here would always return epoch and disable
                // the detection entirely. Do not "fix" by adding a Locale argument.
                SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmssz");
                long v = dateF.parse("19700101000000GMT+00:00").getTime();

                adj = longValueOf(v);

                localeCache.put(locale, adj);
            }

            if (adj.longValue() != 0L)
            {
                return new Date(date.getTime() - adj.longValue());
            }

            return date;
        }
    }

    private static Long longValueOf(long v)
    {
        return Longs.valueOf(v);
    }
}

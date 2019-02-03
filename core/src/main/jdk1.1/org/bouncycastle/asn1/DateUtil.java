package org.bouncycastle.asn1;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

class DateUtil
{
    private static Long ZERO = longValueOf(0);

    private static final Map localeCache = new HashMap();

    static Locale EN_Locale = forEN();

    private static Locale forEN()
    {
        if ("en".equalsIgnoreCase(Locale.getDefault().getLanguage()))
        {
            return Locale.getDefault();
        }
        
/*
        Locale[] locales = Locale.getAvailableLocales();
        for (int i = 0; i != locales.length; i++)
        {
            if ("en".equalsIgnoreCase(locales[i].getLanguage()))
            {
                return locales[i];
            }
        }
*/

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
                SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmssz");
                long v = dateF.parse("19700101000000GMT+00:00").getTime();

                if (v == 0)
                {
                    adj = ZERO;
                }
                else
                {
                    adj = longValueOf(v);
                }

                localeCache.put(locale, adj);
            }

            if (adj != ZERO)
            {
                return new Date(date.getTime() - adj.longValue());
            }

            return date;
        }
    }

    private static Long longValueOf(long v)
    {
        return new Long(v);
    }
}

package org.bouncycastle.asn1.test;

import java.text.DateFormat;
import java.util.Date;
import java.util.Locale;

import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.util.test.SimpleTest;

public class LocaleTest
    extends SimpleTest
{
    public String getName()
    {
        return "LocaleTest";
    }

    private void doTestLocale(Locale l)
        throws Exception
    {
        long time = 1538063166000L;
        String timeString = "180927154606GMT+00:00";
        String longTimeString = "20180927154606Z";

        Locale.setDefault(l);

        isTrue("a", time == new DERUTCTime(timeString).getAdjustedDate().getTime());
        isTrue("b", time == new DERGeneralizedTime(longTimeString).getDate().getTime());

        isTrue("c", time == new DERUTCTime(new Date(time)).getAdjustedDate().getTime());
        isTrue("d", time == new DERGeneralizedTime(new Date(time)).getDate().getTime());

        Date d = new Date();

        isTrue("e", (d.getTime() - (d.getTime() % 1000)) == new DERUTCTime(d).getAdjustedDate().getTime());
        isTrue("f", (d.getTime() - (d.getTime() % 1000)) == new DERGeneralizedTime(d).getDate().getTime());
    }

    public void performTest()
        throws Exception
    {
        Locale defLocale = Locale.getDefault();

        Locale list[] = DateFormat.getAvailableLocales();
        for (int i = 0; i != list.length; i++)
        {
            if (!list[i].getCountry().equals("TH")    // skip Thailand as it appears the JVM is now a day out on this one.
             && !list[i].getCountry().equals("JP"))   // and it appears the change in era is causing issues here.
            {
                doTestLocale(list[i]);
            }
        }

        Locale.setDefault(defLocale);
    }

    public static void main(
        String[] args)
    {
        runTest(new LocaleTest());
    }
}

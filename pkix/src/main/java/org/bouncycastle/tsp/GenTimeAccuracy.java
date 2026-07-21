package org.bouncycastle.tsp;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.tsp.Accuracy;

/**
 * Wrapper for the {@code Accuracy} field of an RFC 3161 TSTInfo, expressing the time deviation
 * around the genTime value of a time-stamp token as a seconds / milliseconds / microseconds triple.
 * Components absent from the underlying ASN.1 structure are reported as zero.
 */
public class GenTimeAccuracy
{
    private Accuracy accuracy;

    public GenTimeAccuracy(Accuracy accuracy)
    {
        this.accuracy = accuracy;
    }

    /**
     * @return the whole-seconds component of the accuracy, 0 if not present.
     */
    public int getSeconds()
    {
        return getTimeComponent(accuracy.getSeconds());
    }

    /**
     * @return the milliseconds component of the accuracy, 0 if not present.
     */
    public int getMillis()
    {
        return getTimeComponent(accuracy.getMillis());
    }

    /**
     * @return the microseconds component of the accuracy, 0 if not present.
     */
    public int getMicros()
    {
        return getTimeComponent(accuracy.getMicros());
    }

    private int getTimeComponent(
        ASN1Integer time)
    {
        if (time != null)
        {
            return time.intValueExact();
        }

        return 0;
    }
    
    /**
     * @return a string of the form {@code seconds.millismicros} (e.g. "1.500000").
     */
    public String toString()
    {                               // digits
        return getSeconds() + "." + format(getMillis()) + format(getMicros());
    }

    private String format(int v)
    {
        if (v < 10)
        {
            return "00" + v;
        }

        if (v < 100)
        {
            return "0" + v;
        }

        return Integer.toString(v);
    }
}

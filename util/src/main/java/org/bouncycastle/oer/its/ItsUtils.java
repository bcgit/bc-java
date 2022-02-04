package org.bouncycastle.oer.its;

import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

public class ItsUtils
{

    /**
     * <pre>
     *     OCTET STRING (SIZE(n))
     * </pre>
     */
    public static byte[] octetStringFixed(byte[] octets, int n)
    {
        if (octets.length != n)
        {
            throw new IllegalArgumentException("octet string out of range");
        }

        return octets;
    }

    /**
     * <pre>
     *     OCTET STRING (SIZE(1..32))
     * </pre>
     */
    public static byte[] octetStringFixed(byte[] octets)
    {
        if (octets.length < 1 || octets.length > 32)
        {
            throw new IllegalArgumentException("octet string out of range");
        }

        return Arrays.clone(octets);
    }

    public static ASN1Sequence toSequence(List objs)
    {
        return new DERSequence((ASN1Encodable[])objs.toArray(new ASN1Encodable[0]));
    }

    public static ASN1Sequence toSequence(ASN1Encodable... objs)
    {
        return new DERSequence(objs);
    }

    @Deprecated
    public static <T> List<T> fillList(final Class<T> type, final ASN1Sequence sequence)
    {
        return AccessController.doPrivileged(new PrivilegedAction<List<T>>()
        {
            public List<T> run()
            {
                try
                {
                    List<T> accumulator = new ArrayList<T>();
                    for (Iterator<ASN1Encodable> it = sequence.iterator(); it.hasNext(); )
                    {
                        Method m = type.getMethod("getInstance", Object.class);
                        accumulator.add(type.cast(m.invoke(null, it.next())));
                    }
                    return accumulator;
                }
                catch (Exception ex)
                {
                    throw new IllegalStateException("could not invoke getInstance on type " + ex.getMessage(), ex);
                }
            }
        });
    }
}

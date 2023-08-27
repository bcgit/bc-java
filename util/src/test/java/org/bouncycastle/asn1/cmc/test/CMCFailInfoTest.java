package org.bouncycastle.asn1.cmc.test;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cmc.CMCFailInfo;
import org.bouncycastle.util.Longs;
import org.bouncycastle.util.test.SimpleTest;

public class CMCFailInfoTest
    extends SimpleTest
{

    // From Page 68, CMC: Structures RFC 5272
    private static Object[][] types = new Object[][]
    {
        {"badAlg", Longs.valueOf(0L) },
        {"badMessageCheck", Longs.valueOf(1L) },
        {"badRequest", Longs.valueOf(2L) },
        {"badTime", Longs.valueOf(3L) },
        {"badCertId", Longs.valueOf(4L) },
        {"unsupportedExt", Longs.valueOf(5L) },
        {"mustArchiveKeys", Longs.valueOf(6L) },
        {"badIdentity", Longs.valueOf(7L) },
        {"popRequired", Longs.valueOf(8L) },
        {"popFailed", Longs.valueOf(9L) },
        {"noKeyReuse", Longs.valueOf(10L) },
        {"internalCAError", Longs.valueOf(11L) },
        {"tryLater", Longs.valueOf(12L) },
        {"authDataFail", Longs.valueOf(13L)}
    };
    private static Map typesMap = new HashMap();

    static
    {
        for (int t = 0; t < types.length; t++)
        {
            typesMap.put(types[t][1], types[t][0]);
        }
    }


    public void performTest()
        throws Exception
    {

        //
        // Check that range has changed and this test has not been updated or vice versa.
        // It is intended to act as a double check on the addition of CMCFailInfo presets by
        // requiring this test to be updated equally to ensure it will pass.
        //

        Field rangeField = CMCFailInfo.class.getDeclaredField("range");
        rangeField.setAccessible(true);

        Map range = (Map)rangeField.get(null);

        isEquals("Range in CMCFailInfo does not match test data.",range.size(), types.length);

        for (Iterator rangeKeys = range.keySet().iterator(); rangeKeys.hasNext(); )
        {
            Object j = rangeKeys.next();
            if (!typesMap.containsKey(Longs.valueOf(((ASN1Integer)j).getValue().longValue())))
            {
                fail("The 'range' map in CMCFailInfo contains a value not in the test ('typesMap') map, value was: " + j.toString());
            }
        }


        for (Iterator typeKeys = typesMap.keySet().iterator(); typeKeys.hasNext(); )
        {
            Object j = typeKeys.next();
            if (!range.containsKey(new ASN1Integer(((Long)j).longValue())))
            {
                fail("The 'typesMap' map in CMCFailInfoTest contains a value not in the CMCFailInfo ('range') map, value was: " + j.toString());
            }
        }


        //
        // Test encoding / decoding
        //

        byte[] b = CMCFailInfo.authDataFail.getEncoded();
        CMCFailInfo r = CMCFailInfo.getInstance(b);
        isEquals(r,CMCFailInfo.authDataFail);

    }

    public String getName()
    {
        return "CMCFailInfoTest";
    }

    public static void main(String[] args)
    {
        runTest(new CMCFailInfoTest());
    }
}

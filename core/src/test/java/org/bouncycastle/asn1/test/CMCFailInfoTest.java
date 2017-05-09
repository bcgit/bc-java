package org.bouncycastle.asn1.test;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cmc.CMCFailInfo;
import org.bouncycastle.util.test.SimpleTest;

public class CMCFailInfoTest
    extends SimpleTest
{

    // From Page 68, CMC: Structures RFC 5272
    private static Object[][] types = new Object[][]{
        {"badAlg", new Long(0L) },
        {"badMessageCheck", new Long(1L) },
        {"badRequest", new Long(2L) },
        {"badTime", new Long(3L) },
        {"badCertId", new Long(4L) },
        {"unsupportedExt", new Long(5L) },
        {"mustArchiveKeys", new Long(6L) },
        {"badIdentity", new Long(7L) },
        {"popRequired", new Long(8L) },
        {"popFailed", new Long(9L) },
        {"noKeyReuse", new Long(10L) },
        {"internalCAError", new Long(11L) },
        {"tryLater", new Long(12L) },
        {"authDataFail", new Long(13L)}
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
        {   Object j = rangeKeys.next();
            if (!typesMap.containsKey(new Long(((ASN1Integer)j).getValue().longValue())))  {
                fail("The 'range' map in CMCFailInfo contains a value not in the test ('typesMap') map, value was: "+j.toString());
            }
        }


        for (Iterator typeKeys = typesMap.keySet().iterator(); typeKeys.hasNext(); )
        {   Object j = typeKeys.next();
            if (!range.containsKey(new ASN1Integer(((Long)j).longValue())))  {
                fail("The 'typesMap' map in CMCFailInfoTest contains a value not in the CMCFailInfo ('range') map, value was: "+j.toString());
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

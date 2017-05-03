package org.bouncycastle.asn1.test;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cmc.CMCStatus;
import org.bouncycastle.util.test.SimpleTest;


public class CMCStatusTest
    extends SimpleTest
{

    public static void main(String[] args)
    {
        runTest(new CMCStatusTest());
    }

    public String getName()
    {
        return "CMCStatusTest";
    }

    // From Page 68, CMC: Structures RFC 5272
    private static Object[][] types = new Object[][]{
        {"success", new Long(0L) },
        // -- reserved            (1),
        {"failed", new Long(2L) },
        {"pending", new Long(3L) },
        {"noSupport", new Long(4L) },
        {"confirmRequired", new Long(5L) },
        {"popRequired", new Long(6L) },
        {"partial", new Long(7L) }
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
        // It is intended to act as a double check on the addition of CMCStatus presets by
        // requiring this test to be updated equally to ensure it will pass.
        //

        Field rangeField = CMCStatus.class.getDeclaredField("range");
        rangeField.setAccessible(true);

        Map range = (Map)rangeField.get(null);

        isEquals("Range in CMCStatus does not match test data.", range.size(), types.length);

        for (Iterator rangeKeys = range.keySet().iterator(); rangeKeys.hasNext(); )
        {
            Object j = rangeKeys.next();
            if (!typesMap.containsKey(new Long(((ASN1Integer)j).getValue().longValue())))
            {
                fail("The 'range' map in CMCStatus contains a value not in the test ('typesMap') map, value was: " + j.toString());
            }
        }


        for (Iterator typeKeys = typesMap.keySet().iterator(); typeKeys.hasNext(); )
        {
            Object j = typeKeys.next();
            if (!range.containsKey(new ASN1Integer(((Long)j).longValue())))
            {
                fail("The 'typesMap' map in CMCStatusTest contains a value not in the CMCStatus ('range') map, value was: " + j.toString());
            }
        }


        //
        // Test encoding / decoding
        //

        byte[] b = CMCStatus.failed.getEncoded();
        CMCStatus r = CMCStatus.getInstance(b);
        isEquals(r, CMCStatus.failed);

    }

}

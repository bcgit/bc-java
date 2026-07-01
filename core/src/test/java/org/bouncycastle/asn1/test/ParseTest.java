package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.util.test.SimpleTest;

public class ParseTest extends SimpleTest
{
    public String getName()
    {
        return "ParseTest";
    }

    public void performTest() throws Exception
    {
        testEmptyInputRejectedCleanly();
    }

    private void testEmptyInputRejectedCleanly()
    {
        // Regression: input that decodes to no object must not leak a NullPointerException
        // (primitive.getClass() via ASN1UniversalType.checkedCast) — it must report a clean
        // parse error. Empty input is the minimal trigger.
        try
        {
            ASN1Sequence.getInstance((Object)new byte[0]);
            fail("No exception thrown");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }

        try
        {
            ASN1TaggedObject.getInstance((Object)new byte[0]);
            fail("No exception thrown");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    public static void main(String[] args)
    {
        runTest(new ParseTest());
    }
}

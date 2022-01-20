package org.bouncycastle.openpgp.test;

import java.util.Arrays;

import org.bouncycastle.bcpg.sig.RegularExpression;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;

public class RegexTest
    extends SimpleTest
{
    public String getName()
    {
        return "RegexTest";
    }

    public void performTest()
        throws Exception
    {
        testRegexGetRegex();
        testRegexBytesAreNullTerminated();
        testCopy();
        testDoNotTolerateNonNullTerminatedStrings();
    }

    public void testRegexGetRegex()
    {
        String regexString = "example.org";
        RegularExpression regex = new RegularExpression(false, regexString);
        isEquals(regexString, regex.getRegex());
    }

    public void testRegexBytesAreNullTerminated()
    {
        String regexString = "example.org";
        RegularExpression regex = new RegularExpression(false, regexString);
        byte[] regexBytes = regex.getRawRegex();
        isTrue(regexBytes[regexBytes.length - 1] == 0);
    }

    public void testCopy()
    {
        String regexString = "openpgp.rocks";
        RegularExpression regex1 = new RegularExpression(false, regexString);
        RegularExpression regex2 = new RegularExpression(regex1.isCritical(), regex1.isLongLength(), regex1.getData());

        isEquals(regex1.isCritical(), regex2.isCritical());
        isEquals(regex1.isLongLength(), regex2.isLongLength());
        isEquals(regex1.getRegex(), regex2.getRegex());
        isTrue(Arrays.equals(regex1.getRawRegex(), regex2.getRawRegex()));
    }

    public void testDoNotTolerateNonNullTerminatedStrings()
    {
        String regexString = "rfc.4880";
        byte[] nonNullTerminated = Strings.toUTF8ByteArray(regexString);

        try
        {
            RegularExpression regex = new RegularExpression(false, false, nonNullTerminated);
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("data in regex missing null termination", e.getMessage());
        }
    }

    public static void main(String[] args)
        throws Exception
    {
        runTest(new RegexTest());
    }
}

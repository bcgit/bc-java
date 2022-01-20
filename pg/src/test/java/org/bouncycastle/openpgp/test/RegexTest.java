package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.sig.RegularExpression;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.SimpleTest;

import java.util.Arrays;

public class RegexTest
    extends SimpleTest
{

    @Override
    public String getName()
    {
        return RegexTest.class.getSimpleName();
    }

    @Override
    public void performTest() throws Exception
    {
        testRegexGetRegex();
        testRegexBytesAreNullTerminated();
        testCopy();
        testDoesNotTolerateNonNullTerminatedData();
    }

    public void testRegexGetRegex()
    {
        String regexString = "example.org";
        RegularExpression regex = new RegularExpression(false , regexString);
        isEquals(regexString, regex.getRegex());
    }

    public void testRegexBytesAreNullTerminated()
    {
        String regexString = "example.org";
        RegularExpression regex = new RegularExpression(false , regexString);
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

    public void testDoesNotTolerateNonNullTerminatedData()
    {
        String regexString = "rfc.4880";
        byte[] nonNullTerminated = Strings.toUTF8ByteArray(regexString);
        try {
            RegularExpression regex = new RegularExpression(false, false, nonNullTerminated);
            regex.getRegex();
            fail("Expected IllegalArgumentException for non-null terminated data.");
        } catch (IllegalArgumentException e) {
            // Expected
        }
    }

    public static void main(String[] args) throws Exception
    {
        runTest(new RegexTest());
    }

}

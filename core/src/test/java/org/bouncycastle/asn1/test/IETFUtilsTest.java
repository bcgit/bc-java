package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.util.test.SimpleTest;

public class IETFUtilsTest
    extends SimpleTest
{
    public String getName()
    {
        return "IETFUtils";
    }

    public void performTest()
        throws Exception
    {
        testValueToString();
    }

    private void testValueToString()
        throws Exception
    {
        IETFUtils.valueToString(new DERUTF8String(" "));

        // RFC 4514 escaping - also a regression guard for the linear (non O(n^2)) valueToString.
        isEquals("plain", "abc", IETFUtils.valueToString(new DERUTF8String("abc")));
        isEquals("comma", "a\\,b", IETFUtils.valueToString(new DERUTF8String("a,b")));
        isEquals("all specials", "\\,\\\"\\\\\\+\\=\\<\\>\\;",
            IETFUtils.valueToString(new DERUTF8String(",\"\\+=<>;")));
        isEquals("leading space", "\\ ab", IETFUtils.valueToString(new DERUTF8String(" ab")));
        isEquals("trailing space", "ab\\ ", IETFUtils.valueToString(new DERUTF8String("ab ")));
        isEquals("leading+trailing space", "\\ ab\\ ", IETFUtils.valueToString(new DERUTF8String(" ab ")));
        isEquals("all spaces", "\\ \\ \\ ", IETFUtils.valueToString(new DERUTF8String("   ")));
        isEquals("interior space kept", "a b", IETFUtils.valueToString(new DERUTF8String("a b")));
        isEquals("leading hash", "\\#abc", IETFUtils.valueToString(new DERUTF8String("#abc")));
        isEquals("non-leading hash kept", "a#b", IETFUtils.valueToString(new DERUTF8String("a#b")));

        // A large all-special value must escape every character and complete in linear time (the
        // previous insert-into-the-buffer-being-scanned loop was O(n^2)).
        int n = 100000;
        StringBuilder commas = new StringBuilder(n);
        for (int i = 0; i < n; i++)
        {
            commas.append(',');
        }
        String escaped = IETFUtils.valueToString(new DERUTF8String(commas.toString()));
        isEquals("large all-comma value fully escaped", 2 * n, escaped.length());
    }

    public static void main(String[] args)
    {
        runTest(new IETFUtilsTest());
    }
}

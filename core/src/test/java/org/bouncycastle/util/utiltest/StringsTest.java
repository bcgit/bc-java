package org.bouncycastle.util.utiltest;

import junit.framework.TestCase;
import org.bouncycastle.util.Strings;

public class StringsTest
    extends TestCase
{
    public void testSplitWithLeadingDelimiter()
    {
        String[] parts = Strings.split(".permitted", '.');
        assertEquals(2, parts.length);
        assertEquals("", parts[0]);
        assertEquals("permitted", parts[1]);
    }

    public void testSplitDomainWithLeadingDot()
    {
        String[] parts = Strings.split(".example.domain.com", '.');
        assertEquals(4, parts.length);
        assertEquals("", parts[0]);
        assertEquals("example", parts[1]);
        assertEquals("domain", parts[2]);
        assertEquals("com", parts[3]);
    }

    public void testSplitNormalDomain()
    {
        String[] parts = Strings.split("example.domain.com", '.');
        assertEquals(3, parts.length);
        assertEquals("example", parts[0]);
        assertEquals("domain", parts[1]);
        assertEquals("com", parts[2]);
    }

    public void testSplitNoDelimiter()
    {
        String[] parts = Strings.split("nodots", '.');
        assertEquals(1, parts.length);
        assertEquals("nodots", parts[0]);
    }

    public void testSplitTrailingDelimiter()
    {
        String[] parts = Strings.split("trailing.", '.');
        assertEquals(2, parts.length);
        assertEquals("trailing", parts[0]);
        assertEquals("", parts[1]);
    }

    public void testSplitOnlyDelimiter()
    {
        String[] parts = Strings.split(".", '.');
        assertEquals(2, parts.length);
        assertEquals("", parts[0]);
        assertEquals("", parts[1]);
    }

    public void testSplitConsecutiveDelimiters()
    {
        String[] parts = Strings.split("a..b", '.');
        assertEquals(3, parts.length);
        assertEquals("a", parts[0]);
        assertEquals("", parts[1]);
        assertEquals("b", parts[2]);
    }
}

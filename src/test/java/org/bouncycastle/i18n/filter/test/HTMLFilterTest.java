package org.bouncycastle.i18n.filter.test;

import org.bouncycastle.i18n.filter.Filter;
import org.bouncycastle.i18n.filter.HTMLFilter;

import junit.framework.TestCase;

public class HTMLFilterTest extends TestCase
{

    private static final String test1 = "hello world";

    private static final String test2 = "<script></script>";

    private static final String test3 = "javascript:attack()";

    private static final String test4 = "\"hello\"";

    public void testDoFilter()
    {
        Filter dummy = new HTMLFilter();

        assertEquals("No filtering", "hello world", dummy.doFilter(test1));
        assertEquals("script tags", "&#60script&#62&#60/script&#62", dummy.doFilter(test2));
        assertEquals("javascript link", "javascript:attack&#40&#41", dummy.doFilter(test3));
        assertEquals("", "&#34hello&#34", dummy.doFilter(test4));
    }

}


package org.bouncycastle.i18n.filter.test;

import org.bouncycastle.i18n.filter.Filter;
import org.bouncycastle.i18n.filter.SQLFilter;

import junit.framework.TestCase;

public class SQLFilterTest extends TestCase 
{

    private static final String test1 = "\'\"=-/\\;\r\n";

    public void testDoFilter() 
    {
        Filter filter = new SQLFilter();
        assertEquals("encode special charaters","\\\'\\\"\\=\\-\\/\\\\\\;\\r\\n",filter.doFilter(test1));
    }

}

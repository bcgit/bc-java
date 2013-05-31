
package org.bouncycastle.i18n.test;

import org.bouncycastle.i18n.filter.test.HTMLFilterTest;
import org.bouncycastle.i18n.filter.test.SQLFilterTest;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class AllTests extends TestCase
{

    public static void main (String[] args)
    {
        junit.textui.TestRunner.run (suite());
    }
    
    public static Test suite()
    {
        TestSuite suite = new TestSuite("i18n tests");
        suite.addTestSuite(HTMLFilterTest.class);
        suite.addTestSuite(SQLFilterTest.class);
        return suite;
    }

}

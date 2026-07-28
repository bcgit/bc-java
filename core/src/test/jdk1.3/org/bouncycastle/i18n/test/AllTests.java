
package org.bouncycastle.i18n.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

// NOTE: jdk1.3 overlay. HTMLFilterTest/SQLFilterTest are excluded from the jdk1.3 build (whole
// org.bouncycastle.i18n package, ant/jdk13.xml, mirroring ant/jdk14.xml) so this suite is empty.
public class AllTests extends TestCase
{

    public static void main (String[] args)
    {
        junit.textui.TestRunner.run (suite());
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("i18n tests");
        return suite;
    }

}

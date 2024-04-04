package org.bouncycastle.test;

import junit.framework.TestCase;
import org.junit.Test;

/**
 * This test asserts the java version running the tests starts with
 * a property value passed in as part of test invocation.
 * <p>
 * -Dtest.java.version.prefix must match the start of System.getProperty("java.version")
 * So:
 * if -Dtest.java.version.prefix=17 and System.getProperty("java.version") = 17.0.4.1
 * Then this test will pass.
 */
public class JVMVersionTest
    extends TestCase
{

    private static final String expectedVersionPropName = "test.java.version.prefix";


    @Test
    public void testAssertExpectedJVM()
    {


        //
        // This project produces a multi-release jar, and we need to test it on different jvm versions
        // This test compares a property "test.java.version.prefix" with the start of the value reported by the JVM.
        // eg:
        // -Dtest.java.version.prefix=1.8
        //
        // It exists because we have had issues with build systems unexpectedly using a different JVM to one we need to test on.
        // It is important for multi-release jars to be exercised on a representative JVM for each JVM they support.
        //
        //
        assertNotNull(String.format("property %s is not set, see comment in test for reason why.", expectedVersionPropName), System.getProperty(expectedVersionPropName));


        String version = System.getProperty("java.version");
        String expectedPrefix = System.getProperty(expectedVersionPropName);

        assertTrue(String.format("JVM Version: '%s' did not start with '%s' see comment in test", version, expectedPrefix), version.startsWith(expectedPrefix));


    }

}

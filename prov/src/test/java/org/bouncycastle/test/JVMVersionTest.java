package org.bouncycastle.test;

import junit.framework.TestCase;

/**
 * This test asserts the java version running the tests starts with
 * a property value passed in as part of test invocation.
 * <p>
 * -Dtest.java.version.prefix must match the start of System.getProperty("java.version")
 * So:
 * if -Dtest.java.version.prefix=17 and System.getProperty("java.version") = 17.0.4.1
 * Then this test will pass.
 */
public class JVMVersionTest extends TestCase
{

    private static final String expectedVersionPropName = "test.java.version.prefix";

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

        String version = System.getProperty("java.version");
        assertNotNull(String.format(
            "system property %s is not set. It guards against the tests being run on an unintended JVM: "
                + "set it to the expected java.version prefix (e.g. 1.8, 11, 17), or to 'any' to accept the current JVM. "
                + "The Ant builds set it from the JAVA_VERSION_PREFIX environment variable.",
            expectedVersionPropName), System.getProperty(expectedVersionPropName));


        String expectedPrefix = System.getProperty(expectedVersionPropName);

        if ("any".equals(expectedPrefix))
        {
            TestCase.assertTrue(true);
            return;
        }

        TestCase.assertTrue(String.format(
            "Tests are running on JVM version '%s' but the build expected a JVM whose java.version starts with '%s'. "
                + "The multi-release jars must be tested on a representative JVM for each version they support, so either "
                + "run the build with the expected JDK (e.g. set JDKPATH for build1-8+), or change the expectation to match: "
                + "the Ant builds take it from the JAVA_VERSION_PREFIX environment variable ('any' accepts any JVM).",
            version, expectedPrefix), version.startsWith(expectedPrefix));

    }

}

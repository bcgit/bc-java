package org.bouncycastle.crypto.test;

import junit.framework.TestCase;
import org.junit.Test;


/**
 * "java.version" must start with the value of "test.java.version.prefix" it acts as
 * an interlock to prevent accidental test execution on a different java version to what
 * is expected.
 */
public class JVMAssertionTest extends TestCase
{
    @Test
    public void testVersion() {
        if (!System.getProperty("java.version").startsWith(System.getProperty("test.java.version.prefix"))) {
            System.out.println(System.getProperty("java.version"));
            System.out.println(System.getProperty("test.java.version.prefix"));
        }
        assertTrue(System.getProperty("java.version").startsWith(System.getProperty("test.java.version.prefix")));
    }
}

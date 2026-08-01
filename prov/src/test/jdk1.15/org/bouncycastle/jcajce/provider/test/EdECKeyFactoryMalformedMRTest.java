package org.bouncycastle.jcajce.provider.test;

import java.security.Security;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.test.EdECKeyFactoryMalformedTest;
import org.bouncycastle.util.test.SimpleTestResult;

/**
 * Runs the EdEC KeyFactory malformed-key regression (R-KEYFAC-1) against the multi-release jar so
 * that the JDK 15+ META-INF/versions/15 edec KeyFactorySpi overlay is exercised. That overlay
 * reimplements engineGeneratePublic with the same fixed-offset enc[8..10] fast path as the base
 * class, so the base test in src/test/java (run by the default suite) does not cover it; this
 * catches drift between the overlay and the base length-guard / InvalidKeySpecException contract.
 */
public class EdECKeyFactoryMalformedMRTest
    extends TestCase
{
    public void testMalformedEdECKeysAgainstMultiReleaseJar()
        throws Exception
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        SimpleTestResult result = (SimpleTestResult)new EdECKeyFactoryMalformedTest().perform();

        assertTrue(result.toString(), result.isSuccessful());
    }
}

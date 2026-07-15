package org.bouncycastle.jcajce.provider.test;

import java.security.Security;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.test.OpenSSHSpecTests;
import org.bouncycastle.util.test.SimpleTestResult;

/**
 * Runs the full OpenSSH key-spec suite (KeyFactory round-trips and passphrase-encrypted
 * openssh-key-v1 decoding for RSA/DSA/EC/Ed25519) against the multi-release jar, so that the
 * JDK 15+ META-INF/versions/15 provider overlays are exercised. The edec KeyFactorySpi has a
 * version-specific overlay here; this catches drift between it and the base (e.g. missing
 * passphrase support or the wrong InvalidKeySpecException contract on the OpenSSH path).
 */
public class OpenSSHKeyFactoryMRTest
    extends TestCase
{
    public void testOpenSSHKeySpecsAgainstMultiReleaseJar()
        throws Exception
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        SimpleTestResult result = (SimpleTestResult)new OpenSSHSpecTests().perform();

        assertTrue(result.toString(), result.isSuccessful());
    }
}

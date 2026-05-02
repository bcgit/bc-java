package org.bouncycastle.jcajce.provider.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.NamedParameterSpec;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Regression test for bc-java issue #2194 - initialising the BC "Falcon"
 * KeyPairGenerator with a {@link NamedParameterSpec} (rather than the
 * BC-specific {@code FalconParameterSpec}) must resolve the variant
 * correctly regardless of the case used in the supplied name.
 */
public class FalconNamedParameterSpecTest
    extends TestCase
{
    protected void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testNamedParameterSpec()
        throws Exception
    {
        String[] names = new String[]
            {
                "Falcon-512", "FALCON-512", "falcon-512",
                "Falcon-1024", "FALCON-1024", "falcon-1024"
            };

        for (int i = 0; i != names.length; i++)
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Falcon", "BC");
            kpg.initialize(new NamedParameterSpec(names[i]), new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();
            assertNotNull("no public key for " + names[i], kp.getPublic());
            assertNotNull("no private key for " + names[i], kp.getPrivate());
        }
    }
}

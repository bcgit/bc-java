package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.InvalidParameterException;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

/**
 * KeyPairGenerator.initialize(int, SecureRandom) across every service the two providers register.
 * <p>
 * A generator that will not take the key size it is handed has to refuse that call, and the
 * exception the JCA defines for it is {@link InvalidParameterException} - "if the keysize is not
 * supported by this KeyPairGenerator object". The PQC generators, which cannot have their parameter
 * set named by a key size at all, threw a bare IllegalArgumentException instead, as did RSA for a
 * size below its floor, so a caller following the JCA and catching the documented type took the
 * exception as an escape rather than a refusal. Since InvalidParameterException extends
 * IllegalArgumentException, callers that were catching the old type still catch the new one, which
 * is asserted below.
 * </p><p>
 * The sweep is over every service both providers register rather than a list of algorithms, so a
 * generator added later is covered without anything being added here.
 * </p>
 */
public class KeyPairGeneratorStrengthTest
    extends TestCase
{
    /**
     * The one strength no algorithm can take, so that a generator which does read the value still
     * reaches its own refusal rather than being handed something it can work with.
     */
    private static final int NONSENSE_STRENGTH = 7;

    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    public void testRefusalUsesTheJcaException()
        throws Exception
    {
        String[] providers = new String[]{ BouncyCastleProvider.PROVIDER_NAME, BouncyCastlePQCProvider.PROVIDER_NAME };

        List violations = new ArrayList();
        int refused = 0;
        int accepted = 0;

        for (int p = 0; p != providers.length; p++)
        {
            Provider provider = Security.getProvider(providers[p]);

            for (Iterator it = keyPairGeneratorNames(provider).iterator(); it.hasNext(); )
            {
                String name = (String)it.next();
                String id = providers[p] + ":" + name;

                try
                {
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance(name, providers[p]);

                    kpg.initialize(NONSENSE_STRENGTH, new SecureRandom());
                    accepted++;
                }
                catch (InvalidParameterException e)
                {
                    refused++;
                }
                catch (IllegalArgumentException e)
                {
                    violations.add(id + " threw " + e.getClass().getName() + ": " + e.getMessage());
                }
                catch (Exception e)
                {
                    violations.add(id + " threw " + e.getClass().getName() + ": " + e.getMessage());
                }
            }
        }

        assertTrue("initialize(int, SecureRandom) did not report a refusal as the JCA defines it - "
            + violations.size() + " services, first: " + violations.subList(0, Math.min(5, violations.size())),
            violations.isEmpty());

        // a guard against the sweep quietly measuring nothing if service enumeration changes shape
        assertTrue("expected the providers to register key pair generators", refused + accepted > 100);
    }

    /**
     * The compatibility half: the new exception is still an IllegalArgumentException, so a caller
     * written against the old behaviour goes on catching it.
     */
    public void testRefusalIsStillAnIllegalArgumentException()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("LMS", BouncyCastlePQCProvider.PROVIDER_NAME);

        try
        {
            kpg.initialize(NONSENSE_STRENGTH, new SecureRandom());
            fail("no exception on initialize(int, SecureRandom)");
        }
        catch (IllegalArgumentException e)
        {
            assertTrue("refusal is not the exception the JCA defines", e instanceof InvalidParameterException);
            assertEquals("use AlgorithmParameterSpec", e.getMessage());
        }
    }

    private static Set keyPairGeneratorNames(Provider provider)
    {
        Set names = new TreeSet();

        for (Iterator it = provider.getServices().iterator(); it.hasNext(); )
        {
            Provider.Service service = (Provider.Service)it.next();

            if ("KeyPairGenerator".equals(service.getType()))
            {
                names.add(service.getAlgorithm());
            }
        }

        return names;
    }
}

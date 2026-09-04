package org.bouncycastle.pqc.jcajce.provider.test;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

/**
 * KeyPairGenerator.initialize(AlgorithmParameterSpec, SecureRandom) across every service the two
 * providers register - the companion of {@link KeyPairGeneratorStrengthTest}, which covers the
 * int overload.
 * <p>
 * That method is declared to throw {@link InvalidAlgorithmParameterException}, so a spec it will not
 * take has to arrive as one. Two families did not manage it: the twenty-three PQC generators that
 * resolve a parameter set by name threw NullPointerException out of a case fold on the null a spec
 * with no getName() produces, which reached their own "is the name known" branch as an escaping
 * exception rather than a refusal; and the two composite generators, whose parameter set is fixed by
 * the algorithm name so that null is the only spec they accept, refused every other one with
 * IllegalArgumentException. RSA answered correctly for a spec of the wrong type but not for one of
 * the right type carrying values its lightweight parameters refuse.
 * </p><p>
 * The sweep is over every service both providers register rather than a list of algorithms, so a
 * generator added later is covered without anything being added here.
 * </p>
 */
public class KeyPairGeneratorSpecTest
    extends TestCase
{
    /**
     * A spec of a type no generator can recognise - in particular one with no getName() method, so
     * the name-resolving generators reach the null that used to end in a NullPointerException.
     */
    private static class AlienSpec
        implements AlgorithmParameterSpec
    {
    }

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

    public void testUnrecognisedSpecReportsTheDeclaredException()
        throws Exception
    {
        List violations = new ArrayList();
        int refused = sweep(new AlienSpec(), false, violations);

        assertTrue("initialize(AlgorithmParameterSpec, SecureRandom) did not report an unusable spec "
            + "as the exception it declares - " + violations.size() + " services, first: "
            + violations.subList(0, Math.min(5, violations.size())), violations.isEmpty());

        // no generator can name a parameter set from a spec nothing recognises, so all of them refuse
        assertTrue("expected the providers to register key pair generators", refused > 100);
    }

    /**
     * A null spec takes the same path. The composite generators accept it - their parameter set is
     * fixed by the algorithm name, so null is the one spec that is right - which is why acceptance
     * is allowed here and not in the case above.
     */
    public void testNullSpecReportsTheDeclaredException()
        throws Exception
    {
        List violations = new ArrayList();

        sweep(null, true, violations);

        assertTrue("initialize(null, SecureRandom) let an exception out that it does not declare - "
            + violations.size() + " services, first: "
            + violations.subList(0, Math.min(5, violations.size())), violations.isEmpty());
    }

    /**
     * A spec of the type the generator wants, carrying values it will not take. RSA reads these in
     * its lightweight parameters, which cannot name a java.security exception themselves.
     */
    public void testWellTypedButInvalidSpec()
        throws Exception
    {
        String[] algorithms = new String[]{ "RSA", "RSASSA-PSS" };

        for (int i = 0; i != algorithms.length; i++)
        {
            expectRefusal(algorithms[i], new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(4)),
                "public exponent cannot be even");
            expectRefusal(algorithms[i], new RSAKeyGenParameterSpec(8, BigInteger.valueOf(0x11)),
                "key strength too small");
        }
    }

    private static void expectRefusal(String algorithm, AlgorithmParameterSpec spec, String message)
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);

        try
        {
            kpg.initialize(spec, new SecureRandom());
            fail("no exception on initialize(" + message + ")");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            assertEquals(message, e.getMessage());
            assertNotNull("the refusal dropped the cause it was translated from", e.getCause());
        }
    }

    private static int sweep(AlgorithmParameterSpec spec, boolean acceptAllowed, List violations)
    {
        String[] providers = new String[]{ BouncyCastleProvider.PROVIDER_NAME, BouncyCastlePQCProvider.PROVIDER_NAME };
        int refused = 0;

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

                    kpg.initialize(spec, new SecureRandom());

                    if (!acceptAllowed)
                    {
                        violations.add(id + " accepted the spec");
                    }
                }
                catch (InvalidAlgorithmParameterException e)
                {
                    refused++;
                }
                catch (Exception e)
                {
                    violations.add(id + " threw " + e.getClass().getName() + ": " + e.getMessage());
                }
            }
        }

        return refused;
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

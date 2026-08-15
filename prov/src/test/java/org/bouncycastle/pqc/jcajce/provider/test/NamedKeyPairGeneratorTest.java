package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.test.PQCNamedParameterSets.Family;

/**
 * Completeness check over every PQC algorithm family that registers parameter-set specific
 * KeyPairGenerators, in either the BC or the BCPQC provider.
 * <p>
 * Two properties are asserted for each such generator, both of which have been wrong in the past
 * (see the 1.86 release notes): an <b>uninitialised</b> generator obtained by parameter set name
 * must generate for that parameter set rather than for its family's default, and an attempt to
 * <b>re-point</b> it at a different parameter set through initialize(AlgorithmParameterSpec, ...)
 * must be refused rather than quietly honoured. A family whose generator silently substitutes its
 * default hands a caller keys at a security level it did not ask for.
 * <p>
 * The per-family tests elsewhere in this package cover their own families in more depth; this test
 * exists so that a family added later cannot be left out of that coverage unnoticed. The families
 * and their parameter sets are listed in {@link PQCNamedParameterSets}.
 */
public class NamedKeyPairGeneratorTest
    extends TestCase
{
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

    public void testNamedGeneratorDefaultsToItsParameterSet()
        throws Exception
    {
        Family[] families = PQCNamedParameterSets.families();

        for (int f = 0; f != families.length; f++)
        {
            Family fam = families[f];

            for (int i = 0; i < fam.specs.length; i += fam.stride)
            {
                String expected = PQCNamedParameterSets.specName(fam.specs[i]);
                String algName = fam.algName(i);

                KeyPairGenerator kpg = KeyPairGenerator.getInstance(algName, fam.provider);

                KeyPair kp = kpg.generateKeyPair();

                assertEquals(fam.label + " " + algName, expected, PQCNamedParameterSets.paramSetName(kp.getPublic()));
                assertEquals(fam.label + " " + algName, expected, PQCNamedParameterSets.paramSetName(kp.getPrivate()));
            }
        }
    }

    public void testNamedGeneratorLockedToItsParameterSet()
        throws Exception
    {
        Family[] families = PQCNamedParameterSets.families();

        for (int f = 0; f != families.length; f++)
        {
            Family fam = families[f];

            for (int i = 0; i != fam.specs.length; i++)
            {
                String algName = fam.algName(i);

                AlgorithmParameterSpec other = fam.specs[i == 0 ? 1 : 0];

                KeyPairGenerator kpg = KeyPairGenerator.getInstance(algName, fam.provider);

                try
                {
                    kpg.initialize(other, new SecureRandom());
                    fail(fam.label + " " + algName + ": no exception");
                }
                catch (InvalidAlgorithmParameterException e)
                {
                    assertTrue(fam.label + " " + algName + ": " + e.getMessage(),
                        e.getMessage().startsWith("key pair generator locked to "));
                }

                kpg.initialize(fam.specs[i], new SecureRandom());
            }
        }
    }

    /**
     * getInstance(spec.getName()) is the natural idiom for turning a parameter set into a
     * generator, and every family supports it - three of them (AIMer, SMAUG-T and NTRU+) only
     * because their parameter set spelling is registered as an alias of the canonical algorithm
     * name. Resolution is all that is asserted here; that the resolved generator then behaves is
     * covered by the two tests above, which drive the canonical names.
     */
    public void testParameterSetNameResolves()
        throws Exception
    {
        Family[] families = PQCNamedParameterSets.families();

        for (int f = 0; f != families.length; f++)
        {
            Family fam = families[f];

            for (int i = 0; i != fam.specs.length; i++)
            {
                String specName = PQCNamedParameterSets.specName(fam.specs[i]);

                assertNotNull(fam.label + " " + specName, KeyPairGenerator.getInstance(specName, fam.provider));
            }
        }
    }
}

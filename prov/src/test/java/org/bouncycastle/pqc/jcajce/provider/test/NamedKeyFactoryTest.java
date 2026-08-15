package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.test.PQCNamedParameterSets.Family;

/**
 * Completeness check over every PQC algorithm family that registers parameter-set specific
 * KeyFactories, the KeyFactory counterpart of {@link NamedKeyPairGeneratorTest}.
 * <p>
 * A caller can use a parameter-set specific KeyFactory as an import policy - a service that will
 * accept keys only at a chosen strength - and decide on whether generatePublic / generatePrivate
 * succeeds. That only holds if the factory rejects a key of any other parameter set of its family,
 * which is what BaseKeyFactorySpi / BasePQCKeyFactorySpi enforce by checking the algorithm OID in
 * the encoding against the OID the factory was constructed for. Three families had overridden both
 * import methods in a way that skipped that check (see the 1.86 release notes), so the property is
 * asserted here for all of them:
 * <ul>
 * <li>the factory named for a parameter set accepts a key of that parameter set, which fails if a
 * factory is constructed with the wrong OID;</li>
 * <li>it rejects a key of any other parameter set of the same family, which fails if a factory is
 * constructed with no OID or with its family's whole set;</li>
 * <li>the family-level factory still accepts every parameter set of its family, the
 * compatibility case.</li>
 * </ul>
 * The families and their parameter sets are listed in {@link PQCNamedParameterSets}.
 */
public class NamedKeyFactoryTest
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

    public void testNamedKeyFactoryAcceptsItsOwnParameterSet()
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
                String where = fam.label + " " + algName;

                KeyPair kp = KeyPairGenerator.getInstance(algName, fam.provider).generateKeyPair();

                X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(kp.getPublic().getEncoded());
                PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded());

                KeyFactory named = KeyFactory.getInstance(algName, fam.provider);

                assertEquals(where, expected, PQCNamedParameterSets.paramSetName(named.generatePublic(pubSpec)));
                assertEquals(where, expected, PQCNamedParameterSets.paramSetName(named.generatePrivate(privSpec)));

                KeyFactory generic = KeyFactory.getInstance(PQCNamedParameterSets.genericNameFor(fam, expected), fam.provider);

                assertEquals(where, expected, PQCNamedParameterSets.paramSetName(generic.generatePublic(pubSpec)));
                assertEquals(where, expected, PQCNamedParameterSets.paramSetName(generic.generatePrivate(privSpec)));
            }
        }
    }

    public void testNamedKeyFactoryRejectsOtherParameterSets()
        throws Exception
    {
        Family[] families = PQCNamedParameterSets.families();

        for (int f = 0; f != families.length; f++)
        {
            Family fam = families[f];

            KeyPair kp = KeyPairGenerator.getInstance(fam.algName(0), fam.provider).generateKeyPair();

            X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(kp.getPublic().getEncoded());
            PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded());

            for (int i = 1; i != fam.specs.length; i++)
            {
                String algName = fam.algName(i);
                String where = fam.label + " key=" + fam.algName(0) + " factory=" + algName;

                KeyFactory other = KeyFactory.getInstance(algName, fam.provider);

                try
                {
                    other.generatePublic(pubSpec);
                    fail(where + ": public key accepted");
                }
                catch (InvalidKeySpecException e)
                {
                    assertTrue(where + ": " + e.getMessage(),
                        e.getMessage().startsWith("incorrect algorithm OID for key: "));
                }

                try
                {
                    other.generatePrivate(privSpec);
                    fail(where + ": private key accepted");
                }
                catch (InvalidKeySpecException e)
                {
                    assertTrue(where + ": " + e.getMessage(),
                        e.getMessage().startsWith("incorrect algorithm OID for key: "));
                }
            }
        }
    }
}

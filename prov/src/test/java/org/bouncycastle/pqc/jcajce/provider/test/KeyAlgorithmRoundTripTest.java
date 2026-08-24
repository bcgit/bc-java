package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.TreeSet;

import junit.framework.TestCase;
import org.bouncycastle.crypto.params.LMOtsParameters;
import org.bouncycastle.crypto.params.LMSigParameters;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.LMSKeyGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SPHINCS256KeyGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.XMSSMTParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.XMSSParameterSpec;

/**
 * A key's {@code getAlgorithm()} has to name a KeyFactory its own provider registers, or the
 * standard JCA round trip
 * {@code KeyFactory.getInstance(key.getAlgorithm(), provider).generatePublic(new X509EncodedKeySpec(key.getEncoded()))}
 * fails for anyone handed the key alone. Every KeyPairGenerator the BCPQC provider registers is
 * swept: generate a pair, rebuild both halves through the KeyFactory the keys themselves name,
 * and require the rebuilt keys to equal the originals.
 * <p>
 * Three families used to fail this: the Streamlined NTRU Prime keys reported "NTRULPRime" - the
 * sibling NTRU LPRime family's name, so the round trip decoded against the wrong family and threw -
 * and the BIKE and classic McEliece keys reported their parameter-set name ("BIKE128",
 * "MCELIECE8192128F") where those families register family-level services only, so the lookup
 * itself failed. SPHINCS-256 keys report "SPHINCS-256", the algorithm's published name, which is
 * now a registered alias of the "SPHINCS256" services. Failures are collected so a new family that
 * misreports shows up as itself rather than as wherever the sweep stopped.
 */
public class KeyAlgorithmRoundTripTest
    extends TestCase
{
    /**
     * A drop in the number of registered KeyPairGenerator services means the sweep stopped
     * covering families rather than that the provider is clean, so it is asserted against a floor.
     */
    private static final int MINIMUM_KEYPAIRGENERATOR_SERVICES = 170;

    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
    }

    public void testEveryKeyPairGeneratorsKeysRoundTripByTheirOwnName()
        throws Exception
    {
        Provider prov = Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME);

        List failures = new ArrayList();
        int count = 0;

        for (Iterator it = new TreeSet(getKeyPairGeneratorAlgorithms(prov)).iterator(); it.hasNext();)
        {
            String algorithm = (String)it.next();

            count++;

            KeyPair kp = generateKeyPair(prov, algorithm);

            checkRoundTrip(prov, algorithm, kp, failures);
        }

        assertTrue("only " + count + " KeyPairGenerator services found", count >= MINIMUM_KEYPAIRGENERATOR_SERVICES);
        assertEquals(failures.toString(), 0, failures.size());
    }

    private void checkRoundTrip(Provider prov, String algorithm, KeyPair kp, List failures)
    {
        String pubAlg = kp.getPublic().getAlgorithm();
        try
        {
            KeyFactory kf = KeyFactory.getInstance(pubAlg, prov);
            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
            if (!kp.getPublic().equals(pub))
            {
                failures.add(algorithm + ": public key changed by round trip through \"" + pubAlg + "\"");
            }
        }
        catch (Exception e)
        {
            failures.add(algorithm + ": public key reports \"" + pubAlg + "\" - " + e);
        }

        String privAlg = kp.getPrivate().getAlgorithm();
        try
        {
            KeyFactory kf = KeyFactory.getInstance(privAlg, prov);
            PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded()));
            if (!kp.getPrivate().equals(priv))
            {
                failures.add(algorithm + ": private key changed by round trip through \"" + privAlg + "\"");
            }
        }
        catch (Exception e)
        {
            failures.add(algorithm + ": private key reports \"" + privAlg + "\" - " + e);
        }
    }

    /**
     * The OID registrations name the same services as the algorithm names do, so they are left out
     * to keep the sweep's failure messages readable.
     */
    private List getKeyPairGeneratorAlgorithms(Provider prov)
    {
        List algorithms = new ArrayList();

        for (Iterator it = prov.getServices().iterator(); it.hasNext();)
        {
            Provider.Service service = (Provider.Service)it.next();

            if (!"KeyPairGenerator".equals(service.getType()))
            {
                continue;
            }

            String algorithm = service.getAlgorithm();

            if (algorithm.indexOf('.') < 0)
            {
                algorithms.add(algorithm);
            }
        }

        return algorithms;
    }

    /**
     * The stateful hash-based families are initialised with their smallest parameters - their
     * defaults are sized for real use and dominate the sweep's run time (the same choices as the
     * SignatureSetParameterTest sweep); everything else generates at its family default.
     */
    private KeyPair generateKeyPair(Provider prov, String algorithm)
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance(algorithm, prov);

        if (algorithm.startsWith("SPHINCS"))
        {
            kpGen.initialize(new SPHINCS256KeyGenParameterSpec(), new SecureRandom());
        }
        else if (algorithm.equals("XMSS"))
        {
            kpGen.initialize(new XMSSParameterSpec(4, XMSSParameterSpec.SHA256), new SecureRandom());
        }
        else if (algorithm.equals("XMSSMT"))
        {
            kpGen.initialize(new XMSSMTParameterSpec(4, 2, XMSSMTParameterSpec.SHA256), new SecureRandom());
        }
        else if (algorithm.equals("LMS"))
        {
            kpGen.initialize(new LMSKeyGenParameterSpec(
                LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1), new SecureRandom());
        }

        return kpGen.generateKeyPair();
    }
}

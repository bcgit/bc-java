package org.bouncycastle.pqc.jcajce.provider.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import junit.framework.TestCase;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.LMSKeyGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.SPHINCS256KeyGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.XMSSMTParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.XMSSParameterSpec;
import org.bouncycastle.util.Strings;

/**
 * Signature.setParameter(...) on the BCPQC signature services - none of which take parameters, as
 * opposed to the ML-DSA and SLH-DSA services in the BC provider, which take a signature context
 * through a {@link ContextParameterSpec} (see the sibling
 * org.bouncycastle.jcajce.provider.test.SignatureSetParameterTest).
 * <p>
 * Every BCPQC signature SPI leaves engineSetParameter / engineGetParameters at the refusal the JCA
 * defines for a service with no parameters, so setParameter has to fail the same way at every point
 * in the signature's life - before initSign / initVerify, after it, and in the middle of update -
 * and has to leave the signature able to go on and produce a signature that verifies. A family that
 * grew a half-implemented setParameter would show up here as a different exception, or as one
 * thrown at some stages but not others.
 */
public class SignatureSetParameterTest
    extends TestCase
{
    private static final byte[] MSG = Strings.toByteArray("the quick brown fox");
    private static final byte[] CONTEXT = Strings.toByteArray("Hello, world!");

    /**
     * One signature algorithm per BCPQC signature family, with the key algorithm to generate for it.
     */
    private static final String[][] SIGNATURE_ALGORITHMS =
        {
            { "SHA512WITHSPHINCS256", "SPHINCS256" },
            { "XMSS-SHA256", "XMSS" },
            { "XMSSMT-SHA256", "XMSSMT" },
            { "LMS", "LMS" },
            { "FALCON-512", "FALCON-512" },
            { "MAYO-1", "MAYO-1" },
            { "SNOVA_24_5_4_SSK", "SNOVA_24_5_4_SSK" },
            { "sqisign_lvl1", "sqisign_lvl1" },
            { "UOV-IS", "UOV-IS" },
            { "QRUOV1Q127L3V156M54", "QRUOV1Q127L3V156M54" },
            { "HAETAE-2", "HAETAE-2" },
            { "AIMer-128f", "AIMer-128f" },
            { "FAEST_128F", "FAEST_128F" },
            { "MQOM2-CAT1-GF256-FAST-R3", "MQOM2-CAT1-GF256-FAST-R3" },
            { "SDITH-HYPERCUBE-CAT1-GF256", "SDITH-HYPERCUBE-CAT1-GF256" }
        };

    /**
     * A drop in the number of registered signature services means the sweep below stopped covering
     * families rather than that the provider is clean, so it is asserted against a floor.
     */
    private static final int MINIMUM_SIGNATURE_SERVICES = 150;

    private static final Map keyPairs = new HashMap();

    public void setUp()
    {
        if (Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * The refusal has to be the same at every stage, and has to leave the signature usable - a
     * caller that probes setParameter still gets a signature out of the object afterwards.
     */
    public void testSetParameterRejectedAtEveryStage()
        throws Exception
    {
        for (int i = 0; i != SIGNATURE_ALGORITHMS.length; i++)
        {
            String algorithm = SIGNATURE_ALGORITHMS[i][0];

            KeyPair kp = getKeyPair(SIGNATURE_ALGORITHMS[i][1]);

            Signature signer = Signature.getInstance(algorithm, "BCPQC");

            checkRejected(algorithm + ": before initSign", signer, new ContextParameterSpec(CONTEXT));

            signer.initSign(kp.getPrivate());

            checkRejected(algorithm + ": after initSign", signer, new ContextParameterSpec(CONTEXT));

            signer.update(MSG);

            checkRejected(algorithm + ": mid update", signer, new ContextParameterSpec(CONTEXT));

            byte[] sig = signer.sign();

            Signature verifier = Signature.getInstance(algorithm, "BCPQC");

            checkRejected(algorithm + ": before initVerify", verifier, new ContextParameterSpec(CONTEXT));

            verifier.initVerify(kp.getPublic());

            checkRejected(algorithm + ": after initVerify", verifier, new ContextParameterSpec(CONTEXT));

            verifier.update(MSG);

            assertTrue(algorithm + ": signature lost to a rejected setParameter", verifier.verify(sig));
        }
    }

    /**
     * A null spec is the way a caller says "no parameters", which is what these services use anyway,
     * but the JCA still leaves refusing it to the service - so it is refused like any other spec
     * rather than quietly accepted.
     */
    public void testSetNullParameterRejected()
        throws Exception
    {
        for (int i = 0; i != SIGNATURE_ALGORITHMS.length; i++)
        {
            String algorithm = SIGNATURE_ALGORITHMS[i][0];

            checkRejected(algorithm + ": null spec",
                Signature.getInstance(algorithm, "BCPQC"), null);
        }
    }

    public void testGetParametersUnsupported()
        throws Exception
    {
        for (int i = 0; i != SIGNATURE_ALGORITHMS.length; i++)
        {
            String algorithm = SIGNATURE_ALGORITHMS[i][0];

            Signature sig = Signature.getInstance(algorithm, "BCPQC");

            try
            {
                sig.getParameters();
                fail(algorithm + ": no exception");
            }
            catch (UnsupportedOperationException e)
            {
                // expected - the service has no parameters to report
            }
        }
    }

    /**
     * The table above names one algorithm per family; this covers the rest of the parameter sets,
     * and any family added since, by asking the provider itself what it registers. Failures are
     * collected so one new service that behaves differently reports as itself rather than as
     * whichever one the sweep happened to reach first.
     */
    public void testAllRegisteredSignatureServicesRejectSetParameter()
        throws Exception
    {
        Provider prov = Security.getProvider(BouncyCastlePQCProvider.PROVIDER_NAME);

        List failures = new ArrayList();
        int count = 0;

        for (Iterator it = new TreeSet(getSignatureAlgorithms(prov)).iterator(); it.hasNext();)
        {
            String algorithm = (String)it.next();

            count++;

            Signature sig = Signature.getInstance(algorithm, prov);

            try
            {
                sig.setParameter(new ContextParameterSpec(CONTEXT));
                failures.add(algorithm + ": setParameter accepted");
            }
            catch (UnsupportedOperationException e)
            {
                // expected
            }
            catch (Exception e)
            {
                failures.add(algorithm + ": setParameter threw " + e.getClass().getName());
            }

            try
            {
                sig.getParameters();
                failures.add(algorithm + ": getParameters answered");
            }
            catch (UnsupportedOperationException e)
            {
                // expected
            }
            catch (Exception e)
            {
                failures.add(algorithm + ": getParameters threw " + e.getClass().getName());
            }
        }

        assertTrue("only " + count + " signature services found", count >= MINIMUM_SIGNATURE_SERVICES);
        assertEquals(failures.toString(), 0, failures.size());
    }

    private void checkRejected(String message, Signature sig, AlgorithmParameterSpec spec)
    {
        try
        {
            sig.setParameter(spec);
            fail(message + ": no exception");
        }
        catch (UnsupportedOperationException e)
        {
            // expected - the service takes no parameters
        }
        catch (Exception e)
        {
            fail(message + ": " + e.getClass().getName() + " - " + e.getMessage());
        }
    }

    /**
     * The OID registrations name the same services as the algorithm names do, so they are left out
     * to keep the sweep's failure messages readable.
     */
    private List getSignatureAlgorithms(Provider prov)
    {
        List algorithms = new ArrayList();

        for (Iterator it = prov.getServices().iterator(); it.hasNext();)
        {
            Provider.Service service = (Provider.Service)it.next();

            if (!"Signature".equals(service.getType()))
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

    private KeyPair getKeyPair(String algorithm)
        throws Exception
    {
        KeyPair kp = (KeyPair)keyPairs.get(algorithm);

        if (kp != null)
        {
            return kp;
        }

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance(algorithm, "BCPQC");

        if (algorithm.equals("SPHINCS256"))
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

        kp = kpGen.generateKeyPair();

        keyPairs.put(algorithm, kp);

        return kp;
    }
}

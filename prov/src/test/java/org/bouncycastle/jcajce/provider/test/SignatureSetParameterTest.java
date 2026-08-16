package org.bouncycastle.jcajce.provider.test;

import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.ProviderException;
import java.security.Security;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import junit.framework.TestCase;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * Signature.setParameter(...) on the ML-DSA and SLH-DSA services, which take a signature context
 * through a {@link ContextParameterSpec}.
 * <p>
 * The context may be set either side of initSign / initVerify, as it may be for the RSASSA-PSS
 * parameters: setting it while the signature already has a key re-initialises the underlying signer
 * at once, and setting it beforehand records it for the key to arrive. Setting it first used to let
 * a NullPointerException out of a method declared to throw InvalidAlgorithmParameterException,
 * from dereferencing the key that was not there yet (github #2396).
 */
public class SignatureSetParameterTest
    extends TestCase
{
    private static final byte[] MSG = Strings.toByteArray("the quick brown fox");
    private static final byte[] CONTEXT = Strings.toByteArray("Hello, world!");

    private static final String[] SIGNATURE_ALGORITHMS =
        {
            "ML-DSA",
            "ML-DSA-65",
            "ML-DSA-65-WITH-SHA512",
            "HASH-ML-DSA",
            "SLH-DSA",
            "SLH-DSA-SHA2-128F",
            "SLH-DSA-SHA2-128F-WITH-SHA256",
            "HASH-SLH-DSA"
        };

    private static final String[] KEY_ALGORITHMS =
        {
            "ML-DSA-65",
            "ML-DSA-65",
            "ML-DSA-65",
            "ML-DSA-65",
            "SLH-DSA-SHA2-128F",
            "SLH-DSA-SHA2-128F",
            "SLH-DSA-SHA2-128F",
            "SLH-DSA-SHA2-128F"
        };

    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Setting the context before initialising has to reach the signer, not be dropped on the way -
     * so the signature it produces must be the one the established after-init order produces, and
     * must not verify against a signature service given no context at all.
     */
    public void testSetParameterBeforeInit()
        throws Exception
    {
        for (int i = 0; i != SIGNATURE_ALGORITHMS.length; i++)
        {
            String algorithm = SIGNATURE_ALGORITHMS[i];

            KeyPair kp = KeyPairGenerator.getInstance(KEY_ALGORITHMS[i], "BC").generateKeyPair();

            Signature before = Signature.getInstance(algorithm, "BC");

            before.setParameter(new ContextParameterSpec(CONTEXT));
            before.initSign(kp.getPrivate());
            before.update(MSG);

            byte[] sigBefore = before.sign();

            Signature after = Signature.getInstance(algorithm, "BC");

            after.initSign(kp.getPrivate());
            after.setParameter(new ContextParameterSpec(CONTEXT));
            after.update(MSG);

            assertTrue(algorithm + ": context set before init did not reach the signer",
                Arrays.areEqual(sigBefore, after.sign()));

            Signature verifier = Signature.getInstance(algorithm, "BC");

            verifier.setParameter(new ContextParameterSpec(CONTEXT));
            verifier.initVerify(kp.getPublic());
            verifier.update(MSG);

            assertTrue(algorithm, verifier.verify(sigBefore));

            Signature noContext = Signature.getInstance(algorithm, "BC");

            noContext.initVerify(kp.getPublic());
            noContext.update(MSG);

            assertFalse(algorithm + ": verified without the context", noContext.verify(sigBefore));
        }
    }

    public void testSetParameterAfterInit()
        throws Exception
    {
        for (int i = 0; i != SIGNATURE_ALGORITHMS.length; i++)
        {
            String algorithm = SIGNATURE_ALGORITHMS[i];

            KeyPair kp = KeyPairGenerator.getInstance(KEY_ALGORITHMS[i], "BC").generateKeyPair();

            Signature signer = Signature.getInstance(algorithm, "BC");

            signer.initSign(kp.getPrivate());
            signer.setParameter(new ContextParameterSpec(CONTEXT));
            signer.update(MSG);

            byte[] sig = signer.sign();

            Signature verifier = Signature.getInstance(algorithm, "BC");

            verifier.initVerify(kp.getPublic());
            verifier.setParameter(new ContextParameterSpec(CONTEXT));
            verifier.update(MSG);

            assertTrue(algorithm, verifier.verify(sig));

            Signature wrongContext = Signature.getInstance(algorithm, "BC");

            wrongContext.initVerify(kp.getPublic());
            wrongContext.setParameter(new ContextParameterSpec(Strings.toByteArray("other context")));
            wrongContext.update(MSG);

            assertFalse(algorithm, wrongContext.verify(sig));
        }
    }

    /**
     * The null spec resolves to the empty context, which is what a signature with no context set
     * uses anyway, so it is accepted before initialisation as well.
     */
    public void testSetNullParameterBeforeInit()
        throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("ML-DSA-65", "BC").generateKeyPair();

        Signature sig = Signature.getInstance("ML-DSA", "BC");

        sig.setParameter(null);
        sig.initSign(kp.getPrivate());
        sig.update(MSG);

        byte[] s = sig.sign();

        Signature verifier = Signature.getInstance("ML-DSA", "BC");

        verifier.initVerify(kp.getPublic());
        verifier.update(MSG);

        assertTrue(verifier.verify(s));
    }

    public void testGetParametersReflectsContextSetBeforeInit()
        throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("ML-DSA-65", "BC").generateKeyPair();

        Signature sig = Signature.getInstance("ML-DSA", "BC");

        sig.setParameter(new ContextParameterSpec(CONTEXT));
        sig.initSign(kp.getPrivate());

        AlgorithmParameters params = sig.getParameters();

        assertNotNull(params);
        assertTrue(Arrays.areEqual(CONTEXT,
            params.getParameterSpec(ContextParameterSpec.class).getContext()));
    }

    /**
     * Re-setting the context replaces the previous one rather than being reported through a stale
     * cached AlgorithmParameters.
     */
    public void testResetContext()
        throws Exception
    {
        byte[] second = Strings.toByteArray("second context");

        KeyPair kp = KeyPairGenerator.getInstance("ML-DSA-65", "BC").generateKeyPair();

        Signature sig = Signature.getInstance("ML-DSA", "BC");

        sig.setParameter(new ContextParameterSpec(CONTEXT));
        sig.initSign(kp.getPrivate());
        sig.setParameter(new ContextParameterSpec(second));

        assertTrue(Arrays.areEqual(second,
            sig.getParameters().getParameterSpec(ContextParameterSpec.class).getContext()));

        sig.update(MSG);

        byte[] s = sig.sign();

        Signature verifier = Signature.getInstance("ML-DSA", "BC");

        verifier.setParameter(new ContextParameterSpec(second));
        verifier.initVerify(kp.getPublic());
        verifier.update(MSG);

        assertTrue(verifier.verify(s));
    }

    /**
     * getParameters() caches the AlgorithmParameters it builds, so a context set after it has been
     * asked for once has to clear that cache rather than go on reporting the previous context.
     * <p>
     * testResetContext above only asks after the second setParameter, so the cache is never
     * populated with the first context there and a stale one would go unnoticed.
     * </p>
     */
    public void testGetParametersNotStaleAfterReset()
        throws Exception
    {
        byte[] second = Strings.toByteArray("second context");

        KeyPair kp = KeyPairGenerator.getInstance("ML-DSA-65", "BC").generateKeyPair();

        Signature sig = Signature.getInstance("ML-DSA", "BC");

        sig.setParameter(new ContextParameterSpec(CONTEXT));
        sig.initSign(kp.getPrivate());

        assertTrue(Arrays.areEqual(CONTEXT,
            sig.getParameters().getParameterSpec(ContextParameterSpec.class).getContext()));

        sig.setParameter(new ContextParameterSpec(second));

        assertTrue("getParameters() still reported the previous context", Arrays.areEqual(second,
            sig.getParameters().getParameterSpec(ContextParameterSpec.class).getContext()));
    }

    /**
     * The RSASSA-PSS services cache getParameters() the same way, so the same question is asked of
     * the sibling path this class's contract is modelled on.
     */
    public void testPssGetParametersNotStaleAfterReset()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");

        kpg.initialize(2048);

        KeyPair kp = kpg.generateKeyPair();

        Signature sig = Signature.getInstance("SHA256withRSAandMGF1", "BC");

        sig.initSign(kp.getPrivate());
        sig.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));

        assertEquals(32,
            ((PSSParameterSpec)sig.getParameters().getParameterSpec(PSSParameterSpec.class)).getSaltLength());

        sig.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 20, 1));

        assertEquals("getParameters() still reported the previous salt length", 20,
            ((PSSParameterSpec)sig.getParameters().getParameterSpec(PSSParameterSpec.class)).getSaltLength());
    }

    public void testSetParameterMidUpdateStillRejected()
        throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("ML-DSA-65", "BC").generateKeyPair();

        Signature sig = Signature.getInstance("ML-DSA", "BC");

        sig.initSign(kp.getPrivate());
        sig.update(MSG);

        try
        {
            sig.setParameter(new ContextParameterSpec(CONTEXT));
            fail("no exception");
        }
        catch (ProviderException e)
        {
            assertEquals("cannot call setParameter in the middle of update", e.getMessage());
        }
    }
}

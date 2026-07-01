package org.bouncycastle.pqc.crypto.mayo;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ParametersWithRandom;

/**
 * Regression test for the retry path in {@link MayoSigner#generateSignature(byte[])}.
 *
 * <p>The retry loop {@code for (int ctr = 0; ctr <= 255; ctr++)} accumulates three
 * {@code long[]} buffers ({@code Mtmp}, {@code Pv}, {@code vPv}) with mulAdd-style
 * (accumulate-into) calls. All three are allocated once before the loop, so on a
 * retry they must be re-zeroed. The reference C implementation
 * (MAYO-C {@code compute_M_and_VPV}) declares {@code Pv} <em>inside</em> the function
 * as {@code uint64_t Pv[...] = {0}}, i.e. fresh per attempt, while {@code mayo_sign}
 * memsets {@code Mtmp} and the {@code VP1V} target on failure.</p>
 *
 * <p>The Java port hoisted {@code Pv}'s allocation out of the loop. Without clearing
 * {@code Pv} on retry, the second attempt computes
 * {@code Pv = P1*V0^T + P1*V1^T} (stale data carried over), corrupting the signature.
 * The KAT vectors never trigger a retry, so this is invisible to the KAT battery.</p>
 *
 * <p>This test forces exactly one retry by overriding {@code sampleSolution} to fail
 * the first attempt, then asserts the produced signature still verifies.</p>
 */
public class MayoRetryTest
    extends TestCase
{
    /**
     * A signer that fails the first {@code sampleSolution} call of every
     * {@code generateSignature}, forcing the retry (ctr > 0) branch to run.
     */
    private static class RetryForcingSigner
        extends MayoSigner
    {
        private int calls = 0;

        boolean sampleSolution(byte[] A, byte[] y, byte[] r, byte[] x)
        {
            // Fail the very first attempt so the retry else-branch executes,
            // re-deriving V (and therefore Pv) for ctr == 1.
            if (calls++ == 0)
            {
                return false;
            }
            return super.sampleSolution(A, y, r, x);
        }
    }

    public void testRetryProducesValidSignature()
        throws Exception
    {
        MayoParameters[] paramSets = new MayoParameters[]
            {
                MayoParameters.mayo1,
                MayoParameters.mayo2,
                MayoParameters.mayo3,
                MayoParameters.mayo5
            };

        SecureRandom random = new SecureRandom();

        for (int i = 0; i < paramSets.length; i++)
        {
            MayoParameters parameters = paramSets[i];

            MayoKeyPairGenerator kpGen = new MayoKeyPairGenerator();
            kpGen.init(new MayoKeyGenerationParameters(random, parameters));
            AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

            byte[] message = ("message for " + parameters).getBytes("UTF-8");

            // Sign with the retry-forcing signer (exercises ctr > 0).
            RetryForcingSigner signer = new RetryForcingSigner();
            signer.init(true, new ParametersWithRandom(
                (MayoPrivateKeyParameters)kp.getPrivate(), random));
            byte[] sigPlusMsg = signer.generateSignature(message);

            // generateSignature returns sig || message; verifySignature expects the
            // signature portion only.
            int sigBytes = parameters.getSigBytes();
            byte[] sig = new byte[sigBytes];
            System.arraycopy(sigPlusMsg, 0, sig, 0, sigBytes);

            MayoSigner verifier = new MayoSigner();
            verifier.init(false, (MayoPublicKeyParameters)kp.getPublic());

            assertTrue("signature produced after a retry must verify for " + parameters,
                verifier.verifySignature(message, sig));
        }
    }
}

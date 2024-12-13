package org.bouncycastle.pqc.crypto.ntru;

import java.security.SecureRandom;

import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.util.SecretWithEncapsulationImpl;
import org.bouncycastle.pqc.math.ntru.Polynomial;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUParameterSet;
import org.bouncycastle.util.Arrays;

/**
 * Encapsulate a secret using NTRU. returns a {@link SecretWithEncapsulation} as encapsulation.
 *
 * @see NTRUKEMExtractor
 * @see <a href="https://ntru.org/">NTRU website</a>
 */
public class NTRUKEMGenerator
    implements EncapsulatedSecretGenerator
{
    private final SecureRandom random;

    /**
     * Constructor
     *
     * @param random a secure random number generator
     */
    public NTRUKEMGenerator(SecureRandom random)
    {
        if (random == null)
        {
            throw new NullPointerException("'random' cannot be null");
        }

        this.random = random;
    }

    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        if (recipientKey == null)
        {
            throw new NullPointerException("'recipientKey' cannot be null");
        }

        NTRUPublicKeyParameters publicKey = (NTRUPublicKeyParameters)recipientKey;

        NTRUParameterSet parameterSet = publicKey.getParameters().getParameterSet();
        NTRUSampling sampling = new NTRUSampling(parameterSet);
        NTRUOWCPA owcpa = new NTRUOWCPA(parameterSet);
        byte[] rm = new byte[parameterSet.owcpaMsgBytes()];
        byte[] rmSeed = new byte[parameterSet.sampleRmBytes()];

        random.nextBytes(rmSeed);

        PolynomialPair pair = sampling.sampleRm(rmSeed);
        Polynomial r = pair.r();
        Polynomial m = pair.m();

        r.s3ToBytes(rm, 0);
        m.s3ToBytes(rm, parameterSet.packTrinaryBytes());

        SHA3Digest sha3256 = new SHA3Digest(256);
        byte[] k = new byte[sha3256.getDigestSize()];

        sha3256.update(rm, 0, rm.length);
        sha3256.doFinal(k, 0);

        r.z3ToZq();

        byte[] c = owcpa.encrypt(r, m, publicKey.publicKey);

        byte[] sharedKey = Arrays.copyOfRange(k, 0, parameterSet.sharedKeyBytes());
        Arrays.clear(k);

        return new SecretWithEncapsulationImpl(sharedKey, c);
    }
}

package org.bouncycastle.pqc.crypto.ntru;

import java.security.SecureRandom;

import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.math.ntru.Polynomial;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUParameterSet;

/**
 * Encapsulate a secret using NTRU. returns a {@link SecretWithEncapsulation} as encapsulation.
 *
 * @see NTRUExtractor
 * @see <a href="https://ntru.org/">NTRU website</a>
 */
public class NTRUGenerator
    implements EncapsulatedSecretGenerator
{
    private final SecureRandom random;

    /**
     * Constructor
     *
     * @param random a secure random number generator
     */
    public NTRUGenerator(SecureRandom random)
    {
        this.random = random;
    }

    @Override
    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter recipientKey)
    {
        NTRUParameterSet parameterSet = ((NTRUPublicKeyParameters)recipientKey).getParameters().parameterSet;
        NTRUSampling sampling = new NTRUSampling(parameterSet);

        byte[] k = new byte[parameterSet.sharedKeyBytes()];
        NTRUOWCPA owcpa = new NTRUOWCPA(parameterSet);
        Polynomial r;
        Polynomial m;
        byte[] rm = new byte[parameterSet.owcpaMsgBytes()];
        byte[] rmSeed = new byte[parameterSet.sampleRmBytes()];

        random.nextBytes(rmSeed);

        PolynomialPair pair = sampling.sampleRm(rmSeed);
        r = pair.r();
        m = pair.m();

        byte[] rm1 = r.s3ToBytes(parameterSet.owcpaMsgBytes());
        System.arraycopy(rm1, 0, rm, 0, rm1.length);
        byte[] rm2 = m.s3ToBytes(rm.length - parameterSet.packTrinaryBytes());
        System.arraycopy(rm2, 0, rm, parameterSet.packTrinaryBytes(), rm2.length);
        SHA3Digest sha3256 = new SHA3Digest(256);
        sha3256.update(rm, 0, rm.length);
        sha3256.doFinal(k, 0);

        r.z3ToZq();
        byte[] c = owcpa.encrypt(r, m, ((NTRUPublicKeyParameters)recipientKey).publicKey);

        return new NTRUEncapsulation(k, c);
    }
}

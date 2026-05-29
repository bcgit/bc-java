package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.sqisign.SQIsignKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.sqisign.SQIsignKeyPairGenerator;
import org.bouncycastle.pqc.crypto.sqisign.SQIsignParameters;
import org.bouncycastle.pqc.crypto.sqisign.SQIsignPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sqisign.SQIsignPublicKeyParameters;
import org.bouncycastle.pqc.crypto.sqisign.SQIsignSigner;

/**
 * KAT-driven tests for SQIsign. Mirrors the structure of {@link MayoTest}: a
 * single {@link #testTestVectors()} method walks every parameter set / KAT file
 * pair via {@link TestUtils#testTestVector} with {@code sampleOnly = true}, so
 * {@link TestSampler} exercises a handful of triplets per level rather than
 * all 100. Each triplet is run through keygen, sign, and verify, with
 * byte-identity asserted against the KAT's expected pk / sk / sm values.
 *
 * <p>SQIsign lvl3 / lvl5 keygen + sign + verify is expensive in pure Java
 * (BigInteger arithmetic over 376-bit / 500-bit primes); even the sampled
 * subset can take many minutes per level. A full sweep would take
 * prohibitively long.</p>
 */
public class SQIsignTest
    extends TestCase
{
    public static void main(String[] args)
        throws Exception
    {
        SQIsignTest test = new SQIsignTest();
        test.testTestVectors();
    }

    private static final SQIsignParameters[] PARAMETER_SETS = new SQIsignParameters[]
        {
            SQIsignParameters.sqisign_lvl1,
            SQIsignParameters.sqisign_lvl3,
            SQIsignParameters.sqisign_lvl5
        };

    private static final String[] files = new String[]{
        "sqisign_lvl1.rsp",
        "sqisign_lvl3.rsp",
        "sqisign_lvl5.rsp",
    };

    public void testTestVectors()
        throws Exception
    {
        long start = System.currentTimeMillis();
        TestUtils.testTestVector(true, false, false, "pqc/crypto/sqisign/kat", files,
            new TestUtils.SignerOperation()
            {
                @Override
                public SecureRandom getSecureRandom(byte[] seed)
                {
                    return new NISTSecureRandom(seed, null);
                }

                @Override
                public AsymmetricCipherKeyPairGenerator getAsymmetricCipherKeyPairGenerator(int fileIndex, SecureRandom random)
                {
                    SQIsignParameters parameters = PARAMETER_SETS[fileIndex];

                    SQIsignKeyPairGenerator kpGen = new SQIsignKeyPairGenerator();
                    kpGen.init(new SQIsignKeyGenerationParameters(random, parameters));
                    return kpGen;
                }

                @Override
                public byte[] getPublicKeyEncoded(CipherParameters pubParams)
                {
                    return ((SQIsignPublicKeyParameters)pubParams).getEncoded();
                }

                @Override
                public byte[] getPrivateKeyEncoded(CipherParameters privParams)
                {
                    return ((SQIsignPrivateKeyParameters)privParams).getEncoded();
                }

                @Override
                public Signer getSigner()
                {
                    return null;
                }

                @Override
                public MessageSigner getMessageSigner()
                {
                    return new SQIsignSigner();
                }
            });
        long end = System.currentTimeMillis();
        System.out.println("SQIsign time cost: " + (end - start) + "ms");
    }
}

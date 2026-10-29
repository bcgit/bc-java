package org.bouncycastle.jcajce.provider.kdf.kbkdf;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.KDFParameters;
import javax.crypto.KDFSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.KDFCounterBytesGenerator;
import org.bouncycastle.crypto.generators.KDFDoublePipelineIterationBytesGenerator;
import org.bouncycastle.crypto.generators.KDFFeedbackBytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KDFCounterParameters;
import org.bouncycastle.crypto.params.KDFDoublePipelineIterationParameters;
import org.bouncycastle.crypto.params.KDFFeedbackParameters;
import org.bouncycastle.jcajce.spec.KBKDFParameterSpec;
import org.bouncycastle.util.Arrays;

/**
 * javax.crypto.KDF SPI for the NIST SP 800-108 Rev. 1 key-based KDFs in counter, feedback and
 * double-pipeline iteration mode with an HMAC PRF, over the light-weight KDFCounterBytesGenerator,
 * KDFFeedbackBytesGenerator and KDFDoublePipelineIterationBytesGenerator. Each derivation builds a fresh
 * generator, so a KDF instance may be shared across threads.
 */
public class KBKDFSpi
    extends KDFSpi
{
    private static final int COUNTER = 0;
    private static final int FEEDBACK = 1;
    private static final int PIPELINE = 2;

    private final int mode;
    private final String digestName;

    KBKDFSpi(KDFParameters kdfParameters, int mode, String digestName)
        throws InvalidAlgorithmParameterException
    {
        super(requireNull(kdfParameters, "KBKDF does not support parameters"));
        this.mode = mode;
        this.digestName = digestName;
    }

    @Override
    protected KDFParameters engineGetParameters()
    {
        return null;
    }

    @Override
    protected SecretKey engineDeriveKey(String alg, AlgorithmParameterSpec derivationSpec)
        throws InvalidAlgorithmParameterException, NoSuchAlgorithmException
    {
        byte[] derivedKey = engineDeriveData(derivationSpec);

        try
        {
            return new SecretKeySpec(derivedKey, alg);
        }
        finally
        {
            Arrays.clear(derivedKey);
        }
    }

    @Override
    protected byte[] engineDeriveData(AlgorithmParameterSpec derivationSpec)
        throws InvalidAlgorithmParameterException
    {
        if (!(derivationSpec instanceof KBKDFParameterSpec spec))
        {
            throw new InvalidAlgorithmParameterException("Invalid AlgorithmParameterSpec provided");
        }

        byte[] keyIn = spec.getKeyIn();
        byte[] fixedInput = spec.getFixedInputData();
        int counterBits = spec.getCounterBits();

        Mac prf = new HMac(createDigest());
        DerivationFunction kdf;
        DerivationParameters params;

        try
        {
            switch (mode)
            {
            case COUNTER:
                if (counterBits == 0)
                {
                    throw new InvalidAlgorithmParameterException("counter mode requires a counter");
                }
                kdf = new KDFCounterBytesGenerator(prf);
                params = new KDFCounterParameters(keyIn, null, fixedInput, counterBits);
                break;
            case FEEDBACK:
                kdf = new KDFFeedbackBytesGenerator(prf);
                params = (counterBits == 0)
                    ? KDFFeedbackParameters.createWithoutCounter(keyIn, spec.getIV(), fixedInput)
                    : KDFFeedbackParameters.createWithCounter(keyIn, spec.getIV(), fixedInput, counterBits);
                break;
            default:
                kdf = new KDFDoublePipelineIterationBytesGenerator(prf);
                params = (counterBits == 0)
                    ? KDFDoublePipelineIterationParameters.createWithoutCounter(keyIn, fixedInput)
                    : KDFDoublePipelineIterationParameters.createWithCounter(keyIn, fixedInput, counterBits);
                break;
            }

            kdf.init(params);

            byte[] result = new byte[spec.getOutputLength()];
            kdf.generateBytes(result, 0, result.length);
            return result;
        }
        catch (IllegalArgumentException e)
        {
            throw new InvalidAlgorithmParameterException(e.getMessage(), e);
        }
        finally
        {
            Arrays.clear(keyIn);
        }
    }

    private Digest createDigest()
    {
        if ("SHA384".equals(digestName))
        {
            return new SHA384Digest();
        }
        if ("SHA512".equals(digestName))
        {
            return new SHA512Digest();
        }
        return new SHA256Digest();
    }

    private static KDFParameters requireNull(KDFParameters kdfParameters, String message)
        throws InvalidAlgorithmParameterException
    {
        if (kdfParameters != null)
        {
            throw new InvalidAlgorithmParameterException(message);
        }
        return null;
    }

    public static class CounterHMacSHA256 extends KBKDFSpi
    {
        public CounterHMacSHA256(KDFParameters p) throws InvalidAlgorithmParameterException { super(p, COUNTER, "SHA256"); }
        public CounterHMacSHA256() throws InvalidAlgorithmParameterException { this(null); }
    }

    public static class CounterHMacSHA384 extends KBKDFSpi
    {
        public CounterHMacSHA384(KDFParameters p) throws InvalidAlgorithmParameterException { super(p, COUNTER, "SHA384"); }
        public CounterHMacSHA384() throws InvalidAlgorithmParameterException { this(null); }
    }

    public static class CounterHMacSHA512 extends KBKDFSpi
    {
        public CounterHMacSHA512(KDFParameters p) throws InvalidAlgorithmParameterException { super(p, COUNTER, "SHA512"); }
        public CounterHMacSHA512() throws InvalidAlgorithmParameterException { this(null); }
    }

    public static class FeedbackHMacSHA256 extends KBKDFSpi
    {
        public FeedbackHMacSHA256(KDFParameters p) throws InvalidAlgorithmParameterException { super(p, FEEDBACK, "SHA256"); }
        public FeedbackHMacSHA256() throws InvalidAlgorithmParameterException { this(null); }
    }

    public static class FeedbackHMacSHA384 extends KBKDFSpi
    {
        public FeedbackHMacSHA384(KDFParameters p) throws InvalidAlgorithmParameterException { super(p, FEEDBACK, "SHA384"); }
        public FeedbackHMacSHA384() throws InvalidAlgorithmParameterException { this(null); }
    }

    public static class FeedbackHMacSHA512 extends KBKDFSpi
    {
        public FeedbackHMacSHA512(KDFParameters p) throws InvalidAlgorithmParameterException { super(p, FEEDBACK, "SHA512"); }
        public FeedbackHMacSHA512() throws InvalidAlgorithmParameterException { this(null); }
    }

    public static class PipelineHMacSHA256 extends KBKDFSpi
    {
        public PipelineHMacSHA256(KDFParameters p) throws InvalidAlgorithmParameterException { super(p, PIPELINE, "SHA256"); }
        public PipelineHMacSHA256() throws InvalidAlgorithmParameterException { this(null); }
    }

    public static class PipelineHMacSHA384 extends KBKDFSpi
    {
        public PipelineHMacSHA384(KDFParameters p) throws InvalidAlgorithmParameterException { super(p, PIPELINE, "SHA384"); }
        public PipelineHMacSHA384() throws InvalidAlgorithmParameterException { this(null); }
    }

    public static class PipelineHMacSHA512 extends KBKDFSpi
    {
        public PipelineHMacSHA512(KDFParameters p) throws InvalidAlgorithmParameterException { super(p, PIPELINE, "SHA512"); }
        public PipelineHMacSHA512() throws InvalidAlgorithmParameterException { this(null); }
    }
}

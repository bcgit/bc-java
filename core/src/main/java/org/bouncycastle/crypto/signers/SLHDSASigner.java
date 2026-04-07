package org.bouncycastle.crypto.signers;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.SLHDSAParameters;
import org.bouncycastle.crypto.params.SLHDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.SLHDSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.slhdsa.SLHDSAEngine;
import org.bouncycastle.pqc.crypto.MessageSigner;

/**
 * SLH-DSA signer.
 * <p>
 * This version is based on the 3rd submission with deference to the updated reference
 * implementation on github as at November 9th 2021. This version includes the changes
 * for the countermeasure for the long-message second preimage attack - see
 * "https://github.com/sphincs/sphincsplus/commit/61cd2695c6f984b4f4d6ed675378ed9a486cbede"
 * for further details.
 * </p>
 */
public class SLHDSASigner
    implements MessageSigner
{
    private static final byte[] DEFAULT_PREFIX = new byte[]{ 0, 0 };

    private byte[] msgPrefix;
    private byte[] optRand;
    private SLHDSAPublicKeyParameters pubKey;
    private SLHDSAPrivateKeyParameters privKey;
    private SecureRandom random;

    private byte[] pkSeed, pkRoot, skSeed, skPrf;

    /**
     * Base constructor.
     */
    public SLHDSASigner()
    {
    }

    public void init(boolean forSigning, CipherParameters param)
    {
        if (param instanceof ParametersWithContext)
        {
            ParametersWithContext withContext = (ParametersWithContext)param;
            param = withContext.getParameters();

            int ctxLength = withContext.getContextLength();
            if (ctxLength > 255)
            {
                throw new IllegalArgumentException("context too long");
            }

            msgPrefix = new byte[2 + ctxLength];
            msgPrefix[0] = 0;
            msgPrefix[1] = (byte)ctxLength;
            withContext.copyContextTo(msgPrefix, 2, ctxLength);
        }
        else
        {
            msgPrefix = DEFAULT_PREFIX;
        }

        SLHDSAParameters parameters;
        if (forSigning)
        {
            pubKey = null;

            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom withRandom = (ParametersWithRandom)param;
                privKey = (SLHDSAPrivateKeyParameters)withRandom.getParameters();
                random = withRandom.getRandom();
            }
            else
            {
                privKey = (SLHDSAPrivateKeyParameters)param;
                random = null;
            }

            skSeed = privKey.getSeed();
            skPrf = privKey.getPrf();
            pkSeed = privKey.getPublicSeed();
            pkRoot = privKey.getRoot();

            parameters = privKey.getParameters();

            // generate randomizer
            optRand = new byte[parameters.getN()];
        }
        else
        {
            pubKey = (SLHDSAPublicKeyParameters)param;
            privKey = null;
            random = null;

            skSeed = null;
            skPrf = null;
            pkSeed = pubKey.getSeed();
            pkRoot = pubKey.getRoot();

            parameters = pubKey.getParameters();
        }

        if (parameters.isPreHash())
        {
            throw new IllegalArgumentException("\"pure\" slh-dsa must use non pre-hash parameters");
        }
    }

    public byte[] generateSignature(byte[] message)
    {
        if (random != null)
        {
            random.nextBytes(optRand);
        }
        else
        {
            System.arraycopy(privKey.getPublicSeed(), 0, optRand, 0, optRand.length);
        }

        return SLHDSAEngine.internalGenerateSignature(privKey.getParameters(), skSeed, skPrf, pkSeed, pkRoot, msgPrefix, message, optRand);
    }

    // Equivalent to slh_verify_internal from specs
    public boolean verifySignature(byte[] message, byte[] signature)
    {
        return SLHDSAEngine.internalVerifySignature(pubKey.getParameters(), pkSeed, pkRoot, msgPrefix, message, signature);
    }

    protected boolean internalVerifySignature(byte[] message, byte[] signature)
    {
        return SLHDSAEngine.internalVerifySignature(pubKey.getParameters(), pkSeed, pkRoot, null, message, signature);
    }
    
    protected byte[] internalGenerateSignature(byte[] message, byte[] optRand)
    {
        return SLHDSAEngine.internalGenerateSignature(privKey.getParameters(), skSeed, skPrf, pkSeed, pkRoot, null, message, optRand);
    }
}

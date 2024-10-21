package org.bouncycastle.pqc.crypto.mldsa;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.params.ParametersWithRandom;

public class MLDSASigner
    implements Signer
{
    private static final byte[] EMPTY_CONTEXT = new byte[0];

    private MLDSAPublicKeyParameters pubKey;
    private MLDSAPrivateKeyParameters privKey;
    private SecureRandom random;

    private MLDSAEngine engine;
    private SHAKEDigest msgDigest;

    public MLDSASigner()
    {
    }

    public void init(boolean forSigning, CipherParameters param)
    {
        byte[] ctx = EMPTY_CONTEXT;
        if (param instanceof ParametersWithContext)
        {
            ParametersWithContext withContext = (ParametersWithContext)param;
            ctx = withContext.getContext();
            param = withContext.getParameters();

            if (ctx.length > 255)
            {
                throw new IllegalArgumentException("context too long");
            }
        }

        MLDSAParameters parameters;
        if (forSigning)
        {
            pubKey = null;

            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom withRandom = (ParametersWithRandom)param;
                privKey = (MLDSAPrivateKeyParameters)withRandom.getParameters();
                random = withRandom.getRandom();
            }
            else
            {
                privKey = (MLDSAPrivateKeyParameters)param;
                random = null;
            }

            parameters = privKey.getParameters();
            engine = parameters.getEngine(random);

            engine.initSign(privKey.tr, false, ctx);
        }
        else
        {
            pubKey = (MLDSAPublicKeyParameters)param;
            privKey = null;
            random = null;

            parameters = pubKey.getParameters();
            engine = parameters.getEngine(null);

            engine.initVerify(pubKey.rho, pubKey.t1, false, ctx);
        }

        if (parameters.isPreHash())
        {
            throw new IllegalArgumentException("\"pure\" ml-dsa must use non pre-hash parameters");
        }

        reset();
    }

    public void update(byte b)
    {
        msgDigest.update(b);
    }

    public void update(byte[] in, int off, int len)
    {
        msgDigest.update(in, off, len);
    }

    public byte[] generateSignature()
        throws CryptoException, DataLengthException
    {
        byte[] rnd = new byte[MLDSAEngine.RndBytes];
        if (random != null)
        {
            random.nextBytes(rnd);
        }

        byte[] sig = engine.generateSignature(msgDigest, privKey.rho, privKey.k, privKey.t0, privKey.s1, privKey.s2, rnd);

        reset();

        return sig;
    }

    public boolean verifySignature(byte[] signature)
    {
        boolean isTrue = engine.verifyInternal(signature, signature.length, msgDigest, pubKey.rho, pubKey.t1);

        reset();

        return isTrue;
    }

    public void reset()
    {
        msgDigest = engine.getShake256Digest();
    }

    protected byte[] internalGenerateSignature(byte[] message, byte[] random)
    {
        MLDSAEngine engine = privKey.getParameters().getEngine(this.random);

        engine.initSign(privKey.tr, false, null);

        return engine.signInternal(message, message.length, privKey.rho, privKey.k, privKey.t0, privKey.s1, privKey.s2, random);
    }

    protected boolean internalVerifySignature(byte[] message, byte[] signature)
    {
        MLDSAEngine engine = pubKey.getParameters().getEngine(random);

        engine.initVerify(pubKey.rho, pubKey.t1, false, null);

        SHAKEDigest msgDigest = engine.getShake256Digest();

        msgDigest.update(message, 0, message.length);

        return engine.verifyInternal(signature, signature.length, msgDigest, pubKey.rho, pubKey.t1);
    }
}

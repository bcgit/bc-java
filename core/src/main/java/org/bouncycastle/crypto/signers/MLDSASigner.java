package org.bouncycastle.crypto.signers;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.mldsa.MLDSAEngine;

public class MLDSASigner
    implements Signer
{
    private static final byte[] EMPTY_CONTEXT = new byte[0];
    private MLDSAPublicKeyParameters pubKey;
    private MLDSAPrivateKeyParameters privKey;
    private SecureRandom random;
    private MLDSAEngine engine;
    private SHAKEDigest msgDigest;

    private byte[] rho, k, t0, t1, s1, s2;
    
    public MLDSASigner()
    {
    }

    public void init(boolean forSigning, CipherParameters param)
    {
        byte[] ctx = EMPTY_CONTEXT;

        this.rho = this.k = this.t0 = this.t1 = this.s1 = this.s2 = null;

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
            engine = MLDSAEngine.getInstance(parameters, random);

            this.rho = privKey.getRho();
            this.t0 = privKey.getT0();
            this.k = privKey.getK();
            this.s1 = privKey.getS1();
            this.s2 = privKey.getS2();

            engine.initSign(privKey.getTr(), false, ctx);
        }
        else
        {
            pubKey = (MLDSAPublicKeyParameters)param;
            privKey = null;
            random = null;

            parameters = pubKey.getParameters();
            engine = MLDSAEngine.getInstance(parameters, null);

            this.t1 = pubKey.getT1();
            this.rho = pubKey.getRho();

            engine.initVerify(rho, t1, false, ctx);
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

    public byte[] generateMu()
        throws CryptoException, DataLengthException
    {
        byte[] mu = engine.generateMu(msgDigest);

        reset();

        return mu;
    }

    public byte[] generateMuSignature(byte[] mu)
        throws CryptoException, DataLengthException
    {
        if (mu.length != MLDSAEngine.CrhBytes)
        {
            throw new DataLengthException("mu value must be " + MLDSAEngine.CrhBytes + " bytes");
        }
        byte[] rnd = new byte[MLDSAEngine.RndBytes];
        if (random != null)
        {
            random.nextBytes(rnd);
        }

        msgDigest.reset();

        byte[] sig = engine.generateSignature(mu, msgDigest, rho, k, t0, s1, s2, rnd);

        reset();

        return sig;
    }

    public byte[] generateSignature()
        throws CryptoException, DataLengthException
    {
        byte[] rnd = new byte[MLDSAEngine.RndBytes];
        if (random != null)
        {
            random.nextBytes(rnd);
        }

        byte[] mu = engine.generateMu(msgDigest);
        byte[] sig = engine.generateSignature(mu, msgDigest, rho, k, t0, s1, s2, rnd);

        reset();

        return sig;
    }

    public boolean verifyMu(byte[] mu)
    {
        if (mu.length != MLDSAEngine.CrhBytes)
        {
            throw new DataLengthException("mu value must be " + MLDSAEngine.CrhBytes + " bytes");
        }

        boolean isTrue = engine.verifyInternalMu(mu);

        reset();

        return isTrue;
    }

    public boolean verifySignature(byte[] signature)
    {
        boolean isTrue = engine.verifyInternal(signature, signature.length, msgDigest, rho, t1);

        reset();

        return isTrue;
    }

    public boolean verifyMuSignature(byte[] mu, byte[] signature)
    {
        if (mu.length != MLDSAEngine.CrhBytes)
        {
            throw new DataLengthException("mu value must be " + MLDSAEngine.CrhBytes + " bytes");
        }

        msgDigest.reset();

        boolean isTrue = engine.verifyInternalMuSignature(mu, signature, signature.length, msgDigest, rho, t1);

        reset();

        return isTrue;
    }

    public void reset()
    {
        msgDigest = engine.getShake256Digest();
    }

    // only used for validation testing
    protected byte[] internalGenerateSignature(byte[] message, byte[] random)
    {
        MLDSAEngine engine = MLDSAEngine.getInstance(privKey.getParameters(), this.random);

        engine.initSign(privKey.getTr(), false, null);

        return engine.signInternal(message, message.length, rho, k, t0, s1, s2, random);
    }

    // only used for validation testing
    protected boolean internalVerifySignature(byte[] message, byte[] signature)
    {
        MLDSAEngine engine = MLDSAEngine.getInstance(pubKey.getParameters(), random);

        engine.initVerify(rho, t1, false, null);

        SHAKEDigest msgDigest = engine.getShake256Digest();

        msgDigest.update(message, 0, message.length);

        return engine.verifyInternal(signature, signature.length, msgDigest, rho, t1);
    }
}

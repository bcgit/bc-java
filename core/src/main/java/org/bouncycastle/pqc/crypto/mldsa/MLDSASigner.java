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

    private MLDSAPrivateKeyParameters privKey;
    private MLDSAPublicKeyParameters pubKey;

    private MLDSAEngine engine;
    private SHAKEDigest msgDigest;

    private SecureRandom random;

    public MLDSASigner()
    {
    }

    public void init(boolean forSigning, CipherParameters param)
    {
        boolean isPreHash;
        byte[] ctx;

        if (param instanceof ParametersWithContext)
        {
            ctx = ((ParametersWithContext)param).getContext();
            param = ((ParametersWithContext)param).getParameters();

            if (ctx.length > 255)
            {
                throw new IllegalArgumentException("context too long");
            }
        }
        else
        {
            ctx = EMPTY_CONTEXT;
        }


        if (forSigning)
        {
            if (param instanceof ParametersWithRandom)
            {
                privKey = (MLDSAPrivateKeyParameters)((ParametersWithRandom)param).getParameters();
                random = ((ParametersWithRandom)param).getRandom();
            }
            else
            {
                privKey = (MLDSAPrivateKeyParameters)param;
                random = null;
            }

            engine = privKey.getParameters().getEngine(this.random);

            engine.initSign(privKey.tr, false, ctx);

            msgDigest = engine.getShake256Digest();

            isPreHash = privKey.getParameters().isPreHash();
        }
        else
        {
            pubKey = (MLDSAPublicKeyParameters)param;

            engine = pubKey.getParameters().getEngine(random);

            engine.initVerify(pubKey.rho, pubKey.t1, false, ctx);

            msgDigest = engine.getShake256Digest();

            isPreHash = pubKey.getParameters().isPreHash();
        }

        if (isPreHash)
        {
            throw new IllegalArgumentException("\"pure\" ml-dsa must use non pre-hash parameters");
        }
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

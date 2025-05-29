package org.bouncycastle.pqc.crypto.mldsa;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.DigestUtils;

public class HashMLDSASigner
    implements Signer
{
    private static final byte[] EMPTY_CONTEXT = new byte[0];

    private MLDSAPublicKeyParameters pubKey;
    private MLDSAPrivateKeyParameters privKey;
    private SecureRandom random;

    private MLDSAEngine engine;
    private Digest digest;

    public HashMLDSASigner()
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
            engine.initSign(privKey.tr, true, ctx);
        }
        else
        {
            pubKey = (MLDSAPublicKeyParameters)param;
            privKey = null;
            random = null;
            parameters = pubKey.getParameters();
            engine = parameters.getEngine(null);
            engine.initVerify(pubKey.rho, pubKey.t1, true, ctx);
        }
        digest = engine.shake256Digest;
        byte[] digestOIDEncoding;
        try
        {
            digestOIDEncoding = DigestUtils.getDigestOid(digest.getAlgorithmName()).getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw new IllegalStateException("oid encoding failed: " + e.getMessage());
        }
        digest.update(digestOIDEncoding, 0, digestOIDEncoding.length);
    }

    public void update(byte b)
    {
        digest.update(b);
    }

    public void update(byte[] in, int off, int len)
    {
        digest.update(in, off, len);
    }

    public byte[] generateSignature()
        throws CryptoException, DataLengthException
    {
        byte[] rnd = new byte[MLDSAEngine.RndBytes];
        if (random != null)
        {
            random.nextBytes(rnd);
        }
        byte[] mu = engine.generateMu(engine.shake256Digest);
        return engine.generateSignature(mu, engine.getShake256Digest(), privKey.rho, privKey.k, privKey.t0, privKey.s1, privKey.s2, rnd);
    }

    public boolean verifySignature(byte[] signature)
    {
        byte[] mu = engine.generateMu(engine.shake256Digest);
        return engine.verifyInternalMuSignature(mu, signature, signature.length, engine.getShake256Digest(), pubKey.rho, pubKey.t1);
    }

    /**
     * reset the internal state
     */
    public void reset()
    {
        digest.reset();
    }

//    TODO: these are probably no longer correct and also need to be marked as protected
//    protected byte[] internalGenerateSignature(byte[] message, SecureRandom random)
//    {
//        MLDSAEngine engine = privKey.getParameters().getEngine(random);
//
//        return engine.signInternal(message, message.length, privKey.rho, privKey.k, privKey.t0, privKey.s1, privKey.s2, random);
//    }
//
//    protected boolean internalVerifySignature(byte[] message, byte[] signature)
//    {
//        MLDSAEngine engine = pubKey.getParameters().getEngine(random);
//
//        return engine.verifyInternal(signature, signature.length, message, message.length, pubKey.rho, pubKey.t1);
//    }

//    private static Digest createDigest(MLDSAParameters parameters)
//    {
    //TODO: MLDSA44 may use SHA2-256, SHA3-256, SHAKE128
    //      MLDSA65 may use SHA3-384, SHA2-512
    //      MLDSA44/65/87 may use SHA2-512, SHA3-512, SHAKE256

//        switch (parameters.getType())
//        {
//        case MLDSAParameters.TYPE_PURE:
//        case MLDSAParameters.TYPE_SHA2_512:
//            return new SHAKEDigest(256);
//        default:
//            throw new IllegalArgumentException("unknown parameters type");
//        }
//    }
}

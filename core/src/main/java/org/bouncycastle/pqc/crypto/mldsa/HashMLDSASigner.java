package org.bouncycastle.pqc.crypto.mldsa;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
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
    private byte[] digestOIDEncoding;

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

        initDigest(parameters);
    }

    private void initDigest(MLDSAParameters parameters)
    {
        digest = createDigest(parameters);

        ASN1ObjectIdentifier oid = DigestUtils.getDigestOid(digest.getAlgorithmName());
        try
        {
            digestOIDEncoding = oid.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw new IllegalStateException("oid encoding failed: " + e.getMessage());
        }
    }

    public void update(byte b)
    {
        digest.update(b);
    }

    public void update(byte[] in, int off, int len)
    {
        digest.update(in, off, len);
    }

    public byte[] generateSignature() throws CryptoException, DataLengthException
    {
        SHAKEDigest msgDigest = finishPreHash();

        byte[] rnd = new byte[MLDSAEngine.RndBytes];
        if (random != null)
        {
            random.nextBytes(rnd);
        }

        return engine.generateSignature(msgDigest, privKey.rho, privKey.k, privKey.t0, privKey.s1, privKey.s2, rnd);
    }

    public boolean verifySignature(byte[] signature)
    {
        SHAKEDigest msgDigest = finishPreHash();

        return engine.verifyInternal(signature, signature.length, msgDigest, pubKey.rho, pubKey.t1);
    }

    /**
     * reset the internal state
     */
    public void reset()
    {
        digest.reset();
    }

    private SHAKEDigest finishPreHash()
    {
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        SHAKEDigest msgDigest = engine.getShake256Digest();
        // TODO It should be possible to include digestOIDEncoding in the memo'ed digest
        msgDigest.update(digestOIDEncoding, 0, digestOIDEncoding.length);
        msgDigest.update(hash, 0, hash.length);
        return msgDigest;
    }

//    TODO: these are probably no longer correct and also need to be marked as protected
//    protected byte[] internalGenerateSignature(byte[] message, byte[] random)
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

    private static Digest createDigest(MLDSAParameters parameters)
    {
        switch (parameters.getType())
        {
        case MLDSAParameters.TYPE_PURE:
        case MLDSAParameters.TYPE_SHA2_512:
            return new SHA512Digest();
        default:
            throw new IllegalArgumentException("unknown parameters type");
        }
    }
}

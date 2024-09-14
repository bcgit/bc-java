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
import org.bouncycastle.util.Arrays;

public class HashMLDSASigner
    implements Signer
{
    private static final byte[] EMPTY_CONTEXT = new byte[0];
    
    private MLDSAPrivateKeyParameters privKey;
    private MLDSAPublicKeyParameters pubKey;

    private MLDSAEngine engine;
    private SecureRandom random;
    private Digest digest;
    private byte[] digestOidEncoding;

    public HashMLDSASigner()
    {
        this.digest = new SHA512Digest();
    }

    public void init(boolean forSigning, CipherParameters param)
    {
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

            engine.initSign(privKey.tr, true, ctx);

            initDigest(privKey);
        }
        else
        {
            pubKey = (MLDSAPublicKeyParameters)param;

            engine = pubKey.getParameters().getEngine(this.random);
            
            engine.initVerify(pubKey.rho, pubKey.t1, true, ctx);

            initDigest(pubKey);
        }

        reset();
    }

    private void initDigest(MLDSAKeyParameters key)
    {
        if (key.getParameters().isPreHash())
        {
            digest = key.getParameters().createDigest();
        }

        ASN1ObjectIdentifier oid = DigestUtils.getDigestOid(digest.getAlgorithmName());
        try
        {
            digestOidEncoding = oid.getEncoded(ASN1Encoding.DER);
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

    @Override
    public void update(byte[] in, int off, int len)
    {
        digest.update(in, off, len);
    }

    @Override
    public byte[] generateSignature() throws CryptoException, DataLengthException
    {
        SHAKEDigest msgDigest = engine.getShake256Digest();

        byte[] rnd = new byte[MLDSAEngine.RndBytes];
        if (random != null)
        {
            random.nextBytes(rnd);
        }

        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        byte[] ds_message = Arrays.concatenate(digestOidEncoding, hash);

        msgDigest.update(ds_message, 0, ds_message.length);

        return engine.generateSignature(msgDigest, privKey.rho, privKey.k, privKey.t0, privKey.s1, privKey.s2, rnd);
    }

    @Override
    public boolean verifySignature(byte[] signature)
    {
        SHAKEDigest msgDigest = engine.getShake256Digest();
        byte[] hash = new byte[digest.getDigestSize()];

        digest.doFinal(hash, 0);

        byte[] ds_message = Arrays.concatenate(digestOidEncoding, hash);

        msgDigest.update(ds_message, 0, ds_message.length);

        return engine.verifyInternal(signature, signature.length, msgDigest, pubKey.rho, pubKey.t1);
    }

    /**
     * reset the internal state
     */
    @Override
    public void reset()
    {
        digest.reset();
    }

//    TODO: these are probably no longer correct and also need to be marked as protected
//    public byte[] internalGenerateSignature(byte[] message, byte[] random)
//    {
//        MLDSAEngine engine = privKey.getParameters().getEngine(this.random);
//
//        return engine.signInternal(message, message.length, privKey.rho, privKey.k, privKey.t0, privKey.s1, privKey.s2, random);
//    }
//
//    public boolean internalVerifySignature(byte[] message, byte[] signature)
//    {
//        MLDSAEngine engine = pubKey.getParameters().getEngine(random);
//
//        return engine.verifyInternal(signature, signature.length, message, message.length, pubKey.rho, pubKey.t1);
//    }
}

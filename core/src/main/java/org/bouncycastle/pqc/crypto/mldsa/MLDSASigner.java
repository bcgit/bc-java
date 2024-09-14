package org.bouncycastle.pqc.crypto.mldsa;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.crypto.params.ParametersWithRandom;

public class MLDSASigner
    implements Signer
{
    private MLDSAPrivateKeyParameters privKey;
    private MLDSAPublicKeyParameters pubKey;

    private MLDSAEngine engine;
    private SHAKEDigest msgDigest;

    private SecureRandom random;

    // TODO: temporary
    private ByteArrayOutputStream bOut = new ByteArrayOutputStream();

    public MLDSASigner()
    {
    }

    public void init(boolean forSigning, CipherParameters param)
    {
        boolean isPreHash;

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

            byte[] ctx = privKey.getContext();
            if (ctx.length > 255)
            {
                throw new IllegalArgumentException("context too long");
            }

            engine.initSign(privKey.tr, false, ctx);

            msgDigest = engine.getShake256Digest();

            isPreHash = privKey.getParameters().isPreHash();
        }
        else
        {
            pubKey = (MLDSAPublicKeyParameters)param;
            engine = null;
            msgDigest =  null;
            isPreHash = pubKey.getParameters().isPreHash();
        }

        if (isPreHash)
        {
            throw new IllegalArgumentException("\"pure\" ml-dsa must use non pre-hash parameters");
        }
    }

    public void update(byte b)
    {
        if (msgDigest != null)
        {
            msgDigest.update(b);
        }
        else
        {
            bOut.write(b);
        }
    }

    public void update(byte[] in, int off, int len)
    {
        if (msgDigest != null)
        {
            msgDigest.update(in, off, len);
        }
        else
        {
            bOut.write(in, off, len);
        }
    }

    public byte[] generateSignature()
        throws CryptoException, DataLengthException
    {
        byte[] rnd = new byte[MLDSAEngine.RndBytes];
        if (random != null)
        {
            random.nextBytes(rnd);
        }

        return engine.generateSignature(msgDigest, privKey.rho, privKey.k, privKey.t0, privKey.s1, privKey.s2, rnd);
    }

    public boolean verifySignature(byte[] signature)
    {
        boolean isTrue = verifySignature(bOut.toByteArray(), signature);

        bOut.reset();

        return isTrue;
    }

    public void reset()
    {
        bOut.reset();
    }

    byte[] generateSignature(byte[] message)
    {
        byte[] rnd = new byte[MLDSAEngine.RndBytes];
        if (random != null)
        {
            random.nextBytes(rnd);
        }

        return engine.signInternal(message, message.length, privKey.rho, privKey.k, privKey.t0, privKey.s1, privKey.s2, rnd);
    }
    
    protected byte[] internalGenerateSignature(byte[] message, byte[] random)
    {
        MLDSAEngine engine = privKey.getParameters().getEngine(this.random);

        engine.initSign(privKey.tr, false, null);
        
        return engine.signInternal(message, message.length, privKey.rho, privKey.k, privKey.t0, privKey.s1, privKey.s2, random);
    }

    boolean verifySignature(byte[] message, byte[] signature)
    {
        MLDSAEngine engine = pubKey.getParameters().getEngine(random);

        byte[] ctx = pubKey.getContext();
        if (ctx.length > 255)
        {
            throw new RuntimeException("Context too long");
        }

        byte[] ds_message = new byte[1 + 1 + ctx.length + message.length];
        ds_message[0] = 0;
        ds_message[1] = (byte)ctx.length;
        System.arraycopy(ctx, 0, ds_message, 2, ctx.length);
        System.arraycopy(message, 0, ds_message, 2 + ctx.length, message.length);

        return engine.verifyInternal(signature, signature.length, ds_message, ds_message.length, pubKey.rho, pubKey.t1);
    }

    public boolean internalVerifySignature(byte[] message, byte[] signature)
    {
        MLDSAEngine engine = pubKey.getParameters().getEngine(random);

        return engine.verifyInternal(signature, signature.length, message, message.length, pubKey.rho, pubKey.t1);
    }
}

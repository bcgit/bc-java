package org.bouncycastle.pqc.crypto.mldsa;

import java.security.InvalidParameterException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;

public class MLDSASigner
    implements MessageSigner
{
    private MLDSAPrivateKeyParameters privKey;
    private MLDSAPublicKeyParameters pubKey;

    private SecureRandom random;

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

            isPreHash = privKey.getParameters().createDigest() != null;
        }
        else
        {
            pubKey = (MLDSAPublicKeyParameters)param;
            isPreHash = pubKey.getParameters().createDigest() != null;
        }

        if (isPreHash)
        {
            throw new InvalidParameterException("\"pure\" slh-dsa must use non pre-hash parameters");
        }
    }

    public byte[] generateSignature(byte[] message)
    {
        MLDSAEngine engine = privKey.getParameters().getEngine(random);

        byte[] ctx = privKey.getContext();
        if (ctx.length > 255)
        {
            throw new RuntimeException("Context too long");
        }

        byte[] rnd = new byte[MLDSAEngine.RndBytes];
        if (random != null)
        {
            random.nextBytes(rnd);
        }

        byte[] ds_message = new byte[1 + 1 + ctx.length + message.length];
        ds_message[0] = 0;
        ds_message[1] = (byte)ctx.length;
        System.arraycopy(ctx, 0, ds_message, 2, ctx.length);
        System.arraycopy(message, 0, ds_message, 2 + ctx.length, message.length);

        return engine.signInternal(ds_message, ds_message.length, privKey.rho, privKey.k, privKey.tr, privKey.t0, privKey.s1, privKey.s2, rnd);
    }
    public byte[] internalGenerateSignature(byte[] message, byte[] random)
    {
        MLDSAEngine engine = privKey.getParameters().getEngine(this.random);

        return engine.signInternal(message, message.length, privKey.rho, privKey.k, privKey.tr, privKey.t0, privKey.s1, privKey.s2, random);
    }

    public boolean verifySignature(byte[] message, byte[] signature)
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

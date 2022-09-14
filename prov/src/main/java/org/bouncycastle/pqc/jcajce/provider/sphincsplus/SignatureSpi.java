package org.bouncycastle.pqc.jcajce.provider.sphincsplus;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusSigner;

public class SignatureSpi
    extends java.security.SignatureSpi
{
    private final Digest digest;
    private final SPHINCSPlusSigner signer;

    protected SignatureSpi(Digest digest, SPHINCSPlusSigner signer)
    {
        this.digest = digest;
        this.signer = signer;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        if (publicKey instanceof BCSPHINCSPlusPublicKey)
        {
            BCSPHINCSPlusPublicKey key = (BCSPHINCSPlusPublicKey)publicKey;

            CipherParameters param = key.getKeyParams();

            signer.init(false, param);
        }
        else
        {
            throw new InvalidKeyException("unknown public key passed to SPHINCS+");
        }
    }

    protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
        throws InvalidKeyException
    {
        this.appRandom = random;
        engineInitSign(privateKey);
    }

    protected void engineInitSign(PrivateKey privateKey)
        throws InvalidKeyException
    {
        if (privateKey instanceof BCSPHINCSPlusPrivateKey)
        {
            BCSPHINCSPlusPrivateKey key = (BCSPHINCSPlusPrivateKey)privateKey;

            CipherParameters param = key.getKeyParams();

            if (appRandom != null)
            {
                signer.init(true, new ParametersWithRandom(param, appRandom));
            }
            else
            {
                signer.init(true, param);
            }
        }
        else
        {
            throw new InvalidKeyException("unknown private key passed to SPHINCS+");
        }
    }

    protected void engineUpdate(byte b)
        throws SignatureException
    {
        digest.update(b);
    }

    protected void engineUpdate(byte[] b, int off, int len)
        throws SignatureException
    {
        digest.update(b, off, len);
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        try
        {
            byte[] sig = signer.generateSignature(hash);

            return sig;
        }
        catch (Exception e)
        {
            throw new SignatureException(e.toString());
        }
    }

    protected boolean engineVerify(byte[] sigBytes)
        throws SignatureException
    {
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        return signer.verifySignature(hash, sigBytes);
    }

    protected void engineSetParameter(AlgorithmParameterSpec params)
    {
        // TODO
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated replaced with #engineSetParameter(java.security.spec.AlgorithmParameterSpec)
     */
    protected void engineSetParameter(String param, Object value)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated
     */
    protected Object engineGetParameter(String param)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    static public class Direct
        extends SignatureSpi
    {
        public Direct()
        {
            super(new NullDigest(), new SPHINCSPlusSigner());
        }
    }
}

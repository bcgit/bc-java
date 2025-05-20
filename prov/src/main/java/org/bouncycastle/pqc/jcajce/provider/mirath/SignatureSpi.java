package org.bouncycastle.pqc.jcajce.provider.mirath;

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.mirath.MirathParameters;
import org.bouncycastle.pqc.crypto.mirath.MirathSigner;
import org.bouncycastle.util.Strings;

public class SignatureSpi
    extends java.security.Signature
{
    private final ByteArrayOutputStream bOut;
    private final MirathSigner signer;
    private SecureRandom random;
    private final MirathParameters parameters;

    protected SignatureSpi(MirathSigner signer)
    {
        super("Mirath");

        this.bOut = new ByteArrayOutputStream();
        this.signer = signer;
        this.parameters = null;
    }

    protected SignatureSpi(MirathSigner signer, MirathParameters parameters)
    {
        super(Strings.toUpperCase(parameters.getName()));
        this.parameters = parameters;

        this.bOut = new ByteArrayOutputStream();
        this.signer = signer;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        if (!(publicKey instanceof BCMirathPublicKey))
        {
            try
            {
                publicKey = new BCMirathPublicKey(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("unknown public key passed to Mirath: " + e.getMessage(), e);
            }
        }

        BCMirathPublicKey key = (BCMirathPublicKey)publicKey;

        if (parameters != null)
        {
            String canonicalAlg = Strings.toUpperCase(parameters.getName());
            if (!canonicalAlg.equals(key.getAlgorithm()))
            {
                throw new InvalidKeyException("signature configured for " + canonicalAlg);
            }
        }

        signer.init(false, key.getKeyParams());
    }

    protected void engineInitSign(PrivateKey privateKey, SecureRandom random)
        throws InvalidKeyException
    {
        this.random = random;
        engineInitSign(privateKey);
    }

    protected void engineInitSign(PrivateKey privateKey)
        throws InvalidKeyException
    {
        if (privateKey instanceof BCMirathPrivateKey)
        {
            BCMirathPrivateKey key = (BCMirathPrivateKey)privateKey;
            CipherParameters param = key.getKeyParams();

            if (parameters != null)
            {
                String canonicalAlg = Strings.toUpperCase(parameters.getName());
                if (!canonicalAlg.equals(key.getAlgorithm()))
                {
                    throw new InvalidKeyException("signature configured for " + canonicalAlg);
                }
            }

            if (random != null)
            {
                signer.init(true, new ParametersWithRandom(param, random));
            }
            else
            {
                signer.init(true, param);
            }
        }
        else
        {
            throw new InvalidKeyException("unknown private key passed to Mirath");
        }
    }

    protected void engineUpdate(byte b)
        throws SignatureException
    {
        bOut.write(b);
    }

    protected void engineUpdate(byte[] b, int off, int len)
        throws SignatureException
    {
        bOut.write(b, off, len);
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        try
        {
            byte[] message = bOut.toByteArray();

            bOut.reset();

            return signer.generateSignature(message);
        }
        catch (Exception e)
        {
            throw new SignatureException(e.toString());
        }
    }

    protected boolean engineVerify(byte[] sigBytes)
        throws SignatureException
    {
        byte[] message = bOut.toByteArray();

        bOut.reset();

        return signer.verifySignature(message, sigBytes);
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

    public static class Base
        extends SignatureSpi
    {
        public Base()
        {
            super(new MirathSigner());
        }
    }

    public static class Mirath_1a_fast
        extends SignatureSpi
    {
        public Mirath_1a_fast()
        {
            super(new MirathSigner(), MirathParameters.mirath_1a_fast);
        }
    }

    public static class Mirath_1a_short
        extends SignatureSpi
    {
        public Mirath_1a_short()
        {
            super(new MirathSigner(), MirathParameters.mirath_1a_short);
        }
    }

    public static class Mirath_1b_fast
        extends SignatureSpi
    {
        public Mirath_1b_fast()
        {
            super(new MirathSigner(), MirathParameters.mirath_1b_fast);
        }
    }

    public static class Mirath_1b_short
        extends SignatureSpi
    {
        public Mirath_1b_short()
        {
            super(new MirathSigner(), MirathParameters.mirath_1b_short);
        }
    }

    public static class Mirath_3a_fast
        extends SignatureSpi
    {
        public Mirath_3a_fast()
        {
            super(new MirathSigner(), MirathParameters.mirath_3a_fast);
        }
    }

    public static class Mirath_3a_short
        extends SignatureSpi
    {
        public Mirath_3a_short()
        {
            super(new MirathSigner(), MirathParameters.mirath_3a_short);
        }
    }

    public static class Mirath_3b_fast
        extends SignatureSpi
    {
        public Mirath_3b_fast()
        {
            super(new MirathSigner(), MirathParameters.mirath_3b_fast);
        }
    }

    public static class Mirath_3b_short
        extends SignatureSpi
    {
        public Mirath_3b_short()
        {
            super(new MirathSigner(), MirathParameters.mirath_3b_short);
        }
    }

    public static class Mirath_5a_fast
        extends SignatureSpi
    {
        public Mirath_5a_fast()
        {
            super(new MirathSigner(), MirathParameters.mirath_5a_fast);
        }
    }

    public static class Mirath_5a_short
        extends SignatureSpi
    {
        public Mirath_5a_short()
        {
            super(new MirathSigner(), MirathParameters.mirath_5a_short);
        }
    }

    public static class Mirath_5b_fast
        extends SignatureSpi
    {
        public Mirath_5b_fast()
        {
            super(new MirathSigner(), MirathParameters.mirath_5b_fast);
        }
    }

    public static class Mirath_5b_short
        extends SignatureSpi
    {
        public Mirath_5b_short()
        {
            super(new MirathSigner(), MirathParameters.mirath_5b_short);
        }
    }
}


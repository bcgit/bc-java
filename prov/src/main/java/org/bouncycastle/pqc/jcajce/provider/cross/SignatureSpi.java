package org.bouncycastle.pqc.jcajce.provider.cross;

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
import org.bouncycastle.pqc.crypto.cross.CrossParameters;
import org.bouncycastle.pqc.crypto.cross.CrossSigner;
import org.bouncycastle.util.Strings;

public class SignatureSpi
    extends java.security.Signature
{
    private final ByteArrayOutputStream bOut;
    private final CrossSigner signer;
    private SecureRandom random;
    private final CrossParameters parameters;

    protected SignatureSpi(CrossSigner signer)
    {
        super("Cross");

        this.bOut = new ByteArrayOutputStream();
        this.signer = signer;
        this.parameters = null;
    }

    protected SignatureSpi(CrossSigner signer, CrossParameters parameters)
    {
        super(Strings.toUpperCase(parameters.getName()));
        this.parameters = parameters;

        this.bOut = new ByteArrayOutputStream();
        this.signer = signer;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        if (!(publicKey instanceof BCCrossPublicKey))
        {
            try
            {
                publicKey = new BCCrossPublicKey(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("unknown public key passed to Cross: " + e.getMessage());
            }
        }

        BCCrossPublicKey key = (BCCrossPublicKey)publicKey;

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
        if (privateKey instanceof BCCrossPrivateKey)
        {
            BCCrossPrivateKey key = (BCCrossPrivateKey)privateKey;
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
            throw new InvalidKeyException("unknown private key passed to Cross");
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
            super(new CrossSigner());
        }
    }

    public static class CrossRsdp1Small
        extends SignatureSpi
    {
        public CrossRsdp1Small()
        {
            super(new CrossSigner(), CrossParameters.cross_rsdp_1_small);
        }
    }

    public static class CrossRsdp1Balanced
        extends SignatureSpi
    {
        public CrossRsdp1Balanced()
        {
            super(new CrossSigner(), CrossParameters.cross_rsdp_1_balanced);
        }
    }

    public static class CrossRsdp1Fast
        extends SignatureSpi
    {
        public CrossRsdp1Fast()
        {
            super(new CrossSigner(), CrossParameters.cross_rsdp_1_fast);
        }
    }

    public static class CrossRsdp3Small
        extends SignatureSpi
    {
        public CrossRsdp3Small()
        {
            super(new CrossSigner(), CrossParameters.cross_rsdp_3_small);
        }
    }

    public static class CrossRsdp3Balanced
        extends SignatureSpi
    {
        public CrossRsdp3Balanced()
        {
            super(new CrossSigner(), CrossParameters.cross_rsdp_3_balanced);
        }
    }

    public static class CrossRsdp3Fast
        extends SignatureSpi
    {
        public CrossRsdp3Fast()
        {
            super(new CrossSigner(), CrossParameters.cross_rsdp_3_fast);
        }
    }

    public static class CrossRsdp5Small
        extends SignatureSpi
    {
        public CrossRsdp5Small()
        {
            super(new CrossSigner(), CrossParameters.cross_rsdp_5_small);
        }
    }

    public static class CrossRsdp5Balanced
        extends SignatureSpi
    {
        public CrossRsdp5Balanced()
        {
            super(new CrossSigner(), CrossParameters.cross_rsdp_5_balanced);
        }
    }

    public static class CrossRsdp5Fast
        extends SignatureSpi
    {
        public CrossRsdp5Fast()
        {
            super(new CrossSigner(), CrossParameters.cross_rsdp_5_fast);
        }
    }

    public static class CrossRsdpg1Small
        extends SignatureSpi
    {
        public CrossRsdpg1Small()
        {
            super(new CrossSigner(), CrossParameters.cross_rsdpg_1_small);
        }
    }

    public static class CrossRsdpg1Balanced
        extends SignatureSpi
    {
        public CrossRsdpg1Balanced()
        {
            super(new CrossSigner(), CrossParameters.cross_rsdpg_1_balanced);
        }
    }

    public static class CrossRsdpg1Fast
        extends SignatureSpi
    {
        public CrossRsdpg1Fast()
        {
            super(new CrossSigner(), CrossParameters.cross_rsdpg_1_fast);
        }
    }

    public static class CrossRsdpg3Small
        extends SignatureSpi
    {
        public CrossRsdpg3Small()
        {
            super(new CrossSigner(), CrossParameters.cross_rsdpg_3_small);
        }
    }

    public static class CrossRsdpg3Balanced
        extends SignatureSpi
    {
        public CrossRsdpg3Balanced()
        {
            super(new CrossSigner(), CrossParameters.cross_rsdpg_3_balanced);
        }
    }

    public static class CrossRsdpg3Fast
        extends SignatureSpi
    {
        public CrossRsdpg3Fast()
        {
            super(new CrossSigner(), CrossParameters.cross_rsdpg_3_fast);
        }
    }

    public static class CrossRsdpg5Small
        extends SignatureSpi
    {
        public CrossRsdpg5Small()
        {
            super(new CrossSigner(), CrossParameters.cross_rsdpg_5_small);
        }
    }

    public static class CrossRsdpg5Balanced
        extends SignatureSpi
    {
        public CrossRsdpg5Balanced()
        {
            super(new CrossSigner(), CrossParameters.cross_rsdpg_5_balanced);
        }
    }

    public static class CrossRsdpg5Fast
        extends SignatureSpi
    {
        public CrossRsdpg5Fast()
        {
            super(new CrossSigner(), CrossParameters.cross_rsdpg_5_fast);
        }
    }

}


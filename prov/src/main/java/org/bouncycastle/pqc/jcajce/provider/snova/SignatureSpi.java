package org.bouncycastle.pqc.jcajce.provider.snova;

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
import org.bouncycastle.pqc.crypto.snova.SnovaParameters;
import org.bouncycastle.pqc.crypto.snova.SnovaSigner;
import org.bouncycastle.util.Strings;

public class SignatureSpi
    extends java.security.Signature
{
    private final ByteArrayOutputStream bOut;
    private final SnovaSigner signer;
    private SecureRandom random;
    private final SnovaParameters parameters;

    protected SignatureSpi(SnovaSigner signer)
    {
        super("Snova");

        this.bOut = new ByteArrayOutputStream();
        this.signer = signer;
        this.parameters = null;
    }

    protected SignatureSpi(SnovaSigner signer, SnovaParameters parameters)
    {
        super(Strings.toUpperCase(parameters.getName()));
        this.parameters = parameters;

        this.bOut = new ByteArrayOutputStream();
        this.signer = signer;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        if (!(publicKey instanceof BCSnovaPublicKey))
        {
            try
            {
                publicKey = new BCSnovaPublicKey(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("unknown public key passed to Snova: " + e.getMessage());
            }
        }

        BCSnovaPublicKey key = (BCSnovaPublicKey)publicKey;

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
        if (privateKey instanceof BCSnovaPrivateKey)
        {
            BCSnovaPrivateKey key = (BCSnovaPrivateKey)privateKey;
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
            throw new InvalidKeyException("unknown private key passed to Snova");
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
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public Base()
        {
            super(new SnovaSigner());
        }
    }

    public static class SNOVA_24_5_4_SSK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_24_5_4_SSK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_24_5_4_SSK);
        }
    }

    public static class SNOVA_24_5_4_ESK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_24_5_4_ESK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_24_5_4_ESK);
        }
    }

    public static class SNOVA_24_5_4_SHAKE_ESK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_24_5_4_SHAKE_ESK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_24_5_4_SHAKE_ESK);
        }
    }

    public static class SNOVA_24_5_4_SHAKE_SSK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_24_5_4_SHAKE_SSK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_24_5_4_SHAKE_SSK);
        }
    }

    public static class SNOVA_24_5_5_SSK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_24_5_5_SSK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_24_5_5_SSK);
        }
    }

    public static class SNOVA_24_5_5_ESK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_24_5_5_ESK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_24_5_5_ESK);
        }
    }

    public static class SNOVA_24_5_5_SHAKE_ESK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_24_5_5_SHAKE_ESK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_24_5_5_SHAKE_ESK);
        }
    }

    public static class SNOVA_24_5_5_SHAKE_SSK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_24_5_5_SHAKE_SSK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_24_5_5_SHAKE_SSK);
        }
    }

    public static class SNOVA_25_8_3_SSK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_25_8_3_SSK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_25_8_3_SSK);
        }
    }

    public static class SNOVA_25_8_3_ESK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_25_8_3_ESK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_25_8_3_ESK);
        }
    }

    public static class SNOVA_25_8_3_SHAKE_ESK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_25_8_3_SHAKE_ESK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_25_8_3_SHAKE_ESK);
        }
    }

    public static class SNOVA_25_8_3_SHAKE_SSK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_25_8_3_SHAKE_SSK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_25_8_3_SHAKE_SSK);
        }
    }

    public static class SNOVA_29_6_5_SSK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_29_6_5_SSK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_29_6_5_SSK);
        }
    }

    public static class SNOVA_29_6_5_ESK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_29_6_5_ESK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_29_6_5_ESK);
        }
    }

    public static class SNOVA_29_6_5_SHAKE_ESK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_29_6_5_SHAKE_ESK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_29_6_5_SHAKE_ESK);
        }
    }

    public static class SNOVA_29_6_5_SHAKE_SSK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_29_6_5_SHAKE_SSK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_29_6_5_SHAKE_SSK);
        }
    }

    public static class SNOVA_37_8_4_SSK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_37_8_4_SSK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_37_8_4_SSK);
        }
    }

    public static class SNOVA_37_8_4_ESK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_37_8_4_ESK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_37_8_4_ESK);
        }
    }

    public static class SNOVA_37_8_4_SHAKE_ESK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_37_8_4_SHAKE_ESK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_37_8_4_SHAKE_ESK);
        }
    }

    public static class SNOVA_37_8_4_SHAKE_SSK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_37_8_4_SHAKE_SSK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_37_8_4_SHAKE_SSK);
        }
    }

    public static class SNOVA_37_17_2_SSK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_37_17_2_SSK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_37_17_2_SSK);
        }
    }

    public static class SNOVA_37_17_2_ESK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_37_17_2_ESK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_37_17_2_ESK);
        }
    }

    public static class SNOVA_37_17_2_SHAKE_ESK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_37_17_2_SHAKE_ESK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_37_17_2_SHAKE_ESK);
        }
    }

    public static class SNOVA_37_17_2_SHAKE_SSK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_37_17_2_SHAKE_SSK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_37_17_2_SHAKE_SSK);
        }
    }

    public static class SNOVA_49_11_3_SSK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_49_11_3_SSK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_49_11_3_SSK);
        }
    }

    public static class SNOVA_49_11_3_ESK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_49_11_3_ESK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_49_11_3_ESK);
        }
    }

    public static class SNOVA_49_11_3_SHAKE_ESK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_49_11_3_SHAKE_ESK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_49_11_3_SHAKE_ESK);
        }
    }

    public static class SNOVA_49_11_3_SHAKE_SSK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_49_11_3_SHAKE_SSK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_49_11_3_SHAKE_SSK);
        }
    }

    public static class SNOVA_56_25_2_SSK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_56_25_2_SSK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_56_25_2_SSK);
        }
    }

    public static class SNOVA_56_25_2_ESK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_56_25_2_ESK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_56_25_2_ESK);
        }
    }

    public static class SNOVA_56_25_2_SHAKE_ESK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_56_25_2_SHAKE_ESK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_56_25_2_SHAKE_ESK);
        }
    }

    public static class SNOVA_56_25_2_SHAKE_SSK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_56_25_2_SHAKE_SSK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_56_25_2_SHAKE_SSK);
        }
    }

    public static class SNOVA_60_10_4_SSK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_60_10_4_SSK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_60_10_4_SSK);
        }
    }

    public static class SNOVA_60_10_4_ESK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_60_10_4_ESK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_60_10_4_ESK);
        }
    }

    public static class SNOVA_60_10_4_SHAKE_ESK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_60_10_4_SHAKE_ESK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_60_10_4_SHAKE_ESK);
        }
    }

    public static class SNOVA_60_10_4_SHAKE_SSK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_60_10_4_SHAKE_SSK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_60_10_4_SHAKE_SSK);
        }
    }

    public static class SNOVA_66_15_3_SSK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_66_15_3_SSK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_66_15_3_SSK);
        }
    }

    public static class SNOVA_66_15_3_ESK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_66_15_3_ESK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_66_15_3_ESK);
        }
    }

    public static class SNOVA_66_15_3_SHAKE_ESK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_66_15_3_SHAKE_ESK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_66_15_3_SHAKE_ESK);
        }
    }

    public static class SNOVA_66_15_3_SHAKE_SSK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_66_15_3_SHAKE_SSK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_66_15_3_SHAKE_SSK);
        }
    }

    public static class SNOVA_75_33_2_SSK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_75_33_2_SSK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_75_33_2_SSK);
        }
    }

    public static class SNOVA_75_33_2_ESK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_75_33_2_ESK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_75_33_2_ESK);
        }
    }

    public static class SNOVA_75_33_2_SHAKE_ESK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_75_33_2_SHAKE_ESK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_75_33_2_SHAKE_ESK);
        }
    }

    public static class SNOVA_75_33_2_SHAKE_SSK
        extends org.bouncycastle.pqc.jcajce.provider.snova.SignatureSpi
    {
        public SNOVA_75_33_2_SHAKE_SSK()
        {
            super(new SnovaSigner(), SnovaParameters.SNOVA_75_33_2_SHAKE_SSK);
        }
    }
}


package org.bouncycastle.pqc.jcajce.provider.mqom;

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
import org.bouncycastle.pqc.crypto.mqom.MQOMParameters;
import org.bouncycastle.pqc.crypto.mqom.MQOMSigner;
import org.bouncycastle.util.Strings;

public class SignatureSpi
        extends java.security.Signature
{
    private final ByteArrayOutputStream bOut;
    private final MQOMSigner signer;
    private final MQOMParameters parameters;
    private SecureRandom random;

    protected SignatureSpi(MQOMSigner signer)
    {
        super("MQOM");
        this.bOut = new ByteArrayOutputStream();
        this.signer = signer;
        this.parameters = null;
    }

    protected SignatureSpi(MQOMSigner signer, MQOMParameters parameters)
    {
        super(Strings.toUpperCase(parameters.getName()));
        this.bOut = new ByteArrayOutputStream();
        this.signer = signer;
        this.parameters = parameters;
    }

    protected void engineInitVerify(PublicKey publicKey)
            throws InvalidKeyException
    {
        if (!(publicKey instanceof BCMQOMPublicKey))
        {
            try
            {
                publicKey = new BCMQOMPublicKey(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("unknown public key passed to MQOM: " + e.getMessage());
            }
        }

        BCMQOMPublicKey key = (BCMQOMPublicKey) publicKey;

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
        if (privateKey instanceof BCMQOMPrivateKey)
        {
            BCMQOMPrivateKey key = (BCMQOMPrivateKey) privateKey;
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
            throw new InvalidKeyException("unknown private key passed to MQOM");
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
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated replaced with engineSetParameter(AlgorithmParameterSpec)
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
        throw new UnsupportedOperationException("engineGetParameter unsupported");
    }

    public static class Base extends SignatureSpi
    {
        public Base()
        {
            super(new MQOMSigner());
        }
    }

    public static class C1Gf2Fr3 extends SignatureSpi
    {
        public C1Gf2Fr3()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat1_gf2_fast_r3);
        }
    }

    public static class C1Gf2Fr5 extends SignatureSpi
    {
        public C1Gf2Fr5()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat1_gf2_fast_r5);
        }
    }

    public static class C1Gf2Sr3 extends SignatureSpi
    {
        public C1Gf2Sr3()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat1_gf2_short_r3);
        }
    }

    public static class C1Gf2Sr5 extends SignatureSpi
    {
        public C1Gf2Sr5()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat1_gf2_short_r5);
        }
    }

    public static class C1Gf16Fr3 extends SignatureSpi
    {
        public C1Gf16Fr3()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat1_gf16_fast_r3);
        }
    }

    public static class C1Gf16Fr5 extends SignatureSpi
    {
        public C1Gf16Fr5()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat1_gf16_fast_r5);
        }
    }

    public static class C1Gf16Sr3 extends SignatureSpi
    {
        public C1Gf16Sr3()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat1_gf16_short_r3);
        }
    }

    public static class C1Gf16Sr5 extends SignatureSpi
    {
        public C1Gf16Sr5()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat1_gf16_short_r5);
        }
    }

    public static class C1Gf256Fr3 extends SignatureSpi
    {
        public C1Gf256Fr3()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat1_gf256_fast_r3);
        }
    }

    public static class C1Gf256Fr5 extends SignatureSpi
    {
        public C1Gf256Fr5()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat1_gf256_fast_r5);
        }
    }

    public static class C1Gf256Sr3 extends SignatureSpi
    {
        public C1Gf256Sr3()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat1_gf256_short_r3);
        }
    }

    public static class C1Gf256Sr5 extends SignatureSpi
    {
        public C1Gf256Sr5()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat1_gf256_short_r5);
        }
    }

    public static class C3Gf2Fr3 extends SignatureSpi
    {
        public C3Gf2Fr3()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat3_gf2_fast_r3);
        }
    }

    public static class C3Gf2Fr5 extends SignatureSpi
    {
        public C3Gf2Fr5()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat3_gf2_fast_r5);
        }
    }

    public static class C3Gf2Sr3 extends SignatureSpi
    {
        public C3Gf2Sr3()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat3_gf2_short_r3);
        }
    }

    public static class C3Gf2Sr5 extends SignatureSpi
    {
        public C3Gf2Sr5()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat3_gf2_short_r5);
        }
    }

    public static class C3Gf16Fr3 extends SignatureSpi
    {
        public C3Gf16Fr3()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat3_gf16_fast_r3);
        }
    }

    public static class C3Gf16Fr5 extends SignatureSpi
    {
        public C3Gf16Fr5()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat3_gf16_fast_r5);
        }
    }

    public static class C3Gf16Sr3 extends SignatureSpi
    {
        public C3Gf16Sr3()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat3_gf16_short_r3);
        }
    }

    public static class C3Gf16Sr5 extends SignatureSpi
    {
        public C3Gf16Sr5()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat3_gf16_short_r5);
        }
    }

    public static class C3Gf256Fr3 extends SignatureSpi
    {
        public C3Gf256Fr3()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat3_gf256_fast_r3);
        }
    }

    public static class C3Gf256Fr5 extends SignatureSpi
    {
        public C3Gf256Fr5()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat3_gf256_fast_r5);
        }
    }

    public static class C3Gf256Sr3 extends SignatureSpi
    {
        public C3Gf256Sr3()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat3_gf256_short_r3);
        }
    }

    public static class C3Gf256Sr5 extends SignatureSpi
    {
        public C3Gf256Sr5()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat3_gf256_short_r5);
        }
    }

    public static class C5Gf2Fr3 extends SignatureSpi
    {
        public C5Gf2Fr3()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat5_gf2_fast_r3);
        }
    }

    public static class C5Gf2Fr5 extends SignatureSpi
    {
        public C5Gf2Fr5()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat5_gf2_fast_r5);
        }
    }

    public static class C5Gf2Sr3 extends SignatureSpi
    {
        public C5Gf2Sr3()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat5_gf2_short_r3);
        }
    }

    public static class C5Gf2Sr5 extends SignatureSpi
    {
        public C5Gf2Sr5()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat5_gf2_short_r5);
        }
    }

    public static class C5Gf16Fr3 extends SignatureSpi
    {
        public C5Gf16Fr3()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat5_gf16_fast_r3);
        }
    }

    public static class C5Gf16Fr5 extends SignatureSpi
    {
        public C5Gf16Fr5()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat5_gf16_fast_r5);
        }
    }

    public static class C5Gf16Sr3 extends SignatureSpi
    {
        public C5Gf16Sr3()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat5_gf16_short_r3);
        }
    }

    public static class C5Gf16Sr5 extends SignatureSpi
    {
        public C5Gf16Sr5()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat5_gf16_short_r5);
        }
    }

    public static class C5Gf256Fr3 extends SignatureSpi
    {
        public C5Gf256Fr3()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat5_gf256_fast_r3);
        }
    }

    public static class C5Gf256Fr5 extends SignatureSpi
    {
        public C5Gf256Fr5()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat5_gf256_fast_r5);
        }
    }

    public static class C5Gf256Sr3 extends SignatureSpi
    {
        public C5Gf256Sr3()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat5_gf256_short_r3);
        }
    }

    public static class C5Gf256Sr5 extends SignatureSpi
    {
        public C5Gf256Sr5()
        {
            super(new MQOMSigner(), MQOMParameters.mqom2_cat5_gf256_short_r5);
        }
    }
}

package org.bouncycastle.pqc.jcajce.provider.qruov;

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
import org.bouncycastle.pqc.crypto.qruov.QRUOVParameters;
import org.bouncycastle.pqc.crypto.qruov.QRUOVSigner;
import org.bouncycastle.util.Strings;

public class SignatureSpi
    extends java.security.Signature
{
    private final ByteArrayOutputStream bOut;
    private final QRUOVSigner signer;
    private SecureRandom random;
    private final QRUOVParameters parameters;

    protected SignatureSpi(QRUOVSigner signer)
    {
        super("QRUOV");
        this.bOut = new ByteArrayOutputStream();
        this.signer = signer;
        this.parameters = null;
    }

    protected SignatureSpi(QRUOVSigner signer, QRUOVParameters parameters)
    {
        super(Strings.toUpperCase(canonicalName(parameters)));
        this.parameters = parameters;
        this.bOut = new ByteArrayOutputStream();
        this.signer = signer;
    }

    private static String canonicalName(QRUOVParameters parameters)
    {
        String raw = parameters.getName();
        int dash = raw.indexOf('-');
        return dash > 0 ? raw.substring(0, dash) : raw;
    }

    protected void engineInitVerify(PublicKey publicKey)
        throws InvalidKeyException
    {
        if (!(publicKey instanceof BCQRUOVPublicKey))
        {
            try
            {
                publicKey = new BCQRUOVPublicKey(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("unknown public key passed to QRUOV: " + e.getMessage());
            }
        }

        BCQRUOVPublicKey key = (BCQRUOVPublicKey)publicKey;

        if (parameters != null)
        {
            String canonicalAlg = Strings.toUpperCase(canonicalName(parameters));
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
        if (privateKey instanceof BCQRUOVPrivateKey)
        {
            BCQRUOVPrivateKey key = (BCQRUOVPrivateKey)privateKey;
            CipherParameters param = key.getKeyParams();

            if (parameters != null)
            {
                String canonicalAlg = Strings.toUpperCase(canonicalName(parameters));
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
            throw new InvalidKeyException("unknown private key passed to QRUOV");
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
            super(new QRUOVSigner());
        }
    }

    public static class QRUOV1Q127L3V156M54
        extends SignatureSpi
    {
        public QRUOV1Q127L3V156M54()
        {
            super(new QRUOVSigner(), QRUOVParameters.qruov_1_q127_L3_v156_m54_shake);
        }
    }

    public static class QRUOV1Q31L3V165M60
        extends SignatureSpi
    {
        public QRUOV1Q31L3V165M60()
        {
            super(new QRUOVSigner(), QRUOVParameters.qruov_1_q31_L3_v165_m60_shake);
        }
    }

    public static class QRUOV1Q31L10V600M70
        extends SignatureSpi
    {
        public QRUOV1Q31L10V600M70()
        {
            super(new QRUOVSigner(), QRUOVParameters.qruov_1_q31_L10_v600_m70_shake);
        }
    }

    public static class QRUOV1Q7L10V740M100
        extends SignatureSpi
    {
        public QRUOV1Q7L10V740M100()
        {
            super(new QRUOVSigner(), QRUOVParameters.qruov_1_q7_L10_v740_m100_shake);
        }
    }

    public static class QRUOV3Q127L3V228M78
        extends SignatureSpi
    {
        public QRUOV3Q127L3V228M78()
        {
            super(new QRUOVSigner(), QRUOVParameters.qruov_3_q127_L3_v228_m78_shake);
        }
    }

    public static class QRUOV3Q31L3V246M87
        extends SignatureSpi
    {
        public QRUOV3Q31L3V246M87()
        {
            super(new QRUOVSigner(), QRUOVParameters.qruov_3_q31_L3_v246_m87_shake);
        }
    }

    public static class QRUOV3Q31L10V890M100
        extends SignatureSpi
    {
        public QRUOV3Q31L10V890M100()
        {
            super(new QRUOVSigner(), QRUOVParameters.qruov_3_q31_L10_v890_m100_shake);
        }
    }

    public static class QRUOV3Q7L10V1100M140
        extends SignatureSpi
    {
        public QRUOV3Q7L10V1100M140()
        {
            super(new QRUOVSigner(), QRUOVParameters.qruov_3_q7_L10_v1100_m140_shake);
        }
    }

    public static class QRUOV5Q127L3V306M105
        extends SignatureSpi
    {
        public QRUOV5Q127L3V306M105()
        {
            super(new QRUOVSigner(), QRUOVParameters.qruov_5_q127_L3_v306_m105_shake);
        }
    }

    public static class QRUOV5Q31L3V324M114
        extends SignatureSpi
    {
        public QRUOV5Q31L3V324M114()
        {
            super(new QRUOVSigner(), QRUOVParameters.qruov_5_q31_L3_v324_m114_shake);
        }
    }

    public static class QRUOV5Q31L10V1120M120
        extends SignatureSpi
    {
        public QRUOV5Q31L10V1120M120()
        {
            super(new QRUOVSigner(), QRUOVParameters.qruov_5_q31_L10_v1120_m120_shake);
        }
    }

    public static class QRUOV5Q7L10V1490M190
        extends SignatureSpi
    {
        public QRUOV5Q7L10V1490M190()
        {
            super(new QRUOVSigner(), QRUOVParameters.qruov_5_q7_L10_v1490_m190_shake);
        }
    }
}

package org.bouncycastle.pqc.jcajce.provider.qruov;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.util.SpecUtil;
import org.bouncycastle.pqc.crypto.qruov.QRUOVKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.qruov.QRUOVKeyPairGenerator;
import org.bouncycastle.pqc.crypto.qruov.QRUOVParameters;
import org.bouncycastle.pqc.crypto.qruov.QRUOVPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.qruov.QRUOVPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.spec.QRUOVParameterSpec;
import org.bouncycastle.util.Strings;

public class QRUOVKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private static final Map parameters = new HashMap();

    static
    {
        // canonical (SHAKE) parameter sets, accepted in lower-case
        parameters.put("qruov1q127l3v156m54", QRUOVParameters.qruov_1_q127_L3_v156_m54_shake);
        parameters.put("qruov1q31l3v165m60", QRUOVParameters.qruov_1_q31_L3_v165_m60_shake);
        parameters.put("qruov1q31l10v600m70", QRUOVParameters.qruov_1_q31_L10_v600_m70_shake);
        parameters.put("qruov1q7l10v740m100", QRUOVParameters.qruov_1_q7_L10_v740_m100_shake);
        parameters.put("qruov3q127l3v228m78", QRUOVParameters.qruov_3_q127_L3_v228_m78_shake);
        parameters.put("qruov3q31l3v246m87", QRUOVParameters.qruov_3_q31_L3_v246_m87_shake);
        parameters.put("qruov3q31l10v890m100", QRUOVParameters.qruov_3_q31_L10_v890_m100_shake);
        parameters.put("qruov3q7l10v1100m140", QRUOVParameters.qruov_3_q7_L10_v1100_m140_shake);
        parameters.put("qruov5q127l3v306m105", QRUOVParameters.qruov_5_q127_L3_v306_m105_shake);
        parameters.put("qruov5q31l3v324m114", QRUOVParameters.qruov_5_q31_L3_v324_m114_shake);
        parameters.put("qruov5q31l10v1120m120", QRUOVParameters.qruov_5_q31_L10_v1120_m120_shake);
        parameters.put("qruov5q7l10v1490m190", QRUOVParameters.qruov_5_q7_L10_v1490_m190_shake);
    }

    QRUOVKeyGenerationParameters param;
    private QRUOVParameters qruovParameters;
    QRUOVKeyPairGenerator engine = new QRUOVKeyPairGenerator();
    SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    boolean initialised = false;

    public QRUOVKeyPairGeneratorSpi()
    {
        super("QRUOV");
    }

    protected QRUOVKeyPairGeneratorSpi(QRUOVParameters qruovParameters)
    {
        super(qruovParameters.getName());
        this.qruovParameters = qruovParameters;
    }

    public void initialize(int strength, SecureRandom random)
    {
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        String name = getNameFromParams(params);
        if (name != null && parameters.containsKey(name))
        {
            param = new QRUOVKeyGenerationParameters(random, (QRUOVParameters)parameters.get(name));
            engine.init(param);
            initialised = true;
        }
        else
        {
            throw new InvalidAlgorithmParameterException("invalid ParameterSpec: " + params);
        }
    }

    private static String getNameFromParams(AlgorithmParameterSpec paramSpec)
    {
        if (paramSpec instanceof QRUOVParameterSpec)
        {
            return Strings.toLowerCase(((QRUOVParameterSpec)paramSpec).getName());
        }
        return Strings.toLowerCase(SpecUtil.getNameFrom(paramSpec));
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            if (qruovParameters != null)
            {
                param = new QRUOVKeyGenerationParameters(random, qruovParameters);
            }
            else
            {
                param = new QRUOVKeyGenerationParameters(random, QRUOVParameters.qruov_1_q127_L3_v156_m54_shake);
            }
            engine.init(param);
            initialised = true;
        }
        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        QRUOVPublicKeyParameters pub = (QRUOVPublicKeyParameters)pair.getPublic();
        QRUOVPrivateKeyParameters priv = (QRUOVPrivateKeyParameters)pair.getPrivate();
        return new KeyPair(new BCQRUOVPublicKey(pub), new BCQRUOVPrivateKey(priv));
    }

    public static class QRUOV1Q127L3V156M54
        extends QRUOVKeyPairGeneratorSpi
    {
        public QRUOV1Q127L3V156M54()
        {
            super(QRUOVParameters.qruov_1_q127_L3_v156_m54_shake);
        }
    }

    public static class QRUOV1Q31L3V165M60
        extends QRUOVKeyPairGeneratorSpi
    {
        public QRUOV1Q31L3V165M60()
        {
            super(QRUOVParameters.qruov_1_q31_L3_v165_m60_shake);
        }
    }

    public static class QRUOV1Q31L10V600M70
        extends QRUOVKeyPairGeneratorSpi
    {
        public QRUOV1Q31L10V600M70()
        {
            super(QRUOVParameters.qruov_1_q31_L10_v600_m70_shake);
        }
    }

    public static class QRUOV1Q7L10V740M100
        extends QRUOVKeyPairGeneratorSpi
    {
        public QRUOV1Q7L10V740M100()
        {
            super(QRUOVParameters.qruov_1_q7_L10_v740_m100_shake);
        }
    }

    public static class QRUOV3Q127L3V228M78
        extends QRUOVKeyPairGeneratorSpi
    {
        public QRUOV3Q127L3V228M78()
        {
            super(QRUOVParameters.qruov_3_q127_L3_v228_m78_shake);
        }
    }

    public static class QRUOV3Q31L3V246M87
        extends QRUOVKeyPairGeneratorSpi
    {
        public QRUOV3Q31L3V246M87()
        {
            super(QRUOVParameters.qruov_3_q31_L3_v246_m87_shake);
        }
    }

    public static class QRUOV3Q31L10V890M100
        extends QRUOVKeyPairGeneratorSpi
    {
        public QRUOV3Q31L10V890M100()
        {
            super(QRUOVParameters.qruov_3_q31_L10_v890_m100_shake);
        }
    }

    public static class QRUOV3Q7L10V1100M140
        extends QRUOVKeyPairGeneratorSpi
    {
        public QRUOV3Q7L10V1100M140()
        {
            super(QRUOVParameters.qruov_3_q7_L10_v1100_m140_shake);
        }
    }

    public static class QRUOV5Q127L3V306M105
        extends QRUOVKeyPairGeneratorSpi
    {
        public QRUOV5Q127L3V306M105()
        {
            super(QRUOVParameters.qruov_5_q127_L3_v306_m105_shake);
        }
    }

    public static class QRUOV5Q31L3V324M114
        extends QRUOVKeyPairGeneratorSpi
    {
        public QRUOV5Q31L3V324M114()
        {
            super(QRUOVParameters.qruov_5_q31_L3_v324_m114_shake);
        }
    }

    public static class QRUOV5Q31L10V1120M120
        extends QRUOVKeyPairGeneratorSpi
    {
        public QRUOV5Q31L10V1120M120()
        {
            super(QRUOVParameters.qruov_5_q31_L10_v1120_m120_shake);
        }
    }

    public static class QRUOV5Q7L10V1490M190
        extends QRUOVKeyPairGeneratorSpi
    {
        public QRUOV5Q7L10V1490M190()
        {
            super(QRUOVParameters.qruov_5_q7_L10_v1490_m190_shake);
        }
    }
}

package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.Ed448KeyPairGenerator;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.X448KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed448KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X448KeyGenerationParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jcajce.spec.XDHParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;

public class KeyPairGeneratorSpi
    extends java.security.KeyPairGeneratorSpi
{
    private static final int EdDSA = -1;
    private static final int XDH = -2;

    private static final int Ed25519 = 1;
    private static final int Ed448 = 2;
    private static final int X25519 = 3;
    private static final int X448 = 4;

    private final int algorithmDeclared;

    private int algorithmInitialized;
    private SecureRandom secureRandom;

    private AsymmetricCipherKeyPairGenerator generator;

    KeyPairGeneratorSpi(int algorithmDeclared)
    {
        this.algorithmDeclared = algorithmDeclared;

        if (getAlgorithmFamily(algorithmDeclared) != algorithmDeclared)
        {
            this.algorithmInitialized = algorithmDeclared;
        }
    }

    public void initialize(int strength, SecureRandom secureRandom)
    {
        int algorithm = getAlgorithmForStrength(strength);

        this.algorithmInitialized = algorithm;
        this.secureRandom = secureRandom;

        this.generator = null;
    }

    public void initialize(AlgorithmParameterSpec paramSpec, SecureRandom secureRandom)
        throws InvalidAlgorithmParameterException
    {
        String name = getNameFromParams(paramSpec);
        if (null == name)
        {
            throw new InvalidAlgorithmParameterException("invalid parameterSpec: " + paramSpec);
        }

        int algorithm = getAlgorithmForName(name);

        if (algorithmDeclared != algorithm &&
            algorithmDeclared != getAlgorithmFamily(algorithm))
        {
            throw new InvalidAlgorithmParameterException("parameterSpec for wrong curve type");
        }

        this.algorithmInitialized = algorithm;
        this.secureRandom = secureRandom;

        this.generator = null;
    }

    public KeyPair generateKeyPair()
    {
        if (algorithmInitialized == 0)
        {
            throw new IllegalStateException("generator not correctly initialized");
        }

        if (null == generator)
        {
            this.generator = setupGenerator();
        }

        AsymmetricCipherKeyPair kp = generator.generateKeyPair();

        switch (algorithmInitialized)
        {
        case Ed25519:
        case Ed448:
            return new KeyPair(new BC15EdDSAPublicKey(kp.getPublic()), new BC15EdDSAPrivateKey(kp.getPrivate()));
        case X25519:
        case X448:
            return new KeyPair(new BC11XDHPublicKey(kp.getPublic()), new BC11XDHPrivateKey(kp.getPrivate()));
        default:
            throw new IllegalStateException("generator not correctly initialized");
        }
    }

    private int getAlgorithmForStrength(int strength)
    {
        switch (strength)
        {
        case 255:
        case 256:
        {
            switch (algorithmDeclared)
            {
            case EdDSA:
            case Ed25519:
                return Ed25519;
            case XDH:
            case X25519:
                return X25519;
            default:
                throw new InvalidParameterException("key size not configurable");
            }
        }
        case 448:
        {
            switch (algorithmDeclared)
            {
            case EdDSA:
            case Ed448:
                return Ed448;
            case XDH:
            case X448:
                return X448;
            default:
                throw new InvalidParameterException("key size not configurable");
            }
        }
        default:
            throw new InvalidParameterException("unknown key size");
        }
    }

    private AsymmetricCipherKeyPairGenerator setupGenerator()
    {
        if (null == secureRandom)
        {
            this.secureRandom = CryptoServicesRegistrar.getSecureRandom();
        }

        switch (algorithmInitialized)
        {
        case Ed25519:
        {
            Ed25519KeyPairGenerator generator = new Ed25519KeyPairGenerator();
            generator.init(new Ed25519KeyGenerationParameters(secureRandom));
            return generator;
        }
        case Ed448:
        {
            Ed448KeyPairGenerator generator = new Ed448KeyPairGenerator();
            generator.init(new Ed448KeyGenerationParameters(secureRandom));
            return generator;
        }
        case X25519:
        {
            X25519KeyPairGenerator generator = new X25519KeyPairGenerator();
            generator.init(new X25519KeyGenerationParameters(secureRandom));
            return generator;
        }
        case X448:
        {
            X448KeyPairGenerator generator = new X448KeyPairGenerator();
            generator.init(new X448KeyGenerationParameters(secureRandom));
            return generator;
        }
        default:
        {
            throw new IllegalStateException("generator not correctly initialized");
        }
        }
    }

    private static int getAlgorithmFamily(int algorithm)
    {
        switch (algorithm)
        {
        case Ed25519:
        case Ed448:
            return EdDSA;
        case X25519:
        case X448:
            return XDH;
        default:
            return algorithm;
        }
    }

    private static int getAlgorithmForName(String name)
        throws InvalidAlgorithmParameterException
    {
        if (name.equalsIgnoreCase(XDHParameterSpec.X25519) || name.equals(EdECObjectIdentifiers.id_X25519.getId()))
        {
            return X25519;
        }
        else if (name.equalsIgnoreCase(EdDSAParameterSpec.Ed25519) || name.equals(EdECObjectIdentifiers.id_Ed25519.getId()))
        {
            return Ed25519;
        }
        else if (name.equalsIgnoreCase(XDHParameterSpec.X448) || name.equals(EdECObjectIdentifiers.id_X448.getId()))
        {
            return X448;
        }
        else if (name.equalsIgnoreCase(EdDSAParameterSpec.Ed448) || name.equals(EdECObjectIdentifiers.id_Ed448.getId()))
        {
            return Ed448;
        }
        throw new InvalidAlgorithmParameterException("invalid parameterSpec name: " + name);
    }

    private static String getNameFromParams(AlgorithmParameterSpec paramSpec)
        throws InvalidAlgorithmParameterException
    {
        if (paramSpec instanceof ECGenParameterSpec)
        {
            return ((ECGenParameterSpec)paramSpec).getName();
        }
        else if (paramSpec instanceof ECNamedCurveGenParameterSpec)
        {
            return ((ECNamedCurveGenParameterSpec)paramSpec).getName();
        }
        else if (paramSpec instanceof NamedParameterSpec)
        {
            return ((NamedParameterSpec)paramSpec).getName();
        }
        else if (paramSpec instanceof EdDSAParameterSpec)
        {
            return ((EdDSAParameterSpec)paramSpec).getCurveName();
        }
        else if (paramSpec instanceof XDHParameterSpec)
        {
            return ((XDHParameterSpec)paramSpec).getCurveName();
        }
        else
        {
            return ECUtil.getNameFrom(paramSpec);
        }
    }

    public static final class EdDSA
        extends KeyPairGeneratorSpi
    {
        public EdDSA()
        {
            super(EdDSA);
        }
    }

    public static final class Ed448
        extends KeyPairGeneratorSpi
    {
        public Ed448()
        {
            super(Ed448);
        }
    }

    public static final class Ed25519
        extends KeyPairGeneratorSpi
    {
        public Ed25519()
        {
            super(Ed25519);
        }
    }

    public static final class XDH
        extends KeyPairGeneratorSpi
    {
        public XDH()
        {
            super(XDH);
        }
    }

    public static final class X448
        extends KeyPairGeneratorSpi
    {
        public X448()
        {
            super(X448);
        }
    }

    public static final class X25519
        extends KeyPairGeneratorSpi
    {
        public X25519()
        {
            super(X25519);
        }
    }
}

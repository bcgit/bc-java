package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
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

    private static final int Ed448 = 0;
    private static final int Ed25519 = 1;
    private static final int X448 = 2;
    private static final int X25519 = 3;

    private int algorithm;
    private AsymmetricCipherKeyPairGenerator generator;

    private boolean initialised;
    private SecureRandom secureRandom;

    KeyPairGeneratorSpi(int algorithm, AsymmetricCipherKeyPairGenerator generator)
    {
        this.algorithm = algorithm;
        this.generator = generator;
    }

    public void initialize(int strength, SecureRandom secureRandom)
    {
        this.secureRandom = secureRandom;
        try
        {
            switch (strength)
            {
            case 255:
            case 256:
                switch (algorithm)
                {
                case EdDSA:
                case Ed25519:
                    algorithmCheck(Ed25519);
                    this.generator = new Ed25519KeyPairGenerator();
                    setupGenerator(Ed25519);
                    break;
                case XDH:
                case X25519:
                    algorithmCheck(X25519);
                    this.generator = new X25519KeyPairGenerator();
                    setupGenerator(X25519);
                    break;
                default:
                    throw new InvalidParameterException("key size not configurable");
                }
                break;
            case 448:
                switch (algorithm)
                {
                case EdDSA:
                case Ed448:
                    algorithmCheck(Ed448);
                    this.generator = new Ed448KeyPairGenerator();
                    setupGenerator(Ed448);
                    break;
                case XDH:
                case X448:
                    algorithmCheck(X448);
                    this.generator = new X448KeyPairGenerator();
                    setupGenerator(X448);
                    break;
                default:
                    throw new InvalidParameterException("key size not configurable");
                }
                break;
            default:
                throw new InvalidParameterException("unknown key size");
            }
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new InvalidParameterException(e.getMessage());
        }
    }

    public void initialize(AlgorithmParameterSpec paramSpec, SecureRandom secureRandom)
        throws InvalidAlgorithmParameterException
    {
        this.secureRandom = secureRandom;

        if (paramSpec instanceof ECGenParameterSpec)
        {
            initializeGenerator(((ECGenParameterSpec)paramSpec).getName());
        }
        else if (paramSpec instanceof ECNamedCurveGenParameterSpec)
        {
            initializeGenerator(((ECNamedCurveGenParameterSpec)paramSpec).getName());
        }
        else if (paramSpec instanceof EdDSAParameterSpec)
        {
            initializeGenerator(((EdDSAParameterSpec)paramSpec).getCurveName());
        }
        else if (paramSpec instanceof XDHParameterSpec)
        {
            initializeGenerator(((XDHParameterSpec)paramSpec).getCurveName());
        }
        else
        {
            String name = ECUtil.getNameFrom(paramSpec);

            if (name != null)
            {
                initializeGenerator(name);
            }
            else
            {
                throw new InvalidAlgorithmParameterException("invalid parameterSpec: " + paramSpec);
            }
        }
    }

    private void algorithmCheck(int algorithm)
        throws InvalidAlgorithmParameterException
    {
        if (this.algorithm != algorithm)
        {
            if (this.algorithm == Ed25519 || this.algorithm == Ed448)
            {
                throw new InvalidAlgorithmParameterException("parameterSpec for wrong curve type");
            }
            if (this.algorithm == EdDSA && (algorithm != Ed25519 && algorithm != Ed448))
            {
                throw new InvalidAlgorithmParameterException("parameterSpec for wrong curve type");
            }
            if (this.algorithm == X25519 || this.algorithm == X448)
            {
                throw new InvalidAlgorithmParameterException("parameterSpec for wrong curve type");
            }
            if (this.algorithm == XDH && (algorithm != X25519 && algorithm != X448))
            {
                throw new InvalidAlgorithmParameterException("parameterSpec for wrong curve type");
            }
        }
    }

    private void initializeGenerator(String name)
        throws InvalidAlgorithmParameterException
    {
        if (name.equalsIgnoreCase(EdDSAParameterSpec.Ed448) || name.equals(EdECObjectIdentifiers.id_Ed448.getId()))
        {
            algorithmCheck(Ed448);
            this.generator = new Ed448KeyPairGenerator();
            setupGenerator(Ed448);
        }
        else if (name.equalsIgnoreCase(EdDSAParameterSpec.Ed25519) || name.equals(EdECObjectIdentifiers.id_Ed25519.getId()))
        {
            algorithmCheck(Ed25519);
            this.generator = new Ed25519KeyPairGenerator();
            setupGenerator(Ed25519);
        }
        else if (name.equalsIgnoreCase(XDHParameterSpec.X448) || name.equals(EdECObjectIdentifiers.id_X448.getId()))
        {
            algorithmCheck(X448);
            this.generator = new X448KeyPairGenerator();
            setupGenerator(X448);
        }
        else if (name.equalsIgnoreCase(XDHParameterSpec.X25519) || name.equals(EdECObjectIdentifiers.id_X25519.getId()))
        {
            algorithmCheck(X25519);
            this.generator = new X25519KeyPairGenerator();
            setupGenerator(X25519);
        }
    }

    public KeyPair generateKeyPair()
    {
        if (generator == null)
        {
            throw new IllegalStateException("generator not correctly initialized");
        }

        if (!initialised)
        {
            setupGenerator(algorithm);
        }

        AsymmetricCipherKeyPair kp = generator.generateKeyPair();

        switch (algorithm)
        {
        case XDH:
        case X25519:
        case X448:
            return new KeyPair(new BCXDHPublicKey(kp.getPublic()), new BCXDHPrivateKey(kp.getPrivate()));

        default:
            return new KeyPair(new BCEdDSAPublicKey(kp.getPublic()), new BCEdDSAPrivateKey(kp.getPrivate()));
        }
    }

    private void setupGenerator(int algorithm)
    {
        initialised = true;

        switch (algorithm)
        {
        case Ed448:
            generator.init(new Ed448KeyGenerationParameters(secureRandom));
            break;
        case EdDSA:
        case Ed25519:
            generator.init(new Ed25519KeyGenerationParameters(secureRandom));
            break;
        case X448:
            generator.init(new X448KeyGenerationParameters(secureRandom));
            break;
        case XDH:
        case X25519:
            generator.init(new X25519KeyGenerationParameters(secureRandom));
            break;
        }
    }

    public static final class EdDSA
        extends KeyPairGeneratorSpi
    {
        public EdDSA()
        {
            super(EdDSA, null);
        }
    }

    public static final class Ed448
        extends KeyPairGeneratorSpi
    {
        public Ed448()
        {
            super(Ed448, new Ed448KeyPairGenerator());
        }
    }

    public static final class Ed25519
        extends KeyPairGeneratorSpi
    {
        public Ed25519()
        {
            super(Ed25519, new Ed25519KeyPairGenerator());
        }
    }

    public static final class XDH
        extends KeyPairGeneratorSpi
    {
        public XDH()
        {
            super(XDH, null);
        }
    }

    public static final class X448
        extends KeyPairGeneratorSpi
    {
        public X448()
        {
            super(X448, new X448KeyPairGenerator());
        }
    }

    public static final class X25519
        extends KeyPairGeneratorSpi
    {
        public X25519()
        {
            super(X25519, new X25519KeyPairGenerator());
        }
    }
}

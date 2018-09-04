package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.security.KeyPair;
import java.security.SecureRandom;

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

public class KeyPairGeneratorSpi
    extends java.security.KeyPairGeneratorSpi
{
    private static final int Ed448 = 0;
    private static final int Ed25519 = 1;
    private static final int X448 = 2;
    private static final int X25519 = 3;

    private final int algorithm;
    private final AsymmetricCipherKeyPairGenerator generator;

    private boolean initialised;
    private SecureRandom secureRandom;

    KeyPairGeneratorSpi(int algorithm, AsymmetricCipherKeyPairGenerator generator)
    {
        this.algorithm = algorithm;
        this.generator = generator;
    }

    public void initialize(int strength, SecureRandom secureRandom)
    {
        // TODO: should we make sure strength makes sense?
        this.secureRandom = secureRandom;
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            initialised = true;

            if (secureRandom == null)
            {
                secureRandom = new SecureRandom();
            }
            
            switch (algorithm)
            {
            case Ed448:
                generator.init(new Ed448KeyGenerationParameters(secureRandom));
                break;
            case Ed25519:
                generator.init(new Ed25519KeyGenerationParameters(secureRandom));
                break;
            case X448:
                generator.init(new X448KeyGenerationParameters(secureRandom));
                break;
            case X25519:
                generator.init(new X25519KeyGenerationParameters(secureRandom));
                break;
            }
        }

        AsymmetricCipherKeyPair kp = generator.generateKeyPair();

        switch (algorithm)
        {
        case Ed448:
            return new KeyPair(new BCEdDSAPublicKey(kp.getPublic()), new BCEdDSAPrivateKey(kp.getPrivate()));
        case Ed25519:
            return new KeyPair(new BCEdDSAPublicKey(kp.getPublic()), new BCEdDSAPrivateKey(kp.getPrivate()));
        case X448:
            return new KeyPair(new BCXDHPublicKey(kp.getPublic()), new BCXDHPrivateKey(kp.getPrivate()));
        case X25519:
            return new KeyPair(new BCXDHPublicKey(kp.getPublic()), new BCXDHPrivateKey(kp.getPrivate()));
        }

        throw new IllegalStateException("generator not correctly initialised");
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

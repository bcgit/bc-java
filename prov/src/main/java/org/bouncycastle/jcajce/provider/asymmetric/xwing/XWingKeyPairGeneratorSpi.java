package org.bouncycastle.jcajce.provider.asymmetric.xwing;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.util.SpecUtil;
import org.bouncycastle.pqc.crypto.xwing.XWingKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.xwing.XWingKeyPairGenerator;
import org.bouncycastle.pqc.crypto.xwing.XWingPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xwing.XWingPublicKeyParameters;
import org.bouncycastle.util.Strings;

/**
 * X-Wing has a single parameter set, so the generator needs no initialisation: {@code initialize(int, SecureRandom)}
 * accepts any strength and only records the SecureRandom, and {@code initialize(AlgorithmParameterSpec, SecureRandom)}
 * accepts a spec naming "X-WING" (for example a NamedParameterSpec) for the same purpose.
 */
public class XWingKeyPairGeneratorSpi
    extends java.security.KeyPairGenerator
{
    private final XWingKeyPairGenerator engine = new XWingKeyPairGenerator();

    private SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
    private boolean initialised = false;

    public XWingKeyPairGeneratorSpi()
    {
        super("X-WING");
    }

    public void initialize(int strength, SecureRandom random)
    {
        if (random != null)
        {
            this.random = random;
        }
        initialised = false;
    }

    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidAlgorithmParameterException
    {
        if (params != null)
        {
            String name = SpecUtil.getNameFrom(params);

            if (name == null || !(Strings.toUpperCase(name).equals("X-WING") || Strings.toUpperCase(name).equals("XWING")))
            {
                throw new InvalidAlgorithmParameterException("invalid ParameterSpec: " + params);
            }
        }

        initialize(256, random);
    }

    public KeyPair generateKeyPair()
    {
        if (!initialised)
        {
            engine.init(new XWingKeyGenerationParameters(random));
            initialised = true;
        }

        AsymmetricCipherKeyPair pair = engine.generateKeyPair();
        XWingPublicKeyParameters pub = (XWingPublicKeyParameters)pair.getPublic();
        XWingPrivateKeyParameters priv = (XWingPrivateKeyParameters)pair.getPrivate();

        return new KeyPair(new BCXWingPublicKey(pub), new BCXWingPrivateKey(priv));
    }
}

package org.bouncycastle.tls.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyFactorySpi;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider;
import org.bouncycastle.util.Arrays;

/**
 * A JcaTlsCryptoProvider modelling a provider ahead of BC that supplies ML-KEM keys: the ML-KEM KeyFactory and
 * KeyPairGenerator hand out key objects that are not BC's, while BC serves everything else, including the KEM
 * operations themselves (github #2466).
 */
class ForeignMLKEMKeysCryptoProvider
    extends JcaTlsCryptoProvider
{
    private final JcaJceHelper helper;

    ForeignMLKEMKeysCryptoProvider()
    {
        this.helper = new ForeignMLKEMKeysHelper(new BouncyCastleProvider());
    }

    public JcaJceHelper getHelper()
    {
        return helper;
    }

    private static boolean isMLKEM(String algorithm)
    {
        return algorithm.toUpperCase().startsWith("ML-KEM");
    }

    private static class ForeignMLKEMKeysHelper
        extends ProviderJcaJceHelper
    {
        ForeignMLKEMKeysHelper(Provider provider)
        {
            super(provider);
        }

        public KeyFactory createKeyFactory(String algorithm)
            throws NoSuchAlgorithmException
        {
            KeyFactory kf = super.createKeyFactory(algorithm);
            if (isMLKEM(algorithm))
            {
                return new KeyFactory(new ForeignKeyFactorySpi(kf), null, algorithm)
                {
                };
            }
            return kf;
        }

        public KeyPairGenerator createKeyPairGenerator(String algorithm)
            throws NoSuchAlgorithmException
        {
            KeyPairGenerator kpg = super.createKeyPairGenerator(algorithm);
            if (isMLKEM(algorithm))
            {
                return new ForeignKeyPairGenerator(kpg);
            }
            return kpg;
        }
    }

    private static class ForeignKeyFactorySpi
        extends KeyFactorySpi
    {
        private final KeyFactory bcFactory;

        ForeignKeyFactorySpi(KeyFactory bcFactory)
        {
            this.bcFactory = bcFactory;
        }

        protected PublicKey engineGeneratePublic(KeySpec keySpec)
            throws InvalidKeySpecException
        {
            return new ForeignPublicKey(bcFactory.generatePublic(keySpec).getEncoded());
        }

        protected PrivateKey engineGeneratePrivate(KeySpec keySpec)
            throws InvalidKeySpecException
        {
            return new ForeignPrivateKey(bcFactory.generatePrivate(keySpec).getEncoded());
        }

        protected KeySpec engineGetKeySpec(Key key, Class keySpec)
            throws InvalidKeySpecException
        {
            throw new InvalidKeySpecException("not supported");
        }

        protected Key engineTranslateKey(Key key)
            throws InvalidKeyException
        {
            throw new InvalidKeyException("not supported");
        }
    }

    private static class ForeignKeyPairGenerator
        extends KeyPairGenerator
    {
        private final KeyPairGenerator bcGenerator;

        ForeignKeyPairGenerator(KeyPairGenerator bcGenerator)
        {
            super(bcGenerator.getAlgorithm());
            this.bcGenerator = bcGenerator;
        }

        public void initialize(int keySize, SecureRandom random)
        {
            bcGenerator.initialize(keySize, random);
        }

        public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException
        {
            bcGenerator.initialize(params, random);
        }

        public KeyPair generateKeyPair()
        {
            KeyPair kp = bcGenerator.generateKeyPair();
            return new KeyPair(new ForeignPublicKey(kp.getPublic().getEncoded()),
                new ForeignPrivateKey(kp.getPrivate().getEncoded()));
        }
    }

    private static class ForeignPublicKey
        implements PublicKey
    {
        private final byte[] encoding;

        ForeignPublicKey(byte[] encoding)
        {
            this.encoding = encoding;
        }

        public String getAlgorithm()
        {
            return "ML-KEM";
        }

        public String getFormat()
        {
            return "X.509";
        }

        public byte[] getEncoded()
        {
            return Arrays.clone(encoding);
        }
    }

    private static class ForeignPrivateKey
        implements PrivateKey
    {
        private final byte[] encoding;

        ForeignPrivateKey(byte[] encoding)
        {
            this.encoding = encoding;
        }

        public String getAlgorithm()
        {
            return "ML-KEM";
        }

        public String getFormat()
        {
            return "PKCS#8";
        }

        public byte[] getEncoded()
        {
            return Arrays.clone(encoding);
        }
    }
}

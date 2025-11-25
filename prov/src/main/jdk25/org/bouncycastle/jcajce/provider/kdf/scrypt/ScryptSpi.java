package org.bouncycastle.jcajce.provider.kdf.scrypt;

import org.bouncycastle.crypto.PasswordConverter;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.jcajce.spec.ScryptKeySpec;
import org.bouncycastle.jcajce.spec.ScryptParameterSpec;
import org.bouncycastle.util.Arrays;

import javax.crypto.KDFParameters;
import javax.crypto.KDFSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * Example KDFSpi that delegates to Bouncy Castle’s SCrypt implementation.
 */
class ScryptSpi
        extends KDFSpi
{
    protected ScryptSpi(KDFParameters kdfParameters)
            throws InvalidAlgorithmParameterException
    {
        super(requireNull(kdfParameters, "Scrypt" + " does not support parameters"));
    }

    @Override
    protected KDFParameters engineGetParameters()
    {
        return null;
    }

    @Override
    protected SecretKey engineDeriveKey(String alg, AlgorithmParameterSpec derivationSpec)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException
    {
        byte[] derived = engineDeriveData(derivationSpec);

        return new SecretKeySpec(derived, alg);
    }

    @Override
    protected byte[] engineDeriveData(AlgorithmParameterSpec derivationSpec)
            throws InvalidAlgorithmParameterException
    {
        if (!(derivationSpec instanceof ScryptParameterSpec))
        {
            throw new InvalidAlgorithmParameterException(
                    "SCrypt requires an SCryptParameterSpec as derivation parameters");
        }

        ScryptKeySpec spec = (ScryptKeySpec) derivationSpec;

        char[] password = spec.getPassword();
        byte[] salt = spec.getSalt();
        int cost = spec.getCostParameter();
        int blockSize = spec.getBlockSize();
        int p = spec.getParallelizationParameter();
        int keyLen = spec.getKeyLength();

        if (salt == null)
        {
            throw new InvalidAlgorithmParameterException("Salt S must be provided.");
        }
        if (cost <= 1)
        {
            throw new InvalidAlgorithmParameterException("Cost parameter N must be > 1.");
        }

        if (keyLen <= 0)
        {
            throw new InvalidAlgorithmParameterException("positive key length required: "
                    + keyLen);
        }

        byte[] derived = SCrypt.generate(
                PasswordConverter.UTF8.convert(password),
                salt, cost, blockSize, p, keyLen / 8);

        Arrays.clear(password);
     
        return derived;
    }

    private static KDFParameters requireNull(KDFParameters kdfParameters,
                                             String message) throws InvalidAlgorithmParameterException
    {
        if (kdfParameters != null)
        {
            throw new InvalidAlgorithmParameterException(message);
        }
        return null;
    }

    public static class ScryptWithUTF8
            extends ScryptSpi
    {
        public ScryptWithUTF8(KDFParameters parameters) throws InvalidAlgorithmParameterException
        {
            super(parameters);
        }
    }
}

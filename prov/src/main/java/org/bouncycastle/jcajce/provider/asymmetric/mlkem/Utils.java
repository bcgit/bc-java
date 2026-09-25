package org.bouncycastle.jcajce.provider.asymmetric.mlkem;

import java.security.InvalidKeyException;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;

class Utils
{
    private static Map parameters = new HashMap();

    private static final MLKEMKeyFactorySpi keyFactory = new MLKEMKeyFactorySpi();

    static
    {
        parameters.put(MLKEMParameterSpec.ml_kem_512.getName(), MLKEMParameters.ml_kem_512);
        parameters.put(MLKEMParameterSpec.ml_kem_768.getName(), MLKEMParameters.ml_kem_768);
        parameters.put(MLKEMParameterSpec.ml_kem_1024.getName(), MLKEMParameters.ml_kem_1024);
    }

    static MLKEMParameters getParameters(String name)
    {
        return (MLKEMParameters)parameters.get(name);
    }

    /**
     * Return the BC form of an ML-KEM public key, converting a key from another provider via its X.509 encoding.
     *
     * @param key the key to convert.
     * @return a BCMLKEMPublicKey for the same key.
     * @throws InvalidKeyException if key is not an ML-KEM public key.
     */
    static BCMLKEMPublicKey toBCPublicKey(Key key)
        throws InvalidKeyException
    {
        if (key instanceof BCMLKEMPublicKey)
        {
            return (BCMLKEMPublicKey)key;
        }

        Key bcKey = keyFactory.engineTranslateKey(key);
        if (!(bcKey instanceof BCMLKEMPublicKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }

        return (BCMLKEMPublicKey)bcKey;
    }

    /**
     * Return the BC form of an ML-KEM private key, converting a key from another provider via its PKCS#8 encoding.
     *
     * @param key the key to convert.
     * @return a BCMLKEMPrivateKey for the same key.
     * @throws InvalidKeyException if key is not an extractable ML-KEM private key.
     */
    static BCMLKEMPrivateKey toBCPrivateKey(Key key)
        throws InvalidKeyException
    {
        if (key instanceof BCMLKEMPrivateKey)
        {
            return (BCMLKEMPrivateKey)key;
        }

        Key bcKey = keyFactory.engineTranslateKey(key);
        if (!(bcKey instanceof BCMLKEMPrivateKey))
        {
            throw new InvalidKeyException("unsupported key type");
        }

        return (BCMLKEMPrivateKey)bcKey;
    }
}

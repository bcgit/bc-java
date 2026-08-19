package org.bouncycastle.jcajce.util;

import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.provider.symmetric.util.ClassUtil;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import java.util.Objects;

public abstract class SpiUtil
{
    // In case of unexpected failure, defaulting to true seems the least bad choice
    private static final boolean HAS_KEM = isClassPresent("javax.crypto.KEMSpi", true);

    public static boolean hasKDF()
    {
        return false;
    }

    public static boolean hasKEM()
    {
        return HAS_KEM;
    }

    private static boolean isClassPresent(String className, boolean defaultResult)
    {
        try
        {
            return ClassUtil.loadClass(SpiUtil.class, "javax.crypto.KEMSpi") != null;
        }
        catch (Exception e)
        {
            return defaultResult;
        }
    }

    public static String resolveDecapsulateAlgorithm(byte[] encapsulation, int from, int to, String algorithm,
                                                     int engineSecretSize, int engineEncapsulationSize, KTSParameterSpec parameterSpec)
            throws DecapsulateException
    {
        Objects.checkFromToIndex(from, to, engineSecretSize);
        Objects.requireNonNull(algorithm, "null algorithm");
        Objects.requireNonNull(encapsulation, "null encapsulation");

        if (encapsulation.length != engineEncapsulationSize)
        {
            throw new DecapsulateException("incorrect encapsulation size");
        }

        return KdfUtil.resolveAlgorithm(parameterSpec, algorithm);
    }

    public static KEM.Encapsulated buildEncapsulated(int from, int to, String algorithm, int engineSecretSize,
                                                     EncapsulatedSecretGenerator kemGen, AsymmetricKeyParameter recipientKey,
                                                     KTSParameterSpec parameterSpec)
    {
        Objects.checkFromToIndex(from, to, engineSecretSize);
        Objects.requireNonNull(algorithm, "null algorithm");

        algorithm = KdfUtil.resolveAlgorithm(parameterSpec, algorithm);

        SecretWithEncapsulation secEnc = kemGen.generateEncapsulated(recipientKey);

        try
        {
            // getEncapsulation()/getSecret() hand back clones, so the originals have to be
            // destroyed as well - KdfUtil.makeSecretKey only clears the secret clone it is passed.
            byte[] encapsulation = secEnc.getEncapsulation();

            SecretKey secretKey = KdfUtil.makeSecretKey(parameterSpec, secEnc.getSecret(),
                    from, to, algorithm);

            return new KEM.Encapsulated(secretKey, encapsulation, null);
        }
        finally
        {
            try
            {
                secEnc.destroy();
            }
            catch (DestroyFailedException e)
            {
                // ignore
            }
        }
    }
}

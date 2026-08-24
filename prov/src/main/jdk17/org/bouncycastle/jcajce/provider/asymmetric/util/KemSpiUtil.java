package org.bouncycastle.jcajce.provider.asymmetric.util;

import java.util.Objects;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;

import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;

/**
 * The prologue and the encapsulate body shared by every {@code javax.crypto.KEMSpi} implementation
 * in this overlay - the ten {@code *EncapsulatorSpi} / {@code *DecapsulatorSpi} pairs across
 * {@code jcajce.provider.asymmetric} and {@code pqc.jcajce.provider}, which differ only in the
 * engine and key they hand in.
 * <p>
 * <b>This class must not be given a {@code jdk1.N} twin, and these methods must not be moved onto a
 * class that has one.</b> Multi-release resolution is per class file: the SPIs exist only in the
 * {@code jdk17} overlay, so on a JDK 25 runtime they are loaded from {@code META-INF/versions/17}
 * while a class that also has a {@code jdk25} copy is loaded from {@code META-INF/versions/25}. A
 * helper hosted on such a class is therefore a different class than the one the SPIs were compiled
 * against. These two methods first lived on {@code org.bouncycastle.jcajce.util.SpiUtil}, whose
 * jdk25 twin exists because {@code hasKDF()} differs there and which consequently carries neither
 * method, and every encapsulate and decapsulate failed with {@code NoSuchMethodError} on JDK 25
 * while JDK 21 was unaffected. {@code jcajce.provider.asymmetric.util} has no overlay above the
 * base tree, so a class added here resolves from {@code versions/17} on every runtime that has the
 * SPIs at all. {@code KemSpiMRTest} in {@code prov/src/test/jdk25} guards this.
 */
public class KemSpiUtil
{
    private KemSpiUtil()
    {
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

package org.bouncycastle.jcajce.provider.symmetric.util;

import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.ChaCha20ParameterSpec;

import org.bouncycastle.jcajce.spec.BCChaCha20ParameterSpec;

/**
 * Converts the JDK's {@link ChaCha20ParameterSpec} into the BC equivalent, {@link BCChaCha20ParameterSpec}, so
 * the provider only has to handle the BC type.
 * <p>
 * This is the Java 11 copy, which uses the class directly; the base copy works by reflection. The two copies must
 * keep the same public members: a caller compiled against the base copy is paired at runtime with this one.
 * </p>
 */
public class ChaCha20SpecUtil
{
    /**
     * Convert a {@link ChaCha20ParameterSpec} into the BC equivalent.
     *
     * @param paramSpec the parameter spec to convert, may be null.
     * @return the equivalent {@link BCChaCha20ParameterSpec}, or null if paramSpec is not a
     * {@link ChaCha20ParameterSpec}.
     * @throws InvalidAlgorithmParameterException if paramSpec is one, but its values cannot be read.
     */
    public static BCChaCha20ParameterSpec toBCChaCha20Spec(final AlgorithmParameterSpec paramSpec)
        throws InvalidAlgorithmParameterException
    {
        if (!(paramSpec instanceof ChaCha20ParameterSpec))
        {
            return null;
        }

        ChaCha20ParameterSpec chaCha20Spec = (ChaCha20ParameterSpec)paramSpec;

        return new BCChaCha20ParameterSpec(chaCha20Spec.getNonce(), chaCha20Spec.getCounter());
    }
}

package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.util.Arrays;

/**
 * Parameter spec for doing KTS based wrapping via the Cipher API.
 */
public class KTSParameterSpec
    implements AlgorithmParameterSpec
{
    private final String wrappingKeyAlgorithm;
    private final int keySizeInBits;
    private final AlgorithmParameterSpec parameterSpec;
    private final AlgorithmIdentifier kdfAlgorithm;
    private byte[] otherInfo;

    /**
     * Builder class for creating a KTSParameterSpec.
     */
    public static final class Builder
    {
        private final String algorithmName;
        private final int keySizeInBits;

        private AlgorithmParameterSpec parameterSpec;
        private AlgorithmIdentifier kdfAlgorithm;
        private byte[] otherInfo;

        /**
         * Basic builder.
         *
         * @param algorithmName the algorithm name for the secret key we use for wrapping.
         * @param keySizeInBits the size of the wrapping key we want to produce in bits.
         */
        public Builder(String algorithmName, int keySizeInBits)
        {
            this(algorithmName, keySizeInBits, null);
        }

        /**
         * Basic builder.
         *
         * @param algorithmName the algorithm name for the secret key we use for wrapping.
         * @param keySizeInBits the size of the wrapping key we want to produce in bits.
         * @param otherInfo     the otherInfo/IV encoding to be applied to the KDF.
         */
        public Builder(String algorithmName, int keySizeInBits, byte[] otherInfo)
        {
            this.algorithmName = algorithmName;
            this.keySizeInBits = keySizeInBits;
            this.kdfAlgorithm = new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf3, new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));
            this.otherInfo = (otherInfo == null) ? new byte[0] : Arrays.clone(otherInfo);
        }

        /**
         * Set the algorithm parameter spec to be used with the wrapper.
         *
         * @param parameterSpec the algorithm parameter spec to be used in wrapping/unwrapping.
         * @return the current Builder instance.
         */
        public Builder withParameterSpec(AlgorithmParameterSpec parameterSpec)
        {
            this.parameterSpec = parameterSpec;

            return this;
        }

        /**
         * Set the KDF algorithm and digest algorithm for wrap key generation.
         *
         * @param kdfAlgorithm the KDF algorithm to apply.
         * @return the current Builder instance.
         */
        public Builder withKdfAlgorithm(AlgorithmIdentifier kdfAlgorithm)
        {
            this.kdfAlgorithm = kdfAlgorithm;

            return this;
        }

        /**
         * Build the new parameter spec.
         *
         * @return a new parameter spec configured according to the builder state.
         */
        public KTSParameterSpec build()
        {
            return new KTSParameterSpec(algorithmName, keySizeInBits, parameterSpec, kdfAlgorithm, otherInfo);
        }
    }

    private KTSParameterSpec(
        String wrappingKeyAlgorithm, int keySizeInBits,
        AlgorithmParameterSpec parameterSpec, AlgorithmIdentifier kdfAlgorithm, byte[] otherInfo)
    {
        this.wrappingKeyAlgorithm = wrappingKeyAlgorithm;
        this.keySizeInBits = keySizeInBits;
        this.parameterSpec = parameterSpec;
        this.kdfAlgorithm = kdfAlgorithm;
        this.otherInfo = otherInfo;
    }

    /**
     * Return the name of the algorithm for the wrapping key this key spec should use.
     *
     * @return the key algorithm.
     */
    public String getKeyAlgorithmName()
    {
        return wrappingKeyAlgorithm;
    }

    /**
     * Return the size of the key (in bits) for the wrapping key this key spec should use.
     *
     * @return length in bits of the key to be calculated.
     */
    public int getKeySize()
    {
        return keySizeInBits;
    }

    /**
     * Return the algorithm parameter spec to be applied with the private key when the encapsulation is decrypted.
     *
     * @return the algorithm parameter spec to be used with the private key.
     */
    public AlgorithmParameterSpec getParameterSpec()
    {
        return parameterSpec;
    }

    /**
     * Return the AlgorithmIdentifier for the KDF to do key derivation after extracting the secret.
     *
     * @return the AlgorithmIdentifier for the SecretKeyFactory's KDF.
     */
    public AlgorithmIdentifier getKdfAlgorithm()
    {
        return kdfAlgorithm;
    }

    /**
     * Return the otherInfo data for initialising the KDF.
     *
     * @return the otherInfo data.
     */
    public byte[] getOtherInfo()
    {
        return Arrays.clone(otherInfo);
    }
}

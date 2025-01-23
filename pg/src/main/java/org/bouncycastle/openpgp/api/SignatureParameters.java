package org.bouncycastle.openpgp.api;

import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.util.Arrays;

import java.util.Date;

/**
 * Parameters for signature generation.
 */
public class SignatureParameters
{
    private int signatureType;
    private Date signatureCreationTime = new Date();
    private int signatureHashAlgorithmId;
    private SignatureSubpacketsFunction hashedSubpacketsFunction;
    private SignatureSubpacketsFunction unhashedSubpacketsFunction;

    private final int[] allowedSignatureTypes;

    private SignatureParameters(int... allowedSignatureTypes)
    {
        this.allowedSignatureTypes = allowedSignatureTypes;
    }

    /**
     * Create default signature parameters object for a direct-key signature.
     *
     * @param policy algorithm policy
     * @return parameters
     */
    public static SignatureParameters directKeySignature(OpenPGPPolicy policy)
    {
        return new SignatureParameters(PGPSignature.DIRECT_KEY)
                .setSignatureType(PGPSignature.DIRECT_KEY)
                .setSignatureHashAlgorithm(policy.getDefaultCertificationSignatureHashAlgorithm())
                .setSignatureCreationTime(new Date());
    }

    /**
     * Create a default signature parameters object for a certification signature.
     * The default signature type is {@link PGPSignature#POSITIVE_CERTIFICATION}, but can be changed to
     * {@link PGPSignature#DEFAULT_CERTIFICATION}, {@link PGPSignature#NO_CERTIFICATION},
     * {@link PGPSignature#CASUAL_CERTIFICATION}.
     *
     * @param policy algorithm policy
     * @return parameters
     */
    public static SignatureParameters certification(OpenPGPPolicy policy)
    {
        return new SignatureParameters(
                PGPSignature.DEFAULT_CERTIFICATION,
                PGPSignature.NO_CERTIFICATION,
                PGPSignature.CASUAL_CERTIFICATION,
                PGPSignature.POSITIVE_CERTIFICATION)
                .setSignatureType(PGPSignature.POSITIVE_CERTIFICATION)
                .setSignatureHashAlgorithm(policy.getDefaultCertificationSignatureHashAlgorithm())
                .setSignatureCreationTime(new Date());
    }

    /**
     * Create a default signature parameters object for a subkey binding signature.
     *
     * @param policy algorithm policy
     * @return parameters
     */
    public static SignatureParameters subkeyBinding(OpenPGPPolicy policy)
    {
        return new SignatureParameters(PGPSignature.SUBKEY_BINDING)
                .setSignatureType(PGPSignature.SUBKEY_BINDING)
                .setSignatureHashAlgorithm(policy.getDefaultCertificationSignatureHashAlgorithm())
                .setSignatureCreationTime(new Date());
    }

    /**
     * Create a default signature parameters object for a primary-key binding (back-sig) signature.
     *
     * @param policy algorithm policy
     * @return parameters
     */
    public static SignatureParameters primaryKeyBinding(OpenPGPPolicy policy)
    {
        return new SignatureParameters(PGPSignature.PRIMARYKEY_BINDING)
                .setSignatureType(PGPSignature.PRIMARYKEY_BINDING)
                .setSignatureHashAlgorithm(policy.getDefaultCertificationSignatureHashAlgorithm())
                .setSignatureCreationTime(new Date());
    }

    /**
     * Create a default signature parameters object for a certification-revocation signature.
     *
     * @param policy algorithm policy
     * @return parameters
     */
    public static SignatureParameters certificationRevocation(OpenPGPPolicy policy)
    {
        return new SignatureParameters(PGPSignature.CERTIFICATION_REVOCATION)
                .setSignatureType(PGPSignature.CERTIFICATION_REVOCATION)
                .setSignatureHashAlgorithm(policy.getDefaultCertificationSignatureHashAlgorithm())
                .setSignatureCreationTime(new Date());
    }

    /**
     * Create a default signature parameters object for a data/document signature.
     * The default signature type is {@link PGPSignature#BINARY_DOCUMENT}, but can be changed to
     * {@link PGPSignature#CANONICAL_TEXT_DOCUMENT}.
     *
     * @param policy algorithm policy
     * @return parameters
     */
    public static SignatureParameters dataSignature(OpenPGPPolicy policy)
    {
        return new SignatureParameters(PGPSignature.BINARY_DOCUMENT, PGPSignature.CANONICAL_TEXT_DOCUMENT)
                .setSignatureType(PGPSignature.BINARY_DOCUMENT)
                .setSignatureHashAlgorithm(policy.getDefaultDocumentSignatureHashAlgorithm())
                .setSignatureCreationTime(new Date());
    }

    /**
     * Change the signature type of the signature to-be-generated to the given type.
     * Depending on which factory method was used to instantiate the signature parameters object,
     * only certain signature types are allowed. Passing an illegal signature type causes an
     * {@link IllegalArgumentException} to be thrown.
     *
     * @param signatureType signature type
     * @return parameters
     * @throws IllegalArgumentException if an illegal signature type is passed
     */
    public SignatureParameters setSignatureType(int signatureType)
    {
        if (!Arrays.contains(allowedSignatureTypes, signatureType))
        {
            throw new IllegalArgumentException("Illegal signature type provided.");
        }

        this.signatureType = signatureType;
        return this;
    }

    /**
     * Return the signature type for the signature to-be-generated.
     *
     * @return signature type
     */
    public int getSignatureType()
    {
        return signatureType;
    }

    /**
     * Change the creation time of the signature to-be-generated.
     *
     * @param signatureCreationTime signature creation time
     * @return parameters
     */
    public SignatureParameters setSignatureCreationTime(Date signatureCreationTime)
    {
        this.signatureCreationTime = signatureCreationTime;
        return this;
    }

    /**
     * Return the creation time of the signature to-be-generated.
     *
     * @return signature creation time
     */
    public Date getSignatureCreationTime()
    {
        return signatureCreationTime;
    }

    /**
     * Change the hash algorithm for the signature to-be-generated.
     *
     * @param signatureHashAlgorithmId signature hash algorithm id
     * @return parameters
     */
    public SignatureParameters setSignatureHashAlgorithm(int signatureHashAlgorithmId)
    {
        this.signatureHashAlgorithmId = signatureHashAlgorithmId;
        return this;
    }

    /**
     * Return the hash algorithm id of the signature to-be-generated.
     *
     * @return hash algorithm id
     */
    public int getSignatureHashAlgorithmId()
    {
        return signatureHashAlgorithmId;
    }

    /**
     * Set a function, which is applied to the hashed subpackets area of the signature to-be-generated.
     *
     * @param subpacketsFunction function to apply to the hashed signature subpackets
     * @return parameters
     */
    public SignatureParameters setHashedSubpacketsFunction(SignatureSubpacketsFunction subpacketsFunction)
    {
        this.hashedSubpacketsFunction = subpacketsFunction;
        return this;
    }

    /**
     * Apply the hashed subpackets function set via {@link #setHashedSubpacketsFunction(SignatureSubpacketsFunction)}
     * to the given hashed subpackets.
     *
     * @param hashedSubpackets hashed signature subpackets
     * @return modified hashed subpackets
     */
    PGPSignatureSubpacketGenerator applyToHashedSubpackets(PGPSignatureSubpacketGenerator hashedSubpackets)
    {
        if (hashedSubpacketsFunction != null)
        {
            return hashedSubpacketsFunction.apply(hashedSubpackets);
        }
        return hashedSubpackets;
    }

    /**
     * Set a function, which is applied to the unhashed subpackets area of the signature to-be-generated.
     *
     * @param subpacketsFunction function to apply to the unhashed signature subpackets
     * @return parameters
     */
    public SignatureParameters setUnhashedSubpacketsFunction(SignatureSubpacketsFunction subpacketsFunction)
    {
        this.unhashedSubpacketsFunction = subpacketsFunction;
        return this;
    }

    /**
     * Apply the unhashed subpackets function set via {@link #setUnhashedSubpacketsFunction(SignatureSubpacketsFunction)}
     * to the given unhashed subpackets.
     *
     * @param unhashedSubpackets unhashed signature subpackets
     * @return modified unhashed subpackets
     */
    PGPSignatureSubpacketGenerator applyToUnhashedSubpackets(PGPSignatureSubpacketGenerator unhashedSubpackets)
    {
        if (unhashedSubpacketsFunction != null)
        {
            return unhashedSubpacketsFunction.apply(unhashedSubpackets);
        }
        return unhashedSubpackets;
    }

    /**
     * Callback, allowing the user to modify {@link SignatureParameters} before use.
     */
    public interface Callback
    {
        /**
         * Apply custom changes to {@link SignatureParameters}.
         *
         * @param parameters parameters instance
         * @return modified parameters, or null
         */
        default SignatureParameters apply(SignatureParameters parameters)
        {
            return parameters;
        }

        /**
         * Shortcut method returning a {@link Callback} which only applies the given
         * {@link SignatureSubpacketsFunction} to the hashed signature subpacket area of a signature.
         *
         * @param function signature subpackets function to apply to the hashed area
         * @return callback
         */
        static Callback modifyHashedSubpackets(SignatureSubpacketsFunction function)
        {
            return new Callback()
            {
                @Override
                public SignatureParameters apply(SignatureParameters parameters)
                {
                    return parameters.setHashedSubpacketsFunction(function);
                }
            };
        }
    }
}

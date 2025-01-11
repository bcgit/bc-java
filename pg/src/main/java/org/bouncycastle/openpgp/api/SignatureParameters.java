package org.bouncycastle.openpgp.api;

import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.util.Arrays;

import java.util.Date;

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

    public static SignatureParameters directKeySignatureParameters(OpenPGPPolicy policy)
    {
        return new SignatureParameters(PGPSignature.DIRECT_KEY)
                .setSignatureType(PGPSignature.DIRECT_KEY)
                .setSignatureHashAlgorithm(policy.getDefaultCertificationSignatureHashAlgorithm())
                .setSignatureCreationTime(new Date());
    }

    public static SignatureParameters certificationSignatureParameters(OpenPGPPolicy policy)
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

    public static SignatureParameters subkeyBindingSignatureParameters(OpenPGPPolicy policy)
    {
        return new SignatureParameters(PGPSignature.SUBKEY_BINDING)
                .setSignatureType(PGPSignature.SUBKEY_BINDING)
                .setSignatureHashAlgorithm(policy.getDefaultCertificationSignatureHashAlgorithm())
                .setSignatureCreationTime(new Date());
    }

    public static SignatureParameters primaryKeyBindingSignatureParameters(OpenPGPPolicy policy)
    {
        return new SignatureParameters(PGPSignature.PRIMARYKEY_BINDING)
                .setSignatureType(PGPSignature.PRIMARYKEY_BINDING)
                .setSignatureHashAlgorithm(policy.getDefaultCertificationSignatureHashAlgorithm())
                .setSignatureCreationTime(new Date());
    }

    public static SignatureParameters certificationRevocationSignatureParameters(OpenPGPPolicy policy)
    {
        return new SignatureParameters(PGPSignature.CERTIFICATION_REVOCATION)
                .setSignatureType(PGPSignature.CERTIFICATION_REVOCATION)
                .setSignatureHashAlgorithm(policy.getDefaultCertificationSignatureHashAlgorithm())
                .setSignatureCreationTime(new Date());
    }

    public SignatureParameters setSignatureType(int signatureType)
    {
        if (!Arrays.contains(allowedSignatureTypes, signatureType))
        {
            throw new IllegalArgumentException("Illegal signature type provided.");
        }

        this.signatureType = signatureType;
        return this;
    }

    public int getSignatureType()
    {
        return signatureType;
    }

    public SignatureParameters setSignatureCreationTime(Date signatureCreationTime)
    {
        this.signatureCreationTime = signatureCreationTime;
        return this;
    }

    public Date getSignatureCreationTime()
    {
        return signatureCreationTime;
    }

    public SignatureParameters setSignatureHashAlgorithm(int signatureHashAlgorithmId)
    {
        this.signatureHashAlgorithmId = signatureHashAlgorithmId;
        return this;
    }

    public int getSignatureHashAlgorithmId()
    {
        return signatureHashAlgorithmId;
    }

    public SignatureParameters setHashedSubpacketsFunction(SignatureSubpacketsFunction subpacketsFunction)
    {
        this.hashedSubpacketsFunction = subpacketsFunction;
        return this;
    }

    PGPSignatureSubpacketGenerator applyToHashedSubpackets(PGPSignatureSubpacketGenerator hashedSubpackets)
    {
        if (hashedSubpacketsFunction != null)
        {
            return hashedSubpacketsFunction.apply(hashedSubpackets);
        }
        return hashedSubpackets;
    }

    public SignatureParameters setUnhashedSubpacketsFunction(SignatureSubpacketsFunction subpacketsFunction)
    {
        this.unhashedSubpacketsFunction = subpacketsFunction;
        return this;
    }

    PGPSignatureSubpacketGenerator applyToUnhashedSubpackets(PGPSignatureSubpacketGenerator unhashedSubpackets)
    {
        if (unhashedSubpacketsFunction != null)
        {
            return unhashedSubpacketsFunction.apply(unhashedSubpackets);
        }
        return unhashedSubpackets;
    }

    public interface Callback
    {
        default SignatureParameters apply(SignatureParameters parameters)
        {
            return parameters;
        }

        static Callback applyToHashedSubpackets(SignatureSubpacketsFunction function)
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

package org.bouncycastle.openpgp;

import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.util.Strings;

/**
 * Builder for thread-safe verifiers for a range of PGP signature types.
 */
public class PGPSignatureVerifierBuilder
{
    private final PGPContentVerifierBuilderProvider verifierBuilderProvider;
    private final PGPPublicKey verificationKey;

    /**
     * Base constructor.
     * 
     * @param verifierBuilderProvider provider to build verifiers from.
     * @param verificationKey the public key which corresponds to the signing key generating the signatures we are looking at.
     */
    public PGPSignatureVerifierBuilder(PGPContentVerifierBuilderProvider verifierBuilderProvider, PGPPublicKey verificationKey)
    {
        this.verifierBuilderProvider = verifierBuilderProvider;
        this.verificationKey = verificationKey;
    }

    /**
      * Instantiate a signature verifier for a {@link PGPSignature#DIRECT_KEY} signature.
      *
      * @param certification the PGP signature containing the certification.
      * @param publicKey public key subject for the direct key signature.
      * @return a verifier.
      * @throws PGPException if signature type is wrong or there is a problem constructing the verifier.
      */
     public PGPSignatureVerifier buildDirectKeyVerifier(PGPSignature certification, final PGPPublicKey publicKey)
         throws PGPException
     {
         if (certification.getSignatureType() != PGPSignature.DIRECT_KEY)
         {
             throw new PGPException("signature is not a direct key signature");
         }

         return doBuildKeyCertificationVerifier(certification, publicKey);
     }

    /**
      * Instantiate a signature verifier for a {@link PGPSignature#KEY_REVOCATION} signature.
      *
      * @param certification the PGP signature containing the certification.
      * @param publicKey public key subject for key revocation signature.
      * @return a verifier.
      * @throws PGPException if signature type is wrong or there is a problem constructing the verifier.
      */
     public PGPSignatureVerifier buildKeyRevocationVerifier(PGPSignature certification, final PGPPublicKey publicKey)
         throws PGPException
     {
         if (certification.getSignatureType() != PGPSignature.KEY_REVOCATION)
         {
             throw new PGPException("signature is not a key revocation signature");
         }

         return doBuildKeyCertificationVerifier(certification, publicKey);
     }

    /**
     * Instantiate a signature verifier for a {@link PGPSignature#PRIMARYKEY_BINDING} signature.
     *
     * @param certification the PGP signature containing the certification.
     * @param primaryKey primary key for the primary key binding signature.
     * @param subKey sub-key  for the primary key binding signature.
     * @return a verifier.
     * @throws PGPException if signature type is wrong or there is a problem constructing the verifier.
     */
    public PGPSignatureVerifier buildPrimaryKeyBindingVerifier(PGPSignature certification, PGPPublicKey primaryKey, PGPPublicKey subKey)
        throws PGPException
    {
        if (certification.getSignatureType() != PGPSignature.PRIMARYKEY_BINDING)
        {
            throw new PGPException("signature is not a primary key binding signature");
        }

        return doBuildKeyBindingVerifier(certification, primaryKey, subKey);
    }

    /**
     * Instantiate a signature verifier for a {@link PGPSignature#SUBKEY_BINDING} signature.
     *
     * @param certification the PGP signature containing the certification.
     * @param primaryKey primary key for the sub-key  binding signature.
     * @param subKey sub-key  for the sub-key  binding signature.
     * @return a verifier.
     * @throws PGPException if signature type is wrong or there is a problem constructing the verifier.
     */
    public PGPSignatureVerifier buildSubKeyBindingVerifier(PGPSignature certification, PGPPublicKey primaryKey, PGPPublicKey subKey)
        throws PGPException
    {
        if (certification.getSignatureType() != PGPSignature.SUBKEY_BINDING)
        {
            throw new PGPException("signature is not a subkey binding signature");
        }

        return doBuildKeyBindingVerifier(certification, primaryKey, subKey);
    }

    /**
      * Instantiate a signature verifier for a {@link PGPSignature#SUBKEY_REVOCATION} signature.
      *
      * @param certification the PGP signature containing the certification.
      * @param primaryKey primary key for the sub-key key revocation signature.
      * @param subKey sub-key for the sub-key key revocation signature.
      * @return a verifier.
      * @throws PGPException if signature type is wrong or there is a problem constructing the verifier.
      */
     public PGPSignatureVerifier buildSubKeyRevocationVerifier(PGPSignature certification, final PGPPublicKey primaryKey, final PGPPublicKey subKey)
         throws PGPException
     {
         if (certification.getSignatureType() != PGPSignature.SUBKEY_REVOCATION)
         {
             throw new PGPException("signature is not a primary key binding signature");
         }

         return doBuildKeyBindingVerifier(certification, primaryKey, subKey);
     }

    /**
     * Return a verifier for a signature as certifying the passed in public key as associated
     * with the passed in user ID.
     *
     * @param userID the user ID, will be converted to UTF8.
     * @param publicKey the key to be verified.
     * @return a verifier.
     * @throws PGPException if signature type is wrong or there is a problem constructing the verifier.
     */
    public PGPSignatureVerifier buildCertificationVerifier(PGPSignature certification, String userID, final PGPPublicKey publicKey)
        throws PGPException
    {
        return buildCertificationVerifier(certification, Strings.toUTF8ByteArray(userID), publicKey);
    }

    /**
     * Return a verifier for a signature as certifying the passed in public key as associated
     * with the passed in raw user ID.
     *
     * @param rawUserID raw encoding of the user ID (assumed a UTF8 string, not user attributes)
     * @param publicKey the key to be verified.
     * @return a verifier.
     * @throws PGPException if signature type is wrong or there is a problem constructing the verifier.
     */
    public PGPSignatureVerifier buildCertificationVerifier(PGPSignature certification, byte[] rawUserID, final PGPPublicKey publicKey)
        throws PGPException
    {
        int signatureType = certification.getSignatureType();
        if (!PGPSignature.isCertification(signatureType)
            && PGPSignature.CERTIFICATION_REVOCATION != signatureType)
        {
            throw new PGPException("signature is neither a certification signature nor a certification revocation");
        }

        return doBuildCertificationVerifier(certification, rawUserID, publicKey);
    }

    /**
     * Return a verifier for a signature as certifying the passed in public key as associated
     * with the passed in user attributes.
     *
     * @param userAttributes user attributes the key was stored under
     * @param publicKey the key to be verified.
     * @return a verifier.
     * @throws PGPException if signature type is wrong or there is a problem constructing the verifier.
     */
    public PGPSignatureVerifier buildCertificationVerifier(PGPSignature certification, PGPUserAttributeSubpacketVector userAttributes, final PGPPublicKey publicKey)
        throws PGPException
    {
        int signatureType = certification.getSignatureType();
        if (!PGPSignature.isCertification(signatureType)
            && PGPSignature.CERTIFICATION_REVOCATION != signatureType)
        {
            throw new PGPException("signature is neither a certification signature nor a certification revocation");
        }

        return doBuildCertificationVerifier(certification, userAttributes, publicKey);
    }

    private PGPSignatureVerifier doBuildCertificationVerifier(PGPSignature certification, final byte[] rawUserID, final PGPPublicKey publicKey)
        throws PGPException
    {
        final PGPSignature localSig = createLocalSig(certification);

        return new PGPSignatureVerifier()
        {
            @Override
            public int getSignatureType()
            {
                return localSig.getSignatureType();
            }

            @Override
            public boolean isVerified()
                throws PGPException
            {
                return localSig.doVerifyCertification(rawUserID, publicKey);
            }
        };
    }

    private PGPSignature createLocalSig(PGPSignature certification)
        throws PGPException
    {
        final PGPSignature localSig = new PGPSignature(certification);

        localSig.init(localSig.createVerifierProvider(verifierBuilderProvider).build(verificationKey));
        return localSig;
    }

    private PGPSignatureVerifier doBuildCertificationVerifier(PGPSignature certification, final PGPUserAttributeSubpacketVector userAttributes, final PGPPublicKey publicKey)
        throws PGPException
    {
        final PGPSignature localSig = createLocalSig(certification);

        return new PGPSignatureVerifier()
        {
            @Override
            public int getSignatureType()
            {
                return localSig.getSignatureType();
            }

            @Override
            public boolean isVerified()
                throws PGPException
            {
                return localSig.doVerifyCertification(userAttributes, publicKey);
            }
        };
    }

    private PGPSignatureVerifier doBuildKeyCertificationVerifier(PGPSignature keyCertification, final PGPPublicKey publicKey)
        throws PGPException
    {
        final PGPSignature localSig = createLocalSig(keyCertification);

        return new PGPSignatureVerifier()
        {
            @Override
            public int getSignatureType()
            {
                return localSig.getSignatureType();
            }

            @Override
            public boolean isVerified()
                throws PGPException
            {
                return localSig.doVerifyCertification(publicKey);
            }
        };
    }

    private PGPSignatureVerifier doBuildKeyBindingVerifier(PGPSignature certification, final PGPPublicKey primaryKey, final PGPPublicKey subKey)
        throws PGPException
    {
        final PGPSignature localSig = createLocalSig(certification);

        return new PGPSignatureVerifier()
        {
            @Override
            public int getSignatureType()
            {
                return localSig.getSignatureType();
            }

            @Override
            public boolean isVerified()
                throws PGPException
            {
                return localSig.doVerifyCertification(primaryKey, subKey);
            }
        };
    }
}

package org.bouncycastle.openpgp.smartcard;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPImplementation;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilderProvider;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.smartcard.operator.ExternalContentSignerBuilder;

public abstract class OpenPGPSmartCardImplementation
{
    public final OpenPGPImplementation implementation;

    public OpenPGPSmartCardImplementation(OpenPGPImplementation implementation)
    {
        this.implementation = implementation;
    }

    /**
     * Provide a {@link PublicKeyDataDecryptorFactory} that decrypts messages by delegating public-key cryptography
     * to the given {@link OpenPGPSmartCard}.
     *
     * @param secretKey stub secret key
     * @param card smart card for message decryption
     * @param userPinProvider provider for the smart cards user PIN
     * @return decryptor factory
     * @throws PGPException
     */
    public abstract PublicKeyDataDecryptorFactory providePublicKeyDataDecryptorFactory(
            OpenPGPKey.OpenPGPSecretKey secretKey,
            OpenPGPSmartCard card,
            KeyPassphraseProvider userPinProvider)
            throws PGPException;

    /**
     * Provide a {@link PGPContentSignerBuilderProvider} that signs messages by delegating public-key cryptography
     * to the given {@link OpenPGPSmartCard}.
     *
     * @param signingKey stub secret key
     * @param card smart card for message signing
     * @param userPinProvider provider for the smart cards user PIN
     * @param hashAlgorithmId signature hash algorithm ID
     * @return content signer builder provider
     * @throws PGPException
     */
    public PGPContentSignerBuilderProvider providePGPContentSignerBuilderProvider(
            OpenPGPKey.OpenPGPSecretKey signingKey,
            OpenPGPSmartCard card,
            KeyPassphraseProvider userPinProvider,
            int hashAlgorithmId)
        throws PGPException
    {
        PGPDigestCalculatorProvider digestCalculatorProvider = implementation.pgpDigestCalculatorProvider();
        return new PGPContentSignerBuilderProvider(hashAlgorithmId)
        {
            @Override
            public PGPContentSignerBuilder get(PGPPublicKey signingPubKey)
            {
                if (!signingKey.getPGPPublicKey().getKeyIdentifier().matchesExplicit(signingPubKey.getKeyIdentifier()))
                {
                    throw new IllegalArgumentException("Wrong public key provided.");
                }

                return new ExternalContentSignerBuilder(
                        card.getSignatureKey(),
                        signingKey,
                        userPinProvider,
                        hashAlgorithmId,
                        digestCalculatorProvider);
            }
        };
    }

    /**
     * Return the implementation name (JcaJce / BC).
     *
     * @return implementation name
     */
    public abstract String getName();
}

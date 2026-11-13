package org.bouncycastle.openpgp.smartcard;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.PublicSubkeyPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey.OpenPGPSecretKey;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilderProvider;
import org.bouncycastle.openpgp.api.operator.PGPContentSignerBuilderProviderFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.security.PublicKey;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

public abstract class OpenPGPSmartCardBackend<T extends OpenPGPSmartCard>
    implements PGPContentSignerBuilderProviderFactory
{
    /**
     * Size of the fingerprint field of an OpenPGP smart card.
     */
    protected static final int STORED_FINGERPRINT_LENGTH = 20;

    /**
     * Number of leading octets of a v6 fingerprint carried by a shortened legacy-hardware identifier.
     */
    protected static final int SHORTENED_IDENTIFIER_LENGTH = 8;

    protected final OpenPGPSmartCardImplementation implementation;
    // Some smart cards expect keys to be passed in JCA format (PublicKey, PrivateKey)
    protected final JcaPGPKeyConverter converter;

    public OpenPGPSmartCardBackend(OpenPGPSmartCardImplementation implementation,
                                   JcaPGPKeyConverter converter)
    {
        this.implementation = implementation;
        this.converter = converter;
    }
    /**
     * Return the name of the backend.
     *
     * @return backend name
     */
    public abstract String getName();

    /**
     * Return a {@link List} of all {@link OpenPGPSmartCard smart cards} managed by this backend.
     *
     * @return list of smart cards
     * @throws CardException if communication with a smart card fails
     * @throws IOException if an IO error occurs while communicating with a card
     */
    public abstract List<T> listSmartCards() throws CardException, IOException;

    /**
     * Provide a {@link PublicKeyDataDecryptorFactory} for the given {@link OpenPGPSecretKey} which has its
     * private key material stored on a {@link OpenPGPSmartCard} managed by this backend.
     *
     * @param decryptionKeyStub OpenPGP secret key which is the stubbed decryption key
     * @param userPinProvider callback to provide the keys user pin
     * @return public key data decryptor factory using the decryption key, or null if no matching key
     * or card is available.
     * @throws PGPException if the key is not usable or if communication with the card fails
     */
    public PublicKeyDataDecryptorFactory providePublicKeyDataDecryptorFactory(
            OpenPGPSecretKey decryptionKeyStub,
            KeyPassphraseProvider userPinProvider)
            throws PGPException
    {
        if (!decryptionKeyStub.getPGPSecretKey().isExternalKey())
        {
            throw new PGPException("Provided secret key is not external");
        }

        List<T> allCards;
        try
        {
            allCards = listSmartCards();
        }
        catch (CardException e)
        {
            throw new PGPException("Cannot list cards.", e);
        }
        catch (IOException e)
        {
            throw new PGPException("Cannot list cards.", e);
        }

        for (Iterator<T> it = allCards.iterator(); it.hasNext();)
        {
            T card = it.next();
            if (!card.hasDecryptionKey())
            {
                continue;
            }

            byte[] fingerprint = card.getDecryptionKey().getFingerprint();
            if (fingerprint == null)
            {
                continue;
            }

            // Compare through fingerprintMatches, NOT by wrapping the card's field in a KeyIdentifier: the
            // stored field is a fixed 20 octets, so an exact compare can never match a version 6 key's
            // 32-octet fingerprint and every v6 card key would be missed. fingerprintMatches also applies
            // the shortened legacy-hardware identifier rule described in
            // https://datatracker.ietf.org/doc/draft-hko-openpgp-identifiers-for-legacy-devices/
            if (!fingerprintMatches(fingerprint, decryptionKeyStub.getPGPPublicKey().getFingerprint()))
            {
                continue;
            }

            // found matching card
            return providePublicKeyDataDecryptorFactory(decryptionKeyStub, card, userPinProvider);
        }
        // no card of this backend holds the key: null lets the caller try the next backend
        return null;
    }

    /**
     * Provide a {@link PublicKeyDataDecryptorFactory} for the given stubbed decryption key and hardware token.
     *
     * @param decryptionKeyStub stubbed decryption key
     * @param card smart card or hardware token
     * @param userPinProvider provider for the cards USER PIN
     * @return public key data decryptor factory
     * @throws PGPException
     */
    protected PublicKeyDataDecryptorFactory providePublicKeyDataDecryptorFactory(
            OpenPGPSecretKey decryptionKeyStub,
            T card,
            KeyPassphraseProvider userPinProvider)
            throws PGPException
    {
        return implementation.providePublicKeyDataDecryptorFactory(decryptionKeyStub, card, userPinProvider);
    }

    /**
     * Return true if the full fingerprint matches the stored fingerprint.
     * <p>
     * Note: The stored fingerprint ({@link OpenPGPHardwareKey#getFingerprint()}) is a 20-octet field.
     * OpenPGP v6 keys have a 32-octet fingerprint, so they will not match exactly and therefore need to
     * be compared in a standardized way.
     * This method has not yet been decided upon, see the links below.
     *
     * @param storedFingerprint 20 octet fingerprint from the cards fingerprint field.
     * @param fullFingerprint full fingerprint of the key (v4 keys have 20, v6 keys 32 octets)
     * @return true if fingerprints match, false otherwise
     *
     * @see <a href="https://mailarchive.ietf.org/arch/msg/openpgp/kfsaZGeAznGKRTBShMg6qerAeVk/">
     *     Discussion on the IETF OpenPGP mailing list</a>
     * @see <a href="https://datatracker.ietf.org/doc/draft-hko-openpgp-identifiers-for-legacy-devices/">
     *     Shortened OpenPGP identifiers for legacy hardware devices</a>
     */
    public boolean fingerprintMatches(byte[] storedFingerprint, byte[] fullFingerprint)
    {
        if (Arrays.areEqual(storedFingerprint, fullFingerprint))
        {
            return true;
        }
        return shortenedIdentifierForLegacyHardwareMatches(storedFingerprint, fullFingerprint);
    }

    /**
     * Compare the full OpenPGP key fingerprint to the 20-octets fingerprint field of a smart card
     * according to the method described in the draft "Shortened OpenPGP identifiers for legacy hardware devices".
     *
     * @param storedFingerprint 20 octets stored fingerprint from smart card
     * @param fullFingerprint calculated, full OpenPGP key fingerprint
     * @return true if the fingerprint matches according to the comparison method described in
     *
     * @see <a href="https://datatracker.ietf.org/doc/draft-hko-openpgp-identifiers-for-legacy-devices/">
     *     Shortened OpenPGP identifiers for legacy hardware devices</a>
     */
    protected boolean shortenedIdentifierForLegacyHardwareMatches(byte[] storedFingerprint,
                                                                  byte[] fullFingerprint)
    {
        // the card's fingerprint field is a fixed 20 octets and holds arbitrary data, so bound both
        // operands before indexing: this is reached with whatever the card happens to contain.
        if (storedFingerprint == null || storedFingerprint.length < STORED_FINGERPRINT_LENGTH
                || fullFingerprint == null || fullFingerprint.length < SHORTENED_IDENTIFIER_LENGTH)
        {
            return false;
        }

        // a shortened identifier repeats the key version number in the leading 12 octets
        int verIdx = STORED_FINGERPRINT_LENGTH - SHORTENED_IDENTIFIER_LENGTH - 1;
        byte version = storedFingerprint[verIdx];
        if (version <= PublicKeyPacket.VERSION_4)
        {
            return false; // v4 keys and lower do not need shortened fingerprints
        }
        for (int i = 0; i < verIdx; i++)
        {
            if (storedFingerprint[i] != 0x00)
            {
                return false;
            }
        }

        return Arrays.constantTimeAreEqual(SHORTENED_IDENTIFIER_LENGTH,
                storedFingerprint, STORED_FINGERPRINT_LENGTH - SHORTENED_IDENTIFIER_LENGTH,
                fullFingerprint, 0);
    }

    /**
     * Convert the keys full fingerprint into a potentially shortened, 20-octets fingerprint.
     * If the keys fingerprint is already 20 octets long, return it as is.
     * Otherwise, shorten it according to the method described in the draft linked below.
     *
     * @param key OpenPGP key
     * @return 20 octets fingerprint
     *
     * @see <a href="https://datatracker.ietf.org/doc/draft-hko-openpgp-identifiers-for-legacy-devices/">
     *     Shortened OpenPGP identifiers for legacy hardware devices</a>
     */
    public byte[] toStoredFingerprint(OpenPGPCertificate.OpenPGPComponentKey key)
    {
        return toStoredFingerprint(key.getPGPPublicKey());
    }

    /**
     * Convert the keys full fingerprint into a potentially shortened, 20-octets fingerprint.
     * If the keys fingerprint is already 20 octets long, return it as is.
     * Otherwise, shorten it according to the method described in the draft linked below.
     *
     * @param key OpenPGP key
     * @return 20 octets fingerprint
     *
     * @see <a href="https://datatracker.ietf.org/doc/draft-hko-openpgp-identifiers-for-legacy-devices/">
     *     Shortened OpenPGP identifiers for legacy hardware devices</a>
     */
    public byte[] toStoredFingerprint(PGPPublicKey key)
    {
        return toStoredFingerprint(key.getFingerprint(), key.getVersion());
    }

    /**
     * Convert the keys full fingerprint into a potentially shortened, 20-octets fingerprint.
     * If the keys fingerprint is already 20 octets long, return it as is.
     * Otherwise, shorten it according to the method described in the draft linked below.
     *
     * @param fullFingerprint full key fingerprint
     * @param version key version
     * @return 20 octets fingerprint
     *
     * @see <a href="https://datatracker.ietf.org/doc/draft-hko-openpgp-identifiers-for-legacy-devices/">
     *     Shortened OpenPGP identifiers for legacy hardware devices</a>
     */
    public byte[] toStoredFingerprint(byte[] fullFingerprint, int version)
    {
        if (version < PublicKeyPacket.VERSION_4)
        {
            throw new IllegalArgumentException("Cannot calculate 20 octets fingerprint for key of version " + version);
        }
        if (fullFingerprint == null || fullFingerprint.length < SHORTENED_IDENTIFIER_LENGTH)
        {
            throw new IllegalArgumentException("Fingerprint too short to shorten");
        }
        if (version == PublicKeyPacket.VERSION_4)
        {
            return Arrays.clone(fullFingerprint);
        }

        // 11*0x00 || version || [8 left-most fp octets]
        byte[] fingerprint = new byte[STORED_FINGERPRINT_LENGTH];
        int versionIdx = STORED_FINGERPRINT_LENGTH - SHORTENED_IDENTIFIER_LENGTH - 1;
        Arrays.fill(fingerprint, 0, versionIdx, (byte)0);
        fingerprint[versionIdx] = (byte)version;
        System.arraycopy(fullFingerprint, 0, fingerprint,
                versionIdx + 1, SHORTENED_IDENTIFIER_LENGTH);
        return fingerprint;
    }

    public T findSmartCard(Integer serialNumber)
            throws CardException, IOException
    {
        List<T> cards = listSmartCards();
        for (Iterator<T> it = cards.iterator(); it.hasNext();)
        {
            T card = it.next();
            Integer cardSerial = card.getSerialNumber();
            if (cardSerial != null && cardSerial.equals(serialNumber))
            {
                return card;
            }
        }
        return null;
    }

    @Override
    public PGPContentSignerBuilderProvider getPGPContentSignerBuilderProvider(
            OpenPGPSecretKey signingKey,
            KeyPassphraseProvider userPinProvider,
            int hashAlgorithmId)
            throws PGPException
    {
        if (!signingKey.getPGPSecretKey().isExternalKey())
        {
            throw new PGPException("Provided secret key is not external");
        }

        List<T> allCards;
        try
        {
            allCards = listSmartCards();
        }
        catch (CardException e)
        {
            throw new PGPException("Cannot list cards.", e);
        }
        catch (IOException e)
        {
            throw new PGPException("Cannot list cards.", e);
        }

        for (Iterator<T> it = allCards.iterator(); it.hasNext();)
        {
            T card = it.next();
            if (!card.hasSignatureKey())
            {
                continue;
            }

            byte[] fingerprint = card.getSignatureKey().getFingerprint();
            if (fingerprint == null)
            {
                continue;
            }

            // Compare through fingerprintMatches, NOT by wrapping the card's field in a KeyIdentifier: the
            // stored field is a fixed 20 octets, so an exact compare can never match a version 6 key's
            // 32-octet fingerprint and every v6 card key would be missed. fingerprintMatches also applies
            // the shortened legacy-hardware identifier rule described in
            // https://datatracker.ietf.org/doc/draft-hko-openpgp-identifiers-for-legacy-devices/
            if (!fingerprintMatches(fingerprint, signingKey.getPGPPublicKey().getFingerprint()))
            {
                continue;
            }

            // found matching card
            return providePGPContentSignerBuilderProvider(signingKey, card, userPinProvider, hashAlgorithmId);
        }
        return null;
    }

    /**
     * Provide a {@link PGPContentSignerBuilderProvider} for the given stubbed signing key and smart card.
     *
     * @param signingKeyStub stub of the signing key
     * @param card smart card of hardware token
     * @param userPinProvider provider for the cards USER PIN
     * @param hashAlgorithmId hash algorithm for the signature
     * @return pgp content signer builder provider
     * @throws PGPException
     */
    protected PGPContentSignerBuilderProvider providePGPContentSignerBuilderProvider(
            OpenPGPSecretKey signingKeyStub,
            T card,
            KeyPassphraseProvider userPinProvider,
            int hashAlgorithmId)
            throws PGPException
    {
        return implementation.providePGPContentSignerBuilderProvider(
                signingKeyStub, card, userPinProvider, hashAlgorithmId);
    }

    public PublicKey convertPublicKey(PGPPublicKey pgpPublicKey)
            throws PGPException
    {
        return converter.getPublicKey(pgpPublicKey);
    }

    public PGPPublicKey convertPublicKey(PublicKey pk,
                                          byte[] storedFingerprint,
                                          Date creationTime)
            throws PGPException
    {
        int[] candidates = determineAlgorithmCandidates(pk);

        PGPPublicKey pgpKey = bruteForcePublicKey(pk, creationTime, storedFingerprint, candidates);
        if (pgpKey == null)
        {
            throw new PGPException("Cannot reconstruct public " + pk.getAlgorithm() + " PGP key.");
        }
        return pgpKey;
    }

    private int[] determineAlgorithmCandidates(PublicKey pk)
            throws PGPException
    {
        // OpenPGP defines different Public Key Algorithm IDs.
        // Some key types have multiple possible pk alg IDs which could be assigned,
        // e.g. Brainpool / NIST curves can be ECDSA or ECDH, X25519 keys can have ID X25519 or ECDH (legacy).
        // Here, we determine suitable algorithm ID candidates for the given public key.
        ASN1Sequence seq = ASN1Sequence.getInstance(pk.getEncoded());
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(seq);
        if (spki == null)
        {
            throw new PGPException("Cannot decode SubjectPublicKeyInfo for public key " + pk.getClass().getName());
        }
        ASN1ObjectIdentifier oid = spki.getAlgorithm().getAlgorithm();

        int[] candidates;
        // RSA
        if (PKCSObjectIdentifiers.rsaEncryption.equals(oid))
        {
            candidates = new int[]{PublicKeyAlgorithmTags.RSA_GENERAL, PublicKeyAlgorithmTags.RSA_ENCRYPT,
                    PublicKeyAlgorithmTags.RSA_SIGN};
        }
        // ECDH / ECDSA with NIST or Brainpool
        else if (X9ObjectIdentifiers.id_ecPublicKey.equals(oid))
        {
            candidates = new int[]{PublicKeyAlgorithmTags.ECDSA, PublicKeyAlgorithmTags.ECDH};
        }
        // Modern or legacy Ed25519
        else if (EdECObjectIdentifiers.id_Ed25519.equals(oid))
        {
            candidates = new int[]{PublicKeyAlgorithmTags.Ed25519, PublicKeyAlgorithmTags.EDDSA_LEGACY};
        }
        // Modern or legacy X25519
        else if (EdECObjectIdentifiers.id_X25519.equals(oid))
        {
            candidates = new int[]{PublicKeyAlgorithmTags.ECDH, PublicKeyAlgorithmTags.X25519};
        }
        // Modern X448 - there is no legacy X448
        else if (EdECObjectIdentifiers.id_X448.equals(oid))
        {
            candidates = new int[]{PublicKeyAlgorithmTags.X448};
        }
        // Modern Ed448 - there is no legacy Ed448
        else if (EdECObjectIdentifiers.id_Ed448.equals(oid))
        {
            candidates = new int[]{PublicKeyAlgorithmTags.Ed448};
        }
        else
        {
            throw new PGPException("Unknown public key algorithm OID: " + oid.getId());
        }
        return candidates;
    }

    protected PGPPublicKey bruteForcePublicKey(
            PublicKey pk,
            Date creationTime,
            byte[] storedFingerprint,
            int[] plausibleAlgorithms)
    {
        for (int keyVersion : new int[]{PublicKeyPacket.VERSION_4, PublicKeyPacket.VERSION_6})
        {
            for (int i = 0; i != plausibleAlgorithms.length; i++)
            {
                int algorithm = plausibleAlgorithms[i];
                PGPPublicKey pgpKey;
                try
                {
                    pgpKey = converter.getPGPPublicKey(keyVersion, algorithm, pk, creationTime);
                }
                catch (PGPException e)
                {
                    // this candidate algorithm cannot represent the key at all (e.g. an Ed448 tag over an
                    // Ed25519 key) - that is a miss, not a failure of the whole search.
                    continue;
                }

                if (fingerprintMatches(storedFingerprint, pgpKey.getFingerprint()))
                {
                    return pgpKey;
                }
            }
        }
        return null;
    }

    /**
     * Convert the given {@link PublicKey} to an OpenPGP {@link PGPPublicKey}.
     *
     * @param pubKey public key
     * @param keyVersion OpenPGP key version (4,5,6...)
     * @param publicKeyAlgorithmTag OpenPGP Public Key Algorithm ID
     * @param creationTime key creation time
     * @param subkey whether the key is an OpenPGP subkey
     * @return pgp public key
     * @throws PGPException
     */
    public PGPPublicKey convertPublicKey(PublicKey pubKey,
                                         int keyVersion,
                                         int publicKeyAlgorithmTag,
                                         Date creationTime,
                                         boolean subkey)
            throws PGPException
    {
        validatePublicKeyAlgorithm(pubKey, publicKeyAlgorithmTag);

        KeyFingerPrintCalculator fpCalc = implementation.implementation.keyFingerPrintCalculator();
        PGPPublicKey pgpPublicKey = converter.getPGPPublicKey(keyVersion, publicKeyAlgorithmTag, pubKey, creationTime);
        if (subkey)
        {
            PublicSubkeyPacket subkeyPacket = new PublicSubkeyPacket(
                    keyVersion, publicKeyAlgorithmTag, creationTime, pgpPublicKey.getPublicKeyPacket().getKey());
            pgpPublicKey = new PGPPublicKey(subkeyPacket, fpCalc);
        }

        return pgpPublicKey;
    }

    /**
     * Verify that the given <pre>publicKeyAlgorithmTag</pre> is assignable to the given public key.
     * @param pubKey public key
     * @param publicKeyAlgorithmTag OpenPGP Public Key Algorithm
     * @throws PGPException unknown public key type
     */
    private void validatePublicKeyAlgorithm(PublicKey pubKey, int publicKeyAlgorithmTag)
            throws PGPException
    {
        int[] candidates = determineAlgorithmCandidates(pubKey);
        boolean validAlgorithmTag = false;
        for (int i = 0; i < candidates.length; i++)
        {
            if (candidates[i] == publicKeyAlgorithmTag)
            {
                validAlgorithmTag = true;
                break;
            }
        }
        if (!validAlgorithmTag)
        {
            throw new IllegalArgumentException("Cannot assign public key algorithm ID " + publicKeyAlgorithmTag +
                    " to " + pubKey.getClass().getName() + " (" + java.util.Arrays.toString(candidates) + ")");
        }
    }
}

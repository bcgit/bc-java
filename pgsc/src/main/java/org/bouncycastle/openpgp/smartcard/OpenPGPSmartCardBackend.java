package org.bouncycastle.openpgp.smartcard;

import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey.OpenPGPSecretKey;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.smartcard.card.CardException;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;

public abstract class OpenPGPSmartCardBackend<T extends OpenPGPSmartCard>
{
    /**
     * Size of the fingerprint field of an OpenPGP smart card.
     */
    protected static final int STORED_FINGERPRINT_LENGTH = 20;

    /**
     * Number of leading octets of a v6 fingerprint carried by a shortened legacy-hardware identifier.
     */
    protected static final int SHORTENED_IDENTIFIER_LENGTH = 8;

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
     * @param secretKey OpenPGP secret key
     * @param userPinProvider callback to provide the keys user pin
     * @return public key data decryptor factory using the decryption key, or null if no matching key
     * or card is available.
     * @throws PGPException if the key is not usable or if communication with the card fails
     */
    public PublicKeyDataDecryptorFactory providePublicKeyDataDecryptorFactory(
            OpenPGPSecretKey secretKey,
            KeyPassphraseProvider userPinProvider)
            throws PGPException
    {
        if (!secretKey.getPGPSecretKey().isExternalKey())
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
            // the shortened legacy-hardware identifier rule (12 octets of the version number followed by
            // the leftmost 8 fingerprint octets).
            if (!fingerprintMatches(fingerprint, secretKey.getPGPPublicKey().getFingerprint()))
            {
                continue;
            }

            // found matching card
            return providePublicKeyDataDecryptorFactory(secretKey, card, userPinProvider);
        }
        // no card of this backend holds the key: null lets the caller try the next backend
        return null;
    }

    public abstract PublicKeyDataDecryptorFactory providePublicKeyDataDecryptorFactory(
            OpenPGPSecretKey secretKey,
            T card,
            KeyPassphraseProvider userPinProvider)
            throws PGPException;

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
        byte version = storedFingerprint[0];
        if (version != PublicKeyPacket.VERSION_6)
        {
            return false;
        }
        for (int i = 1; i != STORED_FINGERPRINT_LENGTH - SHORTENED_IDENTIFIER_LENGTH; i++)
        {
            if (storedFingerprint[i] != version)
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

        byte[] fingerprint = new byte[STORED_FINGERPRINT_LENGTH];
        Arrays.fill(fingerprint, (byte)version);
        System.arraycopy(fullFingerprint, 0, fingerprint,
            STORED_FINGERPRINT_LENGTH - SHORTENED_IDENTIFIER_LENGTH, SHORTENED_IDENTIFIER_LENGTH);
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
}

package org.bouncycastle.smartcard;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPCertificate;
import org.bouncycastle.openpgp.api.OpenPGPKey.OpenPGPSecretKey;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.smartcard.card.CardException;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Objects;

public abstract class OpenPGPSmartCardBackend<T extends OpenPGPSmartCard>
{
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
     * @throws NoSuchElementException if no matching smart card is found
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
        catch (CardException | IOException e)
        {
            throw new PGPException("Cannot list cards.", e);
        }
        for (T card : allCards)
        {
            if (!card.hasDecryptionKey())
            {
                continue;
            }

            byte[] fingerprint = card.getDecryptionKey().getFingerprint();
            KeyIdentifier asIdentifier = new KeyIdentifier(fingerprint);
            if (!secretKey.getKeyIdentifier().matchesExplicit(asIdentifier))
            {
                continue;
            }

            // found matching card
            return providePublicKeyDataDecryptorFactory(secretKey, card, userPinProvider);
        }
        throw new NoSuchElementException("No matching card found.");
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
     * @param _20OctetFingerprint 20 octet fingerprint from the cards fingerprint field.
     * @param fullFingerprint full fingerprint of the key (v4 keys have 20, v6 keys 32 octets)
     * @return true if fingerprints match, false otherwise
     *
     * @see <a href="Discussion on IETF OpenPGP Mailing List">
     *     https://mailarchive.ietf.org/arch/msg/openpgp/kfsaZGeAznGKRTBShMg6qerAeVk/</a>
     * @see <a href="Draft: Shortened OpenPGP identifiers for legacy hardware devices">
     *     https://datatracker.ietf.org/doc/draft-hko-openpgp-identifiers-for-legacy-devices/</a>
     */
    public boolean fingerprintMatches(byte[] _20OctetFingerprint, byte[] fullFingerprint)
    {
        if (Arrays.areEqual(_20OctetFingerprint, fullFingerprint))
        {
            return true;
        }
        return shortenedIdentifierForLegacyHardwareMatches(_20OctetFingerprint, fullFingerprint);
    }

    /**
     * Compare the full OpenPGP key fingerprint to the 20-octets fingerprint field of a smart card
     * according to the method described in the draft "Shortened OpenPGP identifiers for legacy hardware devices".
     *
     * @param _20OctetsFingerprint 20 octets stored fingerprint from smart card
     * @param fullFingerprint calculated, full OpenPGP key fingerprint
     * @return true if the fingerprint matches according to the comparison method described in
     *
     * @see <a href="Draft: Shortened OpenPGP identifiers for legacy hardware devices">
     *     https://datatracker.ietf.org/doc/draft-hko-openpgp-identifiers-for-legacy-devices/</a>
     */
    protected boolean shortenedIdentifierForLegacyHardwareMatches(byte[] _20OctetsFingerprint,
                                                                  byte[] fullFingerprint)
    {
        boolean isShortenedFingerprint = true;
        // shortened identifier has key version number in the first 12 octets of the fingerprint field.
        byte version = _20OctetsFingerprint[0];
        for (int i = 1; i < 12; i++)
        {
            if (_20OctetsFingerprint[i] != version)
            {
                isShortenedFingerprint = false;
                break;
            }
        }

        if (isShortenedFingerprint)
        {
            if (version == 6)
            {
                return Arrays.constantTimeAreEqual(8, _20OctetsFingerprint, 12, fullFingerprint, 0);
            }
        }
        return false;
    }

    /**
     * Convert the keys full fingerprint into a potentially shortened, 20-octets fingerprint.
     * If the keys fingerprint is already 20 octets long, return it as is.
     * Otherwise, shorten it according to the method described in the draft linked below.
     *
     * @param key OpenPGP key
     * @return 20 octets fingerprint
     *
     * @see <a href="Draft: Shortened OpenPGP identifiers for legacy hardware devices">
     *     https://datatracker.ietf.org/doc/draft-hko-openpgp-identifiers-for-legacy-devices/</a>
     */
    public byte[] to20_OctetsFingerprint(OpenPGPCertificate.OpenPGPComponentKey key)
    {
        return to20_OctetsFingerprint(key.getPGPPublicKey());
    }

    /**
     * Convert the keys full fingerprint into a potentially shortened, 20-octets fingerprint.
     * If the keys fingerprint is already 20 octets long, return it as is.
     * Otherwise, shorten it according to the method described in the draft linked below.
     *
     * @param key OpenPGP key
     * @return 20 octets fingerprint
     *
     * @see <a href="Draft: Shortened OpenPGP identifiers for legacy hardware devices">
     *     https://datatracker.ietf.org/doc/draft-hko-openpgp-identifiers-for-legacy-devices/</a>
     */
    public byte[] to20_OctetsFingerprint(PGPPublicKey key)
    {
        return to20_OctetsFingerprint(key.getFingerprint(), key.getVersion());
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
     * @see <a href="Draft: Shortened OpenPGP identifiers for legacy hardware devices">
     *     https://datatracker.ietf.org/doc/draft-hko-openpgp-identifiers-for-legacy-devices/</a>
     */
    public byte[] to20_OctetsFingerprint(byte[] fullFingerprint, int version)
    {
        if (version < PublicKeyPacket.VERSION_4)
        {
            throw new IllegalArgumentException("Cannot calculate 20 octets fingerprint for key of version " + version);
        }
        if (version == PublicKeyPacket.VERSION_4)
        {
            return fullFingerprint;
        }
        else
        {
            byte[] fingerprint = new byte[20];
            Arrays.fill(fingerprint, (byte) version);
            System.arraycopy(fullFingerprint, 0, fingerprint, 12, 8);
            return fingerprint;
        }
    }

    public T findSmartCard(Integer serialNumber)
            throws CardException, IOException
    {
        List<T> cards = listSmartCards();
        for (T card : cards)
        {
            if (Objects.equals(card.getSerialNumber(), serialNumber))
            {
                return card;
            }
        }
        return null;
    }
}

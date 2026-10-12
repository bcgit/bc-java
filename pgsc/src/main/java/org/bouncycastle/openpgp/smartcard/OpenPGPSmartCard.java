package org.bouncycastle.openpgp.smartcard;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.api.KeyPassphraseProvider;
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPComponentKey;
import org.bouncycastle.openpgp.api.OpenPGPKey;
import org.bouncycastle.openpgp.api.OpenPGPKey.OpenPGPPrivateKey;
import org.bouncycastle.openpgp.api.exception.KeyPassphraseException;
import org.bouncycastle.openpgp.smartcard.card.SupportedAlgorithms;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.openpgp.smartcard.card.CardException;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

/**
 * Abstract OpenPGP Smart Card class.
 */
public abstract class OpenPGPSmartCard
{

    private final OpenPGPSmartCardBackend backend;
    private final Map<Byte, OpenPGPHardwareKey> keys = new HashMap<>();

    public OpenPGPSmartCard(OpenPGPSmartCardBackend backend)
    {
        this.backend = backend;
    }

    /**
     * Return the {@link OpenPGPSmartCardBackend} that manages this smart card.
     *
     * @return backend
     */
    public OpenPGPSmartCardBackend getBackend()
    {
        return backend;
    }

    /**
     * Return the serial number of this smart card.
     *
     * @return serial number
     */
    public abstract Integer getSerialNumber();

    /**
     * Return the version number of this smart card.
     *
     * @return version number
     */
    public abstract String getVersion();

    public abstract SupportedAlgorithms getSupportedAlgorithms();

    protected void clearKeys()
    {
        keys.clear();
    }

    protected void putKey(OpenPGPHardwareKey key)
    {
        keys.put(key.getKeyRef(), key);
    }

    /**
     * Return true, if the smart card supports the given {@link OpenPGPComponentKey}.
     *
     * @param keyRef key reference
     * @param key OpenPGP key
     * @return true if the card supports the key
     *
     * @throws CardException if communication with the card fails
     */
    public boolean isKeySupported(byte keyRef, OpenPGPComponentKey key)
            throws CardException
    {
        return getSupportedAlgorithms().filter(keyRef).supports(key);
    }

    /**
     * Return the {@link OpenPGPHardwareKey} identified by the given key reference.
     * If the card does not contain a key for the given keyRef, this method throws a {@link NoSuchElementException}.
     *
     * @param keyRef key reference
     * @return hardware key
     */
    public OpenPGPHardwareKey getKeyByKeyRef(byte keyRef)
    {
        OpenPGPHardwareKey hwKey = keys.get(keyRef);
        if (hwKey == null)
        {
            throw new NoSuchElementException("No key with keyRef " + keyRef);
        }
        return hwKey;
    }

    /**
     * Return the {@link OpenPGPHardwareKey} from the slot that contains the given fingerprint.
     * If no such key is found, this method throws a {@link NoSuchElementException}.
     * <p>
     * Note: The fingerprint field of OpenPGP smart cards is a 20-octet field that can contain arbitrary
     * data.
     * When comparing 32-octet OpenPGP v6 fingerprints, those are shortened according to guidance in
     * <a href="https://datatracker.ietf.org/doc/draft-hko-openpgp-identifiers-for-legacy-devices/">
     *     OpenPGP key identifiers for legacy hardware devices</a>
     * before the comparison is performed.
     * Since the smart card does not make use of this field and does not validate its contents, you MUST NOT
     * rely on this field to identify keys.
     *
     * @param fingerprint fingerprint
     * @return hardware key
     */
    public OpenPGPHardwareKey getKeyByFingerprint(byte[] fingerprint)
    {
        for (OpenPGPHardwareKey key : getKeys())
        {
            if (backend.fingerprintMatches(key.getFingerprint(), fingerprint))
            {
                return key;
            }
        }
        // -DM Hex.toHexString
        throw new NoSuchElementException("No key with fingerprint " + org.bouncycastle.util.encoders.Hex.toHexString(fingerprint));
    }

    /**
     * Return a list of all {@link OpenPGPHardwareKey keys} on the card.
     *
     * @return list of all keys
     */
    public List<OpenPGPHardwareKey> getKeys()
    {
        return new ArrayList<>(keys.values());
    }

    /**
     * Return true, if the card has a key with the given key reference.
     *
     * @param keyRef key reference
     * @return true if card has a key for keyRef, false otherwise
     */
    public boolean hasKey(byte keyRef)
    {
        try
        {
            return getKeyByKeyRef(keyRef) != null;
        }
        catch (NoSuchElementException e)
        {
            return false;
        }
    }

    /**
     * Returns true, if the card has a key with the given fingerprint.
     * <p>
     * Note: The fingerprint field of OpenPGP smart cards is a 20-octet field that can contain arbitrary
     * data.
     * Since the smart card does not make use of this field and does not validate its contents, you MUST NOT
     * rely on this field to identify keys.
     * Notably OpenPGP v6 keys, which have a 32-octet fingerprint, will cause mismatches with the 20-octet field.
     *
     * @param fingerprint fingerprint
     * @return true if the card has a key with a matching fingerprint field
     */
    public boolean hasKeyWithFingerprint(byte[] fingerprint)
    {
        try
        {
            return getKeyByFingerprint(fingerprint) != null;
        }
        catch (NoSuchElementException e)
        {
            return false;
        }
    }

    /**
     * Return true, if the card has a signature key (with keyRef {@link OpenPGPHardwareKey#KEY_REF_SIGNATURE}).
     *
     * @return true if card has signature key
     */
    public boolean hasSignatureKey()
    {
        return hasKey(OpenPGPHardwareKey.KEY_REF_SIGNATURE);
    }

    /**
     * Return the {@link OpenPGPHardwareKey signing key} of the card.
     *
     * @return signing key
     * @throws NoSuchElementException if the card has no signing key
     */
    public OpenPGPHardwareKey getSignatureKey()
    {
        return getKeyByKeyRef(OpenPGPHardwareKey.KEY_REF_SIGNATURE);
    }

    /**
     * Return true if the card has a decryption key (with keyRef {@link OpenPGPHardwareKey#KEY_REF_DECRYPTION}).
     *
     * @return true if card has decryption key
     */
    public boolean hasDecryptionKey()
    {
        return hasKey(OpenPGPHardwareKey.KEY_REF_DECRYPTION);
    }

    /**
     * Return the {@link OpenPGPHardwareKey decryption key} of the card.
     *
     * @return decryption key
     * @throws NoSuchElementException if the card has no decryption key
     */
    public OpenPGPHardwareKey getDecryptionKey()
    {
        return getKeyByKeyRef(OpenPGPHardwareKey.KEY_REF_DECRYPTION);
    }

    /**
     * Return true if the card has an authentication key (with keyRef {@link OpenPGPHardwareKey#KEY_REF_AUTHENTICATION}).
     *
     * @return true if card has authentication key
     */
    public boolean hasAuthenticationKey()
    {
        return hasKey(OpenPGPHardwareKey.KEY_REF_AUTHENTICATION);
    }

    /**
     * Return the {@link OpenPGPHardwareKey authentication key} of the card.
     *
     * @return authentication key
     * @throws NoSuchElementException if the card has no authentication key
     */
    public OpenPGPHardwareKey getAuthenticationKey()
    {
        return getKeyByKeyRef(OpenPGPHardwareKey.KEY_REF_AUTHENTICATION);
    }

    /**
     * Change the user PIN (PW1,PW2) of the card.
     *
     * @param oldPinProvider provider for the old card user PIN
     * @param newPinProvider provider for the new card user PIN
     * @return this
     * @throws CardException if the card PIN cannot be changed.
     */
    public abstract OpenPGPSmartCard changeUserPIN(CardPinProvider oldPinProvider,
                                                   CardPinProvider newPinProvider)
        throws CardException;

    /**
     * Change the admin PIN (PW3) of the card.
     *
     * @param oldPinProvider provider for the old card admin PIN
     * @param newPinProvider provider for the new card admin PIN
     * @return this
     * @throws CardException if the card PIN cannot be changed.
     */
    public abstract OpenPGPSmartCard changeAdminPIN(CardPinProvider oldPinProvider,
                                                    CardPinProvider newPinProvider)
        throws CardException;

    /**
     * Reset the smart card, clearing all key slots and resetting the admin PIN, user PIN to their defaults.
     *
     * @return this
     * @throws CardException if communication with the card failed
     */
    public abstract OpenPGPSmartCard reset() throws CardException;

    /**
     * Upload the given {@link OpenPGPPrivateKey} to the signing key slot on the card.
     *
     * @param key OpenPGP private key
     * @param adminPinProvider provider for the admin pin of the card
     * @return card
     * @throws CardException if communication with the card fails
     * @throws PGPException if the key cannot be prepared for the card
     */
    public OpenPGPSmartCard uploadSigningKey(OpenPGPPrivateKey key, KeyPassphraseProvider adminPinProvider)
            throws PGPException, CardException
    {
        return uploadKey(OpenPGPHardwareKey.KEY_REF_SIGNATURE, key, adminPinProvider);
    }

    /**
     * Upload the given {@link OpenPGPPrivateKey} to the decryption key slot on the card.
     *
     * @param key OpenPGP private key
     * @param adminPinProvider provider for the admin pin of the card
     * @return card
     * @throws CardException if communication with the card fails
     * @throws PGPException if the key cannot be prepared for the card
     */
    public OpenPGPSmartCard uploadDecryptionKey(OpenPGPPrivateKey key, KeyPassphraseProvider adminPinProvider)
            throws CardException, PGPException
    {
        return uploadKey(OpenPGPHardwareKey.KEY_REF_DECRYPTION, key, adminPinProvider);
    }

    /**
     * Upload the given {@link OpenPGPPrivateKey} to the authentication key slot on the card.
     *
     * @param key OpenPGP private key
     * @param adminPinProvider provider for the admin pin of the card
     * @return card
     * @throws CardException if communication with the card fails
     * @throws PGPException if the key cannot be prepared for the card
     */
    public OpenPGPSmartCard uploadAuthenticationKey(OpenPGPPrivateKey key, KeyPassphraseProvider adminPinProvider)
            throws CardException, PGPException
    {
        return uploadKey(OpenPGPHardwareKey.KEY_REF_AUTHENTICATION, key, adminPinProvider);
    }

    /**
     * Upload the given key to the slot identified by <pre>keyRef</pre>.
     * The admin PIN is required from the <pre>adminPinProvider</pre>.
     * @param keyRef key ref
     * @param key key
     * @param adminPinProvider provider for the admin pin of the card
     * @return card
     * @throws CardException if communication with the card fails
     * @throws PGPException if the key cannot be prepared for the card
     */
    public OpenPGPSmartCard uploadKey(byte keyRef,
                                      OpenPGPPrivateKey key,
                                      KeyPassphraseProvider adminPinProvider)
            throws PGPException, CardException
    {
        char[] adminPin = requireUserPin(adminPinProvider, key.getSecretKey());
        OpenPGPSmartCard card;
        try
        {
            card = uploadKey(keyRef, key, adminPin);
        }
        finally
        {
            Arrays.fill(adminPin, '\0');
        }
        return card;
    }

    /**
     * Upload the given {@link OpenPGPPrivateKey} to the given keyRef slot on the card.
     * Note: This method is not guaranteed to clear out the <pre>adminPin</pre> so you need to do that yourselves.
     * @param keyRef keyRef
     * @param key OpenPGP private key
     * @param adminPin admin pin of the card
     * @return card
     * @throws CardException if communication with the card fails
     * @throws PGPException if the key cannot be prepared for the card
     */
    protected abstract OpenPGPSmartCard uploadKey(byte keyRef,
                                               OpenPGPPrivateKey key,
                                               char[] adminPin)
            throws CardException, PGPException;


    /**
     * Return the {@link PGPPublicKey} component of the key in the slot identified by keyRef.
     * <p>
     * Note: The key might be reconstructed on the fly.
     * In this case, {@link org.bouncycastle.bcpg.PublicKeyAlgorithmTags Public key algorithm} and version
     * number might be brute-forced by comparing the resulting {@link PGPPublicKey keys} fingerprint to the
     * contents of the cards {@link OpenPGPHardwareKey#getFingerprint()} field.
     *
     * @param keyRef key reference
     * @return PGPPublicKey representation
     * @throws CardException if communication with the card fails
     * @throws PGPException if the key cannot be reconstructed
     */
    public abstract PGPPublicKey reconstructPGPPublicKey(byte keyRef)
            throws CardException, PGPException;

    /**
     * Return a {@link String} representing the card type.
     * This is an informative description of the device.
     *
     * @return card type
     */
    public abstract String getCardType();

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder(getCardType()).append("[").append(getSerialNumber()).append("]\n");
        for (OpenPGPHardwareKey k : getKeys())
        {
            sb.append(k.getKeyRef()).append(": ");
            byte[] fp = k.getFingerprint();
            if (fp == null)
            {
                sb.append("<empty>");
            }
            else
            {
                sb.append(new KeyIdentifier(fp));
            }
            sb.append("\n");
        }
        return sb.toString();
    }

    /**
     * Create a raw signature over the provided data.
     * @param data algorithm-specific encoding of a message digest
     * @param key hardware-backed key to create the signature with
     * @param stubKey stub of the signing key
     * @param userPinProvider provider for the device user PIN
     * @return raw signature
     * @throws KeyPassphraseException if the wrong PIN was provided
     * @throws CardException if communication with the card fails
     */
    public abstract byte[] sign(byte[] data,
                                OpenPGPHardwareKey key,
                                OpenPGPKey.OpenPGPSecretKey stubKey,
                                KeyPassphraseProvider userPinProvider)
        throws KeyPassphraseException, CardException;

    /**
     * Fetch the card's user PIN. A {@link KeyPassphraseProvider} keeps ownership of the array it
     * hands out - both implementations BC ships return the application's own array by reference -
     * so a copy is returned here, and that copy is the caller's to zeroize once the card has
     * verified it.
     */
    protected char[] requireUserPin(KeyPassphraseProvider userPinProvider, OpenPGPKey.OpenPGPSecretKey signingKey)
            throws KeyPassphraseException
    {
        char[] pin = Arrays.clone(userPinProvider.getKeyPassword(signingKey));
        if (pin == null || pin.length == 0)
        {
            throw new KeyPassphraseException(signingKey, new IllegalStateException("PIN required."));
        }
        return pin;
    }

    /**
     * Decrypt public-key-encrypted session-data.
     *
     * @param message algorithm-specific ciphertext of the encrypted session data
     * @param openPGPHardwareKey hardware-backed key to perform decryption with
     * @param stubKey stub of the decryption key
     * @param userPinProvider provider for the devices user PIN
     * @return decrypted session data
     * @throws KeyPassphraseException if the wrong PIN was provided
     * @throws CardException if the message cannot be decrypted, e.g. because communication fails
     */
    public abstract byte[] decrypt(byte[] message,
                          OpenPGPHardwareKey openPGPHardwareKey,
                          OpenPGPKey.OpenPGPSecretKey stubKey,
                          KeyPassphraseProvider userPinProvider)
            throws PGPException, CardException;

    /**
     * Decrypt a public-key-encrypted session-key.
     *
     * @param publicKey algorithm-specific ephemeral per-message public key
     * @param openPGPHardwareKey hardware-backed key to perform decryption with
     * @param stubKey stub of the decryption key
     * @param userPinProvider provider for the devices user PIN
     * @return decrypted session data
     * @throws KeyPassphraseException if the wrong passphrase was provided
     * @throws CardException if the message cannot be decrypted, e.g. because communication fails
     */
    public abstract byte[] decrypt(PublicKey publicKey,
                          OpenPGPHardwareKey openPGPHardwareKey,
                          OpenPGPKey.OpenPGPSecretKey stubKey,
                          KeyPassphraseProvider userPinProvider)
            throws PGPException, CardException;

    @FunctionalInterface
    public interface CardPinProvider {
        char[] providePIN(OpenPGPSmartCard card);
    }
}

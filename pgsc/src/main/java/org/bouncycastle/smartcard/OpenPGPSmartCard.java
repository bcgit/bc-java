package org.bouncycastle.smartcard;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.api.OpenPGPCertificate.OpenPGPComponentKey;
import org.bouncycastle.openpgp.api.OpenPGPKey.OpenPGPPrivateKey;
import org.bouncycastle.smartcard.card.CardException;

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
    protected final Map<Byte, OpenPGPHardwareKey> keys = new HashMap<>();

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
    public abstract boolean isKeySupported(byte keyRef, OpenPGPComponentKey key)
            throws CardException;

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
     * Since the smart card does not make use of this field and does not validate its contents, you MUST NOT
     * rely on this field to identify keys.
     * Notably OpenPGP v6 keys, which have a 32-octet fingerprint, will cause mismatches with the 20-octet field.
     *
     * @param fingerprint fingerprint
     * @return hardware key
     */
    public OpenPGPHardwareKey getKeyByFingerprint(byte[] fingerprint)
    {
        for (OpenPGPHardwareKey key : getKeys())
        {
            if (org.bouncycastle.util.Arrays.constantTimeAreEqual(key.getFingerprint(), fingerprint))
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
     * @param adminPin admin pin of the card
     * @return card
     * @throws CardException if communication with the card fails
     * @throws PGPException if the key cannot be prepared for the card
     */
    public OpenPGPSmartCard uploadSigningKey(OpenPGPPrivateKey key, char[] adminPin)
            throws CardException, PGPException
    {
        return uploadKey(OpenPGPHardwareKey.KEY_REF_SIGNATURE, key, adminPin);
    }

    /**
     * Upload the given {@link OpenPGPPrivateKey} to the decryption key slot on the card.
     *
     * @param key OpenPGP private key
     * @param adminPin admin pin of the card
     * @return card
     * @throws CardException if communication with the card fails
     * @throws PGPException if the key cannot be prepared for the card
     */
    public OpenPGPSmartCard uploadDecryptionKey(OpenPGPPrivateKey key, char[] adminPin)
            throws CardException, PGPException
    {
        return uploadKey(OpenPGPHardwareKey.KEY_REF_DECRYPTION, key, adminPin);
    }

    /**
     * Upload the given {@link OpenPGPPrivateKey} to the authentication key slot on the card.
     *
     * @param key OpenPGP private key
     * @param adminPin admin pin of the card
     * @return card
     * @throws CardException if communication with the card fails
     * @throws PGPException if the key cannot be prepared for the card
     */
    public OpenPGPSmartCard uploadAuthenticationKey(OpenPGPPrivateKey key, char[] adminPin)
            throws CardException, PGPException
    {
        return uploadKey(OpenPGPHardwareKey.KEY_REF_AUTHENTICATION, key, adminPin);
    }

    /**
     * Upload the given {@link OpenPGPPrivateKey} to the given keyRef slot on the card.
     * @param keyRef keyRef
     * @param key OpenPGP private key
     * @param adminPin admin pin of the card
     * @return card
     * @throws CardException if communication with the card fails
     * @throws PGPException if the key cannot be prepared for the card
     */
    public abstract OpenPGPSmartCard uploadKey(byte keyRef,
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

}

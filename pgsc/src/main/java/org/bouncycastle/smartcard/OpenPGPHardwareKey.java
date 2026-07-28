package org.bouncycastle.smartcard;

import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.smartcard.card.CardException;

import java.util.Date;

/**
 * An OpenPGP key stored on a {@link OpenPGPSmartCard}.
 */
public class OpenPGPHardwareKey
{
    /**
     * Key used to generate signatures.
     * <p>
     * Presumably related to {@link org.bouncycastle.bcpg.sig.KeyFlags#SIGN_DATA}.
     */
    public static final byte KEY_REF_SIGNATURE = 1;

    /**
     * Key used to decrypt messages.
     * <p>
     * Presumably related to {@link org.bouncycastle.bcpg.sig.KeyFlags#ENCRYPT_COMMS} and
     * {@link org.bouncycastle.bcpg.sig.KeyFlags#ENCRYPT_STORAGE}.
     */
    public static final byte KEY_REF_DECRYPTION = 2;

    /**
     * Key used for authentication.
     * <p>
     * Presumably related to {@link org.bouncycastle.bcpg.sig.KeyFlags#AUTHENTICATION}.
     */
    public static final byte KEY_REF_AUTHENTICATION = 3;

    /**
     * Key was generated on the device itself.
     */
    public static final byte STATE_GENERATED = 1;

    /**
     * Key was generated somewhere else and was imported onto the device.
     * A copy of the private key MAY exist somewhere else.
     */
    public static final byte STATE_IMPORTED = 2;

    private final OpenPGPSmartCard smartCard;
    private final byte keyRef;
    private final byte[] fingerprint;
    private final Date generationTime;
    private final byte state;

    public OpenPGPHardwareKey(OpenPGPSmartCard smartCard,
                              byte keyRef,
                              byte state,
                              byte[] fingerprint,
                              Date generationTime)
    {
        this.smartCard = smartCard;
        this.keyRef = keyRef;
        this.fingerprint = fingerprint;
        this.generationTime = generationTime;
        this.state = state;
    }

    /**
     * Return the contents of the fingerprint field.
     * Note: The fingerprint field of OpenPGP smart cards is a 20-octet field that can contain arbitrary
     * data.
     * Since the smart card does not make use of this field and does not validate its contents, you MUST NOT
     * rely on this field to identify keys.
     * Notably OpenPGP v6 keys, which have a 32-octet fingerprint, will cause mismatches with the 20-octet field.
     *
     * @return content of fingerprint field
     */
    public byte[] getFingerprint()
    {
        return fingerprint;
    }

    /**
     * Retrieve the full OpenPGP key fingerprint by reconstructing the
     * {@link org.bouncycastle.openpgp.PGPPublicKey} and retrieving its fingerprint.
     *
     * @return full fingerprint
     * @throws PGPException if the key cannot be reconstructed
     * @throws CardException if communication with the card fails
     */
    public byte[] reconstructFullFingerprint()
            throws PGPException, CardException
    {
        return getSmartCard().reconstructPGPPublicKey(getKeyRef())
                .getFingerprint();
    }

    /**
     * Return the {@link KeyIdentifier} based on the reconstructed full key fingerprint.
     *
     * @return key identifier
     * @throws PGPException if the key cannot be reconstructed
     * @throws CardException if communication with the card fails
     */
    public KeyIdentifier getFullKeyIdentifier()
            throws PGPException, CardException
    {
        return new KeyIdentifier(reconstructFullFingerprint());
    }

    /**
     * Return the creation time of the key.
     * @return creation time
     */
    public Date getCreationTime()
    {
        return generationTime;
    }

    /**
     * Return the key reference (keyRef) of this key.
     *
     * @return key ref
     */
    public byte getKeyRef()
    {
        return keyRef;
    }

    /**
     * Return the {@link OpenPGPSmartCard} this key is stored on.
     *
     * @return smart card
     */
    public OpenPGPSmartCard getSmartCard()
    {
        return smartCard;
    }

    /**
     * Return true if the key has been imported onto the device.
     * Note: A copy of the private key MAY still exist somewhere else.
     *
     * @return true if key was imported
     */
    public boolean isImported()
    {
        return state == STATE_IMPORTED;
    }

    /**
     * Return true if the key was generated on/by the device itself.
     *
     * @return true if key was generated
     */
    public boolean isGenerated()
    {
        return state == STATE_GENERATED;
    }
}

package org.bouncycastle.openpgp.api;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.PreferredAEADCiphersuites;

/**
 * Encryption mode (SEIPDv1 / SEIPDv2 / OED) and algorithms.
 */
public class MessageEncryptionMechanism
{
    private final EncryptedDataPacketType mode;
    private final int symmetricKeyAlgorithm;
    private final int aeadAlgorithm;

    /**
     * Create a {@link MessageEncryptionMechanism} tuple.
     *
     * @param mode                  encryption mode (packet type)
     * @param symmetricKeyAlgorithm symmetric key algorithm for message encryption
     * @param aeadAlgorithm         aead algorithm for message encryption
     */
    private MessageEncryptionMechanism(EncryptedDataPacketType mode,
                                       int symmetricKeyAlgorithm,
                                       int aeadAlgorithm)
    {
        this.mode = mode;
        this.symmetricKeyAlgorithm = symmetricKeyAlgorithm;
        this.aeadAlgorithm = aeadAlgorithm;
    }

    public EncryptedDataPacketType getMode()
    {
        return mode;
    }

    public int getSymmetricKeyAlgorithm()
    {
        return symmetricKeyAlgorithm;
    }

    public int getAeadAlgorithm()
    {
        return aeadAlgorithm;
    }

    /**
     * The data will not be encrypted.
     * Useful for sign-only operations.
     *
     * @return unencrypted encryption setup
     */
    public static MessageEncryptionMechanism unencrypted()
    {
        int none = 0;
        return new MessageEncryptionMechanism(EncryptedDataPacketType.SEIPDv1,
            SymmetricKeyAlgorithmTags.NULL, none);
    }

    @Deprecated
    public static MessageEncryptionMechanism legacyEncryptedNonIntegrityProtected(int symmetricKeyAlgorithm)
    {
        int none = 0;
        return new MessageEncryptionMechanism(EncryptedDataPacketType.SED, symmetricKeyAlgorithm, none);
    }

    /**
     * The data will be encrypted and integrity protected using a SEIPDv1 packet.
     *
     * @param symmetricKeyAlgorithm symmetric cipher algorithm for message encryption
     * @return sym. enc. integrity protected encryption setup
     */
    public static MessageEncryptionMechanism integrityProtected(int symmetricKeyAlgorithm)
    {
        int none = 0;
        return new MessageEncryptionMechanism(EncryptedDataPacketType.SEIPDv1, symmetricKeyAlgorithm, none);
    }

    /**
     * The data will be OCB-encrypted as specified by the non-standard LibrePGP document.
     *
     * @param symmetricKeyAlgorithm symmetric key algorithm which will be combined with OCB to form
     *                              an OCB-encrypted data packet
     * @return LibrePGP OCB encryption setup
     */
    public static MessageEncryptionMechanism librePgp(int symmetricKeyAlgorithm)
    {
        return new MessageEncryptionMechanism(EncryptedDataPacketType.LIBREPGP_OED,
            symmetricKeyAlgorithm, AEADAlgorithmTags.OCB);
    }

    /**
     * The data will be AEAD-encrypted using the method described in RFC9580.
     *
     * @param symmetricKeyAlgorithm symmetric cipher algorithm
     * @param aeadAlgorithm         AEAD algorithm
     * @return AEAD encryption setup
     */
    public static MessageEncryptionMechanism aead(int symmetricKeyAlgorithm, int aeadAlgorithm)
    {
        return new MessageEncryptionMechanism(EncryptedDataPacketType.SEIPDv2, symmetricKeyAlgorithm, aeadAlgorithm);
    }

    public static MessageEncryptionMechanism aead(PreferredAEADCiphersuites.Combination combination)
    {
        return aead(combination.getSymmetricAlgorithm(), combination.getAeadAlgorithm());
    }

    /**
     * Return true, if the message will be encrypted.
     *
     * @return is encrypted
     */
    public boolean isEncrypted()
    {
        return symmetricKeyAlgorithm != SymmetricKeyAlgorithmTags.NULL;
    }

    @Override
    public int hashCode()
    {
        return mode.hashCode()
            + 13 * symmetricKeyAlgorithm
            + 17 * aeadAlgorithm;
    }

    @Override
    public boolean equals(Object obj)
    {
        if (obj == null)
        {
            return false;
        }
        if (this == obj)
        {
            return true;
        }
        if (!(obj instanceof MessageEncryptionMechanism))
        {
            return false;
        }
        MessageEncryptionMechanism m = (MessageEncryptionMechanism)obj;
        return getMode() == m.getMode()
            && getSymmetricKeyAlgorithm() == m.getSymmetricKeyAlgorithm()
            && getAeadAlgorithm() == m.getAeadAlgorithm();
    }

    @Override
    public String toString()
    {
        String out = mode.name() + "[cipher: " + symmetricKeyAlgorithm;
        if (mode == EncryptedDataPacketType.SEIPDv2 || mode == EncryptedDataPacketType.LIBREPGP_OED)
        {
            out += " aead: " + aeadAlgorithm;
        }
        return out + "]";
    }
}

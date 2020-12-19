package org.bouncycastle.openpgp;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.EmbeddedSignature;
import org.bouncycastle.bcpg.sig.Exportable;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.IntendedRecipientFingerprint;
import org.bouncycastle.bcpg.sig.IssuerFingerprint;
import org.bouncycastle.bcpg.sig.IssuerKeyID;
import org.bouncycastle.bcpg.sig.KeyExpirationTime;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.bcpg.sig.PreferredAlgorithms;
import org.bouncycastle.bcpg.sig.PrimaryUserID;
import org.bouncycastle.bcpg.sig.Revocable;
import org.bouncycastle.bcpg.sig.RevocationKey;
import org.bouncycastle.bcpg.sig.RevocationKeyTags;
import org.bouncycastle.bcpg.sig.RevocationReason;
import org.bouncycastle.bcpg.sig.SignatureCreationTime;
import org.bouncycastle.bcpg.sig.SignatureExpirationTime;
import org.bouncycastle.bcpg.sig.SignatureTarget;
import org.bouncycastle.bcpg.sig.SignerUserID;
import org.bouncycastle.bcpg.sig.TrustSignature;

/**
 * Generator for signature subpackets.
 */
public class PGPSignatureSubpacketGenerator
{
    List packets = new ArrayList();

    /**
     * Base constructor, creates an empty generator.
     */
    public PGPSignatureSubpacketGenerator()
    {
    }

    /**
     * Constructor for pre-initialising the generator from an existing one.
     *
     * @param sigSubV an initial set of subpackets.
     */
    public PGPSignatureSubpacketGenerator(PGPSignatureSubpacketVector sigSubV)
    {
        for (int i = 0; i != sigSubV.packets.length; i++)
        {
            packets.add(sigSubV.packets[i]);
        }
    }

    /**
     * Specify, whether or not the signature is revocable.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param isRevocable true if the signature should be revocable, false otherwise.
     */
    public void setRevocable(boolean isCritical, boolean isRevocable)
    {
        packets.add(new Revocable(isCritical, isRevocable));
    }

    /**
     * Specify, whether or not the signature should be marked as exportable.
     * If this subpacket is missing, the signature is treated as being exportable.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param isExportable true if the signature should be exportable, false otherwise.
     */
    public void setExportable(boolean isCritical, boolean isExportable)
    {
        packets.add(new Exportable(isCritical, isExportable));
    }

    /**
     * Specify the set of features of the key.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param feature features
     */
    public void setFeature(boolean isCritical, byte feature)
    {
        packets.add(new Features(isCritical, feature));
    }

    /**
     * Add a TrustSignature packet to the signature. The values for depth and trust are
     * largely installation dependent but there are some guidelines in RFC 4880 -
     * 5.2.3.13.
     *
     * @param isCritical  true if the packet is critical.
     * @param depth       depth level.
     * @param trustAmount trust amount.
     */
    public void setTrust(boolean isCritical, int depth, int trustAmount)
    {
        packets.add(new TrustSignature(isCritical, depth, trustAmount));
    }

    /**
     * Set the number of seconds a key is valid for after the time of its creation. A
     * value of zero means the key never expires.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param seconds
     */
    public void setKeyExpirationTime(boolean isCritical, long seconds)
    {
        packets.add(new KeyExpirationTime(isCritical, seconds));
    }

    /**
     * Set the number of seconds a signature is valid for after the time of its creation.
     * A value of zero means the signature never expires.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param seconds
     */
    public void setSignatureExpirationTime(boolean isCritical, long seconds)
    {
        packets.add(new SignatureExpirationTime(isCritical, seconds));
    }

    /**
     * Set the creation time for the signature.
     * <p>
     * Note: this overrides the generation of a creation time when the signature is
     * generated.
     */
    public void setSignatureCreationTime(boolean isCritical, Date date)
    {
        packets.add(new SignatureCreationTime(isCritical, date));
    }

    /**
     * Specify the preferred hash algorithms of the key.
     * See {@link org.bouncycastle.bcpg.HashAlgorithmTags}.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param algorithms array of algorithms in descending preference
     */
    public void setPreferredHashAlgorithms(boolean isCritical, int[] algorithms)
    {
        packets.add(new PreferredAlgorithms(SignatureSubpacketTags.PREFERRED_HASH_ALGS, isCritical,
            algorithms));
    }

    /**
     * Specify the preferred symmetric encryption algorithms of the key.
     * See {@link org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags}.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param algorithms array of algorithms in descending preference
     */
    public void setPreferredSymmetricAlgorithms(boolean isCritical, int[] algorithms)
    {
        packets.add(new PreferredAlgorithms(SignatureSubpacketTags.PREFERRED_SYM_ALGS, isCritical,
            algorithms));
    }

    /**
     * Specify the preferred compression algorithms of this key.
     * See {@link org.bouncycastle.bcpg.CompressionAlgorithmTags}.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param algorithms array of algorithms in descending preference
     */
    public void setPreferredCompressionAlgorithms(boolean isCritical, int[] algorithms)
    {
        packets.add(new PreferredAlgorithms(SignatureSubpacketTags.PREFERRED_COMP_ALGS, isCritical,
            algorithms));
    }

    /**
     * Set this keys key flags.
     * See {@link PGPKeyFlags}.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param flags flags
     */
    public void setKeyFlags(boolean isCritical, int flags)
    {
        packets.add(new KeyFlags(isCritical, flags));
    }

    /**
     * Add a signer user-id to the signature.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param userID signer user-id
     *
     * @deprecated use {@link #addSignerUserID(boolean, String)} instead.
     */
    public void setSignerUserID(boolean isCritical, String userID)
    {
        addSignerUserID(isCritical, userID);
    }

    /**
     * Add a signer user-id to the signature.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param userID signer user-id
     */
    public void addSignerUserID(boolean isCritical, String userID)
    {
        if (userID == null)
        {
            throw new IllegalArgumentException("attempt to set null SignerUserID");
        }

        packets.add(new SignerUserID(isCritical, userID));
    }

    public void setSignerUserID(boolean isCritical, byte[] rawUserID)
    {
        if (rawUserID == null)
        {
            throw new IllegalArgumentException("attempt to set null SignerUserID");
        }

        packets.add(new SignerUserID(isCritical, false, rawUserID));
    }

    /**
     * Add an embedded signature packet.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param pgpSignature embedded signature
     * @throws IOException in case of an error
     *
     * @deprecated use {@link #addEmbeddedSignature(boolean, PGPSignature)} instead.
     */
    public void setEmbeddedSignature(boolean isCritical, PGPSignature pgpSignature)
        throws IOException
    {
        addEmbeddedSignature(isCritical, pgpSignature);
    }

    /**
     * Add an embedded signature packet.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param pgpSignature embedded signature
     * @throws IOException in case of an error
     */
    public void addEmbeddedSignature(boolean isCritical, PGPSignature pgpSignature)
        throws IOException
    {
        byte[] sig = pgpSignature.getEncoded();
        byte[] data;

        if (sig.length - 1 > 256)
        {
            data = new byte[sig.length - 3];
        }
        else
        {
            data = new byte[sig.length - 2];
        }

        System.arraycopy(sig, sig.length - data.length, data, 0, data.length);

        packets.add(new EmbeddedSignature(isCritical, false, data));
    }

    public void setPrimaryUserID(boolean isCritical, boolean isPrimaryUserID)
    {
        packets.add(new PrimaryUserID(isCritical, isPrimaryUserID));
    }

    /**
     * Add a notation data packet to the signature.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param isHumanReadable true if the notation is human-readable.
     * @param notationName name of the notation key
     * @param notationValue value of the notation
     *
     * @deprecated use {@link #addNotationData(boolean, boolean, String, String)} instead.
     */
    public void setNotationData(boolean isCritical, boolean isHumanReadable, String notationName,
                                String notationValue)
    {
        addNotationData(isCritical, isHumanReadable, notationName, notationValue);
    }

    /**
     * Add a notation data packet to the signature.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param isHumanReadable true if the notation is human-readable.
     * @param notationName name of the notation key.
     * @param notationValue value of the notation.
     */
    public void addNotationData(boolean isCritical, boolean isHumanReadable, String notationName,
                                String notationValue)
    {
        packets.add(new NotationData(isCritical, isHumanReadable, notationName, notationValue));
    }

    /**
     * Sets revocation reason sub packet.
     * See {@link org.bouncycastle.bcpg.sig.RevocationReasonTags}.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param reason reason code for the revocation
     * @param description human readable description of the revocation reason
     */
    public void setRevocationReason(boolean isCritical, byte reason, String description)
    {
        packets.add(new RevocationReason(isCritical, reason, description));
    }

    /**
     * Adds a revocation key sub packet.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param keyAlgorithm algorithm of the revocation key
     * @param fingerprint fingerprint of the revocation key
     *
     * @deprecated use {@link #addRevocationKey(boolean, int, byte[])} instead.
     */
    public void setRevocationKey(boolean isCritical, int keyAlgorithm, byte[] fingerprint)
    {
        addRevocationKey(isCritical, keyAlgorithm, fingerprint);
    }

    /**
     * Adds a revocation key sub packet.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param keyAlgorithm algorithm of the revocation key
     * @param fingerprint fingerprint of the revocation key
     */
    public void addRevocationKey(boolean isCritical, int keyAlgorithm, byte[] fingerprint)
    {
        packets.add(new RevocationKey(isCritical, RevocationKeyTags.CLASS_DEFAULT, keyAlgorithm,
            fingerprint));
    }

    /**
     * Sets issuer key-id subpacket.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param keyID id of the key that issued the signature
     */
    public void setIssuerKeyID(boolean isCritical, long keyID)
    {
        packets.add(new IssuerKeyID(isCritical, keyID));
    }

    /**
     * Sets the signature target sub packet.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param publicKeyAlgorithm algorithm of the key that issued the signature that is being referred to.
     * @param hashAlgorithm hash algorithm that was used to calculate the hash data.
     * @param hashData hash of the signature that is being referred to.
     */
    public void setSignatureTarget(boolean isCritical, int publicKeyAlgorithm, int hashAlgorithm, byte[] hashData)
    {
        packets.add(new SignatureTarget(isCritical, publicKeyAlgorithm, hashAlgorithm, hashData));
    }

    /**
     * Sets the signature issuer fingerprint for the signing key.
     *
     * @param isCritical true if critical, false otherwise.
     * @param secretKey the secret key used to generate the associated signature.
     */
    public void setIssuerFingerprint(boolean isCritical, PGPSecretKey secretKey)
    {
        this.setIssuerFingerprint(isCritical, secretKey.getPublicKey());
    }

    /**
     * Sets the signature issuer fingerprint for the signing key.
     *
     * @param isCritical true if critical, false otherwise.
     * @param publicKey the public key needed to verify the associated signature.
     */
    public void setIssuerFingerprint(boolean isCritical, PGPPublicKey publicKey)
    {
        packets.add(new IssuerFingerprint(isCritical, publicKey.getVersion(), publicKey.getFingerprint()));
    }

    /**
     * Adds a intended recipient fingerprint for an encrypted payload the signature is associated with.
     *
     * @param isCritical true if critical, false otherwise.
     * @param publicKey the public key the encrypted payload was encrypted against.
     *
     * @deprecated use {@link #addIntendedRecipientFingerprint(boolean, PGPPublicKey)} instead.
     */
    public void setIntendedRecipientFingerprint(boolean isCritical, PGPPublicKey publicKey)
    {
        addIntendedRecipientFingerprint(isCritical, publicKey);
    }

    /**
     * Adds a intended recipient fingerprint for an encrypted payload the signature is associated with.
     *
     * @param isCritical true if critical, false otherwise.
     * @param publicKey the public key the encrypted payload was encrypted against.
     */
    public void addIntendedRecipientFingerprint(boolean isCritical, PGPPublicKey publicKey)
    {
        packets.add(new IntendedRecipientFingerprint(isCritical,
                publicKey.getVersion(), publicKey.getFingerprint()));
    }

    /**
     * Add a custom subpacket.
     * Miscellaneous subpackets are subpackets that Bouncycastle does not recognize or
     * doesn't have first class support for.
     *
     * @param subpacket subpacket
     */
    public void addCustomSubpacket(SignatureSubpacket subpacket)
    {
        packets.add(subpacket);
    }

    /**
     * Remove a previously set packet from the generator.
     *
     * @param packet the signature subpacket to remove.
     */
    public boolean removePacket(SignatureSubpacket packet)
    {
        return packets.remove(packet);
    }

    /**
     * Return true if a particular subpacket type exists.
     *
     * @param type type to look for.
     * @return true if present, false otherwise.
     */
    public boolean hasSubpacket(
        int type)
    {
        for (int i = 0; i != packets.size(); i++)
        {
            if (((SignatureSubpacket)packets.get(i)).getType() == type)
            {
                return true;
            }
        }

        return false;
    }

    /**
     * Return all signature subpackets of the passed in type currently in
     * the generator.
     *
     * @param type subpacket type code
     * @return an array of zero or more matching subpackets.
     */
    public SignatureSubpacket[] getSubpackets(
        int    type)
    {
        List list = new ArrayList();

        for (int i = 0; i != packets.size(); i++)
        {
            if (((SignatureSubpacket)packets.get(i)).getType() == type)
            {
                list.add(packets.get(i));
            }
        }

        return (SignatureSubpacket[])list.toArray(new SignatureSubpacket[]{});
    }

    public PGPSignatureSubpacketVector generate()
    {
        return new PGPSignatureSubpacketVector(
            (SignatureSubpacket[])packets.toArray(new SignatureSubpacket[packets.size()]));
    }
}

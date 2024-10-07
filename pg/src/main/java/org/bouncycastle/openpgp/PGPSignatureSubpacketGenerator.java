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
import org.bouncycastle.bcpg.sig.LibrePGPPreferredEncryptionModes;
import org.bouncycastle.bcpg.sig.NotationData;
import org.bouncycastle.bcpg.sig.PolicyURI;
import org.bouncycastle.bcpg.sig.PreferredAEADCiphersuites;
import org.bouncycastle.bcpg.sig.PreferredAlgorithms;
import org.bouncycastle.bcpg.sig.PreferredKeyServer;
import org.bouncycastle.bcpg.sig.PrimaryUserID;
import org.bouncycastle.bcpg.sig.RegularExpression;
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
    List<SignatureSubpacket> packets = new ArrayList<SignatureSubpacket>();

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
        if (sigSubV != null)
        {
            for (int i = 0; i != sigSubV.packets.length; i++)
            {
                packets.add(sigSubV.packets[i]);
            }
        }
    }

    /**
     * Specify, whether or not the signature is revocable.
     *
     * @param isCritical  true if should be treated as critical, false otherwise.
     * @param isRevocable true if the signature should be revocable, false otherwise.
     */
    public void setRevocable(boolean isCritical, boolean isRevocable)
    {
        if (contains(SignatureSubpacketTags.REVOCABLE))
        {
            throw new IllegalStateException("Revocable exists in the Signature Subpacket Generator");
        }
        packets.add(new Revocable(isCritical, isRevocable));
    }

    /**
     * Specify, whether the signature should be marked as exportable.
     * If this subpacket is missing, the signature is treated as being exportable.
     * The subpacket is marked as critical, as is required (for non-exportable signatures) by the spec.
     *
     * @param isExportable true if the signature should be exportable, false otherwise.
     */
    public void setExportable(boolean isExportable)
    {
        setExportable(true, isExportable);
    }

    /**
     * Specify, whether or not the signature should be marked as exportable.
     * If this subpacket is missing, the signature is treated as being exportable.
     *
     * @param isCritical   true if should be treated as critical, false otherwise.
     * @param isExportable true if the signature should be exportable, false otherwise.
     */
    public void setExportable(boolean isCritical, boolean isExportable)
    {
        if (contains(SignatureSubpacketTags.EXPORTABLE))
        {
            throw new IllegalStateException("Exportable Certification exists in the Signature Subpacket Generator");
        }
        packets.add(new Exportable(isCritical, isExportable));
    }

    /**
     * Specify the set of features of the key.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param feature    features
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
     * The subpacket will be marked as critical, as is recommended by the spec.
     *
     * @param seconds seconds from key creation to expiration
     */
    public void setKeyExpirationTime(long seconds)
    {
        setKeyExpirationTime(true, seconds);
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
     * The subpacket will be marked as critical, as is recommended by the spec.
     *.
     * @param seconds seconds from signature creation to expiration
     */
    public void setSignatureExpirationTime(long seconds)
    {
        setSignatureExpirationTime(true, seconds);
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
     * The subpacket will be marked as critical, as is recommended by the spec.
     * <p>
     * Note: this overrides the generation of a creation time when the signature is
     * generated.
     * @param date date
     */
    public void setSignatureCreationTime(Date date)
    {
        setSignatureCreationTime(true, date);
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
     * This method is BROKEN!
     * Specify the preferred AEAD algorithms of this key.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param algorithms array of algorithms in descending preference
     * @deprecated use {@link #setPreferredAEADCiphersuites(boolean, PreferredAEADCiphersuites.Combination[])}
     * or {@link #setPreferredLibrePgpEncryptionModes(boolean, int[])} instead.
     */
    @Deprecated
    public void setPreferredAEADAlgorithms(boolean isCritical, int[] algorithms)
    {
        packets.add(new PreferredAlgorithms(SignatureSubpacketTags.PREFERRED_AEAD_ALGORITHMS, isCritical,
            algorithms));
    }

    /**
     * Specify the preferred OpenPGP AEAD ciphersuites of this key.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-preferred-aead-ciphersuites">
     *     RFC9580: Preferred AEAD Ciphersuites</a>
     *
     * @param isCritical true, if this packet should be treated as critical, false otherwise.
     * @param algorithms array of algorithms in descending preference
     */
    public void setPreferredAEADCiphersuites(boolean isCritical, PreferredAEADCiphersuites.Combination[] algorithms)
    {
        packets.add(new PreferredAEADCiphersuites(isCritical, algorithms));
    }

    /**
     * Specify the preferred OpenPGP AEAD ciphersuites of this key.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-preferred-aead-ciphersuites">
     *     RFC9580: Preferred AEAD Ciphersuites</a>
     *
     * @param builder builder to build the ciphersuites packet from
     */
    public void setPreferredAEADCiphersuites(PreferredAEADCiphersuites.Builder builder)
    {
        packets.add(builder.build());
    }

    /**
     * Set the preferred encryption modes for LibrePGP keys.
     * Note: LibrePGP is not OpenPGP. An application strictly compliant to only the OpenPGP standard will not
     * know how to handle LibrePGP encryption modes.
     * The LibrePGP spec states that this subpacket shall be ignored and the application shall instead assume
     * {@link org.bouncycastle.bcpg.AEADAlgorithmTags#OCB}.
     *
     * @see <a href="https://www.ietf.org/archive/id/draft-koch-librepgp-01.html#name-preferred-encryption-modes">
     *     LibrePGP: Preferred Encryption Modes</a>
     * @see org.bouncycastle.bcpg.AEADAlgorithmTags for possible algorithms
     *
     * @param isCritical whether the packet is critical
     * @param algorithms list of algorithms
     * @deprecated the use of this subpacket is deprecated in LibrePGP
     */
    @Deprecated
    public void setPreferredLibrePgpEncryptionModes(boolean isCritical, int[] algorithms)
    {
        packets.add(new LibrePGPPreferredEncryptionModes(isCritical, algorithms));
    }

    /**
     * Specify the preferred key server for the signed user-id / key.
     * Note, that the key server might also be a http/ftp etc. URI pointing to the key itself.
     *
     * @param isCritical true if the subpacket should be treated as critical
     * @param uri key server URI
     */
    public void setPreferredKeyServer(boolean isCritical, String uri)
    {
        packets.add(new PreferredKeyServer(isCritical, uri));
    }

    public void addPolicyURI(boolean isCritical, String policyUri)
    {
        packets.add(new PolicyURI(isCritical, policyUri));
    }

    /**
     * Set this keys key flags.
     * See {@link PGPKeyFlags}.
     * The subpacket will be marked as critical, as is recommended by the spec.
     *
     * @param flags      flags
     */
    public void setKeyFlags(int flags)
    {
        setKeyFlags(true, flags);
    }

    /**
     * Set this keys key flags.
     * See {@link PGPKeyFlags}.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param flags      flags
     */
    public void setKeyFlags(boolean isCritical, int flags)
    {
        packets.add(new KeyFlags(isCritical, flags));
    }

    /**
     * Add a signer user-id to the signature.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param userID     signer user-id
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
     * @param userID     signer user-id
     */
    public void addSignerUserID(boolean isCritical, String userID)
    {
        if (userID == null)
        {
            throw new IllegalArgumentException("attempt to set null SignerUserID");
        }

        packets.add(new SignerUserID(isCritical, userID));
    }

    /**
     * Add a signer user-id to the signature.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param rawUserID  signer user-id
     * @deprecated use {@link #addSignerUserID(boolean, byte[])} instead.
     */
    public void setSignerUserID(boolean isCritical, byte[] rawUserID)
    {
        addSignerUserID(isCritical, rawUserID);
    }

    /**
     * Add a signer user-id to the signature.
     *
     * @param isCritical true if should be treated as critical, false otherwise.
     * @param rawUserID  signer user-id
     */
    public void addSignerUserID(boolean isCritical, byte[] rawUserID)
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
     * @param isCritical   true if should be treated as critical, false otherwise.
     * @param pgpSignature embedded signature
     * @throws IOException in case of an error
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
     * @param isCritical   true if should be treated as critical, false otherwise.
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
     * @param isCritical      true if should be treated as critical, false otherwise.
     * @param isHumanReadable true if the notation is human-readable.
     * @param notationName    name of the notation key
     * @param notationValue   value of the notation
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
     * @param isCritical      true if should be treated as critical, false otherwise.
     * @param isHumanReadable true if the notation is human-readable.
     * @param notationName    name of the notation key.
     * @param notationValue   value of the notation.
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
     * @param isCritical  true if should be treated as critical, false otherwise.
     * @param reason      reason code for the revocation
     * @param description human readable description of the revocation reason
     */
    public void setRevocationReason(boolean isCritical, byte reason, String description)
    {
        packets.add(new RevocationReason(isCritical, reason, description));
    }

    /**
     * Adds a revocation key sub packet.
     *
     * @param isCritical   true if should be treated as critical, false otherwise.
     * @param keyAlgorithm algorithm of the revocation key
     * @param fingerprint  fingerprint of the revocation key (v4 only)
     * @deprecated the revocation key mechanism is deprecated. Applications MUST NOT generate such a packet.
     */
    public void setRevocationKey(boolean isCritical, int keyAlgorithm, byte[] fingerprint)
    {
        addRevocationKey(isCritical, keyAlgorithm, fingerprint);
    }

    /**
     * Adds a revocation key sub packet.
     *
     * @param isCritical   true if should be treated as critical, false otherwise.
     * @param keyAlgorithm algorithm of the revocation key
     * @param fingerprint  fingerprint of the revocation key (v4 only)
     * @deprecated the revocation key mechanism is deprecated. Applications MUST NOT generate such a packet.
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
     * @param keyID      id of the key that issued the signature
     */
    public void setIssuerKeyID(boolean isCritical, long keyID)
    {
        packets.add(new IssuerKeyID(isCritical, keyID));
    }

    /**
     * Sets the signature target sub packet.
     *
     * @param isCritical         true if should be treated as critical, false otherwise.
     * @param publicKeyAlgorithm algorithm of the key that issued the signature that is being referred to.
     * @param hashAlgorithm      hash algorithm that was used to calculate the hash data.
     * @param hashData           hash of the signature that is being referred to.
     */
    public void setSignatureTarget(boolean isCritical, int publicKeyAlgorithm, int hashAlgorithm, byte[] hashData)
    {
        packets.add(new SignatureTarget(isCritical, publicKeyAlgorithm, hashAlgorithm, hashData));
    }

    /**
     * Sets the signature issuer fingerprint for the signing key.
     *
     * @param isCritical true if critical, false otherwise.
     * @param secretKey  the secret key used to generate the associated signature.
     */
    public void setIssuerFingerprint(boolean isCritical, PGPSecretKey secretKey)
    {
        this.setIssuerFingerprint(isCritical, secretKey.getPublicKey());
    }

    /**
     * Sets the signature issuer fingerprint for the signing key.
     *
     * @param isCritical true if critical, false otherwise.
     * @param publicKey  the public key needed to verify the associated signature.
     */
    public void setIssuerFingerprint(boolean isCritical, PGPPublicKey publicKey)
    {
        packets.add(new IssuerFingerprint(isCritical, publicKey.getVersion(), publicKey.getFingerprint()));
    }

    /**
     * Adds a intended recipient fingerprint for an encrypted payload the signature is associated with.
     *
     * @param isCritical true if critical, false otherwise.
     * @param publicKey  the public key the encrypted payload was encrypted against.
     * @deprecated use {@link #addIntendedRecipientFingerprint(boolean, PGPPublicKey)} instead.
     */
    public void setIntendedRecipientFingerprint(boolean isCritical, PGPPublicKey publicKey)
    {
        addIntendedRecipientFingerprint(isCritical, publicKey);
    }

    /**
     * Adds a intended recipient fingerprint for an encrypted payload the signature is associated with.
     * The subpacket will be marked as critical, as is recommended by the spec.
     *
     * @param publicKey  the public key the encrypted payload was encrypted against.
     */
    public void addIntendedRecipientFingerprint(PGPPublicKey publicKey)
    {
        // RFC9580 states, that the packet SHOULD be critical if generated in a v6 signature,
        //  but it doesn't harm to default to critical for any signature version
        addIntendedRecipientFingerprint(true, publicKey);
    }

    /**
     * Adds a intended recipient fingerprint for an encrypted payload the signature is associated with.
     *
     * @param isCritical true if critical, false otherwise.
     * @param publicKey  the public key the encrypted payload was encrypted against.
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
     * Remove all {@link SignatureSubpacket} objects of the given subpacketType from the underlying subpacket vector.
     * @param subpacketType type to remove
     * @return true if any packet was removed, false otherwise
     */
    public boolean removePacketsOfType(int subpacketType)
    {
        boolean remove = false;
        for (int i = packets.size() - 1; i >= 0; i--) {
            if (packets.get(i).getType() == subpacketType) {
                packets.remove(i);
                remove = true;
            }
        }
        return remove;
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
        int type)
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

    private boolean contains(int type)
    {
        for (int i = 0; i < packets.size(); ++i)
        {
            if (((SignatureSubpacket)packets.get(i)).getType() == type)
            {
                return true;
            }
        }
        return false;
    }

    /**
     * Adds a regular expression.
     * The subpacket is marked as critical, as is recommended by the spec.
     *
     * @param regularExpression the regular expression
     */
    public void addRegularExpression(String regularExpression)
    {
        addRegularExpression(true, regularExpression);
    }

    /**
     * Adds a regular expression.
     *
     * @param isCritical        true if should be treated as critical, false otherwise.
     * @param regularExpression the regular expression
     */
    public void addRegularExpression(boolean isCritical, String regularExpression)
    {
        if (regularExpression == null)
        {
            throw new IllegalArgumentException("attempt to set null regular expression");
        }
        packets.add(new RegularExpression(isCritical, regularExpression));
    }
}

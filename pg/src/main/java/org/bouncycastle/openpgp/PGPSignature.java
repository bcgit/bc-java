package org.bouncycastle.openpgp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashUtils;
import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.bcpg.MPInteger;
import org.bouncycastle.bcpg.Packet;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SignaturePacket;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.TrustPacket;
import org.bouncycastle.bcpg.sig.IssuerFingerprint;
import org.bouncycastle.bcpg.sig.IssuerKeyID;
import org.bouncycastle.bcpg.sig.RevocationReason;
import org.bouncycastle.bcpg.sig.RevocationReasonTags;
import org.bouncycastle.math.ec.rfc8032.Ed25519;
import org.bouncycastle.math.ec.rfc8032.Ed448;
import org.bouncycastle.openpgp.operator.PGPContentVerifier;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilder;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;

/**
 * A PGP signature object.
 */
public class PGPSignature
    extends PGPDefaultSignatureGenerator
{
    /**
     * The signature is made over some binary data.
     * No preprocessing is applied.
     * <br>
     * This signature type is used to create data signatures.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-binary-signature-type-id-0x">
     * RFC9580 - Binary Signature of a Document</a>
     */
    public static final int BINARY_DOCUMENT = 0x00;

    /**
     * The signature is made over text data.
     * In a preprocessing step, the text data is canonicalized (line endings may be altered).
     * <br>
     * This signature type is used to create data signatures.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-text-signature-type-id-0x01">
     * RFC9580 - Text Signature of a Canonical Document</a>
     */
    public static final int CANONICAL_TEXT_DOCUMENT = 0x01;

    /**
     * The signature is made only over its own signature subpackets.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-standalone-signature-type-i">
     * RFC9580 - Standalone Signature</a>
     */
    public static final int STAND_ALONE = 0x02;

    /**
     * Generic certification over a user-id or user-attribute.
     * The issuer of a generic certification does not make any claims as to what extent they checked
     * the authenticity of the identity claim.
     * <br>
     * This signature type is used to bind user information to primary keys, or to certify the identity claim
     * of a third party.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-generic-certification-signa">
     * RFC9580 - Generic Certification Signature of a User ID and Public Key Packet</a>
     */
    public static final int DEFAULT_CERTIFICATION = 0x10;

    /**
     * Persona certification over a user-id or user-attribute.
     * The issuer of a persona certification did explicitly not check the authenticity of the identity claim.
     * <br>
     * This signature type is used to bind user information to primary keys, or to certify the identity claim
     * of a third party.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-persona-certification-signa">
     * RFC9580 - Persona Certification Signature of a User ID and Public Key Packet</a>
     */
    public static final int NO_CERTIFICATION = 0x11;

    /**
     * Casual certification over a user-id or user-attribute.
     * The issuer of a casual certification did some casual verification to check the authenticity of the
     * identity claim.
     * <br>
     * This signature type is used to bind user information to primary keys, or to certify the identity claim
     * of a third party.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-casual-certification-signat">
     * RFC9580 - Casual Certification of a User ID an Public Key Packet</a>
     */
    public static final int CASUAL_CERTIFICATION = 0x12;

    /**
     * Positive certification over a user-id or user-attribute.
     * The issuer of a positive certification did extensive effort to check the authenticity of the identity claim.
     * <br>
     * This signature type is used to bind user information to primary keys, or to certify the identity claim
     * of a third party.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-positive-certification-sign">
     * RFC9580 - Positive Certification Signature of a User ID and Public Key Packet</a>
     */
    public static final int POSITIVE_CERTIFICATION = 0x13;

    /**
     * Subkey Binding Signature to bind a subkey to a primary key.
     * This signature type is used to bind a subkey to the primary key of a certificate.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-subkey-binding-signature-ty">
     * RFC9580 - Subkey Binding Signature</a>
     */
    public static final int SUBKEY_BINDING = 0x18;

    /**
     * Primary-Key Binding Signature to bind a signing-capable subkey to a primary key.
     * This (back-) signature is used as an embedded signature in a {@link #SUBKEY_BINDING} signature and acts as
     * a claim by the subkey, stating that it is in fact a subkey of the primary key.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-primary-key-binding-signatu">
     * RFC9580 - Primary Key Binding Signature</a>
     */
    public static final int PRIMARYKEY_BINDING = 0x19;

    /**
     * The signature is made directly over a primary key.
     * If issued as a self-signature, its contents apply to the whole certificate, meaning this signature
     * is appropriate to set algorithm preferences which also apply to its subkeys.
     * Issued as a signature over a third-party certificate, it can be used to mark said certificate as a CA.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-direct-key-signature-type-i">
     * RFC9580 - Direct Key Signature</a>
     */
    public static final int DIRECT_KEY = 0x1f;

    /**
     * The signature is used to revoke a primary key (and in turn the whole certificate with all its subkeys).
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-key-revocation-signature-ty">
     * RFC9580 - Key Revocation Signature</a>
     */
    public static final int KEY_REVOCATION = 0x20;

    /**
     * The signature is used to revoke the binding of a particular subkey.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-subkey-revocation-signature">
     * RFC9580 - Subkey Revocation Signature</a>
     */
    public static final int SUBKEY_REVOCATION = 0x28;

    /**
     * The signature is used to revoke a user-id certification signature
     * ({@link #DEFAULT_CERTIFICATION}, {@link #NO_CERTIFICATION}, {@link #CASUAL_CERTIFICATION},
     * {@link #POSITIVE_CERTIFICATION}) or {@link #DIRECT_KEY} signature.
     * Issued as a self-signature, it can be used to revoke an identity claim.
     * Issued over a third-party certificate, it revokes the attestation of the third-party's claim.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-certification-revocation-si">
     * RFC9580 - Certification Revocation Signature</a>
     */
    public static final int CERTIFICATION_REVOCATION = 0x30;

    /**
     * The signature is only meaningful for the timestamp contained in it.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-timestamp-signature-type-id">
     * RFC9580 - Timestamp Signature</a>
     */
    public static final int TIMESTAMP = 0x40;

    /**
     * This signature is issued over another signature and can act as an attestation of that signature.
     * This concept can be used to "approve" third-party certifications over the own key, allowing
     * third-party certifications to be published on key-servers that usually strip such signatures
     * to prevent certificate flooding.
     *
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-third-party-confirmation-si">
     * RFC9580 - Third-Party Confirmation Signature/a>
     */
    public static final int THIRD_PARTY_CONFIRMATION = 0x50;

    final SignaturePacket sigPck;
    private final TrustPacket trustPck;

    private volatile PGPContentVerifier verifier;

    private static SignaturePacket cast(Packet packet)
        throws IOException
    {
        if (!(packet instanceof SignaturePacket))
        {
            throw new IOException("unexpected packet in stream: " + packet);
        }
        return (SignaturePacket)packet;
    }

    /**
     * Parse a {@link PGPSignature} from an OpenPGP packet input stream.
     *
     * @param pIn packet input stream
     * @throws IOException
     * @throws PGPException
     */
    public PGPSignature(
        BCPGInputStream pIn)
        throws IOException, PGPException
    {
        this(cast(pIn.readPacket()));
    }

    PGPSignature(
        PGPSignature signature)
    {
        super(signature.getVersion());
        sigPck = signature.sigPck;
        sigType = signature.sigType;
        trustPck = signature.trustPck;
    }

    PGPSignature(
        SignaturePacket sigPacket)
    {
        this(sigPacket, null);
    }

    PGPSignature(
        SignaturePacket sigPacket,
        TrustPacket trustPacket)
    {
        super(sigPacket.getVersion());
        this.sigPck = sigPacket;
        this.sigType = sigPck.getSignatureType();
        this.trustPck = trustPacket;
    }

    /**
     * Return the OpenPGP version number for this signature.
     *
     * @return signature version number.
     */
    public int getVersion()
    {
        return sigPck.getVersion();
    }

    /**
     * Return the key algorithm associated with this signature.
     *
     * @return signature key algorithm.
     */
    public int getKeyAlgorithm()
    {
        return sigPck.getKeyAlgorithm();
    }

    /**
     * Return the hash algorithm associated with this signature.
     *
     * @return signature hash algorithm.
     */
    public int getHashAlgorithm()
    {
        return sigPck.getHashAlgorithm();
    }

    /**
     * Return the digest prefix of the signature.
     *
     * @return digest prefix
     */
    public byte[] getDigestPrefix()
    {
        return sigPck.getFingerPrint();
    }

    /**
     * Return true if this signature represents a certification.
     *
     * @return true if this signature represents a certification, false otherwise.
     */
    public boolean isCertification()
    {
        return isCertification(getSignatureType());
    }

    /**
     * Initialize the signature for verification.
     *
     * @param verifierBuilderProvider provide the implementation for signature verification
     * @param pubKey                  issuer public key
     * @throws PGPException
     */
    public void init(PGPContentVerifierBuilderProvider verifierBuilderProvider, PGPPublicKey pubKey)
        throws PGPException
    {
        if (sigType == 0xFF)
        {
            throw new PGPException("Illegal signature type 0xFF provided.");
        }

        if (getVersion() == SignaturePacket.VERSION_6 && pubKey.getVersion() != PublicKeyPacket.VERSION_6)
        {
            throw new PGPException("MUST NOT verify v6 signature with non-v6 key.");
        }

        if (getVersion() == SignaturePacket.VERSION_4 && pubKey.getVersion() != PublicKeyPacket.VERSION_4)
        {
            throw new PGPException("MUST NOT verify v4 signature with non-v4 key.");
        }

        PGPContentVerifierBuilder verifierBuilder = createVerifierProvider(verifierBuilderProvider);

        init(verifierBuilder.build(pubKey));
    }

    PGPContentVerifierBuilder createVerifierProvider(PGPContentVerifierBuilderProvider verifierBuilderProvider)
        throws PGPException
    {
        return verifierBuilderProvider.get(sigPck.getKeyAlgorithm(), sigPck.getHashAlgorithm());
    }

    void init(PGPContentVerifier verifier)
        throws PGPException
    {
        this.verifier = verifier;
        this.lastb = 0;
        this.sigOut = verifier.getOutputStream();

        checkSaltSize();
        updateWithSalt();
    }

    private void checkSaltSize()
        throws PGPException
    {
        if (getVersion() != SignaturePacket.VERSION_6)
        {
            return;
        }

        int expectedSaltSize = HashUtils.getV6SignatureSaltSizeInBytes(getHashAlgorithm());
        if (expectedSaltSize != sigPck.getSalt().length)
        {
            throw new PGPException("RFC9580 defines the salt size for " + PGPUtil.getDigestName(getHashAlgorithm()) +
                " as " + expectedSaltSize + " octets, but signature has " + sigPck.getSalt().length + " octets.");
        }
    }

    private void updateWithSalt()
        throws PGPException
    {
        if (getVersion() == SignaturePacket.VERSION_6)
        {
            try
            {
                sigOut.write(sigPck.getSalt());
            }
            catch (IOException e)
            {
                throw new PGPException("Could not update with salt.", e);
            }
        }
    }

    /**
     * Finish the verification and return true if the signature is "correct".
     * Note: The fact that this method returned <pre>true</pre> does not yet mean that the signature is valid.
     * A correct signature may very well be expired, the issuer key may be revoked, etc.
     * All these constraints are not checked by this method.
     *
     * @return true if the signature is correct
     * @throws PGPException
     */
    public boolean verify()
        throws PGPException
    {
        try
        {
            sigOut.write(this.getSignatureTrailer());

            sigOut.close();
        }
        catch (IOException e)
        {
            throw new PGPException(e.getMessage(), e);
        }

        return verifier.verify(this.getSignature());
    }


    /**
     * Verify the signature as certifying the passed in public key as associated
     * with the passed in user attributes.
     *
     * @param userAttributes user attributes the key was stored under
     * @param key            the key to be verified.
     * @return true if the signature matches, false otherwise.
     * @throws PGPException
     */
    public boolean verifyCertification(
        PGPUserAttributeSubpacketVector userAttributes,
        PGPPublicKey key)
        throws PGPException
    {
        if (verifier == null)
        {
            throw new PGPException("PGPSignature not initialised - call init().");
        }

        if (!PGPSignature.isCertification(sigType)
            && PGPSignature.CERTIFICATION_REVOCATION != sigType)
        {
            throw new PGPException("signature is neither a certification signature nor a certification revocation.");
        }

        return doVerifyCertification(userAttributes, key);
    }

    boolean doVerifyCertification(
        PGPUserAttributeSubpacketVector userAttributes,
        PGPPublicKey key)
        throws PGPException
    {
        updateWithPublicKey(key);

        getAttributesHash(userAttributes);

        addTrailer();

        return verifier.verify(this.getSignature());
    }

    /**
     * Verify the signature as certifying the passed in public key as associated
     * with the passed in id.
     *
     * @param id  id the key was stored under
     * @param key the key to be verified.
     * @return true if the signature matches, false otherwise.
     * @throws PGPException
     */
    public boolean verifyCertification(
        String id,
        PGPPublicKey key)
        throws PGPException
    {
        return verifyCertification(Strings.toUTF8ByteArray(id), key);
    }

    /**
     * Verify the signature as certifying the passed in public key as associated
     * with the passed in rawID.
     *
     * @param rawID id the key was stored under in its raw byte form.
     * @param key   the key to be verified.
     * @return true if the signature matches, false otherwise.
     * @throws PGPException
     */
    public boolean verifyCertification(
        byte[] rawID,
        PGPPublicKey key)
        throws PGPException
    {
        if (verifier == null)
        {
            throw new PGPException("PGPSignature not initialised - call init().");
        }

        if (!PGPSignature.isCertification(sigType)
            && PGPSignature.CERTIFICATION_REVOCATION != sigType)
        {
            throw new PGPException("signature is neither a certification signature nor a certification revocation.");
        }

        return doVerifyCertification(rawID, key);
    }

    boolean doVerifyCertification(byte[] rawID, PGPPublicKey key)
        throws PGPException
    {
        updateWithPublicKey(key);

        //
        // hash in the rawID
        //
        updateWithIdData(0xb4, rawID);

        addTrailer();

        return verifier.verify(this.getSignature());
    }

    /**
     * Verify a certification for the passed in key against the passed in
     * master key.
     *
     * @param masterKey the key we are verifying against.
     * @param pubKey    the key we are verifying.
     * @return true if the certification is valid, false otherwise.
     * @throws PGPException
     */
    public boolean verifyCertification(
        PGPPublicKey masterKey,
        PGPPublicKey pubKey)
        throws PGPException
    {
        if (verifier == null)
        {
            throw new PGPException("PGPSignature not initialised - call init().");
        }

        if (PGPSignature.SUBKEY_BINDING != sigType
            && PGPSignature.PRIMARYKEY_BINDING != sigType
            && PGPSignature.SUBKEY_REVOCATION != sigType)
        {
            throw new PGPException("signature is not a key binding signature.");
        }

        return doVerifyCertification(masterKey, pubKey);
    }

    boolean doVerifyCertification(
        PGPPublicKey masterKey,
        PGPPublicKey pubKey)
        throws PGPException
    {
        updateWithPublicKey(masterKey);
        updateWithPublicKey(pubKey);

        addTrailer();

        return verifier.verify(this.getSignature());
    }

    private void addTrailer()
    {
        try
        {
            sigOut.write(sigPck.getSignatureTrailer());

            sigOut.close();
        }
        catch (IOException e)
        {
            throw new PGPRuntimeOperationException(e.getMessage(), e);
        }
    }

    /**
     * Verify a key certification, such as a revocation, for the passed in key.
     *
     * @param pubKey the key we are checking.
     * @return true if the certification is valid, false otherwise.
     * @throws PGPException
     */
    public boolean verifyCertification(
        PGPPublicKey pubKey)
        throws PGPException
    {
        if (verifier == null)
        {
            throw new PGPException("PGPSignature not initialised - call init().");
        }

        if (this.getSignatureType() != KEY_REVOCATION
            && this.getSignatureType() != DIRECT_KEY)
        {
            throw new PGPException("signature is not a key signature");
        }

        return doVerifyCertification(pubKey);
    }

    boolean doVerifyCertification(
        PGPPublicKey pubKey)
        throws PGPException
    {
        updateWithPublicKey(pubKey);

        addTrailer();

        return verifier.verify(this.getSignature());
    }

    /**
     * Return the type id of the signature.
     *
     * @return type id
     * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-signature-types">
     * RFC9580 - Signature Types</a>
     */
    public int getSignatureType()
    {
        return sigPck.getSignatureType();
    }

    /**
     * Return the id of the key that created the signature.
     * Note: Since signatures of version 4 or later encode the issuer information inside a
     * signature subpacket ({@link IssuerKeyID} or {@link IssuerFingerprint}), there is not
     * a single source of truth for the key-id.
     * To match any suitable issuer keys, use {@link #getKeyIdentifiers()} instead.
     *
     * @return keyID of the signatures corresponding key.
     */
    public long getKeyID()
    {
        return sigPck.getKeyID();
    }

    /**
     * Create a list of {@link KeyIdentifier} objects, for all {@link IssuerFingerprint}
     * and {@link IssuerKeyID} signature subpackets found in either the hashed or unhashed areas
     * of the signature.
     *
     * @return all detectable {@link KeyIdentifier KeyIdentifiers}
     */
    public List<KeyIdentifier> getKeyIdentifiers()
    {
        List<KeyIdentifier> identifiers = new ArrayList<KeyIdentifier>();
        if (getVersion() <= SignaturePacket.VERSION_3)
        {
            identifiers.add(new KeyIdentifier(getKeyID()));
        }
        else
        {
            identifiers.addAll(getHashedKeyIdentifiers());
            identifiers.addAll(getUnhashedKeyIdentifiers());
        }
        return identifiers;
    }

    public boolean hasKeyIdentifier(KeyIdentifier identifier)
    {
        for (Iterator it = getKeyIdentifiers().iterator(); it.hasNext(); )
        {
            if (((KeyIdentifier)it.next()).matchesExplicit(identifier))
            {
                return true;
            }
        }
        return false;
    }

    /**
     * Return a list of all {@link KeyIdentifier KeyIdentifiers} that could be derived from
     * any {@link IssuerFingerprint} or {@link IssuerKeyID} subpackets of the hashed signature
     * subpacket area.
     *
     * @return hashed key identifiers
     */
    public List<KeyIdentifier> getHashedKeyIdentifiers()
    {
        return extractKeyIdentifiers(sigPck.getHashedSubPackets());
    }

    /**
     * Return a list of all {@link KeyIdentifier KeyIdentifiers} that could be derived from
     * any {@link IssuerFingerprint} or {@link IssuerKeyID} subpackets of the unhashed signature
     * subpacket area.
     *
     * @return unhashed key identifiers
     */
    public List<KeyIdentifier> getUnhashedKeyIdentifiers()
    {
        return extractKeyIdentifiers(sigPck.getUnhashedSubPackets());
    }

    private List<KeyIdentifier> extractKeyIdentifiers(SignatureSubpacket[] subpackets)
    {
        List<KeyIdentifier> identifiers = new ArrayList<KeyIdentifier>();
        for (int idx = 0; idx != subpackets.length; idx++)
        {
            SignatureSubpacket s = subpackets[idx];
            if (s instanceof IssuerFingerprint)
            {
                IssuerFingerprint issuer = (IssuerFingerprint)s;
                identifiers.add(new KeyIdentifier(issuer.getFingerprint()));
            }

            if (s instanceof IssuerKeyID)
            {
                IssuerKeyID issuer = (IssuerKeyID)s;
                identifiers.add(new KeyIdentifier(issuer.getKeyID()));
            }
        }
        return identifiers;
    }

    /**
     * Return the creation time of the signature.
     *
     * @return the signature creation time.
     */
    public Date getCreationTime()
    {
        return new Date(sigPck.getCreationTime());
    }

    public byte[] getSignatureTrailer()
    {
        return sigPck.getSignatureTrailer();
    }

    /**
     * Return true if the signature has either hashed or unhashed subpackets.
     *
     * @return true if either hashed or unhashed subpackets are present, false otherwise.
     */
    public boolean hasSubpackets()
    {
        return sigPck.getHashedSubPackets() != null || sigPck.getUnhashedSubPackets() != null;
    }

    /**
     * Return the hashed subpackets of the signature.
     * Hashed signature subpackets are covered by the signature.
     *
     * @return hashed signature subpackets
     */
    public PGPSignatureSubpacketVector getHashedSubPackets()
    {
        return createSubpacketVector(sigPck.getHashedSubPackets());
    }

    /**
     * Return the unhashed subpackets of the signature.
     * As unhashed signature subpackets are NOT covered by the signature, an attacker might inject false
     * information after the fact, therefore only "self-authenticating" information from this area can
     * be trusted.
     * Self-authenticating information are for example the {@link org.bouncycastle.bcpg.sig.IssuerKeyID}
     * or {@link org.bouncycastle.bcpg.sig.IssuerFingerprint}, whose authenticity can be confirmed by
     * verifying the signature using the declared key.
     *
     * @return unhashed signature subpackets
     */
    public PGPSignatureSubpacketVector getUnhashedSubPackets()
    {
        return createSubpacketVector(sigPck.getUnhashedSubPackets());
    }

    private PGPSignatureSubpacketVector createSubpacketVector(SignatureSubpacket[] pcks)
    {
        if (pcks != null)
        {
            return new PGPSignatureSubpacketVector(pcks);
        }

        return null;
    }

    /**
     * Return the salt of a v6 signature.
     *
     * @return salt
     */
    byte[] getSalt()
    {
        return sigPck.getSalt();
    }

    /**
     * Return the cryptographic raw signature contained in the OpenPGP signature packet.
     * The value is dependent on the signing algorithm.
     *
     * @return cryptographic signature
     * @throws PGPException
     */
    public byte[] getSignature()
        throws PGPException
    {
        MPInteger[] sigValues = sigPck.getSignature();
        byte[] signature;

        if (sigValues != null)
        {
            if (sigValues.length == 1)    // an RSA signature
            {
                signature = BigIntegers.asUnsignedByteArray(sigValues[0].getValue());
            }
            else if (getKeyAlgorithm() == PublicKeyAlgorithmTags.EDDSA_LEGACY)
            {
                byte[] a = BigIntegers.asUnsignedByteArray(sigValues[0].getValue());
                byte[] b = BigIntegers.asUnsignedByteArray(sigValues[1].getValue());
                if (a.length + b.length > Ed25519.SIGNATURE_SIZE)
                {
                    signature = new byte[Ed448.SIGNATURE_SIZE];
                    System.arraycopy(a, 0, signature, Ed448.PUBLIC_KEY_SIZE - a.length, a.length);
                    System.arraycopy(b, 0, signature, Ed448.SIGNATURE_SIZE - b.length, b.length);
                }
                else
                {
                    signature = new byte[Ed25519.SIGNATURE_SIZE];
                    System.arraycopy(a, 0, signature, Ed25519.PUBLIC_KEY_SIZE - a.length, a.length);
                    System.arraycopy(b, 0, signature, Ed25519.SIGNATURE_SIZE - b.length, b.length);
                }
            }
            else
            {
                try
                {
                    ASN1EncodableVector v = new ASN1EncodableVector();
                    v.add(new ASN1Integer(sigValues[0].getValue()));
                    v.add(new ASN1Integer(sigValues[1].getValue()));

                    signature = new DERSequence(v).getEncoded();
                }
                catch (IOException e)
                {
                    throw new PGPException("exception encoding DSA sig.", e);
                }
            }
        }
        else
        {
            signature = sigPck.getSignatureBytes();
        }

        return signature;
    }

    /**
     * Return the OpenPGP packet encoding of the signature.
     *
     * @return OpenPGP packet encoding
     * @throws IOException
     */
    public byte[] getEncoded()
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        this.encode(bOut);

        return bOut.toByteArray();
    }

    /**
     * Return an encoding of the signature, with trust packets stripped out if forTransfer is true.
     *
     * @param forTransfer if the purpose of encoding is to send key to other users.
     * @return a encoded byte array representing the key.
     * @throws IOException in case of encoding error.
     */
    public byte[] getEncoded(boolean forTransfer)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        this.encode(bOut, forTransfer);

        return bOut.toByteArray();
    }

    /**
     * Encode the signature to an OpenPGP packet stream.
     * This method does not strip out any trust packets.
     *
     * @param outStream packet stream
     * @throws IOException
     */
    public void encode(
        OutputStream outStream)
        throws IOException
    {
        encode(outStream, false);
    }

    /**
     * Encode the signature to outStream, with trust packets stripped out if forTransfer is true.
     *
     * @param outStream   stream to write the key encoding to.
     * @param forTransfer if the purpose of encoding is to send key to other users.
     * @throws IOException in case of encoding error.
     */
    public void encode(
        OutputStream outStream,
        boolean forTransfer)
        throws IOException
    {
        // Exportable signatures MUST NOT be exported if forTransfer==true
        if (forTransfer && (!getHashedSubPackets().isExportable() || !getUnhashedSubPackets().isExportable()))
        {
            return;
        }

        BCPGOutputStream out = BCPGOutputStream.wrap(outStream);

        out.writePacket(sigPck);
        if (!forTransfer && trustPck != null)
        {
            out.writePacket(trustPck);
        }
    }

    /**
     * Return true if the passed in signature type represents a certification, false if the signature type is not.
     *
     * @param signatureType
     * @return true if signatureType is a certification, false otherwise.
     */
    public static boolean isCertification(int signatureType)
    {
        return PGPSignature.DEFAULT_CERTIFICATION == signatureType
            || PGPSignature.NO_CERTIFICATION == signatureType
            || PGPSignature.CASUAL_CERTIFICATION == signatureType
            || PGPSignature.POSITIVE_CERTIFICATION == signatureType;
    }

    public static boolean isRevocation(int signatureType)
    {
        return PGPSignature.KEY_REVOCATION == signatureType
            || PGPSignature.CERTIFICATION_REVOCATION == signatureType
            || PGPSignature.SUBKEY_REVOCATION == signatureType;
    }

    public boolean isHardRevocation()
    {
        if (!isRevocation(getSignatureType()))
        {
            return false; // no revocation
        }

        if (!hasSubpackets())
        {
            return true; // consider missing subpackets (and therefore missing reason) as hard revocation
        }

        // only consider reasons from the hashed packet area
        RevocationReason reason = getHashedSubPackets() != null ?
            getHashedSubPackets().getRevocationReason() : null;
        if (reason == null)
        {
            return true; // missing reason packet is hard
        }

        byte code = reason.getRevocationReason();
        if (code >= 100 && code <= 110)
        {
            // private / experimental reasons are considered hard
            return true;
        }

        // Reason is not from the set of known soft reasons
        return code != RevocationReasonTags.KEY_SUPERSEDED &&
            code != RevocationReasonTags.KEY_RETIRED &&
            code != RevocationReasonTags.USER_NO_LONGER_VALID;
    }

    /**
     * Return true, if the cryptographic signature encoding of the two signatures match.
     *
     * @param sig1 first signature
     * @param sig2 second signature
     * @return true if both signatures contain the same cryptographic signature
     */
    public static boolean isSignatureEncodingEqual(PGPSignature sig1, PGPSignature sig2)
    {
        return Arrays.areEqual(sig1.sigPck.getSignatureBytes(), sig2.sigPck.getSignatureBytes());
    }

    /**
     * Join two copies of the same signature.
     * As an entity might append additional information to an existing signatures unhashed subpacket area
     * (e.g. an embedded {@link #THIRD_PARTY_CONFIRMATION} signature), an implementation might want to
     * join an existing instance of a signature with an updated copy, e.g. retrieved from a key server.
     * This method merges both signature instances by joining unhashed subpackets.
     *
     * @param sig1 first signature
     * @param sig2 second signature
     * @return merged signature
     * @throws PGPException
     */
    public static PGPSignature join(PGPSignature sig1, PGPSignature sig2)
        throws PGPException
    {
        if (sig1.getVersion() < SignaturePacket.VERSION_4)
        {
            // Version 2/3 signatures have no subpackets, so don't need to get merged.
            return sig1;
        }

        if (sig1.getVersion() != sig2.getVersion() ||
            !isSignatureEncodingEqual(sig1, sig2))
        {
            throw new IllegalArgumentException("These are different signatures.");
        }

        // merge unhashed subpackets
        SignatureSubpacket[] sig1Unhashed = sig1.getUnhashedSubPackets().packets;
        SignatureSubpacket[] sig2Unhashed = sig2.getUnhashedSubPackets().packets;
        List<SignatureSubpacket> merged = new ArrayList<SignatureSubpacket>(java.util.Arrays.asList(sig1Unhashed));

        for (int i = 0; i != sig2Unhashed.length; i++)
        {
            SignatureSubpacket subpacket = sig2Unhashed[i];
            boolean found = false;
            for (int j = 0; j != sig1Unhashed.length; j++)
            {
                SignatureSubpacket existing = sig1Unhashed[j];

                if (subpacket.equals(existing))
                {
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                merged.add(subpacket);
            }
        }

        SignatureSubpacket[] unhashed = (SignatureSubpacket[])merged.toArray(new SignatureSubpacket[0]);
        return new PGPSignature(
            new SignaturePacket(
                sig1.getVersion(),
                sig1.sigPck.hasNewPacketFormat(),
                sig1.getSignatureType(),
                sig1.getKeyID(),
                sig1.getKeyAlgorithm(),
                sig1.getHashAlgorithm(),
                sig1.getHashedSubPackets().packets,
                unhashed,
                sig1.getDigestPrefix(),
                sig1.sigPck.getSignature()
            )
        );
    }
}

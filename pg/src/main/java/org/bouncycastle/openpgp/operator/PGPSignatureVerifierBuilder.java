package org.bouncycastle.openpgp.operator;

import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.SignaturePacket;
import org.bouncycastle.bcpg.UserAttributeSubpacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPRuntimeOperationException;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPUserAttributeSubpacketVector;
import org.bouncycastle.util.Strings;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Build signature verifiers for OpenPGP signatures.
 */
public class PGPSignatureVerifierBuilder {

    private final PGPSignature signature;
    private final PGPPublicKey signingKey;
    private final PGPContentVerifierBuilderProvider verifierBuilderProvider;

    public PGPSignatureVerifierBuilder(PGPSignature signature,
                                        PGPPublicKey signingKey,
                                        PGPContentVerifierBuilderProvider verifierBuilderProvider) {
        this.signature = signature;
        this.signingKey = signingKey;
        this.verifierBuilderProvider = verifierBuilderProvider;
    }

    /**
     * Instantiate a signature verifier for a {@link PGPSignature#DIRECT_KEY} signature.
     *
     * @param signedKey key over which the signature was made.
     * @return signature verifier
     * @throws PGPException
     */
    public PGPSignatureVerifier directKeySignature(PGPPublicKey signedKey)
            throws PGPException {
        if (signature.getSignatureType() != PGPSignature.DIRECT_KEY) {
            throw new PGPException("Signature is not a direct-key signature.");
        }

        return keySignature(signedKey);
    }

    /**
     * Instantiate a signature verifier for a {@link PGPSignature#SUBKEY_BINDING} signature.
     *
     * @param primaryKey primary (master) key
     * @param subKey subkey
     * @return signature verifier
     * @throws PGPException
     */
    public PGPSignatureVerifier subkeyBindingSignature(PGPPublicKey primaryKey, PGPPublicKey subKey)
            throws PGPException {
        if (signature.getSignatureType() != PGPSignature.SUBKEY_BINDING) {
            throw new PGPException("Signature is not a subkey binding signature.");
        }

        return keyBindingSignature(primaryKey, subKey);
    }

    /**
     * Instantiate a signature verifier for a {@link PGPSignature#PRIMARYKEY_BINDING} signature.
     *
     * @param primaryKey primary (master) key
     * @param subKey subkey
     * @return signature verifier
     * @throws PGPException
     */
    public PGPSignatureVerifier primaryKeyBindingSignature(PGPPublicKey primaryKey, PGPPublicKey subKey)
            throws PGPException {
        if (signature.getSignatureType() != PGPSignature.PRIMARYKEY_BINDING) {
            throw new PGPException("Signature is not a primary key binding signature.");
        }

        return keyBindingSignature(primaryKey, subKey);
    }

    /**
     * Instantiate a signature verifier for a {@link PGPSignature#KEY_REVOCATION} signature.
     * Note: To verify subkey revocations, use {@link #subKeyRevocationSignature(PGPPublicKey, PGPPublicKey)} instead.
     *
     * @param key revoked key
     * @return signature verifier
     * @throws PGPException
     */
    public PGPSignatureVerifier keyRevocationSignature(PGPPublicKey key) throws PGPException {
        if (signature.getSignatureType() != PGPSignature.KEY_REVOCATION) {
            throw new PGPException("Signature is not a key revocation signature.");
        }

        return keySignature(key);
    }

    /**
     * Instantiate a signature verifier for a {@link PGPSignature#SUBKEY_REVOCATION} signature.
     * @param primaryKey primary (master) key
     * @param subKey revoked subkey
     * @return signature verifier
     * @throws PGPException
     */
    public PGPSignatureVerifier subKeyRevocationSignature(PGPPublicKey primaryKey, PGPPublicKey subKey)
            throws PGPException {
        if (signature.getSignatureType() != PGPSignature.SUBKEY_REVOCATION) {
            throw new PGPException("Signature is not a sub-key revocation signature.");
        }

        return keyBindingSignature(primaryKey, subKey);
    }

    /**
     * Instantiate a signature verifier for user-id certifications.
     *
     * @param userId user-id
     * @param signedKey key that the user-id is bound to
     * @return signature verifier
     * @throws PGPException
     */
    public PGPSignatureVerifier userIdSignature(byte[] userId, PGPPublicKey signedKey)
            throws PGPException {
        if (signature.getSignatureType() != PGPSignature.DEFAULT_CERTIFICATION
                && signature.getSignatureType() != PGPSignature.NO_CERTIFICATION
                && signature.getSignatureType() != PGPSignature.CASUAL_CERTIFICATION
                && signature.getSignatureType() != PGPSignature.POSITIVE_CERTIFICATION) {
            throw new PGPException("Signature is not a certification signature.");
        }

        return userIdSignature(signedKey, userId);
    }

    /**
     * Instantiate a signature verifier for user-id certifications.
     *
     * @param userId user-id
     * @param signedKey key that the user-id is bound to
     * @return signature verifier
     * @throws PGPException
     */
    public PGPSignatureVerifier userIdSignature(String userId, PGPPublicKey signedKey)
            throws PGPException {
        return userIdSignature(toBytes(userId), signedKey);
    }

    /**
     * Instantiate a signature verifier for user-attribute certifications.
     *
     * @param userAttributes user-attributes
     * @param signedKey key that the user-attributes are bound to
     * @return signature verifier
     * @throws PGPException
     */
    public PGPSignatureVerifier userAttributesSignature(PGPUserAttributeSubpacketVector userAttributes, PGPPublicKey signedKey)
            throws PGPException {
        if (signature.getSignatureType() != PGPSignature.DEFAULT_CERTIFICATION
                && signature.getSignatureType() != PGPSignature.NO_CERTIFICATION
                && signature.getSignatureType() != PGPSignature.CASUAL_CERTIFICATION
                && signature.getSignatureType() != PGPSignature.POSITIVE_CERTIFICATION) {
            throw new PGPException("Signature is not a certification signature.");
        }

        return userAttributesSignature(signedKey, toBytes(userAttributes));
    }

    /**
     * Instantiate a signature verifier for a {@link PGPSignature#THIRD_PARTY_CONFIRMATION} signature.
     *
     * @param confirmedSignature the signature that is being confirmed
     * @return signature verifier
     * @throws PGPException
     */
    public PGPSignatureVerifier thirdPartyConfirmationSignature(PGPSignature confirmedSignature)
            throws PGPException {
        if (signature.getSignatureType() != PGPSignature.THIRD_PARTY_CONFIRMATION) {
            throw new PGPException("Signature is not a third-party confirmation signature.");
        }

        return thirdPartyConfirmationSignature(toBytes(confirmedSignature));
    }

    /**
     * Instantiate a signature verifier for a {@link PGPSignature#TIMESTAMP} signature.
     *
     * @return signature verifier
     * @throws PGPException
     */
    public PGPSignatureVerifier timestampSignature() throws PGPException {
        if (signature.getSignatureType() != PGPSignature.TIMESTAMP) {
            throw new PGPException("Signature is not a timestampt signature.");
        }

        return new PGPSignatureVerifier() {
            @Override
            public boolean verify() throws PGPException {
                VersionedPGPSignatureVerifier signatureVerifier = getVerifier();
                return signatureVerifier.verify();
            }
        };
    }

    /**
     * Instantiate a signature verifier for a message signature
     * ({@link PGPSignature#BINARY_DOCUMENT} or {@link PGPSignature#CANONICAL_TEXT_DOCUMENT}).
     *
     * @param message data the signature is made over
     * @return signature verifier
     * @throws PGPException
     */
    public PGPSignatureVerifier messageSignature(byte[] message) throws PGPException {
        if (signature.getSignatureType() != PGPSignature.CANONICAL_TEXT_DOCUMENT
                && signature.getSignatureType() != PGPSignature.BINARY_DOCUMENT) {
            throw new PGPException("Signature is nether of type CANONICAL_TEXT_DOCUMENT, nor of type BINARY_DOCUMENT.");
        }

        return new PGPSignatureVerifier() {
            @Override
            public boolean verify() throws PGPException {
                VersionedPGPSignatureVerifier signatureVerifier = getVerifier();
                signatureVerifier.update(message);
                return signatureVerifier.verify();
            }
        };
    }

    /**
     * Instantiate a signature verifier for a message signature
     * ({@link PGPSignature#BINARY_DOCUMENT} or {@link PGPSignature#CANONICAL_TEXT_DOCUMENT}).
     *
     * @param messageIn input stream containing the data the signature is made over
     * @return signature verifier
     * @throws PGPException
     */
    public PGPSignatureVerifier messageSignature(InputStream messageIn) throws PGPException {
        if (signature.getSignatureType() != PGPSignature.CANONICAL_TEXT_DOCUMENT
                && signature.getSignatureType() != PGPSignature.BINARY_DOCUMENT) {
            throw new PGPException("Signature is nether of type CANONICAL_TEXT_DOCUMENT, nor of type BINARY_DOCUMENT.");
        }

        return new PGPSignatureVerifier() {
            @Override
            public boolean verify() throws PGPException, IOException {
                VersionedPGPSignatureVerifier signatureVerifier = getVerifier();
                byte[] buf = new byte[8192];
                int r;
                while ((r = messageIn.read(buf)) != -1) {
                    signatureVerifier.update(buf, 0, r);
                }
                return signatureVerifier.verify();
            }
        };
    }

    private VersionedPGPSignatureVerifier getVerifier() throws PGPException {
        PGPContentVerifierBuilder verifierBuilder = verifierBuilderProvider.get(
                signature.getKeyAlgorithm(), signature.getHashAlgorithm());

        PGPContentVerifier contentVerifier = verifierBuilder.build(signingKey);

        return VersionedPGPSignatureVerifier.getVerifier(
                signature, contentVerifier);
    }

    private PGPSignatureVerifier keyBindingSignature(PGPPublicKey primaryKey, PGPPublicKey subKey) {
        return new PGPSignatureVerifier() {
            @Override
            public boolean verify() throws PGPException {
                VersionedPGPSignatureVerifier signatureVerifier = getVerifier();
                signatureVerifier.updateWithPublicKey(toBytes(primaryKey));
                signatureVerifier.updateWithPublicKey(toBytes(subKey));
                return signatureVerifier.verify();
            }
        };
    }

    private PGPSignatureVerifier keySignature(PGPPublicKey key) {
        return new PGPSignatureVerifier() {
            @Override
            public boolean verify() throws PGPException {
                VersionedPGPSignatureVerifier signatureVerifier = getVerifier();
                signatureVerifier.updateWithPublicKey(toBytes(key));
                return signatureVerifier.verify();
            }
        };
    }

    private PGPSignatureVerifier userIdSignature(PGPPublicKey key, byte[] userData) {
        return new PGPSignatureVerifier() {
            @Override
            public boolean verify() throws PGPException {
                VersionedPGPSignatureVerifier signatureVerifier = getVerifier();
                signatureVerifier.updateWithPublicKey(toBytes(key));
                signatureVerifier.updateWithUserId(userData);
                return signatureVerifier.verify();
            }
        };
    }

    private PGPSignatureVerifier userAttributesSignature(PGPPublicKey key, byte[] userAttributes) {
        return new PGPSignatureVerifier() {
            @Override
            public boolean verify() throws PGPException {
                VersionedPGPSignatureVerifier signatureVerifier = getVerifier();
                signatureVerifier.updateWithPublicKey(toBytes(key));
                signatureVerifier.updateWithUserAttributes(userAttributes);
                return signatureVerifier.verify();
            }
        };
    }

    private PGPSignatureVerifier thirdPartyConfirmationSignature(byte[] confirmedSignature) {
        return new PGPSignatureVerifier() {
            @Override
            public boolean verify() throws PGPException {
                VersionedPGPSignatureVerifier signatureVerifier = getVerifier();
                signatureVerifier.updateWithThirdPartySignature(confirmedSignature);
                return signatureVerifier.verify();
            }
        };
    }

    private static byte[] toBytes(PGPPublicKey key) {
        try {
            return key.getPublicKeyPacket().getEncodedContents();
        } catch (IOException e) {
            throw new PGPRuntimeOperationException("exception preparing key.", e);
        }
    }

    private static byte[] toBytes(String userId) {
        return Strings.toUTF8ByteArray(userId);
    }

    private static byte[] toBytes(PGPUserAttributeSubpacketVector userAttributes) {
        try {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            UserAttributeSubpacket[] packets = userAttributes.toSubpacketArray();
            for (int i = 0; i != packets.length; i++) {
                packets[i].encode(bOut);
            }
            return bOut.toByteArray();
        } catch (IOException e) {
            throw new PGPRuntimeOperationException("cannot encode subpacket array", e);
        }
    }

    private static byte[] toBytes(PGPSignature signature) {
        try {
            return encodeSignatureWithoutUnhashedData(signature);
        } catch (IOException e) {
            throw new PGPRuntimeOperationException("cannot encode signature", e);
        }
    }

    private static byte[] encodeSignatureWithoutUnhashedData(PGPSignature signature) throws IOException {
        SignaturePacket packet = signature.getSignaturePacket();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut = new BCPGOutputStream(bOut);

        int version = packet.getVersion();
        pOut.write(version);

        if (version == 3 || version == 2)
        {
            pOut.write(5); // the length of the next block

            long    time = packet.getCreationTime() / 1000;

            pOut.write(packet.getSignatureType());
            pOut.write((byte)(time >> 24));
            pOut.write((byte)(time >> 16));
            pOut.write((byte)(time >> 8));
            pOut.write((byte)time);

            long keyID = packet.getKeyID();
            pOut.write((byte)(keyID >> 56));
            pOut.write((byte)(keyID >> 48));
            pOut.write((byte)(keyID >> 40));
            pOut.write((byte)(keyID >> 32));
            pOut.write((byte)(keyID >> 24));
            pOut.write((byte)(keyID >> 16));
            pOut.write((byte)(keyID >> 8));
            pOut.write((byte)(keyID));

            pOut.write(packet.getKeyAlgorithm());
            pOut.write(packet.getHashAlgorithm());
        }
        else if (version == 4)
        {
            pOut.write(packet.getSignatureType());
            pOut.write(packet.getKeyAlgorithm());
            pOut.write(packet.getHashAlgorithm());

            ByteArrayOutputStream    sOut = new ByteArrayOutputStream();

            for (int i = 0; i != packet.getHashedSubPackets().length; i++)
            {
                packet.getHashedSubPackets()[i].encode(sOut);
            }

            byte[]                   data = sOut.toByteArray();

            pOut.write(data.length >> 8);
            pOut.write(data.length);
            pOut.write(data);

            // Do not include unhashed data
            pOut.write(0);
            pOut.write(0);
        }
        else
        {
            throw new IOException("unknown version: " + version);
        }

        pOut.write(packet.getFingerPrint());

        if (packet.getSignature() != null)
        {
            for (int i = 0; i != packet.getSignature().length; i++)
            {
                pOut.writeObject(packet.getSignature()[i]);
            }
        }
        else
        {
            pOut.write(packet.getSignatureBytes());
        }

        pOut.close();

        ByteArrayOutputStream sigOut = new ByteArrayOutputStream();
        byte[] sigEncoding = bOut.toByteArray();

        // We need the old format
        BCPGOutputStream bSigOut = new BCPGOutputStream(sigOut, PacketTags.SIGNATURE, sigEncoding.length, true);
        bSigOut.write(sigEncoding);
        bSigOut.close();

        return sigOut.toByteArray();
    }
}

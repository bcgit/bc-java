package org.bouncycastle.openpgp.operator;

import org.bouncycastle.bcpg.UnsupportedPacketVersionException;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPRuntimeOperationException;
import org.bouncycastle.openpgp.PGPSignature;

import java.io.IOException;
import java.io.OutputStream;

/**
 * OpenPGP signature-verifier that allows different data-encoding schemes for different signature versions.
 */
abstract class VersionedPGPSignatureVerifier {

    protected final PGPContentVerifier contentVerifier;
    protected final OutputStream sigOut;
    protected byte lastb;
    protected final PGPSignature signature;

    VersionedPGPSignatureVerifier(PGPContentVerifier contentVerifier, PGPSignature signature) {
        this.signature = signature;
        this.contentVerifier = contentVerifier;
        sigOut = contentVerifier.getOutputStream();
        lastb = 0;
    }

    /**
     * Get a signature verifier instance for the given signature.
     *
     * @param signature OpenPGP signature to verify
     * @param contentVerifier OpenPGP content verifier
     * @return versioned signature verifier
     */
    static VersionedPGPSignatureVerifier getVerifier(PGPSignature signature, PGPContentVerifier contentVerifier) {
        switch (signature.getVersion()) {
            case PGPSignature.VERSION_3:
                return new VersionedPGPSignatureVerifier.V3(contentVerifier, signature);

            case PGPSignature.VERSION_4:
                return new VersionedPGPSignatureVerifier.V4(contentVerifier, signature);

            case PGPSignature.VERSION_5:
                return new VersionedPGPSignatureVerifier.V5(contentVerifier, signature);

            case PGPSignature.VERSION_6:
                return new VersionedPGPSignatureVerifier.V6(contentVerifier, signature);

            default:
                throw new UnsupportedPacketVersionException("Unsupported PGP signature version: " + signature);
        }
    }

    /**
     * Update the signature verifier with public key data.
     *
     * @param key encoded public key
     */
    abstract void updateWithPublicKey(byte[] key);

    /**
     * Update the signature verifier with user-id data.
     *
     * @param rawUserId UTF8 encoded user-id
     */
    abstract void updateWithUserId(byte[] rawUserId);

    /**
     * Update the signature verifier with user-attribute data.
     *
     * @param userAttributesBytes encoded user-attributes
     */
    abstract void updateWithUserAttributes(byte[] userAttributesBytes);

    /**
     * Update the signature verifier with a third-party signature.
     *
     * @param confirmedSignature encoded signature which gets confirmed.
     */
    abstract void updateWithThirdPartySignature(byte[] confirmedSignature);

    /**
     * Update the signature verifier with a 4-octet-length-prefixed byte array.
     *
     * @param data bytes
     */
    void updateWith4OctetsLengthAndData(byte[] data) {
        this.update((byte)(data.length >> 24));
        this.update((byte)(data.length >> 16));
        this.update((byte)(data.length >> 8));
        this.update((byte)(data.length));
        this.update(data);
    }

    /**
     * Signature verifier for version 3 signatures.
     */
    static class V3 extends VersionedPGPSignatureVerifier {

        V3(PGPContentVerifier contentVerifier, PGPSignature signature) {
            super(contentVerifier, signature);
        }

        @Override
        void updateWithPublicKey(byte[] keyBody) {
            throw new UnsupportedPacketVersionException("OpenPGP v3 does not specify key-signatures.");
        }

        @Override
        void updateWithUserId(byte[] rawUserId) {
            this.update(rawUserId);
        }

        @Override
        void updateWithUserAttributes(byte[] idBytes) {
            this.update(idBytes);
        }

        @Override
        void updateWithThirdPartySignature(byte[] confirmedSignature) {
            throw new UnsupportedPacketVersionException("OpenPGP v3 does not specify third-party confirmation signatures.");
        }
    }

    /**
     * Signature verifier for version 4 signature.
     */
    static class V4 extends VersionedPGPSignatureVerifier {

        V4(PGPContentVerifier contentVerifier, PGPSignature signature) {
            super(contentVerifier, signature);
        }

        @Override
        void updateWithPublicKey(byte[] keyBody) {
            this.update((byte) 0x99);
            this.update((byte) (keyBody.length >> 8));
            this.update((byte) (keyBody.length));
            this.update(keyBody);
        }

        @Override
        void updateWithUserId(byte[] idBytes) {
            this.update((byte) 0xb4);
            updateWith4OctetsLengthAndData(idBytes);
        }

        @Override
        void updateWithUserAttributes(byte[] idBytes) {
            this.update((byte) 0xd1);
            updateWith4OctetsLengthAndData(idBytes);
        }

        @Override
        void updateWithThirdPartySignature(byte[] confirmedSignature) {
            this.update((byte) 0x88);
            updateWith4OctetsLengthAndData(confirmedSignature);
        }
    }

    /**
     * Signature verifier for version 5 signatures.
     */
    static class V5 extends VersionedPGPSignatureVerifier {

        V5(PGPContentVerifier contentVerifier, PGPSignature signature) {
            super(contentVerifier, signature);
        }

        @Override
        void updateWithPublicKey(byte[] keyBody) {
            this.update((byte) 0x9a);
            updateWith4OctetsLengthAndData(keyBody);
        }

        @Override
        void updateWithUserId(byte[] idBytes) {
            this.update((byte) 0xb4);
            updateWith4OctetsLengthAndData(idBytes);
        }

        @Override
        void updateWithUserAttributes(byte[] idBytes) {
            this.update((byte) 0xd1);
            updateWith4OctetsLengthAndData(idBytes);
        }

        @Override
        void updateWithThirdPartySignature(byte[] confirmedSignature) {
            this.update((byte) 0x88);
            updateWith4OctetsLengthAndData(confirmedSignature);
        }
    }

    /**
     * Signature verifier for version 6 signatures.
     */
    static class V6 extends VersionedPGPSignatureVerifier {

        V6(PGPContentVerifier contentVerifier, PGPSignature signature) {
            super(contentVerifier, signature);
        }

        @Override
        void updateWithPublicKey(byte[] keyBody) {
            // this.update(signature.getSalt());
            this.update((byte) 0x9b);
            updateWith4OctetsLengthAndData(keyBody);
        }

        @Override
        void updateWithUserId(byte[] idBytes) {
            this.update((byte) 0xb4);
            updateWith4OctetsLengthAndData(idBytes);
        }

        @Override
        void updateWithUserAttributes(byte[] idBytes) {
            this.update((byte) 0xd1);
            updateWith4OctetsLengthAndData(idBytes);
        }

        @Override
        void updateWithThirdPartySignature(byte[] confirmedSignature) {
            // this.update(signature.getSalt());
            this.update((byte) 0x88);
            updateWith4OctetsLengthAndData(confirmedSignature);
        }
    }

    /**
     * Update the verifier with a single byte.
     * If the signature type is {@link PGPSignature#CANONICAL_TEXT_DOCUMENT}, line endings need to be converted
     * to <pre>CR-LF</pre>, which this method takes care of.
     *
     * @param b byte
     */
    void update(
            byte b)
    {
        if (signature.getSignatureType() != PGPSignature.CANONICAL_TEXT_DOCUMENT) {
            byteUpdate(b);
            return;
        }

        if (b == '\r')
        {
            byteUpdate((byte)'\r');
            byteUpdate((byte)'\n');
        }
        else if (b == '\n')
        {
            if (lastb != '\r')
            {
                byteUpdate((byte)'\r');
                byteUpdate((byte)'\n');
            }
        }
        else
        {
            byteUpdate(b);
        }

        lastb = b;
    }

    /**
     * Update the signature verifier with an array of bytes.
     *
     * @param bytes bytes
     */
    void update(
            byte[] bytes)
    {
        this.update(bytes, 0, bytes.length);
    }

    /**
     * Update the signature verifier with an array of bytes.
     *
     * @param bytes bytes
     * @param off offset
     * @param length length
     */
    void update(
            byte[] bytes,
            int off,
            int length)
    {
        if (signature.getSignatureType() != PGPSignature.CANONICAL_TEXT_DOCUMENT) {
            blockUpdate(bytes, off, length);
            return;
        }

        int finish = off + length;

        for (int i = off; i != finish; i++)
        {
            this.update(bytes[i]);
        }
    }

    /**
     * Update the signature verifier with a single byte without taking care for converted line endings.
     *
     * @param b byte
     */
    void byteUpdate(byte b)
    {
        try
        {
            sigOut.write(b);
        }
        catch (IOException e)
        {
            throw new PGPRuntimeOperationException(e.getMessage(), e);
        }
    }

    /**
     * Update the signature verifier with an array of bytes without taking care for converted line endings.
     *
     * @param block bytes
     * @param off offset
     * @param len length
     */
    void blockUpdate(byte[] block, int off, int len)
    {
        try
        {
            sigOut.write(block, off, len);
        }
        catch (IOException e)
        {
            throw new PGPRuntimeOperationException(e.getMessage(), e);
        }
    }

    /**
     * Update the signature verifier with the signatures trailer and finalize the verification by checking for
     * signature correctness.
     *
     * @return <pre>true</pre> if the signature is correct, <pre>false</pre> otherwise
     * @throws PGPException
     */
    boolean verify()
            throws PGPException
    {
        addTrailer();

        return contentVerifier.verify(signature.getSignature());
    }

    /**
     * Update the signature verifier with the signatures trailer and close the verifier stream.
     */
    private void addTrailer()
    {
        try
        {
            sigOut.write(signature.getSignatureTrailer());

            sigOut.close();
        }
        catch (IOException e)
        {
            throw new PGPRuntimeOperationException(e.getMessage(), e);
        }
    }
}

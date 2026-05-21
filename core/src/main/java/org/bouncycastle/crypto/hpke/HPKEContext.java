package org.bouncycastle.crypto.hpke;

import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * An HPKE encryption / decryption context produced by one of the
 * {@code HPKE.setup*R} (recipient) factory methods, or &mdash; via the
 * {@link HPKEContextWithEncapsulation} subclass &mdash; by one of the
 * {@code HPKE.setup*S} (sender) factories.
 * <p>
 * The context is stateful: each {@link #seal(byte[], byte[])} /
 * {@link #open(byte[], byte[])} call advances an internal sequence number that
 * is XOR-mixed into the AEAD nonce per RFC 9180 &sect;5.2, allowing a single
 * context to encrypt or decrypt many messages in order without nonce reuse.
 * {@link #export(byte[], int)} derives auxiliary key material from the
 * exporter secret and is deterministic &mdash; repeated calls with the same
 * {@code (exporterContext, L)} return the same bytes.
 * <p>
 * Senders should use {@link HPKEContextWithEncapsulation#getEncapsulation}
 * to obtain the {@code enc} octet string that must be transmitted alongside
 * the first ciphertext so the receiver can run the matching {@code setup*R}.
 */
public class HPKEContext
{
    protected final AEAD aead;
    protected final HKDF hkdf;
    protected final byte[] exporterSecret;
    protected final byte[] suiteId;

    HPKEContext(AEAD aead, HKDF hkdf, byte[] exporterSecret, byte[] suiteId)
    {
        this.aead = aead;
        this.hkdf = hkdf;
        this.exporterSecret = exporterSecret;
        this.suiteId = suiteId;
    }

    public byte[] export(byte[] exportContext, int L)
    {
        return hkdf.LabeledExpand(exporterSecret, suiteId, "sec", exportContext, L);
    }

    public byte[] seal(byte[] aad, byte[] message)
        throws InvalidCipherTextException
    {
        return aead.seal(aad, message);
    }

    public byte[] seal(byte[] aad, byte[] pt, int ptOffset, int ptLength)
        throws InvalidCipherTextException
    {
        return aead.seal(aad, pt, ptOffset, ptLength);
    }

    public byte[] open(byte[] aad, byte[] ct)
        throws InvalidCipherTextException
    {
        return aead.open(aad, ct);
    }

    public byte[] open(byte[] aad, byte[] ct, int ctOffset, int ctLength)
        throws InvalidCipherTextException
    {
        return aead.open(aad, ct, ctOffset, ctLength);
    }

    public byte[] extract(byte[] salt, byte[] ikm)
    {
        return hkdf.Extract(salt, ikm);
    }

    public byte[] expand(byte[] prk, byte[] info, int L)
    {
        return hkdf.Expand(prk, info, L);
    }
}

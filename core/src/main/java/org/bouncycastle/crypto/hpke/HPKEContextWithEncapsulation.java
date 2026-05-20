package org.bouncycastle.crypto.hpke;

import org.bouncycastle.util.Arrays;

/**
 * Sender-side {@link HPKEContext} that additionally carries the {@code enc}
 * octet string produced by the KEM's encapsulation step.
 * <p>
 * Returned by {@code HPKE.setupBaseS} / {@code SetupPSKS} /
 * {@code setupAuthS} / {@code setupAuthPSKS}. The recipient never produces
 * this subclass &mdash; the recipient already has the {@code enc} as input to
 * the matching {@code setup*R} call.
 * <p>
 * {@link #getEncapsulation()} returns a defensive copy of the encapsulated
 * key for transmission to the recipient (typically prepended to the first
 * ciphertext or carried in a wire-format wrapper such as MLS or OHTTP).
 */
public class HPKEContextWithEncapsulation
    extends HPKEContext
{
    final byte[] encapsulation;

    public HPKEContextWithEncapsulation(HPKEContext context, byte[] encapsulation)
    {
        super(context.aead, context.hkdf, context.exporterSecret, context.suiteId);
        this.encapsulation = encapsulation;
    }

    public byte[] getEncapsulation()
    {
        return Arrays.clone(encapsulation);
    }
}

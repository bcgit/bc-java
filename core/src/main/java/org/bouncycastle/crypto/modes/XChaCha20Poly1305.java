package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.XChaCha20Engine;
import org.bouncycastle.crypto.macs.Poly1305;

/**
 * XChaCha20-Poly1305 AEAD construction as described in
 * draft-irtf-cfrg-xchacha-03 sec. 2.4.
 * <p>
 * Identical to {@link ChaCha20Poly1305} except that the underlying stream
 * cipher is {@link XChaCha20Engine} (192 bit nonce instead of 96 bit). The
 * extended nonce makes random-nonce strategies safe at scale: with a 192
 * bit nonce, collisions remain negligibly likely up to 2^80 messages per
 * key, removing the per-key counter / deterministic-nonce constraint that
 * standard ChaCha20-Poly1305 imposes.
 */
public class XChaCha20Poly1305
    extends ChaCha20Poly1305
{
    public XChaCha20Poly1305()
    {
        this(new Poly1305());
    }

    public XChaCha20Poly1305(Mac poly1305)
    {
        super(poly1305, new XChaCha20Engine(), 24);
    }

    public String getAlgorithmName()
    {
        return "XChaCha20Poly1305";
    }
}

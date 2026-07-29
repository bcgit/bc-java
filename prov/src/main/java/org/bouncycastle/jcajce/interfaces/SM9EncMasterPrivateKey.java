package org.bouncycastle.jcajce.interfaces;

import java.security.PrivateKey;

/**
 * Interface for an SM9 (GM/T 0044) encryption master private key, the KGC-held
 * root of the identity-based scheme. User key pairs are derived through the
 * {@link SM9EncUserKeyGenerator} extraction method with an explicit hid - the one
 * encryption master key serves KEM / public-key encryption (hid = 0x03) and
 * key exchange (hid = 0x02), the KGC's published hid distinguishing them.
 */
public interface SM9EncMasterPrivateKey
    extends PrivateKey, SM9EncUserKeyGenerator
{
}

package org.bouncycastle.jcajce.interfaces;

import java.security.PrivateKey;

/**
 * Interface for an SM9 (GM/T 0044) signature master private key, the KGC-held
 * root of the identity-based scheme. User key pairs are derived through the
 * {@link SM9SigUserKeyGenerator} extraction method (hid = 0x01 applied
 * internally, GM/T 0044.2).
 */
public interface SM9SigMasterPrivateKey
    extends PrivateKey, SM9SigUserKeyGenerator
{
}

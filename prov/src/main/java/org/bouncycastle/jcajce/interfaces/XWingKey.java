package org.bouncycastle.jcajce.interfaces;

import java.security.Key;

/**
 * Base interface for the keys of X-Wing, the X25519 and ML-KEM-768 hybrid KEM of
 * draft-connolly-cfrg-xwing-kem. X-Wing has a single parameter set, so there is no parameter spec to
 * return; the interface marks the key type.
 */
public interface XWingKey
    extends Key
{
}

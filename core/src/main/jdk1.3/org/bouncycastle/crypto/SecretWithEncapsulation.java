package org.bouncycastle.crypto;

import javax.security.auth.DestroyFailedException;

/**
 * Interface describing secret with encapsulation details.
 */
public interface SecretWithEncapsulation
{
// Destroyable methods (javax.security.auth.Destroyable is a 1.4 API; the jce/src backport
// supplies Destroyable/DestroyFailedException for the 1.3 build). destroy() declares the same
// checked exception as the base so callers' catch (DestroyFailedException) stays reachable.
    void destroy()
        throws DestroyFailedException;
    boolean isDestroyed();

    /**
     * Return the secret associated with the encapsulation.
     *
     * @return the secret the encapsulation is for.
     */
    byte[] getSecret();

    /**
     * Return the data that carries the secret in its encapsulated form.
     *
     * @return the encapsulation of the secret.
     */
    byte[] getEncapsulation();
}

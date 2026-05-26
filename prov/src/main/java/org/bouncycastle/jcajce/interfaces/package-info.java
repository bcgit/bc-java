/**
 * JCA-style key interfaces specific to BC's provider — e.g. {@code BCFKSKey},
 * {@code MLDSAKey}, {@code XDHKey} — letting callers downcast a {@link java.security.Key}
 * from {@code KeyFactory.getInstance(..., "BC")} into the algorithm-specific accessor
 * shape without depending on the concrete implementation classes.
 */
package org.bouncycastle.jcajce.interfaces;

/**
 * Operators binding the high-level OpenPGP API to key material held outside the OpenPGP key -
 * typically on a hardware token - per draft-dkg-openpgp-external-secrets. The session-key recovery
 * flow lives here expressed over byte-level primitives; the {@code bc} and {@code jcajce}
 * subpackages bind those primitives to a crypto stack.
 */
package org.bouncycastle.openpgp.api.operator;

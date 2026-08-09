/**
 * Software simulation of an OpenPGP smart card, for exercising the
 * {@link org.bouncycastle.openpgp.smartcard} API without hardware.
 * <p>
 * <b>Test and development use only</b> - the simulated card holds its "protected" private keys in the
 * heap of the calling process and will hand them back on request. It provides none of the isolation that
 * is the entire point of a real token.
 */
package org.bouncycastle.openpgp.smartcard.simulator;

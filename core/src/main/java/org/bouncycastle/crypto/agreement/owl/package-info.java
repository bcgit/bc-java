/**
 * Support classes for the Owl augmented PAKE (Hao, Bag, Chen, Lopez 2024).
 * <p>
 * Owl is an academic protocol — not (yet) an IETF standard. It extends J-PAKE with explicit
 * user-registration and key-confirmation phases. Users wanting a standardised PAKE should
 * prefer the existing J-PAKE in {@link org.bouncycastle.crypto.agreement.jpake} /
 * {@code org.bouncycastle.crypto.agreement.ecjpake}.
 */
package org.bouncycastle.crypto.agreement.owl;

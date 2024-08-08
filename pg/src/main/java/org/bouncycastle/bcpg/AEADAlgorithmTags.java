package org.bouncycastle.bcpg;

/**
 * AEAD Algorithm IDs.
 * RFC9580 (OpenPGP) defines IDs 1 through 3, while LibrePGP only defines 1 and 2.
 * Further, the use of AEAD differs between OpenPGP and LibrePGP.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-aead-algorithms">
 *     OpenPGP - AEAD Algorithms</a>
 * @see <a href="https://www.ietf.org/archive/id/draft-koch-librepgp-00.html#name-encryption-modes">
 *     LibrePGP - Encryption Modes</a>
 */
public interface AEADAlgorithmTags
{
    /**
     * EAX with 16-bit nonce/IV and 16-bit auth tag length.
     */
    int EAX = 1;
    /**
     * OCB with 15-bit nonce/IV and 16-bit auth tag length.
     * RFC9580-compliant implementations MUST implement OCB.
     */
    int OCB = 2;
    /**
     * GCM with 12-bit nonce/IV and 16-bit auth tag length.
     * OpenPGP only.
     */
    int GCM = 3;

    // 100 to 110: Experimental algorithms
}

package org.bouncycastle.bcpg;

/**
 * AEAD Algorithm IDs.
 * Crypto-Refresh (OpenPGP) defines IDs 1 through 3, while LibrePGP only defines 1 and 2.
 * Further, the use of AEAD differs between C-R and LibrePGP.
 *
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-13.html#name-aead-algorithms">
 *     Crypto-Refresh: AEAD Algorithms</a>
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
     * C-R compliant implementations MUST implement OCB.
     */
    int OCB = 2;
    /**
     * GCM with 12-bit nonce/IV and 16-bit auth tag length.
     * OpenPGP only.
     */
    int GCM = 3;

    // 100 to 110: Experimental algorithms
}

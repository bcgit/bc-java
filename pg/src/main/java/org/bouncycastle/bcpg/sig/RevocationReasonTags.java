package org.bouncycastle.bcpg.sig;

/**
 * Revocation reason tags.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.23">
 *     RFC4880 - Reason for Revocation</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-reason-for-revocation">
 *     RFC9580 - Reason for Revocation</a>
 */
public interface RevocationReasonTags
{
    byte NO_REASON = 0;              // No reason specified (key revocations or cert revocations)
    byte KEY_SUPERSEDED = 1;         // Key is superseded (key revocations)
    byte KEY_COMPROMISED = 2;        // Key material has been compromised (key revocations)
    byte KEY_RETIRED = 3;            // Key is retired and no longer used (key revocations)
    byte USER_NO_LONGER_VALID = 32;  // User ID information is no longer valid (cert revocations)

    // 100-110 - Private Use
}

package org.bouncycastle.bcpg.sig;

public interface RevocationReasonTags
{
    byte NO_REASON = 0;              // No reason specified (key revocations or cert revocations)
    byte KEY_SUPERSEDED = 1;         // Key is superseded (key revocations)
    byte KEY_COMPROMISED = 2;        // Key material has been compromised (key revocations)
    byte KEY_RETIRED = 3;            // Key is retired and no longer used (key revocations)
    byte USER_NO_LONGER_VALID = 32;  // User ID information is no longer valid (cert revocations)

    // 100-110 - Private Use
}

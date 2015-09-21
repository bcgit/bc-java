package org.bouncycastle.openpgp.wot;

public interface TrustConst
{
    int TRUST_RECORD_LEN = 40;
    int SIGS_PER_RECORD = (TRUST_RECORD_LEN - 10) / 5;
    int ITEMS_PER_HTBL_RECORD = (TRUST_RECORD_LEN - 2) / 4;
    int ITEMS_PER_HLST_RECORD = (TRUST_RECORD_LEN - 6) / 5;
    int ITEMS_PER_PREF_RECORD = TRUST_RECORD_LEN - 10;
    int MAX_LIST_SIGS_DEPTH = 20;
    int MAX_CACHE_SIZE = 1024 * 1024;

    int TRUST_MASK = 15;
    /** o: not yet calculated/assigned */
    int TRUST_UNKNOWN = 0;
    // /** e: calculation may be invalid */
    // int TRUST_EXPIRED = 1; // unused?! gnupg seems to never assign this value...
    /** q: not enough information for calculation */
    int TRUST_UNDEFINED = 2;
    /** n: never trust this pubkey */
    int TRUST_NEVER = 3;
    /** m: marginally trusted */
    int TRUST_MARGINAL = 4;
    /** f: fully trusted */
    int TRUST_FULL = 5;
    /** u: ultimately trusted */
    int TRUST_ULTIMATE = 6;

    // BEGIN trust values not covered by the mask
    /** r: revoked */
    int TRUST_FLAG_REVOKED = 32;
    /** r: revoked but for subkeys */
    int TRUST_FLAG_SUB_REVOKED = 64;
    /** d: key/uid disabled */
    int TRUST_FLAG_DISABLED = 128;
    /** a check-trustdb is pending */
    int TRUST_FLAG_PENDING_CHECK = 256;
    // END trust values not covered by the mask
}

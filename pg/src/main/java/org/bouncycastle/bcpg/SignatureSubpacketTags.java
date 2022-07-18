package org.bouncycastle.bcpg;

/**
 * Basic PGP signature sub-packet tag types.
 */
public interface SignatureSubpacketTags 
{
    int CREATION_TIME = 2;         // signature creation time
    int EXPIRE_TIME = 3;           // signature expiration time
    int EXPORTABLE = 4;            // exportable certification
    int TRUST_SIG = 5;             // trust signature
    int REG_EXP = 6;               // regular expression
    int REVOCABLE = 7;             // revocable
    int KEY_EXPIRE_TIME = 9;       // key expiration time
    int PLACEHOLDER = 10;          // placeholder for backward compatibility
    int PREFERRED_SYM_ALGS = 11;   // preferred symmetric algorithms
    int REVOCATION_KEY = 12;       // revocation key
    int ISSUER_KEY_ID = 16;        // issuer key ID
    int NOTATION_DATA = 20;        // notation data
    int PREFERRED_HASH_ALGS = 21;  // preferred hash algorithms
    int PREFERRED_COMP_ALGS = 22;  // preferred compression algorithms
    int KEY_SERVER_PREFS = 23;     // key server preferences
    int PREFERRED_KEY_SERV = 24;   // preferred key server
    int PRIMARY_USER_ID = 25;      // primary user id
    int POLICY_URL = 26;           // policy URL
    int KEY_FLAGS = 27;            // key flags
    int SIGNER_USER_ID = 28;       // signer's user id
    int REVOCATION_REASON = 29;    // reason for revocation
    int FEATURES = 30;             // features
    int SIGNATURE_TARGET = 31;     // signature target
    int EMBEDDED_SIGNATURE = 32;   // embedded signature
    int ISSUER_FINGERPRINT = 33;   // issuer key fingerprint
//  public static final int PREFERRED_AEAD_ALGORITHMS = 34; // RESERVED since crypto-refresh-05
int INTENDED_RECIPIENT_FINGERPRINT = 35;   // intended recipient fingerprint
    int ATTESTED_CERTIFICATIONS = 37;   // attested certifications (RESERVED)
    int KEY_BLOCK = 38;            // Key Block (RESERVED)
    int PREFERRED_AEAD_ALGORITHMS = 39;   // preferred AEAD algorithms
}

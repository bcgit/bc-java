package org.bouncycastle.bcpg;

/**
 * Basic PGP packet tag types.
 */
public interface PacketTags 
{
      int RESERVED =  0 ;                //  Reserved - a packet tag must not have this value
      int PUBLIC_KEY_ENC_SESSION = 1;    // Public-Key Encrypted Session Key Packet
      int SIGNATURE = 2;                 // Signature Packet
      int SYMMETRIC_KEY_ENC_SESSION = 3; // Symmetric-Key Encrypted Session Key Packet
      int ONE_PASS_SIGNATURE = 4 ;       // One-Pass Signature Packet
      int SECRET_KEY = 5;                // Secret Key Packet
      int PUBLIC_KEY = 6 ;               // Public Key Packet
      int SECRET_SUBKEY = 7;             // Secret Subkey Packet
      int COMPRESSED_DATA = 8;           // Compressed Data Packet
      int SYMMETRIC_KEY_ENC = 9;         // Symmetrically Encrypted Data Packet
      int MARKER = 10;                   // Marker Packet
      int LITERAL_DATA = 11;             // Literal Data Packet
      int TRUST = 12;                    // Trust Packet
      int USER_ID = 13;                  // User ID Packet
      int PUBLIC_SUBKEY = 14;            // Public Subkey Packet
      int USER_ATTRIBUTE = 17;           // User attribute
      int SYM_ENC_INTEGRITY_PRO = 18;    // Symmetric encrypted, integrity protected
      int MOD_DETECTION_CODE = 19;       // Modification detection code
      int AEAD_ENC_DATA = 20;            // AEAD Encrypted Data (seems deprecated)
      int PADDING = 21;                  // Padding Packet
      
      int EXPERIMENTAL_1 = 60;           // Private or Experimental Values
      int EXPERIMENTAL_2 = 61;
      int EXPERIMENTAL_3 = 62;
      int EXPERIMENTAL_4 = 63;
}

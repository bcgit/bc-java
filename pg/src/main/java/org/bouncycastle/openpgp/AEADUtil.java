package org.bouncycastle.openpgp;

import org.bouncycastle.bcpg.AEADUtils;
import org.bouncycastle.bcpg.SymmetricKeyUtils;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

class AEADUtil
{
    /**
     * Derive a message key and IV from the given session key.
     * The result is a byte array containing the key bytes followed by the IV.
     * To split them, use {@link #org.bouncycastle.bcpg.AEADUtils.splitMessageKeyAndIv(byte[], int, int)}.
     *
     * @param aeadAlgo   AEAD algorithm
     * @param cipherAlgo symmetric cipher algorithm
     * @param sessionKey session key
     * @param salt       salt
     * @param hkdfInfo   HKDF info
     * @return message key and appended IV
     * @throws PGPException
     */
    static byte[] deriveMessageKeyAndIv(int aeadAlgo, int cipherAlgo, byte[] sessionKey, byte[] salt, byte[] hkdfInfo)
        throws PGPException
    {
        // Is it okay to have this common logic be implemented using BCs lightweight API?
        // Should we move it to BcAEADUtil instead and also provide a JCE implementation?
        HKDFParameters hkdfParameters = new HKDFParameters(sessionKey, salt, hkdfInfo);
        HKDFBytesGenerator hkdfGen = new HKDFBytesGenerator(new SHA256Digest());

        hkdfGen.init(hkdfParameters);
        int keyLen = SymmetricKeyUtils.getKeyLengthInOctets(cipherAlgo);
        int ivLen = AEADUtils.getIVLength(aeadAlgo);
        byte[] messageKeyAndIv = new byte[keyLen + ivLen - 8];
        hkdfGen.generateBytes(messageKeyAndIv, 0, messageKeyAndIv.length);
        return messageKeyAndIv;
    }
}

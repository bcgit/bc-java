package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.util.Pack;

/**
 * Support class for constructing integrated encryption ciphers
 * for doing basic message exchanges on top of key agreement ciphers.
 * Follows the description given in IEEE Std 1363a.
 */
public class OldIESEngine
    extends IESEngine
{
    /**
     * set up for use with stream mode, where the key derivation function
     * is used to provide a stream of bytes to xor with the message.
     *
     * @param agree the key agreement used as the basis for the encryption
     * @param kdf   the key derivation function used for byte generation
     * @param mac   the message authentication code generator for the message
     */
    public OldIESEngine(
        BasicAgreement agree,
        DerivationFunction kdf,
        Mac mac)
    {
        super(agree, kdf, mac);
    }


    /**
     * set up for use in conjunction with a block cipher to handle the
     * message.
     *
     * @param agree  the key agreement used as the basis for the encryption
     * @param kdf    the key derivation function used for byte generation
     * @param mac    the message authentication code generator for the message
     * @param cipher the cipher to used for encrypting the message
     */
    public OldIESEngine(
        BasicAgreement agree,
        DerivationFunction kdf,
        Mac mac,
        BufferedBlockCipher cipher)
    {
        super(agree, kdf, mac, cipher);
    }

    protected byte[] getLengthTag(byte[] p2)
    {
        byte[] L2 = new byte[4];
        if (p2 != null)
        {
            Pack.intToBigEndian(p2.length * 8, L2, 0);
        }
        return L2;
    }
}

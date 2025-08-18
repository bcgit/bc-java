package org.bouncycastle.openpgp.operator;

import org.bouncycastle.bcpg.GnuExtendedS2K;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.openpgp.PGPException;

/**
 * Secret key encryptor that allows to represent a secret key embedded
 * on a smartcard, using GNU S2K extensions.
 * <p>
 * This extension is documented on GnuPG documentation DETAILS file,
 * section "GNU extensions to the S2K algorithm".
 */
public class GnuDivertToCardSecretKeyEncryptor
    extends PBESecretKeyEncryptor
{
    private byte[] serial;

    public GnuDivertToCardSecretKeyEncryptor(PGPDigestCalculator s2kDigestCalculator, byte[] serial)
    {
        super(0, s2kDigestCalculator, 0, null, null);
        this.s2k = new GnuExtendedS2K(S2K.GNU_PROTECTION_MODE_DIVERT_TO_CARD);
        this.serial = new byte[serial.length + 1];
        this.serial[0] = (byte)serial.length;
        System.arraycopy(serial, 0, this.serial, 1, serial.length);
    }

    @Override
    public byte[] encryptKeyData(byte[] key, byte[] keyData, int keyOff,
                                 int keyLen)
        throws PGPException
    {
        if (serial != null && serial.length > 16)
        {
            byte[] result = new byte[17];
            System.arraycopy(serial, 0, result, 0, result.length);
            return result;
        }
        return serial;
    }

    @Override
    public byte[] getKey()
        throws PGPException
    {
        return null;
    }

    @Override
    public byte[] getCipherIV()
    {
        return new byte[0];
    }
}

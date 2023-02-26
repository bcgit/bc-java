package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * Represents revocation key OpenPGP signature sub packet.
 */
public class RevocationKey extends SignatureSubpacket
{
    // 1 octet of class, 
    // 1 octet of public-key algorithm ID, 
    // 20 octets of fingerprint
    public RevocationKey(boolean isCritical, boolean isLongLength, byte[] data)
    {
        super(SignatureSubpacketTags.REVOCATION_KEY, isCritical, isLongLength, data);
    }

    public RevocationKey(boolean isCritical, byte signatureClass, int keyAlgorithm, byte[] fingerprint)
    {
        super(SignatureSubpacketTags.REVOCATION_KEY, isCritical, false,
            createData(signatureClass, (byte)keyAlgorithm, fingerprint));
    }

    private static byte[] createData(byte signatureClass, byte keyAlgorithm, byte[] fingerprint)
    {
        byte[] data = new byte[2 + fingerprint.length];
        data[0] = signatureClass;
        data[1] = keyAlgorithm;
        System.arraycopy(fingerprint, 0, data, 2, fingerprint.length);
        return data;
    }

    public byte getSignatureClass()
    {
        return data[0];
    }

    public int getAlgorithm()
    {
        return data[1] & 0xff;
    }

    public byte[] getFingerprint()
    {
        byte[] fingerprint = new byte[data.length - 2];
        System.arraycopy(data, 2, fingerprint, 0, fingerprint.length);
        return fingerprint;
    }
}

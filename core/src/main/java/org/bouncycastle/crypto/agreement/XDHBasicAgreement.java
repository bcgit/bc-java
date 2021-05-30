package org.bouncycastle.crypto.agreement;

import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.RawAgreement;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;

import java.math.BigInteger;

/**
 * Key agreement using X25519 or X448. Same as Weierstrauss curve based ECDH,
 * except this uses the U-coordinate while ECDH uses the X-coordinate.
 */
public class XDHBasicAgreement
    implements BasicAgreement
{
    private final boolean fixEndian;

    private AsymmetricKeyParameter key;

    private int fieldSize = 0;

    public XDHBasicAgreement()
    {
        this(false);
    }

    public XDHBasicAgreement(boolean fixEndian)
    {
        this.fixEndian = fixEndian;
    }

    public void init(
        CipherParameters key)
    {
        if (key instanceof X25519PrivateKeyParameters) {
            this.fieldSize = 32;
        }
        else if (key instanceof X448PrivateKeyParameters)
        {
            this.fieldSize = 56;
        }
        else
        {
            throw new IllegalArgumentException("key is neither X25519 nor X448");
        }

        this.key = (AsymmetricKeyParameter) key;
    }

    public int getFieldSize()
    {
        return fieldSize;
    }

    public BigInteger calculateAgreement(
        CipherParameters pubKey)
    {
        RawAgreement agreement = (fieldSize == 32) ? new X25519Agreement() : new X448Agreement();

        agreement.init(key);

        byte[] Z = new byte[fieldSize];
        agreement.calculateAgreement(pubKey, Z, 0);

        if (fixEndian)
        {
            // convert Z to big endian.
            byte[] beEncoded = new byte[fieldSize];
            for (int i = 0; i < fieldSize; i++)
            {
                beEncoded[i] = Z[fieldSize - 1 -i];
            }
            return new BigInteger(1, beEncoded);
        }
        else
        {
            // do not fix endian for the use with org.bouncycastle.crypto.engines.IESEngine
            return new BigInteger(1, Z);
        }
    }
}

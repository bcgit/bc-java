package org.bouncycastle.crypto.agreement;

import java.math.BigInteger;

import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.RawAgreement;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;

/**
 * Key agreement using X25519 or X448. Same as Weierstrauss curve based ECDH,
 * except this uses the U-coordinate while ECDH uses the X-coordinate.
 */
public class XDHBasicAgreement
    implements BasicAgreement
{
    private AsymmetricKeyParameter key;
    private RawAgreement agreement;
    private int fieldSize = 0;

    public XDHBasicAgreement()
    {
    }

    public void init(
        CipherParameters key)
    {
        if (key instanceof X25519PrivateKeyParameters)
        {
            this.fieldSize = 32;
            this.agreement = new X25519Agreement();
        }
        else if (key instanceof X448PrivateKeyParameters)
        {
            this.fieldSize = 56;
            this.agreement = new X448Agreement();
        }
        else
        {
            throw new IllegalArgumentException("key is neither X25519 nor X448");
        }

        this.key = (AsymmetricKeyParameter)key;

        agreement.init(key);
    }

    public int getFieldSize()
    {
        return fieldSize;
    }

    public BigInteger calculateAgreement(
        CipherParameters pubKey)
    {
        byte[] Z = new byte[fieldSize];
        agreement.calculateAgreement(pubKey, Z, 0);

        return new BigInteger(1, Z);
    }
}

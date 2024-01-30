package org.bouncycastle.pqc.crypto.xwing;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.util.Arrays;

public class XWingPrivateKeyParameters
    extends XWingKeyParameters
{
    private final KyberPrivateKeyParameters kybPriv;
    private final X25519PrivateKeyParameters xdhPriv;

    XWingPrivateKeyParameters(AsymmetricKeyParameter kybPriv, AsymmetricKeyParameter xdhPriv)
    {
        super(true);

        this.kybPriv = (KyberPrivateKeyParameters)kybPriv;
        this.xdhPriv = (X25519PrivateKeyParameters)xdhPriv;
    }

    public XWingPrivateKeyParameters(byte[] encoding)
    {
        super(false);

        this.kybPriv = new KyberPrivateKeyParameters(KyberParameters.kyber768, Arrays.copyOfRange(encoding, 0, encoding.length - X25519PrivateKeyParameters.KEY_SIZE));
        this.xdhPriv = new X25519PrivateKeyParameters(encoding, encoding.length - X25519PrivateKeyParameters.KEY_SIZE);
    }

    KyberPrivateKeyParameters getKyberPrivateKey()
    {
        return kybPriv;
    }

    X25519PrivateKeyParameters getXDHPrivateKey()
    {
        return xdhPriv;
    }

    public byte[] getEncoded()
    {
        return Arrays.concatenate(kybPriv.getEncoded(), xdhPriv.getEncoded());
    }
}

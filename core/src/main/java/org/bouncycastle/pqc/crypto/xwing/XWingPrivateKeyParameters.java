package org.bouncycastle.pqc.crypto.xwing;

import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.util.Arrays;

public class XWingPrivateKeyParameters
    extends XWingKeyParameters
{
    private final transient byte[] seed;
    private final transient MLKEMPrivateKeyParameters kyberPrivateKey;
    private final transient X25519PrivateKeyParameters xdhPrivateKey;
    private final transient MLKEMPublicKeyParameters kyberPublicKey;
    private final transient X25519PublicKeyParameters xdhPublicKey;

    public XWingPrivateKeyParameters(byte[] seed,
                                     MLKEMPrivateKeyParameters kyberPrivateKey,
                                     X25519PrivateKeyParameters xdhPrivateKey,
                                     MLKEMPublicKeyParameters kyberPublicKey,
                                     X25519PublicKeyParameters xdhPublicKey)
    {
        super(true);
        this.seed = Arrays.clone(seed);
        this.kyberPrivateKey = kyberPrivateKey;
        this.xdhPrivateKey = xdhPrivateKey;
        this.kyberPublicKey = kyberPublicKey;
        this.xdhPublicKey = xdhPublicKey;
    }

    public XWingPrivateKeyParameters(byte[] seed)
    {
        super(true);
        XWingPrivateKeyParameters key = (XWingPrivateKeyParameters)XWingKeyPairGenerator.genKeyPair(seed).getPrivate();
        this.seed = key.seed;
        this.kyberPrivateKey = key.kyberPrivateKey;
        this.xdhPrivateKey = key.xdhPrivateKey;
        this.kyberPublicKey = key.kyberPublicKey;
        this.xdhPublicKey = key.xdhPublicKey;
    }

    public byte[] getSeed()
    {
        return Arrays.clone(seed);
    }

    MLKEMPrivateKeyParameters getKyberPrivateKey()
    {
        return kyberPrivateKey;
    }

    MLKEMPublicKeyParameters getKyberPublicKey()
    {
        return kyberPublicKey;
    }

    X25519PrivateKeyParameters getXDHPrivateKey()
    {
        return xdhPrivateKey;
    }

    X25519PublicKeyParameters getXDHPublicKey()
    {
        return xdhPublicKey;
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(seed);
    }
}

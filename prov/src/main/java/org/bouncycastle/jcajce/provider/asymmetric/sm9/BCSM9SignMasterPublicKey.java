package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.io.IOException;
import java.security.PublicKey;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.SM9SignMasterPublicKeyParameters;
import org.bouncycastle.jcajce.interfaces.SM9SignMasterPublicKey;

/**
 * JCA wrapper for an SM9 signature master public key (P_pub-s, a point of G2).
 * Use {@link #getUserPublicKey(byte[])} to form a signer's public key, the key a
 * {@code SM9} {@link java.security.Signature} verifies against.
 * <p>
 * The JCA {@code getEncoded()} is an X.509 SubjectPublicKeyInfo under the GM algorithm OID
 * (the JCA convention); the bare GM/T 0080-2020 key bytes are available via the
 * lightweight key-parameter class's {@code getEncoded()}.
 */
public class BCSM9SignMasterPublicKey
    implements SM9SignMasterPublicKey
{
    private static final long serialVersionUID = 1L;

    private final transient SM9SignMasterPublicKeyParameters keyParams;

    BCSM9SignMasterPublicKey(SM9SignMasterPublicKeyParameters keyParams)
    {
        this.keyParams = keyParams;
    }

    SM9SignMasterPublicKeyParameters getKeyParameters()
    {
        return keyParams;
    }

    public PublicKey getUserPublicKey(byte[] id)
    {
        return new BCSM9SignPublicKey(keyParams, id);
    }

    public String getAlgorithm()
    {
        return "SM9-SIGN";
    }

    public String getFormat()
    {
        return "X.509";
    }

    public byte[] getEncoded()
    {
        try
        {
            SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(GMObjectIdentifiers.sm9sign), keyParams.getEncoded());
            return info.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw Exceptions.illegalStateException("unable to encode SM9 master public key", e);
        }
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        if (!(o instanceof BCSM9SignMasterPublicKey))
        {
            return false;
        }
        return Arrays.areEqual(getEncoded(), ((BCSM9SignMasterPublicKey)o).getEncoded());
    }

    public int hashCode()
    {
        return Arrays.hashCode(getEncoded());
    }

    private Object writeReplace()
    {
        return new SM9KeyProxy(false, getEncoded());
    }
}

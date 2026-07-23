package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.io.IOException;
import java.security.PublicKey;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.SM9EncMasterPublicKeyParameters;
import org.bouncycastle.jcajce.interfaces.SM9EncMasterPublicKey;

/**
 * JCA wrapper for an SM9 encryption master public key (P_pub-e, a point of G1).
 * Use {@link #getUserPublicKey(byte[])} to form a recipient's public key, the key
 * supplied to {@code KeyGenerator.SM9-KEM} when encapsulating to that identity.
 * <p>
 * The JCA {@code getEncoded()} is an X.509 SubjectPublicKeyInfo under the GM algorithm OID
 * (the JCA convention); the bare GM/T 0080-2020 key bytes are available via the
 * lightweight key-parameter class's {@code getEncoded()}.
 */
public class BCSM9EncMasterPublicKey
    implements SM9EncMasterPublicKey
{
    private static final long serialVersionUID = 1L;

    private final transient SM9EncMasterPublicKeyParameters keyParams;

    BCSM9EncMasterPublicKey(SM9EncMasterPublicKeyParameters keyParams)
    {
        this.keyParams = keyParams;
    }

    SM9EncMasterPublicKeyParameters getKeyParameters()
    {
        return keyParams;
    }

    public PublicKey getUserPublicKey(byte[] id)
    {
        return new BCSM9EncPublicKey(this, id);
    }
    
    public String getAlgorithm()
    {
        return "SM9-ENC";
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
                new AlgorithmIdentifier(GMObjectIdentifiers.sm9encrypt), keyParams.getEncoded());
            return info.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw Exceptions.illegalStateException("unable to encode SM9 encryption master public key", e);
        }
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        if (!(o instanceof BCSM9EncMasterPublicKey))
        {
            return false;
        }
        return Arrays.areEqual(getEncoded(), ((BCSM9EncMasterPublicKey)o).getEncoded());
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

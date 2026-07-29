package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.io.IOException;
import java.security.PublicKey;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.SM9SigMasterPublicKeyParameters;
import org.bouncycastle.jcajce.interfaces.SM9SigMasterPublicKey;

/**
 * JCA wrapper for an SM9 signature master public key (P_pub-s, a point of G2).
 * Use {@link #getUserPublicKey(byte[])} to form a signer's public key, the key a
 * {@code SM9} {@link java.security.Signature} verifies against.
 * <p>
 * The JCA {@code getEncoded()} is an X.509 SubjectPublicKeyInfo under the GM algorithm OID
 * (the JCA convention); the bare GM/T 0080-2020 key bytes are available via the
 * lightweight key-parameter class's {@code getEncoded()}.
 */
public class BCSM9SigMasterPublicKey
    implements SM9SigMasterPublicKey
{
    private static final long serialVersionUID = 1L;

    private final transient SM9SigMasterPublicKeyParameters keyParams;

    BCSM9SigMasterPublicKey(SM9SigMasterPublicKeyParameters keyParams)
    {
        this.keyParams = keyParams;
    }

    SM9SigMasterPublicKeyParameters getKeyParameters()
    {
        return keyParams;
    }

    public PublicKey getUserPublicKey(byte[] identity)
    {
        return new BCSM9SigPublicKey(keyParams, identity);
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
        if (!(o instanceof BCSM9SigMasterPublicKey))
        {
            return false;
        }
        return Arrays.areEqual(getEncoded(), ((BCSM9SigMasterPublicKey)o).getEncoded());
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

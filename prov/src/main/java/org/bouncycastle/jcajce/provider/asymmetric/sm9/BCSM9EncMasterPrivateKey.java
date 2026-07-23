package org.bouncycastle.jcajce.provider.asymmetric.sm9;

import java.io.IOException;
import java.security.PrivateKey;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.SM9EncMasterPrivateKeyParameters;

/**
 * JCA wrapper for an SM9 encryption master private key (ke), held by the KGC.
 * Use {@link #extractPrivateKey(byte[])} (a KGC operation, hid = 0x03) to derive
 * a user's decryption key.
 * <p>
 * The JCA {@code getEncoded()} is a PKCS#8 PrivateKeyInfo under the GM algorithm OID
 * (the JCA convention); the bare GM/T 0080-2020 key bytes are available via the
 * lightweight key-parameter class's {@code getEncoded()}.
 */
public class BCSM9EncMasterPrivateKey
    implements PrivateKey
{
    private static final long serialVersionUID = 1L;

    private final transient SM9EncMasterPrivateKeyParameters keyParams;

    public BCSM9EncMasterPrivateKey(SM9EncMasterPrivateKeyParameters keyParams)
    {
        this.keyParams = keyParams;
    }

    public SM9EncMasterPrivateKeyParameters getKeyParameters()
    {
        return keyParams;
    }

    public BCSM9EncMasterPublicKey getMasterPublicKey()
    {
        return new BCSM9EncMasterPublicKey(keyParams.getPublicKeyParameters());
    }

    /**
     * Derive the decryption private key of the user identified by {@code id}. The
     * JCA-idiomatic route to the same derivation is {@code KeyPairGenerator.SM9-ENC}
     * initialised with an {@link org.bouncycastle.jcajce.spec.SM9UserKeyParameterSpec},
     * which returns the user's full key pair.
     */
    public BCSM9EncPrivateKey extractPrivateKey(byte[] id)
    {
        return new BCSM9EncPrivateKey(keyParams.generatePrivateKey(id));
    }

    public String getAlgorithm()
    {
        return "SM9-ENC";
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    public byte[] getEncoded()
    {
        try
        {
            PrivateKeyInfo info = new PrivateKeyInfo(
                new AlgorithmIdentifier(GMObjectIdentifiers.sm9encrypt), new DEROctetString(keyParams.getEncoded()));
            return info.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw Exceptions.illegalStateException("unable to encode SM9 encryption master private key", e);
        }
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        if (!(o instanceof BCSM9EncMasterPrivateKey))
        {
            return false;
        }
        return Arrays.constantTimeAreEqual(getEncoded(), ((BCSM9EncMasterPrivateKey)o).getEncoded());
    }

    public int hashCode()
    {
        // derive from the public master key, never the secret ke
        return Arrays.hashCode(keyParams.getPublicKeyParameters().getEncoded());
    }

    private Object writeReplace()
    {
        return new SM9KeyProxy(true, getEncoded());
    }
}

package org.bouncycastle.pqc.jcajce.provider.qruov;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.pqc.crypto.qruov.QRUOVPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.QRUOVKey;
import org.bouncycastle.pqc.jcajce.spec.QRUOVParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class BCQRUOVPrivateKey
    implements PrivateKey, QRUOVKey
{
    private static final long serialVersionUID = 1L;

    private transient QRUOVPrivateKeyParameters params;
    private transient ASN1Set attributes;

    public BCQRUOVPrivateKey(QRUOVPrivateKeyParameters params)
    {
        this.params = params;
    }

    public BCQRUOVPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        this.params = (QRUOVPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo);
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        if (o instanceof BCQRUOVPrivateKey)
        {
            BCQRUOVPrivateKey otherKey = (BCQRUOVPrivateKey)o;
            return Arrays.constantTimeAreEqual(params.getEncoded(), otherKey.params.getEncoded());
        }
        return false;
    }

    public int hashCode()
    {
        // QR-UOV private keys require package-private engine routines to expand the public key from seeds.
        return getAlgorithm().hashCode();
    }

    public final String getAlgorithm()
    {
        return Strings.toUpperCase(canonicalName());
    }

    public byte[] getEncoded()
    {
        try
        {
            PrivateKeyInfo pki = PrivateKeyInfoFactory.createPrivateKeyInfo(params, attributes);
            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public QRUOVParameterSpec getParameterSpec()
    {
        return QRUOVParameterSpec.fromName(canonicalName());
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    QRUOVPrivateKeyParameters getKeyParams()
    {
        return params;
    }

    private String canonicalName()
    {
        String raw = params.getParameters().getName();
        int dash = raw.indexOf('-');
        return dash > 0 ? raw.substring(0, dash) : raw;
    }

    private void readObject(ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();
        byte[] enc = (byte[])in.readObject();
        init(PrivateKeyInfo.getInstance(enc));
    }

    private void writeObject(ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();
        out.writeObject(this.getEncoded());
    }
}

package org.bouncycastle.pqc.jcajce.provider.qruov;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pqc.crypto.qruov.QRUOVPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.QRUOVKey;
import org.bouncycastle.pqc.jcajce.spec.QRUOVParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class BCQRUOVPublicKey
    implements PublicKey, QRUOVKey
{
    private static final long serialVersionUID = 1L;

    private transient QRUOVPublicKeyParameters params;

    public BCQRUOVPublicKey(QRUOVPublicKeyParameters params)
    {
        this.params = params;
    }

    public BCQRUOVPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        this.params = (QRUOVPublicKeyParameters)PublicKeyFactory.createKey(keyInfo);
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        if (o instanceof BCQRUOVPublicKey)
        {
            BCQRUOVPublicKey otherKey = (BCQRUOVPublicKey)o;
            return Arrays.areEqual(params.getEncoded(), otherKey.params.getEncoded());
        }
        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getEncoded());
    }

    public final String getAlgorithm()
    {
        return Strings.toUpperCase(canonicalName());
    }

    public byte[] getEncoded()
    {
        try
        {
            SubjectPublicKeyInfo pki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(params);
            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public String getFormat()
    {
        return "X.509";
    }

    public QRUOVParameterSpec getParameterSpec()
    {
        return QRUOVParameterSpec.fromName(canonicalName());
    }

    QRUOVPublicKeyParameters getKeyParams()
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
        init(SubjectPublicKeyInfo.getInstance(enc));
    }

    private void writeObject(ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();
        out.writeObject(this.getEncoded());
    }
}

package org.bouncycastle.pqc.jcajce.provider.uov;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pqc.crypto.uov.UOVPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.UOVKey;
import org.bouncycastle.pqc.jcajce.spec.UOVParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Fingerprint;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class BCUOVPublicKey
    implements PublicKey, UOVKey
{
    private static final long serialVersionUID = 1L;

    private transient UOVPublicKeyParameters params;
    private transient String algorithm;
    private transient byte[] encoding;

    public BCUOVPublicKey(UOVPublicKeyParameters params)
    {
        this.params = params;
        this.algorithm = Strings.toUpperCase(params.getParameters().getName());
    }

    public BCUOVPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        this.encoding = null;
        this.params = (UOVPublicKeyParameters)PublicKeyFactory.createKey(keyInfo);
        this.algorithm = Strings.toUpperCase(params.getParameters().getName());
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        if (o instanceof BCUOVPublicKey)
        {
            BCUOVPublicKey other = (BCUOVPublicKey)o;
            return Arrays.areEqual(params.getEncoded(), other.params.getEncoded());
        }
        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getEncoded());
    }

    public final String getAlgorithm()
    {
        return algorithm;
    }

    public byte[] getPublicData()
    {
        return params.getEncoded();
    }

    public byte[] getEncoded()
    {
        if (encoding == null)
        {
            try
            {
                encoding = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(params).getEncoded();
            }
            catch (IOException e)
            {
                return null;
            }
        }
        return Arrays.clone(encoding);
    }

    public String getFormat()
    {
        return "X.509";
    }

    public UOVParameterSpec getParameterSpec()
    {
        return UOVParameterSpec.fromName(params.getParameters().getName());
    }

    public String toString()
    {
        byte[] keyBytes = params.getEncoded();
        int previewLen = Math.min(16, keyBytes.length);

        StringBuilder buf = new StringBuilder();
        String nl = Strings.lineSeparator();
        buf.append(getAlgorithm())
            .append(" Public Key [")
            .append(new Fingerprint(keyBytes).toString())
            .append("] (")
            .append(keyBytes.length)
            .append(" bytes)")
            .append(nl)
            .append("    public data: ")
            // -DM Hex.toHexString
            .append(Hex.toHexString(keyBytes, 0, previewLen));
        if (keyBytes.length > previewLen)
        {
            buf.append("...");
        }
        buf.append(nl);

        return buf.toString();
    }

    UOVPublicKeyParameters getKeyParams()
    {
        return params;
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

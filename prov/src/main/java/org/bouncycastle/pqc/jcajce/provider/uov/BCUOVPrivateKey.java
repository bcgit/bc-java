package org.bouncycastle.pqc.jcajce.provider.uov;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.pqc.crypto.uov.UOVPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.UOVKey;
import org.bouncycastle.pqc.jcajce.spec.UOVParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class BCUOVPrivateKey
    implements PrivateKey, UOVKey
{
    private static final long serialVersionUID = 1L;

    private transient UOVPrivateKeyParameters params;
    private transient String algorithm;
    private transient byte[] encoding;
    private transient ASN1Set attributes;

    public BCUOVPrivateKey(UOVPrivateKeyParameters params)
    {
        this.params = params;
        this.algorithm = Strings.toUpperCase(params.getParameters().getName());
    }

    public BCUOVPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.encoding = keyInfo.getEncoded();
        this.attributes = keyInfo.getAttributes();
        this.params = (UOVPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo);
        this.algorithm = Strings.toUpperCase(params.getParameters().getName());
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }
        if (o instanceof BCUOVPrivateKey)
        {
            BCUOVPrivateKey other = (BCUOVPrivateKey)o;
            // Constant-time compare — private keys may be checked against
            // attacker-influenced values.
            return Arrays.constantTimeAreEqual(params.getEncoded(), other.params.getEncoded());
        }
        return false;
    }

    public int hashCode()
    {
        // UOV private keys require package-private engine routines to expand the public key from the seed.
        return getAlgorithm().hashCode();
    }

    public final String getAlgorithm()
    {
        return algorithm;
    }

    public byte[] getEncoded()
    {
        if (encoding == null)
        {
            try
            {
                encoding = PrivateKeyInfoFactory.createPrivateKeyInfo(params, attributes).getEncoded();
            }
            catch (IOException e)
            {
                return null;
            }
        }
        return Arrays.clone(encoding);
    }

    public UOVParameterSpec getParameterSpec()
    {
        return UOVParameterSpec.fromName(params.getParameters().getName());
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    UOVPrivateKeyParameters getKeyParams()
    {
        return params;
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

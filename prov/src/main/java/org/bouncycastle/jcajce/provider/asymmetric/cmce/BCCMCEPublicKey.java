package org.bouncycastle.jcajce.provider.asymmetric.cmce;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.CMCEPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.interfaces.CMCEPublicKey;
import org.bouncycastle.jcajce.spec.CMCEParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Fingerprint;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class BCCMCEPublicKey
    implements CMCEPublicKey
{
    private static final long serialVersionUID = 1L;

    private transient CMCEPublicKeyParameters params;

    private transient String algorithm;

    public BCCMCEPublicKey(
        CMCEPublicKeyParameters params)
    {
        init(params);
    }

    public BCCMCEPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        this.params = (CMCEPublicKeyParameters)PublicKeyFactory.createKey(keyInfo);
        this.algorithm = CMCEParameterSpec.fromName(params.getParameters().getName()).getName();
    }

    private void init(CMCEPublicKeyParameters params)
    {
        this.params = params;
        this.algorithm = CMCEParameterSpec.fromName(params.getParameters().getName()).getName();
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCCMCEPublicKey)
        {
            BCCMCEPublicKey otherKey = (BCCMCEPublicKey)o;

            return Arrays.areEqual(this.getEncoded(), otherKey.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(getEncoded());
    }

    /**
     * @return name of the algorithm - "CMCE..." followed by the parameter type.
     */
    public final String getAlgorithm()
    {
        return algorithm;
    }

    public byte[] getPublicData()
    {
        return params.getPublicKey();
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

    public CMCEParameterSpec getParameterSpec()
    {
        return CMCEParameterSpec.fromName(params.getParameters().getName());
    }

    public String toString()
    {
        StringBuilder buf = new StringBuilder();
        String nl = Strings.lineSeparator();
        byte[] keyBytes = params.getPublicKey();

        // -DM Hex.toHexString
        buf.append(getAlgorithm())
            .append(" ")
            .append("Public Key").append(" [")
            .append(new Fingerprint(keyBytes).toString())
            .append("]")
            .append(nl)
            .append("    public data: ")
            .append(Hex.toHexString(keyBytes))
            .append(nl);

        return buf.toString();
    }

    CMCEPublicKeyParameters getKeyParams()
    {
        return params;
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        init(SubjectPublicKeyInfo.getInstance(enc));
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}

package org.bouncycastle.jcajce.provider.asymmetric.frodokem;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.FrodoKEMPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jcajce.interfaces.FrodoKEMPublicKey;
import org.bouncycastle.jcajce.spec.FrodoKEMParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Fingerprint;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class BCFrodoKEMPublicKey
    implements FrodoKEMPublicKey
{
    private static final long serialVersionUID = 1L;

    private transient FrodoKEMPublicKeyParameters params;

    private transient String algorithm;

    public BCFrodoKEMPublicKey(
        FrodoKEMPublicKeyParameters params)
    {
        init(params);
    }

    public BCFrodoKEMPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        this.params = (FrodoKEMPublicKeyParameters)PublicKeyFactory.createKey(keyInfo);
        this.algorithm = FrodoKEMParameterSpec.fromName(params.getParameters().getName()).getName();
    }

    private void init(FrodoKEMPublicKeyParameters params)
    {
        this.params = params;
        this.algorithm = FrodoKEMParameterSpec.fromName(params.getParameters().getName()).getName();
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCFrodoKEMPublicKey)
        {
            BCFrodoKEMPublicKey otherKey = (BCFrodoKEMPublicKey)o;

            return Arrays.areEqual(this.getEncoded(), otherKey.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(getEncoded());
    }

    /**
     * @return name of the algorithm - "FRODOKEM..." followed by the parameter type.
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

    public FrodoKEMParameterSpec getParameterSpec()
    {
        return FrodoKEMParameterSpec.fromName(params.getParameters().getName());
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

    FrodoKEMPublicKeyParameters getKeyParams()
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

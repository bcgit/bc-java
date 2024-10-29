package org.bouncycastle.jcajce.provider.asymmetric.mlkem;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.MLKEMPublicKey;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Fingerprint;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class BCMLKEMPublicKey
    implements MLKEMPublicKey
{
    private static final long serialVersionUID = 1L;

    private transient MLKEMPublicKeyParameters params;

    private transient String algorithm;

    public BCMLKEMPublicKey(
            MLKEMPublicKeyParameters params)
    {
        init(params);
    }

    public BCMLKEMPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        this.params = (MLKEMPublicKeyParameters)PublicKeyFactory.createKey(keyInfo);
        this.algorithm = Strings.toUpperCase(MLKEMParameterSpec.fromName(params.getParameters().getName()).getName());
    }

    private void init(MLKEMPublicKeyParameters params)
    {
        this.params = params;
        this.algorithm = Strings.toUpperCase(MLKEMParameterSpec.fromName(params.getParameters().getName()).getName());
    }
    /**
     * Compare this ML-KEM public key with another object.
     *
     * @param o the other object
     * @return the result of the comparison
     */
    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof BCMLKEMPublicKey)
        {
            BCMLKEMPublicKey otherKey = (BCMLKEMPublicKey)o;

            return Arrays.areEqual(this.getEncoded(), otherKey.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(getEncoded());
    }

    /**
     * @return name of the algorithm - "ML-KEM" followed by the parameter type.
     */
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

    public MLKEMParameterSpec getParameterSpec()
    {
        return MLKEMParameterSpec.fromName(params.getParameters().getName());
    }

    public String toString()
    {
        StringBuilder buf = new StringBuilder();
        String nl = Strings.lineSeparator();
        byte[] keyBytes = params.getEncoded();

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

    MLKEMPublicKeyParameters getKeyParams()
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

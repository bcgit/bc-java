package org.bouncycastle.jcajce.provider.asymmetric.slhdsa;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.SLHDSAPublicKey;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Fingerprint;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class BCSLHDSAPublicKey
    implements SLHDSAPublicKey
{
    private static final long serialVersionUID = 1L;

    private transient SLHDSAPublicKeyParameters params;

    public BCSLHDSAPublicKey(
        SLHDSAPublicKeyParameters params)
    {
        this.params = params;
    }

    public BCSLHDSAPublicKey(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        this.params = (SLHDSAPublicKeyParameters)PublicKeyFactory.createKey(keyInfo);
    }
    
    /**
     * Compare this SPHINCS-256 public key with another object.
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

        if (o instanceof BCSLHDSAPublicKey)
        {
            BCSLHDSAPublicKey otherKey = (BCSLHDSAPublicKey)o;

            return Arrays.areEqual(params.getEncoded(), otherKey.params.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getEncoded());
    }

    /**
     * @return name of the algorithm - "SLH-DSA" followed by the parameter type.
     */
    public final String getAlgorithm()
    {
        return "SLH-DSA" + "-" + Strings.toUpperCase(params.getParameters().getName());
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

    public SLHDSAParameterSpec getParameterSpec()
    {
        return SLHDSAParameterSpec.fromName(params.getParameters().getName());
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
    
    SLHDSAPublicKeyParameters getKeyParams()
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

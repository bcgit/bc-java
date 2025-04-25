package org.bouncycastle.jcajce.provider.asymmetric.slhdsa;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jcajce.interfaces.SLHDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.SLHDSAPublicKey;
import org.bouncycastle.jcajce.spec.SLHDSAParameterSpec;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.slhdsa.SLHDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Fingerprint;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class BCSLHDSAPrivateKey
    implements SLHDSAPrivateKey
{
    private static final long serialVersionUID = 1L;

    private transient SLHDSAPrivateKeyParameters params;
    private transient ASN1Set attributes;

    public BCSLHDSAPrivateKey(
        SLHDSAPrivateKeyParameters params)
    {
        this.params = params;
    }

    public BCSLHDSAPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        this.params = (SLHDSAPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo);
    }

    /**
     * Compare this SPHINCS-256 private key with another object.
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

        if (o instanceof BCSLHDSAPrivateKey)
        {
            BCSLHDSAPrivateKey otherKey = (BCSLHDSAPrivateKey)o;

            return Arrays.areEqual(params.getEncoded(), otherKey.params.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getEncoded());
    }

    /**
     * @return name of the algorithm - "SLH-DSA..."
     */
    public final String getAlgorithm()
    {
        return "SLH-DSA" + "-" + Strings.toUpperCase(params.getParameters().getName());
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

    public SLHDSAPublicKey getPublicKey()
    {
        return new BCSLHDSAPublicKey(new SLHDSAPublicKeyParameters(params.getParameters(), params.getPublicKey()));
    }

    public SLHDSAParameterSpec getParameterSpec()
    {
        return SLHDSAParameterSpec.fromName(params.getParameters().getName());
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    public String toString()
    {
        StringBuilder buf = new StringBuilder();
        String nl = Strings.lineSeparator();
        byte[] keyBytes = params.getPublicKey();

        // -DM Hex.toHexString
        buf.append(getAlgorithm())
            .append(" ")
            .append("Private Key").append(" [")
            .append(new Fingerprint(keyBytes).toString())
            .append("]")
            .append(nl)
            .append("    public data: ")
            .append(Hex.toHexString(keyBytes))
            .append(nl);

        return buf.toString();
    }

    SLHDSAPrivateKeyParameters getKeyParams()
    {
        return params;
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        init(PrivateKeyInfo.getInstance(enc));
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}

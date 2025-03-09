package org.bouncycastle.jcajce.provider.asymmetric.mldsa;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPublicKey;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.jcajce.provider.util.KeyUtil;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Fingerprint;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class BCMLDSAPrivateKey
    implements MLDSAPrivateKey
{
    private static final long serialVersionUID = 1L;

    private transient MLDSAPrivateKeyParameters params;
    private transient String algorithm;
    private transient byte[] encoding;
    private transient ASN1Set attributes;

    public BCMLDSAPrivateKey(
            MLDSAPrivateKeyParameters params)
    {
        this.params = params;
        this.algorithm = Strings.toUpperCase(MLDSAParameterSpec.fromName(params.getParameters().getName()).getName());
    }

    public BCMLDSAPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
            throws IOException
    {
        this.encoding = keyInfo.getEncoded();
        init((MLDSAPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo), keyInfo.getAttributes());
    }

    private void init(MLDSAPrivateKeyParameters params, ASN1Set attributes)
    {
        this.attributes = attributes;
        this.params = params;
        algorithm = Strings.toUpperCase(MLDSAParameterSpec.fromName(params.getParameters().getName()).getName());
    }

    /**
     * Compare this ML-DSA private key with another object.
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

        if (o instanceof BCMLDSAPrivateKey)
        {
            BCMLDSAPrivateKey otherKey = (BCMLDSAPrivateKey)o;

            return Arrays.areEqual(params.getEncoded(), otherKey.params.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getEncoded());
    }

    /**
     * @return name of the algorithm
     */
    public final String getAlgorithm()
    {
        return algorithm;
    }

    public MLDSAPrivateKey getPrivateKey(boolean preferSeedOnly)
    {
        if (preferSeedOnly)
        {
            byte[] seed = params.getSeed();
            if (seed != null)
            {
                return new BCMLDSAPrivateKey(this.params.getParametersWithFormat(MLDSAPrivateKeyParameters.SEED_ONLY));
            }
        }

        return new BCMLDSAPrivateKey(this.params.getParametersWithFormat(MLDSAPrivateKeyParameters.EXPANDED_KEY));
    }

    public byte[] getEncoded()
    {
        if (encoding == null)
        {
            encoding = KeyUtil.getEncodedPrivateKeyInfo(params, attributes);
        }

        return Arrays.clone(encoding);
    }

    public MLDSAPublicKey getPublicKey()
    {
        MLDSAPublicKeyParameters publicKeyParameters = params.getPublicKeyParameters();
        if (publicKeyParameters == null)
        {
            return null;
        }
        return new BCMLDSAPublicKey(publicKeyParameters);
    }

    @Override
    public byte[] getPrivateData()
    {
        return params.getEncoded();
    }

    @Override
    public byte[] getSeed()
    {
        return params.getSeed();
    }

    public MLDSAParameterSpec getParameterSpec()
    {
        return MLDSAParameterSpec.fromName(params.getParameters().getName());
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

    MLDSAPrivateKeyParameters getKeyParams()
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

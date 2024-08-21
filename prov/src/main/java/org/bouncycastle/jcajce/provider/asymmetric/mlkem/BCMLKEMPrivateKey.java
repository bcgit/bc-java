package org.bouncycastle.jcajce.provider.asymmetric.mlkem;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLKEMPublicKey;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class BCMLKEMPrivateKey
    implements MLKEMPrivateKey
{
    private static final long serialVersionUID = 1L;

    private transient KyberPrivateKeyParameters params;
    private transient String algorithm;
    private transient ASN1Set attributes;

    public BCMLKEMPrivateKey(
            KyberPrivateKeyParameters params)
    {
        this.params = params;
        this.algorithm = MLKEMParameterSpec.fromName(params.getParameters().getName()).getName();
    }

    public BCMLKEMPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.attributes = keyInfo.getAttributes();;
        this.params = (KyberPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo);
        this.algorithm = MLKEMParameterSpec.fromName(params.getParameters().getName()).getName();
    }

    /**
     * Compare this ML-KEM private key with another object.
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

        if (o instanceof BCMLKEMPrivateKey)
        {
            BCMLKEMPrivateKey otherKey = (BCMLKEMPrivateKey)o;

            return Arrays.areEqual(params.getEncoded(), otherKey.params.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getEncoded());
    }

    /**
     * @return name of the algorithm - "ML-KEM"
     */
    public final String getAlgorithm()
    {
        return algorithm;
//        return MLKEMParameterSpec.fromName(params.getParameters().getName()).getName().toUpperCase();
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

    public MLKEMPublicKey getPublicKey()
    {
        return new BCMLKEMPublicKey(params.getPublicKeyParameters());
    }

    public MLKEMParameterSpec getParameterSpec()
    {
        return MLKEMParameterSpec.fromName(params.getParameters().getName());
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    KyberPrivateKeyParameters getKeyParams()
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

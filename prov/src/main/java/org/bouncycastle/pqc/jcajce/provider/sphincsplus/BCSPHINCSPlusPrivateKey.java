package org.bouncycastle.pqc.jcajce.provider.sphincsplus;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.SPHINCSPlusPrivateKey;
import org.bouncycastle.pqc.jcajce.interfaces.SPHINCSPlusPublicKey;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;
import org.bouncycastle.util.Arrays;

public class BCSPHINCSPlusPrivateKey
    implements PrivateKey, SPHINCSPlusPrivateKey
{
    private static final long serialVersionUID = 1L;

    private transient SPHINCSPlusPrivateKeyParameters params;
    private transient ASN1Set attributes;

    public BCSPHINCSPlusPrivateKey(
        SPHINCSPlusPrivateKeyParameters params)
    {
        this.params = params;
    }

    public BCSPHINCSPlusPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        this.params = (SPHINCSPlusPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo);
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

        if (o instanceof BCSPHINCSPlusPrivateKey)
        {
            BCSPHINCSPlusPrivateKey otherKey = (BCSPHINCSPlusPrivateKey)o;

            return Arrays.areEqual(params.getEncoded(), otherKey.params.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return Arrays.hashCode(params.getEncoded());
    }

    /**
     * @return name of the algorithm - "SPHINCS+"
     */
    public final String getAlgorithm()
    {
        return "SPHINCS+";
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

    public SPHINCSPlusPublicKey getPublicKey()
    {
        return new BCSPHINCSPlusPublicKey(new SPHINCSPlusPublicKeyParameters(params.getParameters(), params.getPublicKey()));
    }

    public SPHINCSPlusParameterSpec getParameterSpec()
    {
        return SPHINCSPlusParameterSpec.fromName(params.getParameters().getName());
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    SPHINCSPlusPrivateKeyParameters getKeyParams()
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

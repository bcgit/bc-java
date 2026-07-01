package org.bouncycastle.jcajce.provider.asymmetric.frodokem;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.kems.frodo.FrodoKEMEngine;
import org.bouncycastle.crypto.params.FrodoKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.FrodoKEMPublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.jcajce.interfaces.FrodoKEMPrivateKey;
import org.bouncycastle.jcajce.spec.FrodoKEMParameterSpec;
import org.bouncycastle.util.Arrays;

public class BCFrodoKEMPrivateKey
    implements FrodoKEMPrivateKey
{
    private static final long serialVersionUID = 1L;

    private transient FrodoKEMPrivateKeyParameters params;

    private transient String algorithm;

    public BCFrodoKEMPrivateKey(
        FrodoKEMPrivateKeyParameters params)
    {
        init(params);
    }

    public BCFrodoKEMPrivateKey(PrivateKeyInfo keyInfo)
        throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
        throws IOException
    {
        this.params = (FrodoKEMPrivateKeyParameters)PrivateKeyFactory.createKey(keyInfo);
        this.algorithm = FrodoKEMParameterSpec.fromName(params.getParameters().getName()).getName();
    }

    private void init(FrodoKEMPrivateKeyParameters params)
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

        if (o instanceof BCFrodoKEMPrivateKey)
        {
            BCFrodoKEMPrivateKey otherKey = (BCFrodoKEMPrivateKey)o;

            return Arrays.constantTimeAreEqual(this.getEncoded(), otherKey.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return getPublicKey().hashCode();
    }

    private BCFrodoKEMPublicKey getPublicKey()
    {
        FrodoKEMEngine engine = FrodoKEMEngine.getInstance(params.getParameters());
        int sBytes = params.getParameters().getSessionKeySize() / 8;
        byte[] pk = Arrays.copyOfRange(params.getPrivateKey(), sBytes, sBytes + engine.getPublicKeySize());
        return new BCFrodoKEMPublicKey(new FrodoKEMPublicKeyParameters(params.getParameters(), pk));
    }

    /**
     * @return name of the algorithm - "FRODOKEM..." followed by the parameter type.
     */
    public final String getAlgorithm()
    {
        return algorithm;
    }

    public byte[] getEncoded()
    {
        try
        {
            PrivateKeyInfo pki = PrivateKeyInfoFactory.createPrivateKeyInfo(params);

            return pki.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    public FrodoKEMParameterSpec getParameterSpec()
    {
        return FrodoKEMParameterSpec.fromName(params.getParameters().getName());
    }

    FrodoKEMPrivateKeyParameters getKeyParams()
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

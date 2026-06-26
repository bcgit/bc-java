package org.bouncycastle.pqc.jcajce.provider.picnic;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.PicnicKey;
import org.bouncycastle.pqc.jcajce.spec.PicnicParameterSpec;
import org.bouncycastle.pqc.legacy.picnic.PicnicPrivateKeyParameters;
import org.bouncycastle.pqc.legacy.picnic.PicnicPublicKeyParameters;
import org.bouncycastle.util.Arrays;

public class BCPicnicPrivateKey
    implements PrivateKey, PicnicKey
{
    private static final long serialVersionUID = 1L;

    private transient PicnicPrivateKeyParameters params;
    private transient ASN1Set attributes;

    public BCPicnicPrivateKey(
            PicnicPrivateKeyParameters params)
    {
        this.params = params;
    }

    public BCPicnicPrivateKey(PrivateKeyInfo keyInfo)
            throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
            throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        this.params = (PicnicPrivateKeyParameters) PrivateKeyFactory.createKey(keyInfo);
    }

    /**
     * Compare this picnic private key with another object.
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

        if (o instanceof BCPicnicPrivateKey)
        {
            BCPicnicPrivateKey otherKey = (BCPicnicPrivateKey)o;

            return Arrays.constantTimeAreEqual(params.getEncoded(), otherKey.params.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return getPublicKey().hashCode();
    }

    private BCPicnicPublicKey getPublicKey()
    {
        byte[] sk = params.getEncoded();
        int stateSizeBytes = (sk.length - 1) / 3;
        int pubKeySize = 1 + 2 * stateSizeBytes;
        byte[] pk = new byte[pubKeySize];
        pk[0] = sk[0];
        System.arraycopy(sk, 1 + stateSizeBytes, pk, 1, pubKeySize - 1);
        return new BCPicnicPublicKey(new PicnicPublicKeyParameters(params.getParameters(), pk));
    }

    /**
     * @return name of the algorithm - "Picnic"
     */
    public final String getAlgorithm()
    {
        return "Picnic";
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

    public PicnicParameterSpec getParameterSpec()
    {
        return PicnicParameterSpec.fromName(params.getParameters().getName());
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    PicnicPrivateKeyParameters getKeyParams()
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

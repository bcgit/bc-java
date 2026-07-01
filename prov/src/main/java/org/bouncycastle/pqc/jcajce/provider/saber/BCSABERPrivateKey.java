package org.bouncycastle.pqc.jcajce.provider.saber;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.pqc.crypto.saber.SABERParameters;
import org.bouncycastle.pqc.crypto.saber.SABERPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.saber.SABERPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.SABERKey;
import org.bouncycastle.pqc.jcajce.spec.SABERParameterSpec;
import org.bouncycastle.util.Arrays;

public class BCSABERPrivateKey
        implements PrivateKey, SABERKey
{
    private static final long serialVersionUID = 1L;

    private transient SABERPrivateKeyParameters params;
    private transient ASN1Set attributes;

    public BCSABERPrivateKey(
            SABERPrivateKeyParameters params)
    {
        this.params = params;
    }

    public BCSABERPrivateKey(PrivateKeyInfo keyInfo)
            throws IOException
    {
        init(keyInfo);
    }

    private void init(PrivateKeyInfo keyInfo)
            throws IOException
    {
        this.attributes = keyInfo.getAttributes();
        this.params = (SABERPrivateKeyParameters) PrivateKeyFactory.createKey(keyInfo);
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

        if (o instanceof BCSABERPrivateKey)
        {
            BCSABERPrivateKey otherKey = (BCSABERPrivateKey)o;

            return Arrays.constantTimeAreEqual(params.getEncoded(), otherKey.params.getEncoded());
        }

        return false;
    }

    public int hashCode()
    {
        return getPublicKey().hashCode();
    }

    private BCSABERPublicKey getPublicKey()
    {
        SABERParameters p = params.getParameters();
        byte[] sk = params.getPrivateKey();
        int pkOff = saberIndcpaSecretKeyBytes(p);
        int pkSize = saberPublicKeyBytes(p);
        byte[] pk = Arrays.copyOfRange(sk, pkOff, pkOff + pkSize);
        return new BCSABERPublicKey(new SABERPublicKeyParameters(p, pk));
    }

    private static int saberIndcpaSecretKeyBytes(SABERParameters p)
    {
        int eq = p.getName().startsWith("u") ? 12 : 13;
        return p.getL() * eq * 32;
    }

    private static int saberPublicKeyBytes(SABERParameters p)
    {
        return p.getL() * 320 + 32;
    }

    /**
     * @return name of the algorithm - "SABER"
     */
    public final String getAlgorithm()
    {
        return "SABER";
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

    public SABERParameterSpec getParameterSpec()
    {
        return SABERParameterSpec.fromName(params.getParameters().getName());
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    SABERPrivateKeyParameters getKeyParams()
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

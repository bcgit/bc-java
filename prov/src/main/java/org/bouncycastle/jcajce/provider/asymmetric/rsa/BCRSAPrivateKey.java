package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Enumeration;

import javax.security.auth.Destroyable;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jcajce.interfaces.BCKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;

public class BCRSAPrivateKey
    implements RSAPrivateKey, Destroyable, PKCS12BagAttributeCarrier, BCKey
{
    static final long serialVersionUID = 5110188922551353628L;

    private static BigInteger ZERO = BigInteger.valueOf(0);

    protected BigInteger modulus;
    protected BigInteger privateExponent;
    private byte[]       algorithmIdentifierEnc = getEncoding(BCRSAPublicKey.DEFAULT_ALGORITHM_IDENTIFIER);

    protected transient AlgorithmIdentifier algorithmIdentifier = BCRSAPublicKey.DEFAULT_ALGORITHM_IDENTIFIER;
    protected transient RSAKeyParameters rsaPrivateKey;
    protected transient PKCS12BagAttributeCarrierImpl   attrCarrier = new PKCS12BagAttributeCarrierImpl();

    private transient volatile boolean destroyed;

    BCRSAPrivateKey(
        RSAKeyParameters key)
    {
        this.modulus = key.getModulus();
        this.privateExponent = key.getExponent();
        this.rsaPrivateKey = key;
    }

    BCRSAPrivateKey(
        AlgorithmIdentifier algID,
        RSAKeyParameters key)
    {
        this.algorithmIdentifier = algID;
        this.algorithmIdentifierEnc = getEncoding(algID);
        
        this.modulus = key.getModulus();
        this.privateExponent = key.getExponent();
        this.rsaPrivateKey = key;
    }

    BCRSAPrivateKey(
        RSAPrivateKeySpec spec)
    {
        this.modulus = spec.getModulus();
        this.privateExponent = spec.getPrivateExponent();
        this.rsaPrivateKey = new RSAKeyParameters(true, modulus, privateExponent);
    }

    BCRSAPrivateKey(
        RSAPrivateKey key)
    {
        this.modulus = key.getModulus();
        this.privateExponent = key.getPrivateExponent();
        this.rsaPrivateKey = new RSAKeyParameters(true, modulus, privateExponent);
    }

    BCRSAPrivateKey(AlgorithmIdentifier algID, org.bouncycastle.asn1.pkcs.RSAPrivateKey key)
    {
        this.algorithmIdentifier = algID;
        this.algorithmIdentifierEnc = getEncoding(algID);

        this.modulus = key.getModulus();
        this.privateExponent = key.getPrivateExponent();
        this.rsaPrivateKey = new RSAKeyParameters(true, modulus, privateExponent);
    }

    public BigInteger getModulus()
    {
        return modulus;
    }

    public BigInteger getPrivateExponent()
    {
        return valueWithCheck(privateExponent);
    }

    BigInteger valueWithCheck(BigInteger value)
    {
        // the null check catches a destroy() in progress whose flag write is not yet visible;
        // as BigInteger is immutable a non-null snapshot is always the intact pre-destroy value.
        if (destroyed || value == null)
        {
            throw new IllegalStateException("key destroyed");
        }

        return value;
    }

    public String getAlgorithm()
    {
        if (algorithmIdentifier.getAlgorithm().equals(PKCSObjectIdentifiers.id_RSASSA_PSS))
        {
            return "RSASSA-PSS";
        }
        return "RSA";
    }

    public String getFormat()
    {
        return "PKCS#8";
    }

    RSAKeyParameters engineGetKeyParameters()
    {
        return rsaPrivateKey;
    }

    public byte[] getEncoded()
    {
        if (destroyed)
        {
            throw new IllegalStateException("key destroyed");
        }

        return KeyUtil.getEncodedPrivateKeyInfo(algorithmIdentifier, new org.bouncycastle.asn1.pkcs.RSAPrivateKey(getModulus(), ZERO, getPrivateExponent(), ZERO, ZERO, ZERO, ZERO, ZERO));
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof RSAPrivateKey))
        {
            return false;
        }

        RSAPrivateKey key = (RSAPrivateKey)o;

        // a destroyed key no longer exposes its value, so it is only equal to itself.
        if (isDestroyed() || ((o instanceof Destroyable) && ((Destroyable)o).isDestroyed()))
        {
            return false;
        }

        int len = Math.max(
            (getModulus().bitLength() + 7) / 8,
            (key.getModulus().bitLength() + 7) / 8);

        return getModulus().equals(key.getModulus())
            && BigIntegers.areSecretValuesEqual(len, getPrivateExponent(), key.getPrivateExponent());
    }

    public int hashCode()
    {
        return getModulus().hashCode();
    }

    /**
     * Destroy this key, clearing the key material it holds.
     * <p>
     * The values are held as {@link BigInteger}s, which are immutable and so cannot be zeroized
     * in place - destruction drops the internal references so the values become unreachable
     * (cleared on garbage collection). The (public) modulus is retained, so {@link #hashCode()}
     * and {@link #getModulus()} remain stable across destruction. The underlying
     * {@link RSAKeyParameters} object is destroyed as well, so keys sharing it are invalidated
     * too. After destruction {@link #isDestroyed()} returns true, {@link #getEncoded()} and
     * {@link #getPrivateExponent()} throw {@link IllegalStateException}, and the key can no
     * longer be serialized.
     */
    public synchronized void destroy()
    {
        if (!destroyed)
        {
            destroyed = true;
            this.privateExponent = null;

            if (rsaPrivateKey != null)
            {
                rsaPrivateKey.destroy();
            }
        }
    }

    public boolean isDestroyed()
    {
        return destroyed;
    }

    public void setBagAttribute(
        ASN1ObjectIdentifier oid,
        ASN1Encodable attribute)
    {
        attrCarrier.setBagAttribute(oid, attribute);
    }

    public ASN1Encodable getBagAttribute(
        ASN1ObjectIdentifier oid)
    {
        return attrCarrier.getBagAttribute(oid);
    }

    public Enumeration getBagAttributeKeys()
    {
        return attrCarrier.getBagAttributeKeys();
    }

    public boolean hasFriendlyName()
    {
        return attrCarrier.hasFriendlyName();
    }

    public void setFriendlyName(String friendlyName)
    {
        attrCarrier.setFriendlyName(friendlyName);
    }
    private void readObject(
        ObjectInputStream   in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        if (algorithmIdentifierEnc == null)
        {
            algorithmIdentifierEnc = getEncoding(BCRSAPublicKey.DEFAULT_ALGORITHM_IDENTIFIER);
        }

        this.algorithmIdentifier = AlgorithmIdentifier.getInstance(algorithmIdentifierEnc);

        this.attrCarrier = new PKCS12BagAttributeCarrierImpl();
        this.rsaPrivateKey = new RSAKeyParameters(true, modulus, privateExponent);
    }

    private synchronized void writeObject(
        ObjectOutputStream  out)
        throws IOException
    {
        // the private values are serialized directly by defaultWriteObject, so a destroyed key
        // cannot be written; IOException, not IllegalStateException, as declared by the contract.
        if (destroyed)
        {
            throw new IOException("key destroyed");
        }

        out.defaultWriteObject();
    }

    public String toString()
    {
        StringBuilder   buf = new StringBuilder();
        String          nl = Strings.lineSeparator();

        buf.append("RSA Private Key [").append(
                    RSAUtil.generateKeyFingerprint(this.getModulus())).append("],[]").append(nl);
        buf.append("            modulus: ").append(this.getModulus().toString(16)).append(nl);

        return buf.toString();
    }

    private static byte[] getEncoding(AlgorithmIdentifier algorithmIdentifier)
    {
        try
        {
            return algorithmIdentifier.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }
}

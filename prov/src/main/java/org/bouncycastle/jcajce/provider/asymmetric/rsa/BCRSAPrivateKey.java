package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.util.Strings;

public class BCRSAPrivateKey
    implements RSAPrivateKey, PKCS12BagAttributeCarrier
{
    static final long serialVersionUID = 5110188922551353628L;

    private static BigInteger ZERO = BigInteger.valueOf(0);

    protected BigInteger modulus;
    protected BigInteger privateExponent;
    private byte[]       algorithmIdentifierEnc = getEncoding(BCRSAPublicKey.DEFAULT_ALGORITHM_IDENTIFIER);

    protected transient AlgorithmIdentifier algorithmIdentifier = BCRSAPublicKey.DEFAULT_ALGORITHM_IDENTIFIER;
    protected transient RSAKeyParameters rsaPrivateKey;
    protected transient PKCS12BagAttributeCarrierImpl   attrCarrier = new PKCS12BagAttributeCarrierImpl();

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
        return privateExponent;
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
        return KeyUtil.getEncodedPrivateKeyInfo(algorithmIdentifier, new org.bouncycastle.asn1.pkcs.RSAPrivateKey(getModulus(), ZERO, getPrivateExponent(), ZERO, ZERO, ZERO, ZERO, ZERO));
    }

    public boolean equals(Object o)
    {
        if (!(o instanceof RSAPrivateKey))
        {
            return false;
        }

        if (o == this)
        {
            return true;
        }

        RSAPrivateKey key = (RSAPrivateKey)o;

        return getModulus().equals(key.getModulus())
            && getPrivateExponent().equals(key.getPrivateExponent());
    }

    public int hashCode()
    {
        return getModulus().hashCode() ^ getPrivateExponent().hashCode();
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

    private void writeObject(
        ObjectOutputStream  out)
        throws IOException
    {
        out.defaultWriteObject();
    }

    public String toString()
    {
        StringBuffer    buf = new StringBuffer();
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

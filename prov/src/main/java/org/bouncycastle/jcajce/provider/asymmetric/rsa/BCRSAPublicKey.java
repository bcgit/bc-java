package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
import org.bouncycastle.util.Strings;

public class BCRSAPublicKey
    implements RSAPublicKey
{
    static final AlgorithmIdentifier DEFAULT_ALGORITHM_IDENTIFIER = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);

    static final long serialVersionUID = 2675817738516720772L;

    private BigInteger modulus;
    private BigInteger publicExponent;

    private transient AlgorithmIdentifier algorithmIdentifier;
    private transient RSAKeyParameters rsaPublicKey;

    BCRSAPublicKey(
        RSAKeyParameters key)
    {
        this(DEFAULT_ALGORITHM_IDENTIFIER, key);
    }

    BCRSAPublicKey(
        AlgorithmIdentifier algId,
        RSAKeyParameters key)
    {
        this.algorithmIdentifier = algId;
        this.modulus = key.getModulus();
        this.publicExponent = key.getExponent();
        this.rsaPublicKey = key;
    }

    BCRSAPublicKey(
        RSAPublicKeySpec spec)
    {
        this.algorithmIdentifier = DEFAULT_ALGORITHM_IDENTIFIER;
        this.modulus = spec.getModulus();
        this.publicExponent = spec.getPublicExponent();
        this.rsaPublicKey = new RSAKeyParameters(false, modulus, publicExponent);
    }

    BCRSAPublicKey(
        RSAPublicKey key)
    {
        this.algorithmIdentifier = DEFAULT_ALGORITHM_IDENTIFIER;
        this.modulus = key.getModulus();
        this.publicExponent = key.getPublicExponent();
        this.rsaPublicKey = new RSAKeyParameters(false, modulus, publicExponent);
    }

    BCRSAPublicKey(
        SubjectPublicKeyInfo info)
    {
        populateFromPublicKeyInfo(info);
    }

    private void populateFromPublicKeyInfo(SubjectPublicKeyInfo info)
    {
        try
        {
            org.bouncycastle.asn1.pkcs.RSAPublicKey  pubKey = org.bouncycastle.asn1.pkcs.RSAPublicKey.getInstance(info.parsePublicKey());

            this.algorithmIdentifier = info.getAlgorithm();
            this.modulus = pubKey.getModulus();
            this.publicExponent = pubKey.getPublicExponent();
            this.rsaPublicKey = new RSAKeyParameters(false, modulus, publicExponent);
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("invalid info structure in RSA public key");
        }
    }

    /**
     * return the modulus.
     *
     * @return the modulus.
     */
    public BigInteger getModulus()
    {
        return modulus;
    }

    /**
     * return the public exponent.
     *
     * @return the public exponent.
     */
    public BigInteger getPublicExponent()
    {
        return publicExponent;
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
        return "X.509";
    }

    public byte[] getEncoded()
    {
        return KeyUtil.getEncodedSubjectPublicKeyInfo(algorithmIdentifier, new org.bouncycastle.asn1.pkcs.RSAPublicKey(getModulus(), getPublicExponent()));
    }

    RSAKeyParameters engineGetKeyParameters()
    {
        return rsaPublicKey;
    }

    public int hashCode()
    {
        return this.getModulus().hashCode() ^ this.getPublicExponent().hashCode();
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof RSAPublicKey))
        {
            return false;
        }

        RSAPublicKey key = (RSAPublicKey)o;

        return getModulus().equals(key.getModulus())
            && getPublicExponent().equals(key.getPublicExponent());
    }

    public String toString()
    {
        StringBuffer    buf = new StringBuffer();
        String          nl = Strings.lineSeparator();

        buf.append("RSA Public Key [").append(RSAUtil.generateKeyFingerprint(this.getModulus())).append("]")
            .append(",[")
            .append(RSAUtil.generateExponentFingerprint(this.getPublicExponent()))
            .append("]")
            .append(nl);
        buf.append("        modulus: ").append(this.getModulus().toString(16)).append(nl);
        buf.append("public exponent: ").append(this.getPublicExponent().toString(16)).append(nl);
        
        return buf.toString();
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        try
        {
            algorithmIdentifier = AlgorithmIdentifier.getInstance(in.readObject());
        }
        catch (Exception e)
        {
            algorithmIdentifier = DEFAULT_ALGORITHM_IDENTIFIER;
        }
        this.rsaPublicKey = new RSAKeyParameters(false, modulus, publicExponent);
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        if (!algorithmIdentifier.equals(DEFAULT_ALGORITHM_IDENTIFIER))
        {
            out.writeObject(algorithmIdentifier.getEncoded());
        }
    }
}

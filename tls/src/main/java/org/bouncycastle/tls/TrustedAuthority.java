package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.util.Arrays;

public class TrustedAuthority
{
    protected short identifierType;
    protected Object identifier;

    public TrustedAuthority(short identifierType, Object identifier)
    {
        if (!isCorrectType(identifierType, identifier))
        {
            throw new IllegalArgumentException("'identifier' is not an instance of the correct type");
        }

        this.identifierType = identifierType;
        this.identifier = identifier;
    }

    public short getIdentifierType()
    {
        return identifierType;
    }

    public Object getIdentifier()
    {
        return identifier;
    }

    public byte[] getCertSHA1Hash()
    {
        return Arrays.clone((byte[])identifier);
    }

    public byte[] getKeySHA1Hash()
    {
        return Arrays.clone((byte[])identifier);
    }

    public X500Name getX509Name()
    {
        checkCorrectType(IdentifierType.x509_name);
        return (X500Name)identifier;
    }

    /**
     * Encode this {@link TrustedAuthority} to an {@link OutputStream}.
     * 
     * @param output
     *            the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(OutputStream output) throws IOException
    {
        TlsUtils.writeUint8(identifierType, output);

        switch (identifierType)
        {
        case IdentifierType.cert_sha1_hash:
        case IdentifierType.key_sha1_hash:
        {
            byte[] sha1Hash = (byte[])identifier;
            output.write(sha1Hash);
            break;
        }
        case IdentifierType.pre_agreed:
        {
            break;
        }
        case IdentifierType.x509_name:
        {
            X500Name dn = (X500Name)identifier;
            byte[] derEncoding = dn.getEncoded(ASN1Encoding.DER);
            TlsUtils.writeOpaque16(derEncoding, output);
            break;
        }
        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }

    /**
     * Parse a {@link TrustedAuthority} from an {@link InputStream}.
     *
     * @param input
     *            the {@link InputStream} to parse from.
     * @return a {@link TrustedAuthority} object.
     * @throws IOException
     */
    public static TrustedAuthority parse(InputStream input) throws IOException
    {
        short identifier_type = TlsUtils.readUint8(input);
        Object identifier;

        switch (identifier_type)
        {
        case IdentifierType.cert_sha1_hash:
        case IdentifierType.key_sha1_hash:
        {
            identifier = TlsUtils.readFully(20, input);
            break;
        }
        case IdentifierType.pre_agreed:
        {
            identifier = null;
            break;
        }
        case IdentifierType.x509_name:
        {
            byte[] derEncoding = TlsUtils.readOpaque16(input, 1);
            ASN1Primitive asn1 = TlsUtils.readDERObject(derEncoding);
            identifier = X500Name.getInstance(asn1);
            break;
        }
        default:
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        return new TrustedAuthority(identifier_type, identifier);
    }

    protected void checkCorrectType(short expectedIdentifierType)
    {
        if (this.identifierType != expectedIdentifierType
            || !isCorrectType(expectedIdentifierType, this.identifier))
        {
            throw new IllegalStateException("TrustedAuthority is not of type " + IdentifierType.getName(expectedIdentifierType));
        }
    }

    protected static boolean isCorrectType(short identifierType, Object identifier)
    {
        switch (identifierType)
        {
        case IdentifierType.cert_sha1_hash:
        case IdentifierType.key_sha1_hash:
            return isSHA1Hash(identifier);
        case IdentifierType.pre_agreed:
            return identifier == null;
        case IdentifierType.x509_name:
            return identifier instanceof X500Name;
        default:
            throw new IllegalArgumentException("'identifierType' is an unsupported IdentifierType");
        }
    }

    protected static boolean isSHA1Hash(Object identifier)
    {
        return identifier instanceof byte[] && ((byte[])identifier).length == 20;
    }
}

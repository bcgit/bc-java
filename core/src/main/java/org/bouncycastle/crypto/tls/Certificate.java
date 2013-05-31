package org.bouncycastle.crypto.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * Parsing and encoding of a <i>Certificate</i> struct from RFC 4346.
 * <p/>
 * <pre>
 * opaque ASN.1Cert<2^24-1>;
 *
 * struct {
 *     ASN.1Cert certificate_list<0..2^24-1>;
 * } Certificate;
 * </pre>
 *
 * @see org.bouncycastle.asn1.x509.Certificate
 */
public class Certificate
{

    public static final Certificate EMPTY_CHAIN = new Certificate(
        new org.bouncycastle.asn1.x509.Certificate[0]);

    protected org.bouncycastle.asn1.x509.Certificate[] certificateList;

    public Certificate(org.bouncycastle.asn1.x509.Certificate[] certificateList)
    {
        if (certificateList == null)
        {
            throw new IllegalArgumentException("'certificateList' cannot be null");
        }

        this.certificateList = certificateList;
    }

    /**
     * @deprecated use {@link #getCertificateList()} instead
     */
    public org.bouncycastle.asn1.x509.Certificate[] getCerts()
    {
        return clone(certificateList);
    }

    /**
     * @return an array of {@link org.bouncycastle.asn1.x509.Certificate} representing a certificate
     *         chain.
     */
    public org.bouncycastle.asn1.x509.Certificate[] getCertificateList()
    {
        return clone(certificateList);
    }

    public org.bouncycastle.asn1.x509.Certificate getCertificateAt(int index)
    {
        return certificateList[index];
    }

    public int getLength()
    {
        return certificateList.length;
    }

    /**
     * @return <code>true</code> if this certificate chain contains no certificates, or
     *         <code>false</code> otherwise.
     */
    public boolean isEmpty()
    {
        return certificateList.length == 0;
    }

    /**
     * Encode this {@link Certificate} to an {@link OutputStream}.
     *
     * @param output the {@link OutputStream} to encode to.
     * @throws IOException
     */
    public void encode(OutputStream output)
        throws IOException
    {
        Vector encCerts = new Vector(this.certificateList.length);
        int totalLength = 0;
        for (int i = 0; i < this.certificateList.length; ++i)
        {
            byte[] encCert = certificateList[i].getEncoded(ASN1Encoding.DER);
            encCerts.addElement(encCert);
            totalLength += encCert.length + 3;
        }

        TlsUtils.writeUint24(totalLength, output);

        for (int i = 0; i < encCerts.size(); ++i)
        {
            byte[] encCert = (byte[])encCerts.elementAt(i);
            TlsUtils.writeOpaque24(encCert, output);
        }
    }

    /**
     * Parse a {@link Certificate} from an {@link InputStream}.
     *
     * @param input the {@link InputStream} to parse from.
     * @return a {@link Certificate} object.
     * @throws IOException
     */
    public static Certificate parse(InputStream input)
        throws IOException
    {
        org.bouncycastle.asn1.x509.Certificate[] certs;
        int left = TlsUtils.readUint24(input);
        if (left == 0)
        {
            return EMPTY_CHAIN;
        }
        Vector tmp = new Vector();
        while (left > 0)
        {
            int size = TlsUtils.readUint24(input);
            left -= 3 + size;

            byte[] buf = TlsUtils.readFully(size, input);

            ByteArrayInputStream bis = new ByteArrayInputStream(buf);
            ASN1Primitive asn1 = new ASN1InputStream(bis).readObject();
            TlsProtocol.assertEmpty(bis);

            tmp.addElement(org.bouncycastle.asn1.x509.Certificate.getInstance(asn1));
        }
        certs = new org.bouncycastle.asn1.x509.Certificate[tmp.size()];
        for (int i = 0; i < tmp.size(); i++)
        {
            certs[i] = (org.bouncycastle.asn1.x509.Certificate)tmp.elementAt(i);
        }
        return new Certificate(certs);
    }

    private org.bouncycastle.asn1.x509.Certificate[] clone(org.bouncycastle.asn1.x509.Certificate[] list)
    {
        org.bouncycastle.asn1.x509.Certificate[] rv = new org.bouncycastle.asn1.x509.Certificate[list.length];

        System.arraycopy(list, 0, rv, 0, rv.length);

        return rv;
    }
}

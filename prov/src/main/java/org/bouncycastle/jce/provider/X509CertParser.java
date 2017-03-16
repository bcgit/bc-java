package org.bouncycastle.jce.provider;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.SignedData;
import org.bouncycastle.x509.X509StreamParserSpi;
import org.bouncycastle.x509.util.StreamParsingException;

/**
 * @deprecated use CertificateFactory or the PEMParser in the openssl package (pkix jar).
 */
public class X509CertParser
    extends X509StreamParserSpi
{
    private static final PEMUtil PEM_PARSER = new PEMUtil("CERTIFICATE");

    private ASN1Set     sData = null;
    private int         sDataObjectCount = 0;
    private InputStream currentStream = null;

    private Certificate readDERCertificate(
        InputStream in)
        throws IOException, CertificateParsingException
    {
        ASN1InputStream dIn = new ASN1InputStream(in);
        ASN1Sequence seq = (ASN1Sequence)dIn.readObject();

        if (seq.size() > 1
                && seq.getObjectAt(0) instanceof ASN1ObjectIdentifier)
        {
            if (seq.getObjectAt(0).equals(PKCSObjectIdentifiers.signedData))
            {
                sData = new SignedData(ASN1Sequence.getInstance(
                                (ASN1TaggedObject)seq.getObjectAt(1), true)).getCertificates();

                return getCertificate();
            }
        }

        return new X509CertificateObject(
                            org.bouncycastle.asn1.x509.Certificate.getInstance(seq));
    }

    private Certificate getCertificate()
        throws CertificateParsingException
    {
        if (sData != null)
        {
            while (sDataObjectCount < sData.size())
            {
                Object obj = sData.getObjectAt(sDataObjectCount++);

                if (obj instanceof ASN1Sequence)
                {
                   return new X509CertificateObject(
                                    org.bouncycastle.asn1.x509.Certificate.getInstance(obj));
                }
            }
        }

        return null;
    }

    private Certificate readPEMCertificate(
        InputStream  in)
        throws IOException, CertificateParsingException
    {
        ASN1Sequence seq = PEM_PARSER.readPEMObject(in);

        if (seq != null)
        {
            return new X509CertificateObject(
                            org.bouncycastle.asn1.x509.Certificate.getInstance(seq));
        }

        return null;
    }

    public void engineInit(InputStream in)
    {
        currentStream = in;
        sData = null;
        sDataObjectCount = 0;

        if (!currentStream.markSupported())
        {
            currentStream = new BufferedInputStream(currentStream);
        }
    }

    public Object engineRead()
        throws StreamParsingException
    {
        try
        {
            if (sData != null)
            {
                if (sDataObjectCount != sData.size())
                {
                    return getCertificate();
                }
                else
                {
                    sData = null;
                    sDataObjectCount = 0;
                    return null;
                }
            }

            currentStream.mark(10);
            int    tag = currentStream.read();

            if (tag == -1)
            {
                return null;
            }

            if (tag != 0x30)  // assume ascii PEM encoded.
            {
                currentStream.reset();
                return readPEMCertificate(currentStream);
            }
            else
            {
                currentStream.reset();
                return readDERCertificate(currentStream);
            }
        }
        catch (Exception e)
        {
            throw new StreamParsingException(e.toString(), e);
        }
    }

    public Collection engineReadAll()
        throws StreamParsingException
    {
        Certificate     cert;
        List certs = new ArrayList();

        while ((cert = (Certificate)engineRead()) != null)
        {
            certs.add(cert);
        }

        return certs;
    }
}

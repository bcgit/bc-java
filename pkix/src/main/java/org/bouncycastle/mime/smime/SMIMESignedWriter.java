package org.bouncycastle.mime.smime;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.mime.Headers;
import org.bouncycastle.mime.MimeWriter;
import org.bouncycastle.mime.encoding.Base64OutputStream;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.Strings;

/**
 * Writer for SMIME Signed objects.
 */
public class SMIMESignedWriter
    extends MimeWriter
{
    public static final Map RFC3851_MICALGS;
    public static final Map RFC5751_MICALGS;
    public static final Map STANDARD_MICALGS;

    static
    {
        Map stdMicAlgs = new HashMap();

        stdMicAlgs.put(CMSAlgorithm.MD5, "md5");
        stdMicAlgs.put(CMSAlgorithm.SHA1, "sha-1");
        stdMicAlgs.put(CMSAlgorithm.SHA224, "sha-224");
        stdMicAlgs.put(CMSAlgorithm.SHA256, "sha-256");
        stdMicAlgs.put(CMSAlgorithm.SHA384, "sha-384");
        stdMicAlgs.put(CMSAlgorithm.SHA512, "sha-512");
        stdMicAlgs.put(CMSAlgorithm.GOST3411, "gostr3411-94");
        stdMicAlgs.put(CMSAlgorithm.GOST3411_2012_256, "gostr3411-2012-256");
        stdMicAlgs.put(CMSAlgorithm.GOST3411_2012_512, "gostr3411-2012-512");

        RFC5751_MICALGS = Collections.unmodifiableMap(stdMicAlgs);

        Map oldMicAlgs = new HashMap();

        oldMicAlgs.put(CMSAlgorithm.MD5, "md5");
        oldMicAlgs.put(CMSAlgorithm.SHA1, "sha1");
        oldMicAlgs.put(CMSAlgorithm.SHA224, "sha224");
        oldMicAlgs.put(CMSAlgorithm.SHA256, "sha256");
        oldMicAlgs.put(CMSAlgorithm.SHA384, "sha384");
        oldMicAlgs.put(CMSAlgorithm.SHA512, "sha512");
        oldMicAlgs.put(CMSAlgorithm.GOST3411, "gostr3411-94");
        oldMicAlgs.put(CMSAlgorithm.GOST3411_2012_256, "gostr3411-2012-256");
        oldMicAlgs.put(CMSAlgorithm.GOST3411_2012_512, "gostr3411-2012-512");

        RFC3851_MICALGS = Collections.unmodifiableMap(oldMicAlgs);

        STANDARD_MICALGS = RFC5751_MICALGS;
    }

    public static class Builder
    {
        private static final String[] detHeaders;
        private static final String[] detValues;
        private static final String[] encHeaders;
        private static final String[] encValues;

        static
        {
            detHeaders = new String[]
                {
                    "Content-Type"
                };

            detValues = new String[]
                {
                    "multipart/signed; protocol=\"application/pkcs7-signature\"",
                };

            encHeaders = new String[]
                {
                    "Content-Type",
                    "Content-Disposition",
                    "Content-Transfer-Encoding",
                    "Content-Description"
                };

            encValues = new String[]
                {
                    "application/pkcs7-mime; name=\"smime.p7m\"; smime-type=enveloped-data",
                    "attachment; filename=\"smime.p7m\"",
                    "base64",
                    "S/MIME Signed Message"
                };
        }

        private final CMSSignedDataStreamGenerator sigGen = new CMSSignedDataStreamGenerator();
        private final Map<String, String> extraHeaders = new LinkedHashMap<String, String>();
        private final boolean encapsulated;
        private final Map micAlgs = STANDARD_MICALGS;
        
        String contentTransferEncoding = "base64";

        public Builder()
        {
            this(false);
        }

        public Builder(
            boolean encapsulated)
        {
            this.encapsulated = encapsulated;
        }

        /**
         * Specify a MIME header (name, value) pair for this builder. If the headerName already exists it will
         * be overridden.
         *
         * @param headerName  name of the MIME header.
         * @param headerValue value of the MIME header.
         * @return the current Builder instance.
         */
        public Builder withHeader(String headerName, String headerValue)
        {
            this.extraHeaders.put(headerName, headerValue);

            return this;
        }

        public Builder addCertificate(X509CertificateHolder certificate)
            throws CMSException
        {
            this.sigGen.addCertificate(certificate);

            return this;
        }

        public Builder addCertificates(Store certificates)
            throws CMSException
        {
            this.sigGen.addCertificates(certificates);

            return this;
        }

        /**
         * Add a generator to produce the signer info required.
         *
         * @param signerGenerator a generator for a signer info object.
         * @return the current Builder instance.
         */
        public Builder addSignerInfoGenerator(SignerInfoGenerator signerGenerator)
        {
            this.sigGen.addSignerInfoGenerator(signerGenerator);

            return this;
        }

        public SMIMESignedWriter build(OutputStream mimeOut)
        {
            Map<String, String> headers = new LinkedHashMap<String, String>();

            String boundary;
            if (encapsulated)
            {
                boundary = null;
                for (int i = 0; i != encHeaders.length; i++)
                {
                    headers.put(encHeaders[i], encValues[i]);
                }
            }
            else
            {
                boundary = generateBoundary();

                // handle Content-Type specially
                StringBuffer contValue = new StringBuffer(detValues[0]);

                addHashHeader(contValue, sigGen.getDigestAlgorithms());

                addBoundary(contValue, boundary);
                headers.put(detHeaders[0], contValue.toString());

                for (int i = 1; i < detHeaders.length; i++)
                {
                    headers.put(detHeaders[i], detValues[i]);
                }
            }

            for (Iterator it = extraHeaders.entrySet().iterator(); it.hasNext();)
            {
                Map.Entry ent = (Map.Entry)it.next();
                headers.put((String)ent.getKey(), (String)ent.getValue());
            }

            return new SMIMESignedWriter(this, headers, boundary, SMimeUtils.autoBuffer(mimeOut));
        }

        private void addHashHeader(
            StringBuffer header,
            List signers)
        {
            int count = 0;

            //
            // build the hash header
            //
            Iterator it = signers.iterator();
            Set micAlgSet = new TreeSet();

            while (it.hasNext())
            {
                AlgorithmIdentifier digest = (AlgorithmIdentifier)it.next();

                String micAlg = (String)micAlgs.get(digest.getAlgorithm());

                if (micAlg == null)
                {
                    micAlgSet.add("unknown");
                }
                else
                {
                    micAlgSet.add(micAlg);
                }
            }

            it = micAlgSet.iterator();

            while (it.hasNext())
            {
                String alg = (String)it.next();

                if (count == 0)
                {
                    if (micAlgSet.size() != 1)
                    {
                        header.append("; micalg=\"");
                    }
                    else
                    {
                        header.append("; micalg=");
                    }
                }
                else
                {
                    header.append(',');
                }

                header.append(alg);

                count++;
            }

            if (count != 0)
            {
                if (micAlgSet.size() != 1)
                {
                    header.append('\"');
                }
            }
        }

        private void addBoundary(
             StringBuffer header,
             String boundary)
        {
             header.append(";\r\n\tboundary=\"");
             header.append(boundary);
             header.append("\"");
        }

        private String generateBoundary()
        {
            SecureRandom random = new SecureRandom();

            return "==" + new BigInteger(180, random).setBit(179).toString(16) + "=";
        }
    }

    private final CMSSignedDataStreamGenerator sigGen;

    private final String boundary;
    private final OutputStream mimeOut;
    private final String contentTransferEncoding;

    private SMIMESignedWriter(Builder builder, Map<String, String> headers, String boundary, OutputStream mimeOut)
    {
        super(new Headers(mapToLines(headers), builder.contentTransferEncoding));

        this.sigGen = builder.sigGen;
        this.contentTransferEncoding = builder.contentTransferEncoding;
        this.boundary = boundary;
        this.mimeOut = mimeOut;
    }

    /**
     * Return a content stream for the signer - note data written to this stream needs to properly
     * canonicalised if necessary.
     *
     * @return an output stream for data to be signed to be written to.
     * @throws IOException on a stream error.
     */
    public OutputStream getContentStream()
        throws IOException
    {
        headers.dumpHeaders(mimeOut);

        mimeOut.write(Strings.toByteArray("\r\n"));

        if (boundary == null)
        {
            return null; // TODO: new ContentOutputStream(sigGen.open(mimeOut, true), mimeOut);
        }
        else
        {
            mimeOut.write(Strings.toByteArray("This is an S/MIME signed message\r\n"));
            mimeOut.write(Strings.toByteArray("\r\n--"));
            mimeOut.write(Strings.toByteArray(boundary));
            mimeOut.write(Strings.toByteArray("\r\n"));

            ByteArrayOutputStream bOut = new ByteArrayOutputStream();

            Base64OutputStream stream = new Base64OutputStream(bOut);

            return new ContentOutputStream(sigGen.open(stream,false, SMimeUtils.createUnclosable(mimeOut)), mimeOut, bOut, stream);
        }
    }

    private class ContentOutputStream
        extends OutputStream
    {
        private final OutputStream main;
        private final OutputStream backing;
        private final ByteArrayOutputStream sigStream;
        private final OutputStream sigBase;

        ContentOutputStream(OutputStream main, OutputStream backing, ByteArrayOutputStream sigStream, OutputStream sigBase)
        {
            this.main = main;
            this.backing = backing;
            this.sigStream = sigStream;
            this.sigBase = sigBase;
        }

        public void write(byte[] buf)
            throws IOException
        {
            main.write(buf);
        }

        public void write(byte[] buf, int off, int len)
            throws IOException
        {
            main.write(buf, off, len);
        }

        public void write(int i)
            throws IOException
        {
            main.write(i);
        }

        public void close()
            throws IOException
        {
            if (boundary != null)
            {
                main.close();

                backing.write(Strings.toByteArray("\r\n--"));
                backing.write(Strings.toByteArray(boundary));
                backing.write(Strings.toByteArray("\r\n"));

                backing.write(Strings.toByteArray("Content-Type: application/pkcs7-signature; name=\"smime.p7s\"\r\n"));
                backing.write(Strings.toByteArray("Content-Transfer-Encoding: base64\r\n"));
                backing.write(Strings.toByteArray("Content-Disposition: attachment; filename=\"smime.p7s\"\r\n"));
                backing.write(Strings.toByteArray("\r\n"));

                if (sigBase != null)
                {
                    sigBase.close();
                }
                
                backing.write(sigStream.toByteArray());

                backing.write(Strings.toByteArray("\r\n--"));
                backing.write(Strings.toByteArray(boundary));
                backing.write(Strings.toByteArray("--\r\n"));
            }

            if (backing != null)
            {
                backing.close();
            }
        }
    }
}

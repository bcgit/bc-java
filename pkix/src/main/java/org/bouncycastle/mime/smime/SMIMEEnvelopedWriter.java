package org.bouncycastle.mime.smime;

import java.io.IOException;
import java.io.OutputStream;
import java.util.LinkedHashMap;
import java.util.Map;

import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.OriginatorInformation;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.mime.Headers;
import org.bouncycastle.mime.MimeIOException;
import org.bouncycastle.mime.MimeWriter;
import org.bouncycastle.mime.encoding.Base64OutputStream;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.Strings;

/**
 * Writer for SMIME Enveloped objects.
 */
public class SMIMEEnvelopedWriter
    extends MimeWriter
{
    public static class Builder
    {
        private static final String[] stdHeaders;
        private static final String[] stdValues;

        static
        {
            stdHeaders = new String[]
                {
                    "Content-Type",
                    "Content-Disposition",
                    "Content-Transfer-Encoding",
                    "Content-Description"
                };

            stdValues = new String[]
                {
                    "application/pkcs7-mime; name=\"smime.p7m\"; smime-type=enveloped-data",
                    "attachment; filename=\"smime.p7m\"",
                    "base64",
                    "S/MIME Encrypted Message"
                };
        }

        private final CMSEnvelopedDataStreamGenerator envGen = new CMSEnvelopedDataStreamGenerator();
        private final Map<String, String> headers = new LinkedHashMap<String, String>();

        String contentTransferEncoding = "base64";

        public Builder()
        {
            for (int i = 0; i != stdHeaders.length; i++)
            {
                headers.put(stdHeaders[i], stdValues[i]);
            }
        }

        /**
         * Set the underlying string size for encapsulated data
         *
         * @param bufferSize length of octet strings to buffer the data.
         */
        public Builder setBufferSize(
            int bufferSize)
        {
            this.envGen.setBufferSize(bufferSize);

            return this;
        }

        public Builder setUnprotectedAttributeGenerator(CMSAttributeTableGenerator unprotectedAttributeGenerator)
        {
            this.envGen.setUnprotectedAttributeGenerator(unprotectedAttributeGenerator);

            return this;
        }

        public Builder setOriginatorInfo(OriginatorInformation originatorInfo)
        {
            this.envGen.setOriginatorInfo(originatorInfo);

            return this;
        }

        /**
         * Specify a MIME header (name, value) pair for this builder. If the headerName already exists it will
         * be overridden.
         *
         * @param headerName name of the MIME header.
         * @param headerValue value of the MIME header.
         *
         * @return the current Builder instance.
         */
        public Builder withHeader(String headerName, String headerValue)
        {
            this.headers.put(headerName, headerValue);

            return this;
        }
        
        /**
         * Add a generator to produce the recipient info required.
         *
         * @param recipientGenerator a generator of a recipient info object.
         *
         * @return the current Builder instance.
         */
        public Builder addRecipientInfoGenerator(RecipientInfoGenerator recipientGenerator)
        {
            this.envGen.addRecipientInfoGenerator(recipientGenerator);

            return this;
        }

        public SMIMEEnvelopedWriter build(OutputStream mimeOut, OutputEncryptor outEnc)
        {
            return new SMIMEEnvelopedWriter(this, outEnc, SMimeUtils.autoBuffer(mimeOut));
        }
    }

    private final CMSEnvelopedDataStreamGenerator envGen;

    private final OutputEncryptor outEnc;
    private final OutputStream mimeOut;
    private final String contentTransferEncoding;

    private SMIMEEnvelopedWriter(Builder builder, OutputEncryptor outEnc, OutputStream mimeOut)
    {
        super(new Headers(mapToLines(builder.headers), builder.contentTransferEncoding));

        this.envGen = builder.envGen;
        this.contentTransferEncoding = builder.contentTransferEncoding;
        this.outEnc = outEnc;
        this.mimeOut = mimeOut;
    }
    
    public OutputStream getContentStream()
        throws IOException
    {
        headers.dumpHeaders(mimeOut);

        mimeOut.write(Strings.toByteArray("\r\n"));

        try
        {
            OutputStream backing = mimeOut;

            if ("base64".equals(contentTransferEncoding))
            {
                backing = new Base64OutputStream(backing);
            }

            OutputStream main = envGen.open(SMimeUtils.createUnclosable(backing), outEnc);

            return new ContentOutputStream(main, backing);
        }
        catch (CMSException e)
        {
            throw new MimeIOException(e.getMessage(), e);
        }
    }

    private class ContentOutputStream
        extends OutputStream
    {
        private final OutputStream main;
        private final OutputStream backing;

        ContentOutputStream(OutputStream main, OutputStream backing)
        {
            this.main = main;
            this.backing = backing;
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
            main.close();
            if (backing != null)
            {
                backing.close();
            }
        }
    }
}

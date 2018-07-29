package org.bouncycastle.mime.smime;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.mime.CanonicalOutputStream;
import org.bouncycastle.mime.Headers;
import org.bouncycastle.mime.MimeContext;
import org.bouncycastle.mime.MimeMultipartContext;
import org.bouncycastle.mime.MimeParserContext;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.io.TeeInputStream;

public class SMimeMultipartContext
    implements MimeMultipartContext
{
    private final SMimeParserContext parserContext;
    private DigestCalculator[] calculators;

    public SMimeMultipartContext(MimeParserContext parserContext, Headers headers)
    {
        this.parserContext = (SMimeParserContext)parserContext;
        this.calculators = createDigestCalculators();
    }

    DigestCalculator[] getDigestCalculators()
    {
        return calculators;
    }

    private DigestCalculator[] createDigestCalculators()
    {
        try
        {
            return new DigestCalculator[] { parserContext.getDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)) };
        }
        catch (OperatorCreationException e)
        {
            return null;
        }
    }

    @Override
    public MimeContext createContext(final int partNo)
        throws IOException
    {
        return new MimeContext()
        {
            @Override
            public InputStream applyContext(Headers headers, InputStream contentStream)
                throws IOException
            {
                if (partNo == 0)
                {
                    OutputStream digestOut = SMimeMultipartContext.this.getDigestCalculators()[0].getOutputStream();

                    headers.dumpHeaders(digestOut);

                    digestOut.write('\r');
                    digestOut.write('\n');

                    return new TeeInputStream(contentStream, new CanonicalOutputStream(parserContext, headers, digestOut));
                }

                return contentStream;
            }
        };
    }

    @Override
    public InputStream applyContext(Headers headers, InputStream contentStream)
        throws IOException
    {
        return contentStream;
    }
}

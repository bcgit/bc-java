package org.bouncycastle.mime.smime;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.mime.CanonicalOutputStream;
import org.bouncycastle.mime.Headers;
import org.bouncycastle.mime.MimeContext;
import org.bouncycastle.mime.MimeMultipartContext;
import org.bouncycastle.mime.MimeParserContext;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.io.TeeInputStream;
import org.bouncycastle.util.io.TeeOutputStream;

public class SMimeMultipartContext
    implements MimeMultipartContext
{
    private final SMimeParserContext parserContext;

    private DigestCalculator[] calculators;


    public SMimeMultipartContext(MimeParserContext parserContext, Headers headers)
    {
        this.parserContext = (SMimeParserContext)parserContext;
        this.calculators = createDigestCalculators(headers);
    }

    DigestCalculator[] getDigestCalculators()
    {
        return calculators;
    }

    OutputStream getDigestOutputStream()
    {
        if (calculators.length == 1)
        {
            return calculators[0].getOutputStream();
        }
        else
        {
            OutputStream compoundStream = calculators[0].getOutputStream();

            for (int i = 1; i < calculators.length; i++)
            {
                compoundStream = new TeeOutputStream(calculators[i].getOutputStream(), compoundStream);
            }

            return compoundStream;
        }
    }

    private DigestCalculator[] createDigestCalculators(Headers headers)
    {
        try
        {
            Map<String, String> contentTypeFields = headers.getContentTypeAttributes();

            String micalgs = (String)contentTypeFields.get("micalg");
            if (micalgs == null)
            {
                throw new IllegalStateException("No micalg field on content-type header");
            }

            String[] algs = micalgs.substring(micalgs.indexOf('=') + 1).split(",");
            DigestCalculator[] dcOut = new DigestCalculator[algs.length];

            for (int t = 0; t < algs.length; t++)
            {
                // Deal with possibility of quoted parts, eg  "SHA1","SHA256" etc
                String alg = SMimeUtils.lessQuotes(algs[t]).trim();
                dcOut[t] = parserContext.getDigestCalculatorProvider().get(
                    new AlgorithmIdentifier(SMimeUtils.getDigestOID(alg)));
            }

            return dcOut;
        }
        catch (OperatorCreationException e)
        {
            return null;
        }
    }

    public MimeContext createContext(final int partNo)
        throws IOException
    {
        return new MimeContext()
        {
            public InputStream applyContext(Headers headers, InputStream contentStream)
                throws IOException
            {
                if (partNo == 0)
                {
                    OutputStream digestOut = getDigestOutputStream();

                    headers.dumpHeaders(digestOut);

                    digestOut.write('\r');
                    digestOut.write('\n');

                    return new TeeInputStream(contentStream, new CanonicalOutputStream(parserContext, headers, digestOut));
                }

                return contentStream;
            }
        };
    }

    public InputStream applyContext(Headers headers, InputStream contentStream)
        throws IOException
    {
        return contentStream;
    }
}

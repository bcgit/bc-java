package org.bouncycastle.cms;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.BERSequenceParser;
import org.bouncycastle.asn1.cms.ContentInfoParser;

public class CMSContentInfoParser
{
    protected ContentInfoParser _contentInfo;
    protected InputStream       _data;

    private final boolean       _berEncoded;

    protected CMSContentInfoParser(
        InputStream data)
        throws CMSException
    {
        _data = data;

        try
        {
            ASN1StreamParser in = new ASN1StreamParser(data);
            ASN1SequenceParser seqParser = (ASN1SequenceParser)in.readObject();

            if (seqParser == null)
            {
                throw new CMSException("No content found.");
            }

            _berEncoded = seqParser instanceof BERSequenceParser;

            _contentInfo = new ContentInfoParser(seqParser);
        }
        catch (IOException e)
        {
            throw new CMSException("IOException reading content.", e);
        }
        catch (ClassCastException e)
        {
            throw new CMSException("Unexpected object reading content.", e);
        }
    }
    
    /**
     * Return true if the outer ContentInfo SEQUENCE of the stream used the
     * indefinite-length (BER) method, false if it carried a definite length
     * (DL/DER). Wire encodings that need to be reproduced or canonicalised
     * exactly (e.g. ETSI archive-time-stamp imprints over the original
     * coding) can use this to learn the original framing without a second
     * pass over the data (see github #1983).
     *
     * @return true for an indefinite-length (BER) ContentInfo, false otherwise.
     */
    public boolean isBEREncoded()
    {
        return _berEncoded;
    }

    /**
     * Close the underlying data stream.
     * @throws IOException if the close fails.
     */
    public void close() throws IOException
    {
        _data.close();
    }
}

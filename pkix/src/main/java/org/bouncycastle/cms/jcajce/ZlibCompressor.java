package org.bouncycastle.cms.jcajce;

import java.io.OutputStream;
import java.util.zip.DeflaterOutputStream;

import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.OutputCompressor;

public class ZlibCompressor
    implements OutputCompressor
{
    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return new AlgorithmIdentifier(CMSObjectIdentifiers.zlibCompress);
    }

    public OutputStream getOutputStream(OutputStream comOut)
    {
        return new DeflaterOutputStream(comOut);
    }
}

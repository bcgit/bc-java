package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ArchiveTimeStampChainGenerator {

    private AlgorithmIdentifier algId;
    private MessageDigest md;

    protected ArchiveTimeStampChainGenerator(final AlgorithmIdentifier algId)
        throws NoSuchAlgorithmException
    {
        this.algId = algId;
        this.md = MessageDigest.getInstance(algId.getAlgorithm().getId());
    }

    public ArchiveTimeStampChain generate() {

        return null;
    }

}

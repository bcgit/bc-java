package org.bouncycastle.dvcs;

import org.bouncycastle.asn1.x509.DigestInfo;

public class MessageImprint
{
    private final DigestInfo messageImprint;

    public MessageImprint(DigestInfo messageImprint)
    {
        this.messageImprint = messageImprint;
    }

    public DigestInfo toASN1Structure()
    {
        return messageImprint;
    }
}

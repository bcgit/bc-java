package org.bouncycastle.jsse.provider;

import java.security.Principal;
import java.util.List;

class JsseSecurityParameters
{
    NamedGroupInfo.PerConnection namedGroups;
    SignatureSchemeInfo.PerConnection signatureSchemes;
    List<byte[]> statusResponses;
    Principal[] trustedIssuers;

    void clear()
    {
        this.namedGroups = null;
        this.signatureSchemes = null;
        this.statusResponses = null;
        this.trustedIssuers = null;
    }
}

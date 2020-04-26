package org.bouncycastle.jsse.provider;

import java.security.Principal;
import java.util.List;

class JsseSecurityParameters
{
    NamedGroupInfo.PerConnection namedGroups;
    List<SignatureSchemeInfo> localSigSchemes, localSigSchemesCert, peerSigSchemes, peerSigSchemesCert;
    List<byte[]> statusResponses;
    Principal[] trustedIssuers;

    void clear()
    {
        this.namedGroups = null;
        this.localSigSchemes = null;
        this.localSigSchemesCert = null;
        this.peerSigSchemes = null;
        this.peerSigSchemesCert = null;
        this.statusResponses = null;
        this.trustedIssuers = null;
    }
}

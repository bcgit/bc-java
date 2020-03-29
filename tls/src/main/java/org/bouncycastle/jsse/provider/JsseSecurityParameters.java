package org.bouncycastle.jsse.provider;

import java.util.List;

class JsseSecurityParameters
{
    List<SignatureSchemeInfo> localSigSchemes, localSigSchemesCert, peerSigSchemes, peerSigSchemesCert;
    List<byte[]> statusResponses;

    void clear()
    {
        this.localSigSchemes = null;
        this.localSigSchemesCert = null;
        this.peerSigSchemes = null;
        this.peerSigSchemesCert = null;
        this.statusResponses = null;
    }
}

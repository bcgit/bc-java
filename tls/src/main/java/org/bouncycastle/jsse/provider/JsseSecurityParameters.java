package org.bouncycastle.jsse.provider;

import java.util.List;

class JsseSecurityParameters
{
    List<SignatureSchemeInfo> localSigSchemes, localSigSchemesCert, peerSigSchemes, peerSigSchemesCert;

    void clear()
    {
        this.localSigSchemes = null;
        this.localSigSchemesCert = null;
        this.peerSigSchemes = null;
        this.peerSigSchemesCert = null;
    }
}

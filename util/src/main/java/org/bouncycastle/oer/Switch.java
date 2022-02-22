package org.bouncycastle.oer;

import org.bouncycastle.asn1.ASN1Encodable;

/**
 * A switch is intended to examine the state of the OER decoding stream
 * and return an oer definition to based on that state.
 */
public interface Switch
{
    Element result(SwitchIndexer indexer);
    ASN1Encodable[] keys();

}

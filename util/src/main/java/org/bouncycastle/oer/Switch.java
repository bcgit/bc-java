package org.bouncycastle.oer;

/**
 * A switch is intended to examine the state of the OER decoding stream
 * and return an oer definition to based on that state.
 */
public interface Switch
{
    OERDefinition.Element result(SwitchIndexer indexer);
}

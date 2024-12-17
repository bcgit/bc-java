package org.bouncycastle.openpgp.api;

import java.util.HashSet;
import java.util.Set;

public class OpenPGPNotationRegistry
{
    private final Set<String> knownNotations = new HashSet<>();

    public boolean isNotationKnown(String notationName)
    {
        return knownNotations.contains(notationName);
    }

    public void addKnownNotation(String notationName)
    {
        this.knownNotations.add(notationName);
    }
}

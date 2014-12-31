package org.bouncycastle.cert.dane;

import java.util.List;

public interface DANEEntryFetcher
{
    List getEntries() throws DANEException;
}

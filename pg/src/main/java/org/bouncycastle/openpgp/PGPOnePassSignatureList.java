package org.bouncycastle.openpgp;

import java.util.Iterator;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Iterable;

/**
 * Holder for a list of PGPOnePassSignatures
 */
public class PGPOnePassSignatureList
    implements Iterable<PGPOnePassSignature>
{
    PGPOnePassSignature[]    sigs;
    
    public PGPOnePassSignatureList(
        PGPOnePassSignature[]    sigs)
    {
        this.sigs = new PGPOnePassSignature[sigs.length];
        
        System.arraycopy(sigs, 0, this.sigs, 0, sigs.length);
    }
    
    public PGPOnePassSignatureList(
        PGPOnePassSignature    sig)
    {
        this.sigs = new PGPOnePassSignature[1];
        this.sigs[0] = sig;
    }
    
    public PGPOnePassSignature get(
        int    index)
    {
        return sigs[index];
    }
    
    public int size()
    {
        return sigs.length;
    }
    
    public boolean isEmpty()
    {
        return (sigs.length == 0);
    }

    /**
     * Support method for Iterable where available.
     */
    public Iterator<PGPOnePassSignature> iterator()
    {
        return new Arrays.Iterator(sigs);
    }
}

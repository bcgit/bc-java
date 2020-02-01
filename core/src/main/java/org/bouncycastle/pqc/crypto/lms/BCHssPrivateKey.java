package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.pqc.crypto.lms.exceptions.LMSException;

public class BCHssPrivateKey
    implements HssPrivateKey
{
    private final LmsPrivateKey rootKey;
    private int l;
    private List<LmsPrivateKey> keys;
    private List<LMSSignature> sig;


    public BCHssPrivateKey(int l, LmsPrivateKey[] keys, LMSSignature[] sig)
    {
        this.l = l;
        this.keys = Collections.unmodifiableList(Arrays.asList(keys));
        this.sig = Collections.unmodifiableList(Arrays.asList(sig));
        this.rootKey = this.keys.get(0);
    }

    private BCHssPrivateKey(int l, List<LmsPrivateKey> keys, List<LMSSignature> sig)
    {
        this.l = l;
        this.keys = Collections.unmodifiableList(keys);
        this.sig = Collections.unmodifiableList(sig);
        this.rootKey = this.keys.get(0);
    }

    static BCHssPrivateKey getInstance(Object src, int maxDepth, int maxSecretSize)
        throws Exception
    {

        if (src instanceof LmsPublicKey)
        {
            return (BCHssPrivateKey)src;
        }
        else if (src instanceof DataInputStream)
        {
            if (((DataInputStream)src).readInt() != 0)
            {
                throw new LMSException("unknown version for hss private key");
            }
            int d = ((DataInputStream)src).readInt();
            if (d > maxDepth)
            {
                throw new LMSException("depth encoded exceeds maxDepth of " + maxDepth);
            }

            ArrayList<LmsPrivateKey> keys = new ArrayList<>();
            ArrayList<LMSSignature> signatures = new ArrayList<>();

            for (int t = 0; t < d; t++)
            {
                keys.add(LmsPrivateKey.getInstance(src, maxSecretSize));
            }

            for (int t = 0; t < d - 1; t++)
            {
                signatures.add(LMSSignature.getInstance(src));
            }

            return new BCHssPrivateKey(d, keys, signatures);

        }
        else if (src instanceof byte[])
        {
            return getInstance(new DataInputStream(new ByteArrayInputStream((byte[])src)), maxDepth, maxSecretSize);
        }
        else if (src instanceof InputStream)
        {
            return getInstance(new DataInputStream((InputStream)src), maxDepth, maxSecretSize);
        }

        throw new IllegalArgumentException("cannot parse " + src);
    }


    @Override
    public synchronized int getRemaining()
    {
        int used = 0;
        int possible = 1;

        int last = keys.size() - 1;

        for (int t = 0; t < keys.size(); t++)
        {
            LmsPrivateKey key = keys.get(t);
            int lim = (1 << key.getParameterSet().getH());
            possible *= lim;

            if (t == last)
            {
                used += key.getQ();
            }
            else
            {
                if (key.getQ() - 1 > 0)
                {
                    used += (key.getQ() - 1) * lim;
                }
            }
        }

        return possible - used;
    }

    @Override
    public synchronized int getL()
    {
        return l;
    }

    @Override
    public synchronized List<LmsPrivateKey> getKeys()
    {
        return keys;
    }

    @Override
    public synchronized int getL(LmsPrivateKey privateKey)
    {
        return keys.indexOf(privateKey);
    }

    @Override
    public synchronized List<LMSSignature> getSig()
    {
        return sig;
    }

    @Override
    public synchronized BCHssPublicKey getPublicKey()
        throws LMSException
    {
        return new BCHssPublicKey(l, rootKey.getPublicKey());
    }


    @Override
    public synchronized void addNewKey(int d, SecureRandom source)
        throws LMSException
    {

        List<LmsPrivateKey> newKeys = new ArrayList<>(keys);

        byte[] I = new byte[16];
        source.nextBytes(I);

        byte[] rootSecret = new byte[32];
        source.nextBytes(rootSecret);

        newKeys.set(d, LMS.generateKeys(rootKey.getParameterSet(), rootKey.getLmOtsType(), 0, I, rootSecret));

        List<LMSSignature> newSig = new ArrayList<>(sig);

        newSig.set(d - 1, LMS.generateSign(newKeys.get(d - 1), newKeys.get(d).getPublicKey().getEncoded()));

        // TODO restore
        //newSig.set(d - 1, LMS.generateSign(newList.get(d), newList.get(d - 1).getPublicKey().getEncoded(), source));

        this.keys = Collections.unmodifiableList(newKeys);
        this.sig = Collections.unmodifiableList(newSig);

    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o)
        {
            return true;
        }
        if (o == null || getClass() != o.getClass())
        {
            return false;
        }

        BCHssPrivateKey that = (BCHssPrivateKey)o;

        if (l != that.l)
        {
            return false;
        }
        if (keys != null ? !keys.equals(that.keys) : that.keys != null)
        {
            return false;
        }
        if (sig != null ? !sig.equals(that.sig) : that.sig != null)
        {
            return false;
        }
        return rootKey != null ? rootKey.equals(that.rootKey) : that.rootKey == null;
    }

    @Override
    public int hashCode()
    {
        int result = l;
        result = 31 * result + (keys != null ? keys.hashCode() : 0);
        result = 31 * result + (sig != null ? sig.hashCode() : 0);
        result = 31 * result + (rootKey != null ? rootKey.hashCode() : 0);
        return result;
    }

    @Override
    public synchronized byte[] getEncoded()
        throws IOException
    {
        //
        // Private keys are implementation dependent.
        //

        Composer composer = Composer.compose()
            .u32str(0) // Version.
            .u32str(l); // Depth

        for (LmsPrivateKey key : keys)
        {
            composer.bytes(key);
        }

        for (LMSSignature s : sig)
        {
            composer.bytes(s);
        }

        return composer.build();
    }
}

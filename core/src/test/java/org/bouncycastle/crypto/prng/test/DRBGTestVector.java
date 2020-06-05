package org.bouncycastle.crypto.prng.test;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.util.encoders.Hex;

public class DRBGTestVector
{
    private String _name;
    private Digest _digest;
    private BlockCipher _cipher;
    private int _keySizeInBits;
    private EntropySource _eSource;
    private boolean _pr;
    private String _nonce;
    private String _personalisation;
    private int _ss;
    private String[] _ev;
    private List _ai = new ArrayList();

    public DRBGTestVector(Digest digest, EntropySource eSource, boolean predictionResistance, String nonce, int securityStrength, String name, String[] expected)
    {
        _digest = digest;
        _eSource = eSource;
        _pr = predictionResistance;
        _nonce = nonce;
        _ss = securityStrength;
        _ev = expected;
        _name = name;
        _personalisation = null;
    }

    public DRBGTestVector(Digest digest, EntropySource eSource, boolean predictionResistance, String nonce, int securityStrength, String[] expected)
    {
        _digest = digest;
        _eSource = eSource;
        _pr = predictionResistance;
        _nonce = nonce;
        _ss = securityStrength;
        _ev = expected;
        _name = null;
        _personalisation = null;
    }

    public DRBGTestVector(BlockCipher cipher, int keySizeInBits, EntropySource eSource, boolean predictionResistance, String nonce, int securityStrength, String name, String[] expected)
    {
        _cipher = cipher;
        _keySizeInBits = keySizeInBits;
        _eSource = eSource;
        _pr = predictionResistance;
        _nonce = nonce;
        _ss = securityStrength;
        _ev = expected;
        _name = name;
        _personalisation = null;
    }

    public DRBGTestVector(BlockCipher cipher, int keySizeInBits, EntropySource eSource, boolean predictionResistance, String nonce, int securityStrength, String[] expected)
    {
        _cipher = cipher;
        _keySizeInBits = keySizeInBits;
        _eSource = eSource;
        _pr = predictionResistance;
        _nonce = nonce;
        _ss = securityStrength;
        _ev = expected;
        _name = null;
        _personalisation = null;
    }

    public Digest getDigest()
    {
        return _digest;
    }

    public BlockCipher getCipher()
    {
        return _cipher;
    }

    public int keySizeInBits()
    {
        return _keySizeInBits;
    }

    public String getName()
    {
        return _name;
    }

    public DRBGTestVector addAdditionalInput(String input)
    {
        _ai.add(input);

        return this;
    }

    public DRBGTestVector setPersonalizationString(String p)
    {
        _personalisation = p;

        return this;
    }

    public EntropySource entropySource()
    {
        return _eSource;
    }

    public boolean predictionResistance()
    {
        return _pr;
    }

    public byte[] nonce()
    {
        if (_nonce == null)
        {
            return null;
        }

        return Hex.decode(_nonce);
    }

    public byte[] personalizationString()
    {
        if (_personalisation == null)
        {
            return null;
        }

        return Hex.decode(_personalisation);
    }

    public int securityStrength()
    {
        return _ss;
    }

    public byte[] expectedValue(int index)
    {
        return Hex.decode(_ev[index]);
    }

    public byte[] additionalInput(int position)
    {
        int len = _ai.size();
        byte[] rv;
        if (position >= len)
        {
            rv = null;
        }
        else
        {
            rv = Hex.decode((String)(_ai.get(position)));
        }
        return rv;
    }

}

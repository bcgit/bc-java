package org.bouncycastle.kmip.wire.enumeration;

public enum KMIPOperation
    implements KMIPEnumeration
{
    Create(0x00000001),
    CreateKeyPair(0x00000002),
    Register(0x00000003),
    Rekey(0x00000004),
    DeriveKey(0x00000005),
    Certify(0x00000006),
    Recertify(0x00000007),
    Locate(0x00000008),
    Check(0x00000009),
    Get(0x0000000A),
    GetAttributes(0x0000000B),
    GetAttributeList(0x0000000C),
    AddAttribute(0x0000000D),
    ModifyAttribute(0x0000000E),
    DeleteAttribute(0x0000000F),
    ObtainLease(0x00000010),
    GetUsageAllocation(0x00000011),
    Activate(0x00000012),
    Revoke(0x00000013),
    Destroy(0x00000014),
    Archive(0x00000015),
    Recover(0x00000016),
    Validate(0x00000017),
    Query(0x00000018),
    Cancel(0x00000019),
    Poll(0x0000001A),
    Notify(0x0000001B),
    Put(0x0000001C),
    RekeyKeyPair(0x0000001D),
    DiscoverVersions(0x0000001E),
    Encrypt(0x0000001F),
    Decrypt(0x00000020),
    Sign(0x00000021),
    SignatureVerify(0x00000022),
    Mac(0x00000023),
    MacVerify(0x00000024),
    RngRetrieve(0x00000025),
    RngSeed(0x00000026),
    Hash(0x00000027),
    CreateSplitKey(0x00000028),
    JoinSplitKey(0x00000029),
    Import(0x0000002A),
    Export(0x0000002B),
    Log(0x0000002C),
    Login(0x0000002D),
    Logout(0x0000002E),
    DelegatedLogin(0x0000002F),
    AdjustAttribute(0x00000030),
    SetAttribute(0x00000031),
    SetEndpointRole(0x00000032),
    Pkcs11(0x00000033),
    Interop(0x00000034),
    ReProvision(0x00000035),
    SetDefaults(0x00000036),
    SetConstraints(0x00000037),
    GetConstraints(0x00000038),
    QueryAsyncRequests(0x00000039),
    Process(0x0000003A),
    Ping(0x0000003B);

    private final int value;

    KMIPOperation(int value)
    {
        this.value = value;
    }

    public int getValue()
    {
        return value;
    }

    public static KMIPOperation fromValue(int value)
    {
        for (KMIPOperation op : values())
        {
            if (op.value == value)
            {
                return op;
            }
        }
        throw new IllegalArgumentException("Invalid Operation value: " + value);
    }

    @Override
    public String toString()
    {
        return String.format("%s (0x%08X)", name(), value);
    }
}


/*
 *  Managed C# wrapper for GameNetworkingSockets library by Valve Software
 *  Copyright (c) 2018 Stanislav Denisov
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */

using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace Valve.Sockets
{
    using Connection = UInt32;
    using ListenSocket = UInt32;
    using Microseconds = Int64;
    using PollGroup = UInt32;
    using POPID = UInt32;

    static class StructSettings
    {
#if VALVE_CALLBACK_PACK_SMALL
		public const int PACK_SIZE = 4;
#elif VALVE_CALLBACK_PACK_LARGE
        public const int PACK_SIZE = 8;
#else
        #error "VALVE_CALLBACK_PACK_SMALL must be defined for Linux, Apple, or FreeBSD platforms. For all other platforms, define VALVE_CALLBACK_PACK_LARGE."
#endif
    }

    [StructLayout(LayoutKind.Sequential, Pack = StructSettings.PACK_SIZE)]
    public struct ConnectionStatusChanged
    {
        private const int CALLBACK = Library.SocketsCallbacks + 1;

        public Connection conn;
        public ConnectionInfo info;

        public ConnectionState oldState;
    }

    [StructLayout(LayoutKind.Sequential, Pack = StructSettings.PACK_SIZE)]
    public unsafe struct AuthenticationStatus
    {
        private const int CALLBACK = Library.SocketsCallbacks + 2;

        public Availability avail;

        public fixed byte debugMsg[256];
    };

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public unsafe struct RelayNetworkStatus
    {
        private const int CALLBACK = Library.UtilsCallbacks + 1;

        public Availability avail;
        public int pingMeasurementInProgress;
        public Availability availNetworkConfig;
        public Availability availAnyRelay;

        public fixed byte debugMsg[256];
    };

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct MessagesSessionRequest
    {
        private const int CALLBACK = Library.MessagesCallbacks + 1;

        public Identity identityRemote;
    };

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct MessagesSessionFailed
    {
        private const int CALLBACK = Library.MessagesCallbacks + 2;

        public ConnectionInfo info;
    };

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void ConnectionStatusChangedCallback(ref ConnectionStatusChanged status);
    
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void AuthenticationStatusChangedCallback(ref AuthenticationStatus status);
    
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void RelayNetworkStatusChangedCallback(ref RelayNetworkStatus status);
    
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void MessagesSessionRequestCallback(ref MessagesSessionRequest status);
    
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void MessagesSessionFailedCallback(ref MessagesSessionFailed status);

    public enum Availability
    {
        CannotTry = -102,
        Failed = -101,
        Previously = -100,
        Retrying = -10,
        NeverTried = 1,
        Waiting = 2,
        Attempting = 3,
        Current = 100,
        Unknown = 0,
    }

    public enum IdentityType
    {
        Invalid = 0,

        SteamID = 16,
        XboxPairwiseID = 17,
        SonyPSN = 18,

        IPAddress = 1,
        GenericString = 2,
        GenericBytes = 3,

        UnknownType = 4,
    }

    public enum FakeIPType
    {
        Invalid,
        NotFake,
        GlobalIPv4,
        LocalIPv4,
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IPAddr : IEquatable<IPAddr>
    {
        public unsafe struct IPv4MappedAddress
        {
            public ulong _8zeros;
            public ushort _0000;
            public ushort _ffff;

            public fixed byte ip[4];
        }

        [StructLayout(LayoutKind.Explicit, Size = 16)]
        public unsafe struct IPAddrData
        {
            [FieldOffset(0)]
            public fixed byte ipv6[16];

            [FieldOffset(0)]
            public IPv4MappedAddress ipv4;
        }

        public IPAddrData ip;

        public ushort port;

        public void Clear()
        {
            Native.SteamAPI_SteamNetworkingIPAddr_Clear(ref this);
        }

        public bool IsIPv6AllZeros()
        {
            return Native.SteamAPI_SteamNetworkingIPAddr_IsIPv6AllZeros(ref this);
        }

        public bool IsLocalHost
        {
            get
            {
                return Native.SteamAPI_SteamNetworkingIPAddr_IsLocalHost(ref this);
            }
        }

        public string GetIP()
        {
            return ip.ParseIP();
        }

        public bool IsIPv4
        {
            get
            {
                return Native.SteamAPI_SteamNetworkingIPAddr_IsIPv4(ref this);
            }
        }

        public void SetLocalHost(ushort port)
        {
            Native.SteamAPI_SteamNetworkingIPAddr_SetIPv6LocalHost(ref this, port);
        }

        public void SetAddress(string ip, ushort port)
        {
            if (ip.Contains(":"))
            {
                Native.SteamAPI_SteamNetworkingIPAddr_SetIPv6(ref this, ip.ParseIPv6(), port);
            }
            else
            {
                Native.SteamAPI_SteamNetworkingIPAddr_SetIPv4(ref this, ip.ParseIPv4(), port);
            }
        }

        public bool Equals(IPAddr other)
        {
            return Native.SteamAPI_SteamNetworkingIPAddr_IsEqualTo(ref this, ref other);
        }

        public string ToString(bool withPort)
        {
            unsafe
            {
                int maxSize = Library.MaxIpAddrStringLength;
                
                Span<byte> span = stackalloc byte[maxSize];

                fixed (byte* ptr = span)
                {
                    Native.SteamAPI_SteamNetworkingIPAddr_ToString(ref this, (IntPtr)ptr, (uint)maxSize, withPort);

                    return Encoding.ASCII.GetString(span);
                }
            }
        }

        public bool ParseString(string ipPort)
        {
            return Native.SteamAPI_SteamNetworkingIPAddr_ParseString(ref this, ipPort);
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct Identity
    {
        public IdentityType type;

        public int size;

        public IdentityData data;

        [StructLayout(LayoutKind.Explicit, Size = 128)]
        public unsafe struct IdentityData
        {
            [FieldOffset(0)]
            public ulong steamID64;

            [FieldOffset(0)]
            public ulong PSNID;

            [FieldOffset(0)]
            public fixed byte genericString[32];

            [FieldOffset(0)]
            public fixed byte xboxPairwiseID[33];

            [FieldOffset(0)]
            public fixed byte genericBytes[32];

            [FieldOffset(0)]
            public fixed byte unknownRawString[128];

            [FieldOffset(0)]
            public IPAddr ip;

            [FieldOffset(0)]
            public fixed uint reserved[32];
        }

        public void Clear()
        {
            Native.SteamAPI_SteamNetworkingIdentity_Clear(ref this);
        }

        public bool IsInvalid()
        {
            return Native.SteamAPI_SteamNetworkingIdentity_IsInvalid(ref this);
        }

        public void SetSteamID(ulong steamID)
        {
            Native.SteamAPI_SteamNetworkingIdentity_SetSteamID(ref this, steamID);
        }

        public ulong GetSteamID()
        {
            return Native.SteamAPI_SteamNetworkingIdentity_GetSteamID(ref this);
        }

        public void SetSteamID64(ulong steamID)
        {
            Native.SteamAPI_SteamNetworkingIdentity_SetSteamID64(ref this, steamID);
        }

        public ulong GetSteamID64()
        {
            return Native.SteamAPI_SteamNetworkingIdentity_GetSteamID64(ref this);
        }

        public bool SetXboxPairwiseID(string id)
        {
            return Native.SteamAPI_SteamNetworkingIdentity_SetXboxPairwiseID(ref this, id);
        }

        public string GetXboxPairwiseID(string id)
        {
            IntPtr ptr = Native.SteamAPI_SteamNetworkingIdentity_GetXboxPairwiseID(ref this);

            return Marshal.PtrToStringAnsi(ptr);
        }

        public void SetIPAddr(ref IPAddr addr)
        {
            Native.SteamAPI_SteamNetworkingIdentity_SetIPAddr(ref this, ref addr);
        }

        public IPAddr GetIPAddr()
        {
            IntPtr ptr = Native.SteamAPI_SteamNetworkingIdentity_GetIPAddr(ref this);

            return Marshal.PtrToStructure<IPAddr>(ptr);
        }

        public void SetLocalHost()
        {
            Native.SteamAPI_SteamNetworkingIdentity_SetLocalHost(ref this);
        }

        public bool IsLocalHost()
        {
            return Native.SteamAPI_SteamNetworkingIdentity_IsLocalHost(ref this);
        }

        public bool SetGenericString(string pszString)
        {
            return Native.SteamAPI_SteamNetworkingIdentity_SetGenericString(ref this, pszString);
        }

        public string GetGenericString()
        {
            IntPtr ptr = Native.SteamAPI_SteamNetworkingIdentity_GetGenericString(ref this);

            return Marshal.PtrToStringAnsi(ptr);
        }

        public bool SetGenericBytes(byte[] bytes)
        {
            unsafe
            {
                fixed (byte* ptr = bytes)
                {
                    return Native.SteamAPI_SteamNetworkingIdentity_SetGenericBytes(ref this, (IntPtr)ptr, (uint)bytes.Length);
                }
            }
        }

        public byte[] GetGenericBytes()
        {
            int size = 0;
            IntPtr ptr = Native.SteamAPI_SteamNetworkingIdentity_GetGenericBytes(ref this, ref size);

            byte[] buffer = new byte[size];
            Marshal.Copy(ptr, buffer, 0, size);

            return buffer;
        }

        public bool Equals(ref Identity other)
        {
            return Native.SteamAPI_SteamNetworkingIdentity_IsEqualTo(ref this, ref other);
        }

        public string ToString(int maxSize)
        {
            unsafe
            {
                Span<byte> span = stackalloc byte[maxSize];

                fixed (byte* ptr = span)
                {
                    Native.SteamAPI_SteamNetworkingIdentity_ToString(ref this, (IntPtr)ptr, (uint)maxSize);

                    return Encoding.ASCII.GetString(span);
                }
            }
        }

        public bool ParseString(string pszStr)
        {
            return Native.SteamAPI_SteamNetworkingIdentity_ParseString(ref this, (uint)Marshal.SizeOf<Identity>(), pszStr);
        }
    }

    public enum ConnectionState
    {
        None = 0,
        Connecting = 1,
        FindingRoute = 2,
        Connected = 3,
        ClosedByPeer = 4,
        ProblemDetectedLocally = 5,
        FinWait = -1,
        Linger = -2,
        Dead = -3,
    }

    public enum ConnectionEnd
    {
        Invalid = 0,

        App_Min = 1000,
        App_Generic = App_Min,
        App_Max = 1999,
        AppException_Min = 2000,
        AppException_Generic = AppException_Min,
        AppException_Max = 2999,

        Local_Min = 3000,
        Local_OfflineMode = 3001,
        Local_ManyRelayConnectivity = 3002,
        Local_HostedServerPrimaryRelay = 3003,
        Local_NetworkConfig = 3004,
        Local_Rights = 3005,
        Local_P2P_ICE_NoPublicAddresses = 3006,
        Local_Max = 3999,

        Remote_Min = 4000,
        Remote_Timeout = 4001,
        Remote_BadCrypt = 4002,
        Remote_BadCert = 4003,
        Remote_NotLoggedIn_DEPRECATED = 4004,
        Remote_NotRunningApp_DEPRECATED = 4005,
        Remote_BadProtocolVersion = 4006,
        Remote_P2P_ICE_NoPublicAddresses = 4007,
        Remote_Max = 4999,

        Misc_Min = 5000,
        Misc_Generic = 5001,
        Misc_InternalError = 5002,
        Misc_Timeout = 5003,
        Misc_RelayConnectivity_DEPRECATED = 5004,
        Misc_SteamConnectivity = 5005,
        Misc_NoRelaySessionsToClient = 5006,
        Misc_ServerNeverReplied = 5007,
        Misc_P2P_Rendezvous = 5008,
        Misc_P2P_NAT_Firewall = 5009,
        Misc_PeerSentNoConnection = 5010,
        Misc_Max = 5999,
    }

    [Flags]
    public enum ConnectionInfoFlags
    {
        Unauthenticated = 1 << 0,
        Unencrypted = 1 << 1,
        LoopbackBuffers = 1 << 2,
        Fast = 1 << 3,
        Relayed = 1 << 4,
        DualWifi = 1 << 5,
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public unsafe struct ConnectionInfo
    {
        public Identity identityRemote;
        public long userData;
        public ListenSocket listenSocket;
        public IPAddr addrRemote;
        private ushort pad1;
        private uint idPOPRemote;
        private uint idPOPRelay;
        public ConnectionState state;
        public int endReason;

        public fixed byte endDebug[128];

        public fixed byte connectionDescription[128];

        public int flags;

        private fixed uint reserved[63];
    }

    [StructLayout(LayoutKind.Sequential, Pack = StructSettings.PACK_SIZE)]
    public unsafe struct ConnectionRealtimeStatus
    {
        public ConnectionState state;

        public int ping;

        public float connectionQualityLocal;
        public float connectionQualityRemote;

        public float outPacketsPerSecond;
        public float outBytesPerSecond;
        public float inPacketsPerSecond;
        public float inBytesPerSecond;

        public int sendRateBytesPerSecond;

        public int pendingUnreliable;
        public int pendingReliable;

        public int sentUnackedReliable;

        public Microseconds queueTime;

        public int maxJitter;

        private fixed uint reserved[15];
    }

    [StructLayout(LayoutKind.Sequential, Pack = StructSettings.PACK_SIZE)]
    public unsafe struct ConnectionRealTimeLaneStatus
    {
        public int pendingUnreliable;
        public int pendingReliable;
        public int sentUnackedReliable;
        public int reservePad1;

        public Microseconds queueTime;

        public fixed uint reserved[10];
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct NetworkingMessage
    {
        public IntPtr data;
        public int size;

        public Connection conn;
        public Identity identityPeer;
        public long connUserData;
        public Microseconds timeReceived;
        public long messageNumber;

        internal IntPtr freeData;
        internal IntPtr release;

        public int channel;
        public int flags;
        public long userData;
        public ushort idxLane;
        public ushort pad1__;

        public void CopyTo(byte[] destination)
        {
            if (destination == null)
                throw new ArgumentNullException("destination");

            Marshal.Copy(data, destination, 0, size);
        }

#if !VALVESOCKETS_SPAN
        public void Destroy()
        {
            if (release == IntPtr.Zero)
                throw new InvalidOperationException("Message not created");

            Native.SteamAPI_SteamNetworkingMessage_t_Release(release);
        }
#endif
    }

    [Flags]
    public enum SendFlags
    {
        Unreliable = 0,
        NoNagle = 1 << 0,
        NoDelay = 1 << 2,
        Reliable = 1 << 3,
        UseCurrentThread = 1 << 4,
        AutoRestartBrokenSession = 1 << 5,
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public unsafe struct PingLocation
    {
        public fixed byte data[512];
    }

    public enum PingType
    {
        Failed = -1,
        Unknown = -2,
    }

    public enum ConfigScope
    {
        Global = 1,
        SocketsInterface = 2,
        ListenSocket = 3,
        Connection = 4,
    }

    public enum ConfigDataType
    {
        Int32 = 1,
        Int64 = 2,
        Float = 3,
        String = 4,
        Ptr = 5,
    }

    public enum ConfigValueEnum
    {
        Invalid = 0,
        TimeoutInitial = 24,
        TimeoutConnected = 25,
        SendBufferSize = 9,
        RecvBufferSize = 47,
        RecvBufferMessages = 48,
        RecvMaxMessageSize = 49,
        RecvMaxSegmentsPerPacket = 50,
        ConnectionUserData = 40,
        SendRateMin = 10,
        SendRateMax = 11,
        NagleTime = 12,
        IP_AllowWithoutAuth = 23,
        IPLocalHost_AllowWithoutAuth = 52,
        MTU_PacketSize = 32,
        MTU_DataSize = 33,
        Unencrypted = 34,
        SymmetricConnect = 37,
        LocalVirtualPort = 38,
        DualWifi_Enable = 39,
        EnableDiagnosticsUI = 46,
        SendTimeSincePreviousPacket = 59,
        
        FakePacketLoss_Send = 2,
        FakePacketLoss_Recv = 3,
        FakePacketLag_Send = 4,
        FakePacketLag_Recv = 5,
        FakePacketJitter_Send_Avg = 53,
        FakePacketJitter_Send_Max = 54,
        FakePacketJitter_Send_Pct = 55,
        FakePacketJitter_Recv_Avg = 56,
        FakePacketJitter_Recv_Max = 57,
        FakePacketJitter_Recv_Pct = 58,
        FakePacketReorder_Send = 6,
        FakePacketReorder_Recv = 7,
        FakePacketReorder_Time = 8,
        FakePacketDup_Send = 26,
        FakePacketDup_Recv = 27,
        FakePacketDup_TimeMax = 28,
        PacketTraceMaxBytes = 41,
        FakeRateLimit_Send_Rate = 42,
        FakeRateLimit_Send_Burst = 43,
        FakeRateLimit_Recv_Rate = 44,
        FakeRateLimit_Recv_Burst = 45,
        
        OutOfOrderCorrectionWindowMicroseconds = 51,
        
        Callback_ConnectionStatusChanged = 201,
        Callback_AuthStatusChanged = 202,
        Callback_RelayNetworkStatusChanged = 203,
        Callback_MessagesSessionRequest = 204,
        Callback_MessagesSessionFailed = 205,
        Callback_CreateConnectionSignaling = 206,
        Callback_FakeIPResult = 207,
        
        P2P_STUN_ServerList = 103,
        P2P_Transport_ICE_Enable = 104,
        P2P_Transport_ICE_Penalty = 105,
        P2P_Transport_SDR_Penalty = 106,
        P2P_TURN_ServerList = 107,
        P2P_TURN_UserList = 108,
        P2P_TURN_PassList = 109,
        P2P_Transport_ICE_Implementation = 110,
        
        SDRClient_ConsecutitivePingTimeoutsFailInitial = 19,
        SDRClient_ConsecutitivePingTimeoutsFail = 20,
        SDRClient_MinPingsBeforePingAccurate = 21,
        SDRClient_SingleSocket = 22,
        SDRClient_ForceRelayCluster = 29,
        SDRClient_DevTicket = 30,
        SDRClient_ForceProxyAddr = 31,
        SDRClient_FakeClusterPing = 36,
        SDRClient_LimitPingProbesToNearestN = 60,
        
        LogLevel_AckRTT = 13,
        LogLevel_PacketDecode = 14,
        LogLevel_Message = 15,
        LogLevel_PacketGaps = 16,
        LogLevel_P2PRendezvous = 17,
        LogLevel_SDRRelayPings = 18,
        
        ECN = 999,
        SDRClient_EnableTOSProbes = 998,
        DELETED_EnumerateDevVars = 35,
    }

    public enum P2PTransportICEEnable
    {
        Default = -1,
        Disable = 0,
        Relay = 1,
        Private = 2,
        Public = 4,
        All = 0x7fffffff,
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct ConfigValue
    {
        public ConfigValueEnum value;
        public ConfigDataType dataType;
        public ConfigurationData data;

        [StructLayout(LayoutKind.Explicit)]
        public struct ConfigurationData
        {
            [FieldOffset(0)]
            public int Int32;

            [FieldOffset(0)]
            public long Int64;

            [FieldOffset(0)]
            public float Float;

            [FieldOffset(0)]
            public IntPtr String;

            [FieldOffset(0)]
            public IntPtr FunctionPtr;
        }
    }

    public enum ConfigValueResult
    {
        BadValue = -1,
        BadScopeObject = -2,
        BufferTooSmall = -3,
        OK = 1,
        OKInherited = 2,
    }

    public enum DebugOutputType
    {
        None = 0,
        Bug = 1,
        Error = 2,
        Important = 3,
        Warning = 4,
        Message = 5,
        Verbose = 6,
        Debug = 7,
        Everything = 8,
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public unsafe struct POPIDRender
    {
        public fixed byte buf[8];
    }

    public enum Result
    {
        None = 0,
        OK = 1,
        Fail = 2,
        NoConnection = 3,
        // NoConnectionRetry = 4,
        InvalidPassword = 5,
        LoggedInElsewhere = 6,
        InvalidProtocolVer = 7,
        InvalidParam = 8,
        FileNotFound = 9,
        Busy = 10,
        InvalidState = 11,
        InvalidName = 12,
        InvalidEmail = 13,
        DuplicateName = 14,
        AccessDenied = 15,
        Timeout = 16,
        Banned = 17,
        AccountNotFound = 18,
        InvalidSteamID = 19,
        ServiceUnavailable = 20,
        NotLoggedOn = 21,
        Pending = 22,
        EncryptionFailure = 23,
        InsufficientPrivilege = 24,
        LimitExceeded = 25,
        Revoked = 26,
        Expired = 27,
        AlreadyRedeemed = 28,
        DuplicateRequest = 29,
        AlreadyOwned = 30,
        IPNotFound = 31,
        PersistFailed = 32,
        LockingFailed = 33,
        LogonSessionReplaced = 34,
        ConnectFailed = 35,
        HandshakeFailed = 36,
        IOFailure = 37,
        RemoteDisconnect = 38,
        ShoppingCartNotFound = 39,
        Blocked = 40,
        Ignored = 41,
        NoMatch = 42,
        AccountDisabled = 43,
        ServiceReadOnly = 44,
        AccountNotFeatured = 45,
        AdministratorOK = 46,
        ContentVersion = 47,
        TryAnotherCM = 48,
        PasswordRequiredToKickSession = 49,
        AlreadyLoggedInElsewhere = 50,
        Suspended = 51,
        Cancelled = 52,
        DataCorruption = 53,
        DiskFull = 54,
        RemoteCallFailed = 55,
        PasswordUnset = 56,
        ExternalAccountUnlinked = 57,
        PSNTicketInvalid = 58,
        ExternalAccountAlreadyLinked = 59,
        RemoteFileConflict = 60,
        IllegalPassword = 61,
        SameAsPreviousValue = 62,
        AccountLogonDenied = 63,
        CannotUseOldPassword = 64,
        InvalidLoginAuthCode = 65,
        AccountLogonDeniedNoMail = 66,
        HardwareNotCapableOfIPT = 67,
        IPTInitError = 68,
        ParentalControlRestricted = 69,
        FacebookQueryError = 70,
        ExpiredLoginAuthCode = 71,
        IPLoginRestrictionFailed = 72,
        AccountLockedDown = 73,
        AccountLogonDeniedVerifiedEmailRequired = 74,
        NoMatchingURL = 75,
        BadResponse = 76,
        RequirePasswordReEntry = 77,
        ValueOutOfRange = 78,
        UnexpectedError = 79,
        Disabled = 80,
        InvalidCEGSubmission = 81,
        RestrictedDevice = 82,
        RegionLocked = 83,
        RateLimitExceeded = 84,
        AccountLoginDeniedNeedTwoFactor = 85,
        ItemDeleted = 86,
        AccountLoginDeniedThrottle = 87,
        TwoFactorCodeMismatch = 88,
        TwoFactorActivationCodeMismatch = 89,
        AccountAssociatedToMultiplePartners = 90,
        NotModified = 91,
        NoMobileDevice = 92,
        TimeNotSynced = 93,
        SmsCodeFailed = 94,
        AccountLimitExceeded = 95,
        AccountActivityLimitExceeded = 96,
        PhoneActivityLimitExceeded = 97,
        RefundToWallet = 98,
        EmailSendFailure = 99,
        NotSettled = 100,
        NeedCaptcha = 101,
        GSLTDenied = 102,
        GSOwnerDenied = 103,
        InvalidItemType = 104,
        IPBanned = 105,
        GSLTExpired = 106,
        InsufficientFunds = 107,
        TooManyPending = 108,
        NoSiteLicensesFound = 109,
        WGNetworkSendExceeded = 110,
        AccountNotFriends = 111,
        LimitedUserAccount = 112,
        CantRemoveItem = 113,
        AccountDeleted = 114,
        ExistingUserCancelledLicense = 115,
        CommunityCooldown = 116,
        NoLauncherSpecified = 117,
        MustAgreeToSSA = 118,
        LauncherMigrated = 119,
        SteamRealmMismatch = 120,
        InvalidSignature = 121,
        ParseFailure = 122,
        NoVerifiedPhone = 123,
        InsufficientBattery = 124,
        ChargerRequired = 125,
        CachedCredentialInvalid = 126,
        PhoneNumberIsVOIP = 127,
        NotSupported = 128,
        FamilySizeLimitExceeded = 129,
    }

#if VALVESOCKETS_SPAN
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void MessageCallback(in NetworkingMessage message);
#endif

    internal static class ArrayPool
    {
        [ThreadStatic]
        private static IntPtr[] pointerBuffer;

        public static IntPtr[] GetPointerBuffer()
        {
            if (pointerBuffer == null)
                pointerBuffer = new IntPtr[Library.MaxMessagesPerBatch];

            return pointerBuffer;
        }
    }

    public class NetworkingSockets
    {
        private IntPtr _nativeSockets;

        public NetworkingSockets()
        {
            _nativeSockets = Native.SteamAPI_SteamNetworkingSockets_v009();

            if (_nativeSockets == IntPtr.Zero)
                throw new InvalidOperationException("Networking sockets not created");
        }

        public ListenSocket CreateListenSocket(ref IPAddr address)
        {
            return Native.SteamAPI_ISteamNetworkingSockets_CreateListenSocketIP(_nativeSockets, ref address, 0, IntPtr.Zero);
        }

        public ListenSocket CreateListenSocket(ref IPAddr address, ConfigValue[] configurations)
        {
            if (configurations == null)
            {
                throw new ArgumentNullException("configurations");
            }

            return Native.SteamAPI_ISteamNetworkingSockets_CreateListenSocketIP(_nativeSockets, ref address, configurations.Length, configurations);
        }

        public Connection Connect(ref IPAddr address)
        {
            return Native.SteamAPI_ISteamNetworkingSockets_ConnectByIPAddress(_nativeSockets, ref address, 0, IntPtr.Zero);
        }

        public Connection Connect(ref IPAddr address, ConfigValue[] configurations)
        {
            if (configurations == null)
            {
                throw new ArgumentNullException("configurations");
            }

            return Native.SteamAPI_ISteamNetworkingSockets_ConnectByIPAddress(_nativeSockets, ref address, configurations.Length, configurations);
        }

        public ListenSocket CreateListenSocketP2P(int localVirtualPort, ConfigValue[] configurations)
        {
            return Native.SteamAPI_ISteamNetworkingSockets_CreateListenSocketP2P(_nativeSockets, localVirtualPort, configurations.Length, configurations);
        }

        public ListenSocket CreateListenSocketP2P(int localVirtualPort)
        {
            return Native.SteamAPI_ISteamNetworkingSockets_CreateListenSocketP2P(_nativeSockets, localVirtualPort, 0, IntPtr.Zero);
        }

        public ListenSocket ConnectP2P(ref Identity identityRemote, int remoteVirtualPort, ConfigValue[] configurations)
        {
            return Native.SteamAPI_ISteamNetworkingSockets_ConnectP2P(_nativeSockets, ref identityRemote, remoteVirtualPort, configurations.Length, configurations);
        }

        public ListenSocket ConnectP2P(ref Identity identityRemote, int remoteVirtualPort)
        {
            return Native.SteamAPI_ISteamNetworkingSockets_ConnectP2P(_nativeSockets, ref identityRemote, remoteVirtualPort, 0, IntPtr.Zero);
        }

        public Result AcceptConnection(Connection connection)
        {
            return Native.SteamAPI_ISteamNetworkingSockets_AcceptConnection(_nativeSockets, connection);
        }

        public bool CloseConnection(Connection connection)
        {
            return CloseConnection(connection, 0, String.Empty, false);
        }

        public bool CloseConnection(Connection connection, int reason, string debug, bool enableLinger)
        {
            if (debug.Length > Library.MaxCloseMessageLength)
            {
                throw new ArgumentOutOfRangeException("debug");
            }

            return Native.SteamAPI_ISteamNetworkingSockets_CloseConnection(_nativeSockets, connection, reason, debug, enableLinger);
        }

        public bool CloseListenSocket(ListenSocket socket)
        {
            return Native.SteamAPI_ISteamNetworkingSockets_CloseListenSocket(_nativeSockets, socket);
        }

        public bool SetConnectionUserData(Connection peer, long userData)
        {
            return Native.SteamAPI_ISteamNetworkingSockets_SetConnectionUserData(_nativeSockets, peer, userData);
        }

        public long GetConnectionUserData(Connection peer)
        {
            return Native.SteamAPI_ISteamNetworkingSockets_GetConnectionUserData(_nativeSockets, peer);
        }

        public void SetConnectionName(Connection peer, string name)
        {
            Native.SteamAPI_ISteamNetworkingSockets_SetConnectionName(_nativeSockets, peer, name);
        }

        public string GetConnectionName(Connection peer)
        {
            int maxSize = Library.MaxSteamNetworkingConnectionName;
            StringBuilder buffer = new StringBuilder(maxSize);
            
            bool success = Native.SteamAPI_ISteamNetworkingSockets_GetConnectionName(_nativeSockets, peer, buffer, maxSize);

            return success ? buffer.ToString() : null;
        }

        public Result SendMessageToConnection(Connection connection, IntPtr data, uint length, out long outMessageNumber)
        {
            return SendMessageToConnection(connection, data, length, SendFlags.Unreliable, out outMessageNumber);
        }

        public Result SendMessageToConnection(Connection connection, IntPtr data, uint length, SendFlags flags, out long outMessageNumber)
        {
            return Native.SteamAPI_ISteamNetworkingSockets_SendMessageToConnection(_nativeSockets, connection, data, length, flags, out outMessageNumber);
        }

        public Result SendMessageToConnection(Connection connection, IntPtr data, int length, SendFlags flags, out long outMessageNumber)
        {
            return SendMessageToConnection(connection, data, (uint)length, flags, out outMessageNumber);
        }

        public Result SendMessageToConnection(Connection connection, byte[] data, out long outMessageNumber)
        {
            if (data == null)
            {
                throw new ArgumentNullException("data");
            }

            return SendMessageToConnection(connection, data, data.Length, SendFlags.Unreliable, out outMessageNumber);
        }

        public Result SendMessageToConnection(Connection connection, byte[] data, SendFlags flags, out long outMessageNumber)
        {
            if (data == null)
            {
                throw new ArgumentNullException("data");
            }

            return SendMessageToConnection(connection, data, data.Length, flags, out outMessageNumber);
        }

        public Result SendMessageToConnection(Connection connection, byte[] data, int length, SendFlags flags, out long outMessageNumber)
        {
            if (data == null)
            {
                throw new ArgumentNullException("data");
            }

            return Native.SteamAPI_ISteamNetworkingSockets_SendMessageToConnection(_nativeSockets, connection, data, (uint)length, flags, out outMessageNumber);
        }

        public void SendMessages(NetworkingMessage[] messages, out long messageNumberOrResult)
        {
            Native.SteamAPI_ISteamNetworkingSockets_SendMessages(_nativeSockets, messages.Length, messages, out messageNumberOrResult);
        }

        public Result FlushMessagesOnConnection(Connection connection)
        {
            return Native.SteamAPI_ISteamNetworkingSockets_FlushMessagesOnConnection(_nativeSockets, connection);
        }

        // Added:: SteamAPI_ISteamNetworkingSockets_ReceiveMessagesOnConnection

        public bool GetConnectionInfo(Connection connection, ref ConnectionInfo info)
        {
            return Native.SteamAPI_ISteamNetworkingSockets_GetConnectionInfo(_nativeSockets, connection, ref info);
        }

        public Result GetConnectionRealTimeStatus(Connection connection, ref ConnectionRealtimeStatus stats, ConnectionRealTimeLaneStatus[] lans)
        {
            return Native.SteamAPI_ISteamNetworkingSockets_GetConnectionRealTimeStatus(_nativeSockets, connection, ref stats, lans.Length, lans);
        }

        public int GetDetailedConnectionStatus(Connection connection, StringBuilder status, int statusLength)
        {
            return Native.SteamAPI_ISteamNetworkingSockets_GetDetailedConnectionStatus(_nativeSockets, connection, status, statusLength);
        }

        public bool GetListenSocketAddress(ListenSocket socket, out IPAddr address)
        {
            return Native.SteamAPI_ISteamNetworkingSockets_GetListenSocketAddress(_nativeSockets, socket, out address);
        }

        public bool CreateSocketPair(ref Connection connectionLeft, ref Connection connectionRight, bool useNetworkLoopback, ref Identity identityLeft, ref Identity identityRight)
        {
            return Native.SteamAPI_ISteamNetworkingSockets_CreateSocketPair(_nativeSockets, ref connectionLeft, ref connectionRight, useNetworkLoopback, ref identityLeft, ref identityRight);
        }

        public Result ConfigureConnectionLanes(Connection connection, int numLans, int[] lanePriorities, ushort[] laneWeights)
        {
            return Native.SteamAPI_ISteamNetworkingSockets_ConfigureConnectionLanes(_nativeSockets, connection, numLans, lanePriorities, laneWeights);
        }

        public bool GetIdentity(ref Identity identity)
        {
            return Native.SteamAPI_ISteamNetworkingSockets_GetIdentity(_nativeSockets, ref identity);
        }

        public Availability InitAuthentication()
        {
            return Native.SteamAPI_ISteamNetworkingSockets_InitAuthentication(_nativeSockets);
        }

        public Availability GetAuthenticationStatus(out AuthenticationStatus details)
        {
            return Native.SteamAPI_ISteamNetworkingSockets_GetAuthenticationStatus(_nativeSockets, out details);
        }

        public PollGroup CreatePollGroup()
        {
            return Native.SteamAPI_ISteamNetworkingSockets_CreatePollGroup(_nativeSockets);
        }

        public bool DestroyPollGroup(PollGroup pollGroup)
        {
            return Native.SteamAPI_ISteamNetworkingSockets_DestroyPollGroup(_nativeSockets, pollGroup);
        }

        public bool SetConnectionPollGroup(PollGroup pollGroup, Connection connection)
        {
            return Native.SteamAPI_ISteamNetworkingSockets_SetConnectionPollGroup(_nativeSockets, connection, pollGroup);
        }

#if VALVESOCKETS_SPAN
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void ReceiveMessagesOnConnection(Connection connection, MessageCallback callback, int maxMessages)
        {
            if (maxMessages > Library.MaxMessagesPerBatch)
            {
                throw new ArgumentOutOfRangeException("maxMessages");
            }

            IntPtr[] nativeMessages = ArrayPool.GetPointerBuffer();
            int messagesCount = Native.SteamAPI_ISteamNetworkingSockets_ReceiveMessagesOnConnection(_nativeSockets, connection, nativeMessages, maxMessages);

            for (int i = 0; i < messagesCount; i++)
            {
                Span<NetworkingMessage> message;

                unsafe
                {
                    message = new Span<NetworkingMessage>((void*)nativeMessages[i], 1);
                }

                callback(in message[0]);

                Native.SteamAPI_SteamNetworkingMessage_t_Release(nativeMessages[i]);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void ReceiveMessagesOnPollGroup(PollGroup pollGroup, MessageCallback callback, int maxMessages)
        {
            if (maxMessages > Library.MaxMessagesPerBatch)
            {
                throw new ArgumentOutOfRangeException("maxMessages");
            }

            IntPtr[] nativeMessages = ArrayPool.GetPointerBuffer();
            int messagesCount = Native.SteamAPI_ISteamNetworkingSockets_ReceiveMessagesOnPollGroup(_nativeSockets, pollGroup, nativeMessages, maxMessages);

            for (int i = 0; i < messagesCount; i++)
            {
                Span<NetworkingMessage> message;

                unsafe
                {
                    message = new Span<NetworkingMessage>((void*)nativeMessages[i], 1);
                }

                callback(in message[0]);

                Native.SteamAPI_SteamNetworkingMessage_t_Release(nativeMessages[i]);
            }
        }
#else
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public int ReceiveMessagesOnConnection(Connection connection, NetworkingMessage[] messages, int maxMessages)
        {
            if (messages == null)
            {
                throw new ArgumentNullException("messages");
            }

            if (maxMessages > Library.MaxMessagesPerBatch)
            {
                throw new ArgumentOutOfRangeException("maxMessages");
            }

            IntPtr[] nativeMessages = ArrayPool.GetPointerBuffer();
            int messagesCount = Native.SteamAPI_ISteamNetworkingSockets_ReceiveMessagesOnConnection(_nativeSockets, connection, nativeMessages, maxMessages);

            for (int i = 0; i < messagesCount; i++)
            {
                messages[i] = Marshal.PtrToStructure<NetworkingMessage>(nativeMessages[i]);
                messages[i].release = nativeMessages[i];
            }

            return messagesCount;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public int ReceiveMessagesOnPollGroup(PollGroup pollGroup, NetworkingMessage[] messages, int maxMessages)
        {
            if (messages == null)
            {
                throw new ArgumentNullException("messages");
            }

            if (maxMessages > Library.MaxMessagesPerBatch)
            {
                throw new ArgumentOutOfRangeException("maxMessages");
            }

            IntPtr[] nativeMessages = ArrayPool.GetPointerBuffer();
            int messagesCount = Native.SteamAPI_ISteamNetworkingSockets_ReceiveMessagesOnPollGroup(_nativeSockets, pollGroup, nativeMessages, maxMessages);

            for (int i = 0; i < messagesCount; i++)
            {
                messages[i] = Marshal.PtrToStructure<NetworkingMessage>(nativeMessages[i]);
                messages[i].release = nativeMessages[i];
            }

            return messagesCount;
        }
#endif

        public interface IConnectionSignaling
        {
            bool SendSignal(Connection conn, ref ConnectionInfo info, string message);
            void Release();
        }

        public class ConnectionSignaling : IDisposable
        {
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.I1)]
            private delegate bool SendSignalDelegate(IntPtr thisPtr, Connection conn, ref ConnectionInfo info, IntPtr pMsg, int cbMsg);

            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            private delegate void ReleaseDelegate(IntPtr thisPtr);

            [StructLayout(LayoutKind.Sequential)]
            private struct VTableStruct
            {
                public IntPtr SendSignal;
                public IntPtr Release;
            }

            private VTableStruct _vTable;
            private IntPtr _ptrVTable;
            private IntPtr _ptrObject;

            private SendSignalDelegate _delegateSendSignal;
            private ReleaseDelegate _delegateRelease;

            private readonly IConnectionSignaling _implementation;

            public IntPtr Handle => _ptrObject;

            private bool _disposed;

            public ConnectionSignaling(IConnectionSignaling implementation)
            {
                _implementation = implementation;

                _delegateSendSignal = new SendSignalDelegate(OnSendSignal);
                _delegateRelease = new ReleaseDelegate(OnRelease);

                _vTable = new VTableStruct
                {
                    SendSignal = Marshal.GetFunctionPointerForDelegate(_delegateSendSignal),
                    Release = Marshal.GetFunctionPointerForDelegate(_delegateRelease)
                };

                _ptrVTable = Marshal.AllocHGlobal(Marshal.SizeOf(_vTable));
                Marshal.StructureToPtr(_vTable, _ptrVTable, false);

                _ptrObject = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(_ptrObject, _ptrVTable);
            }

            private bool OnSendSignal(IntPtr thisPtr, Connection conn, ref ConnectionInfo info, IntPtr pMsg, int cbMsg)
            {
                string message = Marshal.PtrToStringAnsi(pMsg, cbMsg);
                return _implementation.SendSignal(conn, ref info, message);
            }

            private void OnRelease(IntPtr thisPtr)
            {
                _implementation.Release();
            }

            public void Dispose()
            {
                Dispose(true);
                GC.SuppressFinalize(this);
            }

            protected virtual void Dispose(bool disposing)
            {
                if (!_disposed)
                {
                    if (disposing)
                    {
                        DisposeManagedResource();
                    }

                    _disposed = true;
                }
            }

            ~ConnectionSignaling()
            {
                Dispose(false);
            }

            private void DisposeManagedResource()
            {
                Marshal.FreeHGlobal(_ptrObject);
                _ptrObject = IntPtr.Zero;

                Marshal.FreeHGlobal(_ptrVTable);
                _ptrVTable = IntPtr.Zero;
            }
        }

        public Connection ConnectP2PCustomSignaling(ConnectionSignaling signaling, ref Identity peerIdentity, int remoteVirtualPort, int optionsLength, ConfigValue[] options)
        {
            return Native.SteamAPI_ISteamNetworkingSockets_ConnectP2PCustomSignaling(_nativeSockets, signaling.Handle, ref peerIdentity, remoteVirtualPort, optionsLength, options);
        }

        public Connection ConnectP2PCustomSignaling(ConnectionSignaling signaling, ref Identity peerIdentity, int remoteVirtualPort)
        {
            return Native.SteamAPI_ISteamNetworkingSockets_ConnectP2PCustomSignaling(_nativeSockets, signaling.Handle, ref peerIdentity, remoteVirtualPort, 0, IntPtr.Zero);
        }

        public interface ISignalingRecvContext
        {
            ConnectionSignaling OnConnectRequest(Connection conn, ref Identity identityPeer, int localVirtualPort);
            void SendRejectionSignal(ref Identity identityPeer, string message);
        }

        public class SignalingRecvContext : IDisposable
        {
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            private delegate ConnectionSignaling OnConnectRequestDelegate(IntPtr thisPtr, Connection conn, ref Identity identityPeer, int localVirtualPort);

            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            private delegate void SendRejectionSignalDelegate(IntPtr thisPtr, ref Identity identityPeer, IntPtr pMsg, int cbMsg);

            [StructLayout(LayoutKind.Sequential)]
            private struct VTableStruct
            {
                public IntPtr OnConnectRequest;
                public IntPtr SendRejectionSignal;
            }

            private VTableStruct _vTable;
            private IntPtr _ptrVTable;
            private IntPtr _ptrObject;

            private OnConnectRequestDelegate _delegateOnConnectRequest;
            private SendRejectionSignalDelegate _delegateSendRejectionSignal;

            private readonly ISignalingRecvContext _implementation;

            public IntPtr Handle => _ptrObject;

            private bool _disposed;

            public SignalingRecvContext(ISignalingRecvContext implementation)
            {
                _implementation = implementation;

                _delegateOnConnectRequest = new OnConnectRequestDelegate(OnConnectRequest);
                _delegateSendRejectionSignal = new SendRejectionSignalDelegate(OnSendRejectionSignal);

                _vTable = new VTableStruct
                {
                    OnConnectRequest = Marshal.GetFunctionPointerForDelegate(_delegateOnConnectRequest),
                    SendRejectionSignal = Marshal.GetFunctionPointerForDelegate(_delegateSendRejectionSignal)
                };

                _ptrVTable = Marshal.AllocHGlobal(Marshal.SizeOf(_vTable));
                Marshal.StructureToPtr(_vTable, _ptrVTable, false);

                _ptrObject = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(_ptrObject, _ptrVTable);
            }

            private ConnectionSignaling OnConnectRequest(IntPtr thisPtr, Connection conn, ref Identity identityPeer, int localVirtualPort)
            {
                return _implementation.OnConnectRequest(conn, ref identityPeer, localVirtualPort);
            }

            private void OnSendRejectionSignal(IntPtr thisPtr, ref Identity identityPeer, IntPtr pMsg, int cbMsg)
            {
                string message = Marshal.PtrToStringAnsi(pMsg, cbMsg);

                _implementation.SendRejectionSignal(ref identityPeer, message);
            }

            public void Dispose()
            {
                Dispose(true);
                GC.SuppressFinalize(this);
            }

            protected virtual void Dispose(bool disposing)
            {
                if (!_disposed)
                {
                    if (disposing)
                    {
                        DisposeManagedResource();
                    }

                    _disposed = true;
                }
            }

            ~SignalingRecvContext()
            {
                Dispose(false);
            }

            private void DisposeManagedResource()
            {
                Marshal.FreeHGlobal(_ptrObject);
                _ptrObject = IntPtr.Zero;

                Marshal.FreeHGlobal(_ptrVTable);
                _ptrVTable = IntPtr.Zero;
            }
        }

        public bool ReceivedP2PCustomSignal(string message, SignalingRecvContext context)
        {
            return Native.SteamAPI_ISteamNetworkingSockets_ReceivedP2PCustomSignal(_nativeSockets, message, message.Length, context.Handle);
        }

        private byte[] GetCertificateRequest()
        {
            int blobSize = 0;

            StringBuilder errorMessage = new StringBuilder();

            errorMessage.Clear();
            errorMessage.EnsureCapacity(Library.MaxErrorMessageLength);

            if (!Native.SteamAPI_ISteamNetworkingSockets_GetCertificateRequest(_nativeSockets, ref blobSize, IntPtr.Zero, errorMessage))
            {
                throw new Exception(errorMessage.ToString());
            }

            errorMessage.Clear();
            errorMessage.EnsureCapacity(Library.MaxErrorMessageLength);

            byte[] buffer = new byte[blobSize];
            unsafe
            {
                fixed (byte* bufferPtr = buffer)
                {
                    if (Native.SteamAPI_ISteamNetworkingSockets_GetCertificateRequest(_nativeSockets, ref blobSize, (IntPtr)bufferPtr, errorMessage))
                    {
                        return buffer;
                    }
                    else
                    {
                        throw new Exception(errorMessage.ToString());
                    }
                }
            }
        }

        private bool SetCertificate(byte[] certificate)
        {
            StringBuilder errorMessage = new StringBuilder(Library.MaxErrorMessageLength);

            return Native.SteamAPI_ISteamNetworkingSockets_SetCertificate(_nativeSockets, certificate, certificate.Length, errorMessage);
        }

        public void RunCallbacks()
        {
            Native.SteamAPI_ISteamNetworkingSockets_RunCallbacks(_nativeSockets);
        }
    }

    public class NetworkingUtils : IDisposable
    {
        private IntPtr _nativeUtils;

        public NetworkingUtils()
        {
            _nativeUtils = Native.SteamAPI_SteamNetworkingUtils_v003();

            if (_nativeUtils == IntPtr.Zero)
                throw new InvalidOperationException("Networking utils not created");
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_nativeUtils != IntPtr.Zero)
            {
                Native.SteamAPI_ISteamNetworkingUtils_SetGlobalCallback_SteamNetConnectionStatusChanged(_nativeUtils, null);
                Native.SteamAPI_ISteamNetworkingUtils_SetDebugOutputFunction(_nativeUtils, DebugOutputType.None, null);
                _nativeUtils = IntPtr.Zero;
            }
        }

        ~NetworkingUtils()
        {
            Dispose(false);
        }

        public IntPtr AllocateMessage(int allocateBuffer, out NetworkingMessage message)
        {
            IntPtr msgPtr = Native.SteamAPI_ISteamNetworkingUtils_AllocateMessage(_nativeUtils, allocateBuffer);

            message = Marshal.PtrToStructure<NetworkingMessage>(msgPtr);
            return msgPtr;
        }

        public void ReleaseMessage(IntPtr msgPtr)
        {
            Native.SteamAPI_SteamNetworkingMessage_t_Release(msgPtr);
        }

        public void InitRelayNetworkAccess()
        {
            Native.SteamAPI_ISteamNetworkingUtils_InitRelayNetworkAccess(_nativeUtils);
        }

        public Availability GetRelayNetworkStatus(out RelayNetworkStatus details)
        {
            return Native.SteamAPI_ISteamNetworkingUtils_GetRelayNetworkStatus(_nativeUtils, out details);
        }

        public float GetRelayNetworkStatus(out PingLocation result)
        {
            return Native.SteamAPI_ISteamNetworkingUtils_GetLocalPingLocation(_nativeUtils, out result);
        }

        public int EstimatePingTimeBetweenTwoLocations(ref PingLocation location1, ref PingLocation location2)
        {
            return Native.SteamAPI_ISteamNetworkingUtils_EstimatePingTimeBetweenTwoLocations(_nativeUtils, ref location1, ref location2);
        }

        public int EstimatePingTimeFromLocalHost(ref PingLocation remoteLocation)
        {
            return Native.SteamAPI_ISteamNetworkingUtils_EstimatePingTimeFromLocalHost(_nativeUtils, ref remoteLocation);
        }

        public string ConvertPingLocationToString(ref PingLocation location)
        {
            unsafe
            {
                Span<byte> buffer = stackalloc byte[Library.MaxSteamNetworkingPingLocationString];
                
                fixed (byte* bufferPtr = buffer)
                {
                    Native.SteamAPI_ISteamNetworkingUtils_ConvertPingLocationToString(_nativeUtils, ref location, (IntPtr)bufferPtr, buffer.Length);

                    return Marshal.PtrToStringAnsi((IntPtr)bufferPtr);
                }
            }
        }

        public bool ParsePingLocationString(string pszString, out PingLocation result)
        {
            return Native.SteamAPI_ISteamNetworkingUtils_ParsePingLocationString(_nativeUtils, pszString, out result);
        }

        public bool CheckPingDataUpToDate(float maxAgeSeconds)
        {
            return Native.SteamAPI_ISteamNetworkingUtils_CheckPingDataUpToDate(_nativeUtils, maxAgeSeconds);
        }

        public int GetPingToDataCenter(POPID popID, out POPID pViaRelayPoP)
        {
            return Native.SteamAPI_ISteamNetworkingUtils_GetPingToDataCenter(_nativeUtils, popID, out pViaRelayPoP);
        }

        public int GetPingToDataCenter(POPID popID)
        {
            return Native.SteamAPI_ISteamNetworkingUtils_GetDirectPingToPOP(_nativeUtils, popID);
        }

        public int GetPOPCount()
        {
            return Native.SteamAPI_ISteamNetworkingUtils_GetPOPCount(_nativeUtils);
        }

        public int GetPOPList(POPID[] list)
        {
            return Native.SteamAPI_ISteamNetworkingUtils_GetPOPList(_nativeUtils, list, list.Length);
        }

        public Microseconds LocalTimestamp
        {
            get
            {
                return Native.SteamAPI_ISteamNetworkingUtils_GetLocalTimestamp(_nativeUtils);
            }
        }

        public void SetDebugCallback(DebugOutputType detailLevel, DebugOutputCallback callback)
        {
            Native.SteamAPI_ISteamNetworkingUtils_SetDebugOutputFunction(_nativeUtils, detailLevel, callback);
        }

        public bool SetGlobalConfigValueInt32(ConfigValueEnum eValue, int val)
        {
            return Native.SteamAPI_ISteamNetworkingUtils_SetGlobalConfigValueInt32(_nativeUtils, eValue, val);
        }

        public bool SetGlobalConfigValueFloat(ConfigValueEnum eValue, int val)
        {
            return Native.SteamAPI_ISteamNetworkingUtils_SetGlobalConfigValueFloat(_nativeUtils, eValue, val);
        }

        public bool SetGlobalConfigValueString(ConfigValueEnum eValue, string val)
        {
            return Native.SteamAPI_ISteamNetworkingUtils_SetGlobalConfigValueString(_nativeUtils, eValue, val);
        }

        public bool SetGlobalConfigValuePtr(ConfigValueEnum eValue, IntPtr val)
        {
            return Native.SteamAPI_ISteamNetworkingUtils_SetGlobalConfigValuePtr(_nativeUtils, eValue, val);
        }

        public bool SetConnectionConfigValueInt32(Connection conn, ConfigValueEnum eValue, int val)
        {
            return Native.SteamAPI_ISteamNetworkingUtils_SetConnectionConfigValueInt32(_nativeUtils, conn, eValue, val);
        }

        public bool SetConnectionConfigValueFloat(Connection conn, ConfigValueEnum eValue, int val)
        {
            return Native.SteamAPI_ISteamNetworkingUtils_SetConnectionConfigValueFloat(_nativeUtils, conn, eValue, val);
        }

        public bool SetConnectionConfigValueString(Connection conn, ConfigValueEnum eValue, string val)
        {
            return Native.SteamAPI_ISteamNetworkingUtils_SetConnectionConfigValueString(_nativeUtils, conn, eValue, val);
        }

        public bool SetStatusCallback(ConnectionStatusChangedCallback callback)
        {
            return Native.SteamAPI_ISteamNetworkingUtils_SetGlobalCallback_SteamNetConnectionStatusChanged(_nativeUtils, callback);
        }

        public bool SetAuthenticationCallback(AuthenticationStatusChangedCallback callback)
        {
            return Native.SteamAPI_ISteamNetworkingUtils_SetGlobalCallback_SteamNetAuthenticationStatusChanged(_nativeUtils, callback);
        }

        public bool SetRelayCallback(RelayNetworkStatusChangedCallback callback)
        {
            return Native.SteamAPI_ISteamNetworkingUtils_SetGlobalCallback_SteamRelayNetworkStatusChanged(_nativeUtils, callback);
        }

        public bool SetConfigurationValue(ConfigValueEnum configurationValue, ConfigScope configurationScope, IntPtr scopeObject, ConfigDataType dataType, IntPtr value)
        {
            return Native.SteamAPI_ISteamNetworkingUtils_SetConfigValue(_nativeUtils, configurationValue, configurationScope, scopeObject, dataType, value);
        }

        public bool SetConfigurationValue(ConfigValueEnum configuration, ConfigScope configurationScope, IntPtr scopeObject)
        {
            return Native.SteamAPI_ISteamNetworkingUtils_SetConfigValueStruct(_nativeUtils, ref configuration, configurationScope, scopeObject);
        }

        public ConfigValueResult GetConfigurationValue(ConfigValueEnum configurationValue, ConfigScope configurationScope, IntPtr scopeObject, ref ConfigDataType dataType, IntPtr result, ref uint resultLength)
        {
            return Native.SteamAPI_ISteamNetworkingUtils_GetConfigValue(_nativeUtils, configurationValue, configurationScope, scopeObject, ref dataType, result, ref resultLength);
        }

        public string GetConfigurationValue(ConfigValueEnum eValue, ref ConfigDataType pOutDataType, ref ConfigScope pOutScope)
        {
            IntPtr ptr = Native.SteamAPI_ISteamNetworkingUtils_GetConfigValueInfo(_nativeUtils, eValue, ref pOutDataType, ref pOutScope);

            string message = Marshal.PtrToStringAnsi(ptr);
            return message;
        }

        public ConfigValue IterateGenericEditableConfigValues(ConfigValueEnum eCurrent, bool bEnumerateDevVars)
        {
            return Native.SteamAPI_ISteamNetworkingUtils_IterateGenericEditableConfigValues(_nativeUtils, eCurrent, bEnumerateDevVars);
        }
    }

    public static class Extensions
    {
        public static uint ParseIPv4(this string ip)
        {
            if (IPAddress.TryParse(ip, out IPAddress address))
            {
                if (address.AddressFamily != AddressFamily.InterNetwork)
                {
                    throw new Exception("Incorrect format of an IPv4 address");
                }
            }

            byte[] bytes = address.GetAddressBytes();

            Array.Reverse(bytes);

            return BitConverter.ToUInt32(bytes, 0);
        }

        public static byte[] ParseIPv6(this string ip)
        {
            IPAddress address = default(IPAddress);

            if (IPAddress.TryParse(ip, out address))
            {
                if (address.AddressFamily != AddressFamily.InterNetworkV6)
                {
                    throw new Exception("Incorrect format of an IPv6 address");
                }
            }

            return address.GetAddressBytes();
        }

        public static unsafe string ParseIP(this IPAddr.IPAddrData ip)
        {
            IPAddress address = new IPAddress(new ReadOnlySpan<byte>(ip.ipv6, 16));
            string converted = address.ToString();

            if (converted.Length > 7 && converted.Remove(7) == "::ffff:")
            {
                IPAddr ipv4 = default(IPAddr);

                ipv4.ip = ip;

                byte[] bytes = BitConverter.GetBytes(Native.SteamAPI_SteamNetworkingIPAddr_GetIPv4(ref ipv4));

                Array.Reverse(bytes);

                address = new IPAddress(bytes);
            }

            return address.ToString();
        }
    }

    public static class Library
    {
        public const int MaxCloseMessageLength = 128;
        public const int MaxMessagesPerBatch = 256;
        public const int SocketsCallbacks = 1220;
        public const int MessagesCallbacks = 1250;
        public const int UtilsCallbacks = 1280;
        public const int MaxErrorMessageLength = 1024;
        
        public const int MaxSteamNetworkingConnectionName = 32;
        public const int MaxIpAddrStringLength = 47;

        public const int MaxSteamNetworkingPingLocationString = 1024;

        private const int MaxMessageSize = 512 * 1024;


        public static bool Initialize()
        {
            return Initialize(null);
        }

        public static bool Initialize(StringBuilder errorMessage)
        {
            if (errorMessage != null && errorMessage.Capacity != MaxErrorMessageLength)
            {
                throw new ArgumentOutOfRangeException("Capacity of the error message must be equal to " + MaxErrorMessageLength);
            }

            return Native.GameNetworkingSockets_Init(IntPtr.Zero, errorMessage);
        }

        public static bool Initialize(ref Identity identity, StringBuilder errorMessage)
        {
            if (errorMessage != null && errorMessage.Capacity != MaxErrorMessageLength)
            {
                throw new ArgumentOutOfRangeException("Capacity of the error message must be equal to " + MaxErrorMessageLength);
            }

            if (Object.Equals(identity, null))
            {
                throw new ArgumentNullException("identity");
            }

            return Native.GameNetworkingSockets_Init(ref identity, errorMessage);
        }

        public static void Deinitialize()
        {
            Native.GameNetworkingSockets_Kill();
        }

        public static void SetCustomMemoryAllocator(MallocDelegate mallocDelegate, FreeDelegate freeDelegate, ReallocDelegate reallocDelegate)
        {
            Native.SteamNetworkingSockets_SetCustomMemoryAllocator(mallocDelegate, freeDelegate, reallocDelegate);
        }
        
        public static void SetLockWaitWarningThreshold(Microseconds threshold)
        {
            Native.SteamNetworkingSockets_SetLockWaitWarningThreshold(threshold);
        }

        public static void SetLockAcquiredCallback(LockCallback callback)
        {
            Native.SteamNetworkingSockets_SetLockAcquiredCallback(callback);
        }

        public static void SetLockHeldCallback(LockCallback callback)
        {
            Native.SteamNetworkingSockets_SetLockHeldCallback(callback);
        }

        public static void SetServiceThreadInitCallback(ServiceThreadInitCallback callback)
        {
            Native.SteamNetworkingSockets_SetServiceThreadInitCallback(callback);
        }
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void LockCallback([MarshalAs(UnmanagedType.LPStr)] string tags, Microseconds usecWaited);
    
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void ServiceThreadInitCallback();

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate IntPtr MallocDelegate(UIntPtr size);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void FreeDelegate(IntPtr ptr);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate IntPtr ReallocDelegate(IntPtr ptr, UIntPtr size);
    
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void DebugOutputCallback(DebugOutputType type, [MarshalAs(UnmanagedType.LPStr)] string msg);

    [SuppressUnmanagedCodeSecurity]
    internal static class Native
    {
        private const string nativeLibrary = "GameNetworkingSockets";

        #region Sockets
        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool GameNetworkingSockets_Init(IntPtr identity, StringBuilder errorMessage);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool GameNetworkingSockets_Init(ref Identity identity, StringBuilder errorMessage);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void GameNetworkingSockets_Kill();
        
        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        public static extern void SteamNetworkingSockets_SetCustomMemoryAllocator(MallocDelegate mallocDelegate, FreeDelegate freeDelegate, ReallocDelegate reallocDelegate);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamNetworkingSockets_SetLockWaitWarningThreshold(Microseconds threshold);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamNetworkingSockets_SetLockAcquiredCallback(LockCallback callback);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamNetworkingSockets_SetLockHeldCallback(LockCallback callback);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamNetworkingSockets_SetServiceThreadInitCallback(ServiceThreadInitCallback callback);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr SteamAPI_SteamNetworkingSockets_v009();

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ListenSocket SteamAPI_ISteamNetworkingSockets_CreateListenSocketIP(IntPtr sockets, ref IPAddr address, int configurationsCount, IntPtr configurations);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ListenSocket SteamAPI_ISteamNetworkingSockets_CreateListenSocketIP(IntPtr sockets, ref IPAddr address, int configurationsCount, ConfigValue[] configurations);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern Connection SteamAPI_ISteamNetworkingSockets_ConnectByIPAddress(IntPtr sockets, ref IPAddr address, int configurationsCount, IntPtr configurations);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern Connection SteamAPI_ISteamNetworkingSockets_ConnectByIPAddress(IntPtr sockets, ref IPAddr address, int configurationsCount, ConfigValue[] configurations);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ListenSocket SteamAPI_ISteamNetworkingSockets_CreateListenSocketP2P(IntPtr sockets, int localVirtualPort, int options, IntPtr configurations);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ListenSocket SteamAPI_ISteamNetworkingSockets_CreateListenSocketP2P(IntPtr sockets, int localVirtualPort, int options, ConfigValue[] configurations);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern Connection SteamAPI_ISteamNetworkingSockets_ConnectP2P(IntPtr sockets, ref Identity identityRemote, int remoteVirtualPort, int options, IntPtr configurations);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern Connection SteamAPI_ISteamNetworkingSockets_ConnectP2P(IntPtr sockets, ref Identity identityRemote, int remoteVirtualPort, int options, ConfigValue[] configurations);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern Result SteamAPI_ISteamNetworkingSockets_AcceptConnection(IntPtr sockets, Connection connection);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_ISteamNetworkingSockets_CloseConnection(IntPtr sockets, Connection peer, int reason, [MarshalAs(UnmanagedType.LPStr)] string debug, bool enableLinger);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_ISteamNetworkingSockets_CloseListenSocket(IntPtr sockets, ListenSocket socket);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_ISteamNetworkingSockets_SetConnectionUserData(IntPtr sockets, Connection peer, long userData);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern long SteamAPI_ISteamNetworkingSockets_GetConnectionUserData(IntPtr sockets, Connection peer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void SteamAPI_ISteamNetworkingSockets_SetConnectionName(IntPtr sockets, Connection peer, [MarshalAs(UnmanagedType.LPStr)] string name);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_ISteamNetworkingSockets_GetConnectionName(IntPtr sockets, Connection peer, StringBuilder buffer, int maxLength);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern Result SteamAPI_ISteamNetworkingSockets_SendMessageToConnection(IntPtr sockets, Connection connection, IntPtr data, uint length, SendFlags flags, out long outMessageNumber);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern Result SteamAPI_ISteamNetworkingSockets_SendMessageToConnection(IntPtr sockets, Connection connection, byte[] data, uint length, SendFlags flags, out long outMessageNumber);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void SteamAPI_ISteamNetworkingSockets_SendMessages(IntPtr sockets, int messageLen, NetworkingMessage[] messages, out long messageNumberOrResult);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern Result SteamAPI_ISteamNetworkingSockets_FlushMessagesOnConnection(IntPtr sockets, Connection connection);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int SteamAPI_ISteamNetworkingSockets_ReceiveMessagesOnConnection(IntPtr sockets, Connection connection, IntPtr[] messages, int maxMessages);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_ISteamNetworkingSockets_GetConnectionInfo(IntPtr sockets, Connection connection, ref ConnectionInfo info);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern Result SteamAPI_ISteamNetworkingSockets_GetConnectionRealTimeStatus(IntPtr sockets, Connection conn, ref ConnectionRealtimeStatus stats, int lanesLength, ConnectionRealTimeLaneStatus[] lanes);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int SteamAPI_ISteamNetworkingSockets_GetDetailedConnectionStatus(IntPtr sockets, Connection connection, StringBuilder status, int statusLength);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_ISteamNetworkingSockets_GetListenSocketAddress(IntPtr sockets, ListenSocket socket, out IPAddr address);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_ISteamNetworkingSockets_CreateSocketPair(IntPtr sockets, ref Connection connectionLeft, ref Connection connectionRight, bool useNetworkLoopback, ref Identity identityLeft, ref Identity identityRight);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern Result SteamAPI_ISteamNetworkingSockets_ConfigureConnectionLanes(IntPtr sockets, Connection conn, int numLanes, [In] int[] lanePriorities, [In] ushort[] laneWeights);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_ISteamNetworkingSockets_GetIdentity(IntPtr sockets, ref Identity identity);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern Availability SteamAPI_ISteamNetworkingSockets_InitAuthentication(IntPtr sockets);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern Availability SteamAPI_ISteamNetworkingSockets_GetAuthenticationStatus(IntPtr sockets, out AuthenticationStatus details);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern PollGroup SteamAPI_ISteamNetworkingSockets_CreatePollGroup(IntPtr sockets);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_ISteamNetworkingSockets_DestroyPollGroup(IntPtr sockets, PollGroup pollGroup);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_ISteamNetworkingSockets_SetConnectionPollGroup(IntPtr sockets, Connection connection, PollGroup pollGroup);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int SteamAPI_ISteamNetworkingSockets_ReceiveMessagesOnPollGroup(IntPtr sockets, PollGroup pollGroup, IntPtr[] messages, int maxMessages);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern Connection SteamAPI_ISteamNetworkingSockets_ConnectP2PCustomSignaling(IntPtr sockets, IntPtr signaling, ref Identity peerIdentity, int remoteVirtualPort, int optionsLength, ConfigValue[] options);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern Connection SteamAPI_ISteamNetworkingSockets_ConnectP2PCustomSignaling(IntPtr sockets, IntPtr signaling, ref Identity peerIdentity, int remoteVirtualPort, int optionsLength, IntPtr options);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_ISteamNetworkingSockets_ReceivedP2PCustomSignal(IntPtr sockets, [MarshalAs(UnmanagedType.LPStr)] string pMsg, int cbMsg, IntPtr context);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_ISteamNetworkingSockets_GetCertificateRequest(IntPtr socket, ref int blobSize, IntPtr pBlob, StringBuilder errMsg);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_ISteamNetworkingSockets_SetCertificate(IntPtr socket, byte[] certificate, int certificateLen, StringBuilder errMsg);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void SteamAPI_ISteamNetworkingSockets_RunCallbacks(IntPtr sockets);
        #endregion

        #region
        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr SteamAPI_SteamNetworkingUtils_v003();

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr SteamAPI_ISteamNetworkingUtils_AllocateMessage(IntPtr utils, int cbAllocateBuffer);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void SteamAPI_ISteamNetworkingUtils_InitRelayNetworkAccess(IntPtr utils);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern Availability SteamAPI_ISteamNetworkingUtils_GetRelayNetworkStatus(IntPtr utils, out RelayNetworkStatus details);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern float SteamAPI_ISteamNetworkingUtils_GetLocalPingLocation(IntPtr utils, out PingLocation result);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int SteamAPI_ISteamNetworkingUtils_EstimatePingTimeBetweenTwoLocations(IntPtr utils, ref PingLocation location1, ref PingLocation location2);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int SteamAPI_ISteamNetworkingUtils_EstimatePingTimeFromLocalHost(IntPtr utils, ref PingLocation remoteLocation);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void SteamAPI_ISteamNetworkingUtils_ConvertPingLocationToString(IntPtr utils, ref PingLocation location, IntPtr buffer, int bufferSize);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_ISteamNetworkingUtils_ParsePingLocationString(IntPtr utils, [MarshalAs(UnmanagedType.LPStr)] string pszString, out PingLocation result);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_ISteamNetworkingUtils_CheckPingDataUpToDate(IntPtr utils, float flMaxAgeSeconds);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int SteamAPI_ISteamNetworkingUtils_GetPingToDataCenter(IntPtr utils, POPID popID, out POPID pViaRelayPoP);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int SteamAPI_ISteamNetworkingUtils_GetDirectPingToPOP(IntPtr utils, POPID popID);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int SteamAPI_ISteamNetworkingUtils_GetPOPCount(IntPtr utils);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int SteamAPI_ISteamNetworkingUtils_GetPOPList(IntPtr utils, POPID[] list, int nListSz);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern Microseconds SteamAPI_ISteamNetworkingUtils_GetLocalTimestamp(IntPtr utils);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void SteamAPI_ISteamNetworkingUtils_SetDebugOutputFunction(IntPtr utils, DebugOutputType eDetailLevel, DebugOutputCallback pfnFunc);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_ISteamNetworkingUtils_SetGlobalConfigValueInt32(IntPtr utils, ConfigValueEnum eValue, int val);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_ISteamNetworkingUtils_SetGlobalConfigValueFloat(IntPtr utils, ConfigValueEnum eValue, float val);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_ISteamNetworkingUtils_SetGlobalConfigValueString(IntPtr utils, ConfigValueEnum eValue, [MarshalAs(UnmanagedType.LPStr)] string val);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_ISteamNetworkingUtils_SetGlobalConfigValuePtr(IntPtr utils, ConfigValueEnum eValue, IntPtr val);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_ISteamNetworkingUtils_SetConnectionConfigValueInt32(IntPtr utils, Connection conn, ConfigValueEnum eValue, int val);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_ISteamNetworkingUtils_SetConnectionConfigValueFloat(IntPtr utils, Connection conn, ConfigValueEnum eValue, float val);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_ISteamNetworkingUtils_SetConnectionConfigValueString(IntPtr utils, Connection conn, ConfigValueEnum eValue, [MarshalAs(UnmanagedType.LPStr)] string val);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_ISteamNetworkingUtils_SetGlobalCallback_SteamNetConnectionStatusChanged(IntPtr utils, ConnectionStatusChangedCallback callback);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_ISteamNetworkingUtils_SetGlobalCallback_SteamNetAuthenticationStatusChanged(IntPtr utils, AuthenticationStatusChangedCallback callback);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_ISteamNetworkingUtils_SetGlobalCallback_SteamRelayNetworkStatusChanged(IntPtr utils, RelayNetworkStatusChangedCallback callback);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_ISteamNetworkingUtils_SetConfigValue(IntPtr utils, ConfigValueEnum eValue, ConfigScope eScopeType, IntPtr scopeObj, ConfigDataType eDataType, /* const void* */ IntPtr pArg);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_ISteamNetworkingUtils_SetConfigValueStruct(IntPtr utils, ref ConfigValueEnum opt, ConfigScope eScopeType, IntPtr scopeObj);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ConfigValueResult SteamAPI_ISteamNetworkingUtils_GetConfigValue(IntPtr utils, ConfigValueEnum eValue, ConfigScope eScopeType, IntPtr scopeObj, ref ConfigDataType pOutDataType, /* void* */ IntPtr pResult, ref uint cbResult);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr SteamAPI_ISteamNetworkingUtils_GetConfigValueInfo(IntPtr utils, ConfigValueEnum eValue, ref ConfigDataType pOutDataType, ref ConfigScope pOutScope);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ConfigValue SteamAPI_ISteamNetworkingUtils_IterateGenericEditableConfigValues(IntPtr utils, ConfigValueEnum eCurrent, bool bEnumerateDevVars);
        #endregion

        #region IPAddr
        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void SteamAPI_SteamNetworkingIPAddr_Clear(ref IPAddr address);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_SteamNetworkingIPAddr_IsIPv6AllZeros(ref IPAddr address);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void SteamAPI_SteamNetworkingIPAddr_SetIPv6(ref IPAddr address, byte[] ip, ushort port);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void SteamAPI_SteamNetworkingIPAddr_SetIPv4(ref IPAddr address, uint ip, ushort port);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_SteamNetworkingIPAddr_IsIPv4(ref IPAddr address);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern uint SteamAPI_SteamNetworkingIPAddr_GetIPv4(ref IPAddr address);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void SteamAPI_SteamNetworkingIPAddr_SetIPv6LocalHost(ref IPAddr address, ushort port);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_SteamNetworkingIPAddr_IsLocalHost(ref IPAddr address);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_SteamNetworkingIPAddr_IsEqualTo(ref IPAddr address, ref IPAddr other);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void SteamAPI_SteamNetworkingIPAddr_ToString(ref IPAddr address, IntPtr buf, uint cbBuf, bool bWithPort);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_SteamNetworkingIPAddr_ParseString(ref IPAddr address, [MarshalAs(UnmanagedType.LPStr)] string pszStr);
        #endregion

        #region Identity
        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void SteamAPI_SteamNetworkingIdentity_Clear(ref Identity identity);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_SteamNetworkingIdentity_IsInvalid(ref Identity identity);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void SteamAPI_SteamNetworkingIdentity_SetSteamID(ref Identity identity, ulong steamID);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong SteamAPI_SteamNetworkingIdentity_GetSteamID(ref Identity identity);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void SteamAPI_SteamNetworkingIdentity_SetSteamID64(ref Identity identity, ulong steamID);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern ulong SteamAPI_SteamNetworkingIdentity_GetSteamID64(ref Identity identity);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_SteamNetworkingIdentity_SetXboxPairwiseID(ref Identity identity, [MarshalAs(UnmanagedType.LPStr)] string pszString);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr SteamAPI_SteamNetworkingIdentity_GetXboxPairwiseID(ref Identity identity);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void SteamAPI_SteamNetworkingIdentity_SetIPAddr(ref Identity identity, ref IPAddr addr);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr SteamAPI_SteamNetworkingIdentity_GetIPAddr(ref Identity identity);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void SteamAPI_SteamNetworkingIdentity_SetLocalHost(ref Identity identity);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_SteamNetworkingIdentity_IsLocalHost(ref Identity identity);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_SteamNetworkingIdentity_SetGenericString(ref Identity identity, [MarshalAs(UnmanagedType.LPStr)] string pszString);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr SteamAPI_SteamNetworkingIdentity_GetGenericString(ref Identity identity);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_SteamNetworkingIdentity_SetGenericBytes(ref Identity identity, IntPtr data, uint cbLen);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr SteamAPI_SteamNetworkingIdentity_GetGenericBytes(ref Identity identity, ref int cbLen);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_SteamNetworkingIdentity_IsEqualTo(ref Identity identity, ref Identity x);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void SteamAPI_SteamNetworkingIdentity_ToString(ref Identity identity, IntPtr buf, uint cbBuf);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        [return: MarshalAs(UnmanagedType.I1)]
        internal static extern bool SteamAPI_SteamNetworkingIdentity_ParseString(ref Identity identity, uint sizeofIdentity, [MarshalAs(UnmanagedType.LPStr)] string pszStr);
        #endregion

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void SteamAPI_SteamNetworkingMessage_t_Release(IntPtr nativeMessage);
    }
}

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text;

internal static class RawetherBridge
{
    // This channel contains only session/driver-send health, never packet bytes.
    private static bool TelemetryActive;
    private static string TelemetryAdapter = "";
    private static string TelemetrySession = Guid.NewGuid().ToString("D");
    private static string TelemetryState = "authenticating";
    private static string TelemetryLastSuccess = "";
    private static int TelemetrySends;
    private static uint TelemetryLastStatus;
    private static string TelemetryLastFailure = "";
    private static uint TelemetryLastFailureStatus;
    private static long TelemetrySendDuration;
    private static int TelemetryAttempt;
    private static int TelemetryRetryRecoveries;
    private static string TelemetryDriverState = "unknown";
    private static string TelemetryServiceState = "unknown";
    private static string TelemetryLinkState = "unknown";
    private static string TelemetryPrunedDay = "";
    private static string TelemetryExitReason = "";
    private static int TelemetryExitCode = -1;
    private static string TelemetryExitedAt = "";

    private static string ReadServiceState(string name)
    {
        try
        {
            using (ServiceController service = new ServiceController(name))
                return service.Status.ToString();
        }
        catch (InvalidOperationException) { return "unknown"; }
        catch (System.ComponentModel.Win32Exception) { return "unknown"; }
        catch (System.Security.SecurityException) { return "unknown"; }
    }

    private static void SnapshotSendFailure()
    {
        TelemetryDriverState = ReadServiceState("PCASp50");
        TelemetryServiceState = ReadServiceState("RJSuService");
        TelemetryLinkState = "unknown";
        try
        {
            foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
                if (String.Equals(adapter.Description, TelemetryAdapter, StringComparison.OrdinalIgnoreCase))
                {
                    TelemetryLinkState = adapter.OperationalStatus.ToString();
                    break;
                }
        }
        catch (NetworkInformationException) { }
        catch (System.Security.SecurityException) { }
    }

    // Only the pinned DLL is supported. Its SendSinglePacket waits on
    // GetOverlappedResult(..., TRUE) for ERROR_IO_PENDING before returning.
    // A failed completed send may still have reached the wire: reuse the same
    // candidate/sequence; never increment a sequence for a retry.
    private static uint RetryEcho(Func<uint> send, Func<int, bool> wait,
                                  Action<string, uint, int, long> record)
    {
        for (int attempt = 1; attempt <= 3; attempt++)
        {
            if (wait(0))
            {
                record("stopped", 995, attempt, 0);
                return 995;
            }
            Stopwatch timer = Stopwatch.StartNew();
            uint status = send();
            long elapsed = timer.ElapsedMilliseconds;
            if (status == 0)
            {
                record("running", status, attempt, elapsed);
                return 0;
            }
            bool retry = status == 31 && attempt < 3;
            record(retry ? "retrying" : "send-failed", status, attempt, elapsed);
            if (!retry) return status;
            if (wait(attempt == 1 ? 1000 : 3000))
            {
                record("stopped", 995, attempt, elapsed);
                return 995;
            }
        }
        return 31;
    }

    private static void RecordEchoAttempt(string state, uint status, int attempt,
                                          long elapsed, int successfulSends)
    {
        if (!TelemetryActive) return;
        TelemetryAttempt = attempt;
        TelemetrySendDuration = elapsed;
        if (state == "retrying" || state == "send-failed")
        {
            // Timestamp before the diagnostic queries so it reflects the send failure.
            TelemetryLastFailure = DateTime.UtcNow.ToString("o");
            TelemetryLastFailureStatus = status;
            SnapshotSendFailure();
        }
        if (state == "running" && attempt > 1) TelemetryRetryRecoveries++;
        RecordKeepalive(state, status, successfulSends + (state == "running" ? 1 : 0));
        if (state != "running" || attempt > 1) AppendSendDiagnostic();
    }

    private static uint SendNextEcho(ref byte[] previous, Func<byte[], uint> send,
                                     Func<int, bool> wait, Action<string, uint, int, long> record)
    {
        byte[] candidate = (byte[])previous.Clone();
        IncrementEncodedUInt32(candidate, 24);
        IncrementEncodedUInt32(candidate, 34);
        uint status = RetryEcho(() => send(candidate), wait, record);
        if (status == 0)
        {
            Array.Clear(previous, 0, previous.Length);
            previous = candidate;
        }
        else Array.Clear(candidate, 0, candidate.Length);
        return status;
    }

    private static string SendDiagnosticFields()
    {
        return ",\"last_failure_at\":" + JsonText(TelemetryLastFailure)
            + ",\"last_failure_status\":" + TelemetryLastFailureStatus
            + ",\"send_duration_ms\":" + TelemetrySendDuration
            + ",\"send_attempt\":" + TelemetryAttempt
            + ",\"retry_recoveries\":" + TelemetryRetryRecoveries
            + ",\"failure_driver_state\":" + JsonText(TelemetryDriverState)
            + ",\"failure_service_state\":" + JsonText(TelemetryServiceState)
            + ",\"failure_link_state\":" + JsonText(TelemetryLinkState)
            + ",\"native_backend\":\"rawether\""
            + ",\"exit_reason\":" + JsonText(TelemetryExitReason)
            + ",\"exit_code\":" + TelemetryExitCode
            + ",\"exited_at\":" + JsonText(TelemetryExitedAt);
    }

    private static void FinalizeTelemetry(int exitCode)
    {
        if (!TelemetryActive) return;
        if (TelemetryState == "running")
            TelemetryExitReason = "stop-requested";
        else if (TelemetryState == "send-failed" || TelemetryState == "retrying")
            TelemetryExitReason = "keepalive-send-failed";
        else
            TelemetryExitReason = "authentication-failed";
        TelemetryExitCode = exitCode;
        TelemetryExitedAt = DateTime.UtcNow.ToString("o");
        TelemetryState = TelemetryExitReason == "stop-requested" ? "stopped" : "exited";
        string folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NJMUCampusNetAssistant");
        SaveKeepaliveTelemetry(folder);
        AppendSendDiagnostic();
    }

    private static void AppendSendDiagnostic()
    {
        SaveSendDiagnostic(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                                       "NJMUCampusNetAssistant", "diagnostics"));
    }

    private static void SaveSendDiagnostic(string folder)
    {
        try
        {
            Directory.CreateDirectory(folder);
            string today = DateTime.UtcNow.ToString("yyyy-MM-dd");
            if (TelemetryPrunedDay != today)
            {
                TelemetryPrunedDay = today;
                foreach (string file in Directory.GetFiles(folder, "native-keepalive-????-??-??.jsonl"))
                {
                    try { if (File.GetLastWriteTimeUtc(file) < DateTime.UtcNow.AddDays(-7)) File.Delete(file); }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                }
            }
            string body = "{\"schema_version\":1,\"timestamp\":" + JsonText(DateTime.UtcNow.ToString("o"))
                + ",\"session_id\":" + JsonText(TelemetrySession)
                + ",\"state\":" + JsonText(TelemetryState)
                + ",\"successful_sends\":" + TelemetrySends
                + ",\"last_send_status\":" + TelemetryLastStatus + SendDiagnosticFields() + "}";
            File.AppendAllText(Path.Combine(folder, "native-keepalive-" + DateTime.UtcNow.ToString("yyyy-MM-dd") + ".jsonl"),
                               body + Environment.NewLine, new UTF8Encoding(false));
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private static string JsonText(string value)
    {
        StringBuilder text = new StringBuilder("\"");
        foreach (char character in value)
        {
            if (character == '"' || character == '\\') text.Append('\\').Append(character);
            else if (character < 32) text.Append("\\u").Append(((int)character).ToString("x4"));
            else text.Append(character);
        }
        return text.Append('"').ToString();
    }

    private static void RecordKeepalive(string state, uint status, int successfulSends)
    {
        if (!TelemetryActive) return;
        TelemetryState = state;
        TelemetryLastStatus = status;
        if (successfulSends > TelemetrySends && status == 0)
            TelemetryLastSuccess = DateTime.UtcNow.ToString("o");
        TelemetrySends = successfulSends;
        string folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NJMUCampusNetAssistant");
        SaveKeepaliveTelemetry(folder);
    }

    private static void SaveKeepaliveTelemetry(string folder)
    {
        string temporary = null;
        try
        {
            Directory.CreateDirectory(folder);
            string target = Path.Combine(folder, "native-keepalive-state.json");
            temporary = target + "." + TelemetrySession + ".tmp";
            string body = "{\"schema_version\":1,\"session_id\":" + JsonText(TelemetrySession)
                + ",\"process_id\":" + Process.GetCurrentProcess().Id
                + ",\"process_started_at\":" + JsonText(Process.GetCurrentProcess().StartTime.ToUniversalTime().ToString("o"))
                + ",\"adapter_description\":" + JsonText(TelemetryAdapter)
                + ",\"updated_at\":" + JsonText(DateTime.UtcNow.ToString("o"))
                + ",\"state\":" + JsonText(TelemetryState)
                + ",\"successful_sends\":" + TelemetrySends
                + ",\"last_send_status\":" + TelemetryLastStatus
                + ",\"last_success_at\":" + JsonText(TelemetryLastSuccess) + SendDiagnosticFields() + "}";
            File.WriteAllText(temporary, body, new UTF8Encoding(false));
            if (File.Exists(target)) File.Replace(temporary, target, null);
            else File.Move(temporary, target);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        finally
        {
            if (temporary != null)
            {
                try { if (File.Exists(temporary)) File.Delete(temporary); }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
    }
    private const uint LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x00000100;
    private const uint LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800;
    private static readonly IntPtr InvalidHandle = new IntPtr(-1);
    private const string SessionMutexName = @"Local\NJMUCampusNetAssistant-RuijieSession";
    private const string SessionStopEventName = @"Local\NJMUCampusNetAssistant-RuijieSessionStop";
    private const uint EVENT_MODIFY_STATE = 0x0002;
    private const uint WAIT_OBJECT_0 = 0x00000000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    private struct OSVERSIONINFOA
    {
        public uint Size;
        public uint Major;
        public uint Minor;
        public uint Build;
        public uint PlatformId;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string ServicePack;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern bool GetVersionEx(ref OSVERSIONINFOA version);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibraryEx(string path, IntPtr file, uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr module, string name);

    [DllImport("kernel32.dll")]
    private static extern bool FreeLibrary(IntPtr module);

    [DllImport("kernel32.dll")]
    private static extern uint SleepEx(uint milliseconds, bool alertable);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr OpenEvent(uint desiredAccess, bool inheritHandle, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetEvent(IntPtr handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateEvent(
        IntPtr eventAttributes, bool manualReset, bool initialState, string name
    );

    [DllImport("kernel32.dll", EntryPoint = "CloseHandle", SetLastError = true)]
    private static extern bool CloseKernelHandle(IntPtr handle);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate IntPtr OpenEnumeration();
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate bool OpenProtocolDriver();
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void CloseProtocolDriver();
    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Ansi)]
    private delegate IntPtr OpenPacketAdapter([MarshalAs(UnmanagedType.LPStr)] string name);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void ClosePacketAdapter(IntPtr adapter);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint GetRawetherError();
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void PacketCompletion(uint errorCode, uint bytesTransferred, IntPtr overlapped);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint PacketReadEx(
        IntPtr adapter, IntPtr packet, IntPtr bytesReturned, IntPtr overlapped,
        PacketCompletion completion
    );
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint CancelPacketRead(IntPtr adapter, IntPtr packet);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate bool SetBpfProgram(IntPtr adapter, IntPtr program, uint length);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint MakeNdisRequest(
        IntPtr adapter, IntPtr request, IntPtr overlapped,
        [MarshalAs(UnmanagedType.I1)] bool wait
    );
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint SendSinglePacket(
        IntPtr adapter, IntPtr packet, uint length, IntPtr overlapped
    );
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint QueryEthCurrentAddress(IntPtr adapter, IntPtr address);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate IntPtr GetAdapter(IntPtr enumeration);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint QueryName(IntPtr adapter, IntPtr buffer, ref uint size);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void CloseHandle(IntPtr handle);

    private static T Export<T>(IntPtr module, string name) where T : class
    {
        IntPtr address = GetProcAddress(module, name);
        if (address == IntPtr.Zero) throw new InvalidOperationException("missing-export:" + name);
        return Marshal.GetDelegateForFunctionPointer(address, typeof(T)) as T;
    }

    private static string Query(QueryName query, IntPtr adapter, out uint status)
    {
        IntPtr buffer = Marshal.AllocHGlobal(260);
        try
        {
            for (int index = 0; index < 260; index++) Marshal.WriteByte(buffer, index, 0);
            uint size = 260;
            status = query(adapter, buffer, ref size);
            return status == 0 ? Marshal.PtrToStringAnsi(buffer) ?? "" : "";
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static string Base64(string value)
    {
        return Convert.ToBase64String(Encoding.Default.GetBytes(value));
    }

    private static int EapolOffset(IntPtr packet, int frameLength)
    {
        if (frameLength < 14) return -1;
        int frame = 0x38;
        int etherType = (Marshal.ReadByte(packet, frame + 12) << 8) |
                        Marshal.ReadByte(packet, frame + 13);
        if ((etherType == 0x8100 || etherType == 0x88a8) && frameLength >= 18)
        {
            etherType = (Marshal.ReadByte(packet, frame + 16) << 8) |
                        Marshal.ReadByte(packet, frame + 17);
            return etherType == 0x888e ? 18 : -1;
        }
        return etherType == 0x888e ? 14 : -1;
    }

    private static bool IsEapol(IntPtr packet, int frameLength)
    {
        return EapolOffset(packet, frameLength) >= 0;
    }

    private static bool IsIdentityRequest(IntPtr packet, int frameLength)
    {
        int offset = EapolOffset(packet, frameLength);
        if (offset < 0 || frameLength < offset + 9) return false;
        int frame = 0x38;
        int bodyLength = (Marshal.ReadByte(packet, frame + offset + 2) << 8) |
                         Marshal.ReadByte(packet, frame + offset + 3);
        return Marshal.ReadByte(packet, frame + offset + 1) == 0 && bodyLength >= 5 &&
               Marshal.ReadByte(packet, frame + offset + 4) == 1 &&
               Marshal.ReadByte(packet, frame + offset + 8) == 1;
    }

    private static bool IsMd5Request(IntPtr packet, int frameLength)
    {
        int offset = EapolOffset(packet, frameLength);
        if (offset < 0 || frameLength < offset + 26) return false;
        int frame = 0x38;
        int bodyLength = (Marshal.ReadByte(packet, frame + offset + 2) << 8) |
                         Marshal.ReadByte(packet, frame + offset + 3);
        int eapLength = (Marshal.ReadByte(packet, frame + offset + 6) << 8) |
                        Marshal.ReadByte(packet, frame + offset + 7);
        return Marshal.ReadByte(packet, frame + offset + 1) == 0 && bodyLength >= 22 &&
               eapLength >= 22 && eapLength <= bodyLength &&
               Marshal.ReadByte(packet, frame + offset + 4) == 1 &&
               Marshal.ReadByte(packet, frame + offset + 8) == 4 &&
               Marshal.ReadByte(packet, frame + offset + 9) == 16;
    }

    private static int RequestIdentifier(IntPtr packet, int frameLength)
    {
        int offset = EapolOffset(packet, frameLength);
        return offset >= 0 && frameLength >= offset + 6
            ? Marshal.ReadByte(packet, 0x38 + offset + 5) : -1;
    }

    private static bool IsEapResult(IntPtr packet, int frameLength, int expectedCode)
    {
        int offset = EapolOffset(packet, frameLength);
        if (offset < 0 || frameLength < offset + 8) return false;
        int frame = 0x38;
        int bodyLength = (Marshal.ReadByte(packet, frame + offset + 2) << 8) |
                         Marshal.ReadByte(packet, frame + offset + 3);
        int eapLength = (Marshal.ReadByte(packet, frame + offset + 6) << 8) |
                        Marshal.ReadByte(packet, frame + offset + 7);
        return Marshal.ReadByte(packet, frame + offset + 1) == 0 && bodyLength >= 4 &&
               eapLength >= 4 && eapLength <= bodyLength &&
               Marshal.ReadByte(packet, frame + offset + 4) == expectedCode;
    }

    private static void DescribeEapol(
        IntPtr packet, int frameLength,
        out int packetType, out int eapCode, out int eapIdentifier, out int eapType
    )
    {
        packetType = -1;
        eapCode = -1;
        eapIdentifier = -1;
        eapType = -1;
        int offset = EapolOffset(packet, frameLength);
        if (offset < 0 || frameLength < offset + 4) return;
        int frame = 0x38;
        packetType = Marshal.ReadByte(packet, frame + offset + 1);
        int bodyLength = (Marshal.ReadByte(packet, frame + offset + 2) << 8) |
                         Marshal.ReadByte(packet, frame + offset + 3);
        if (packetType != 0 || bodyLength < 4 || frameLength < offset + 8) return;
        eapCode = Marshal.ReadByte(packet, frame + offset + 4);
        eapIdentifier = Marshal.ReadByte(packet, frame + offset + 5);
        int eapLength = (Marshal.ReadByte(packet, frame + offset + 6) << 8) |
                        Marshal.ReadByte(packet, frame + offset + 7);
        if ((eapCode == 1 || eapCode == 2) && eapLength >= 5 && bodyLength >= 5 &&
            frameLength >= offset + 9)
            eapType = Marshal.ReadByte(packet, frame + offset + 8);
    }

    private static bool InstallEapolFilter(IntPtr adapter, SetBpfProgram setBpf)
    {
        byte[] program = new byte[] {
            0x28,0x00,0x00,0x00,0x0c,0x00,0x00,0x00,
            0x15,0x00,0x04,0x00,0x8e,0x88,0x00,0x00,
            0x28,0x00,0x00,0x00,0x0c,0x00,0x00,0x00,
            0x15,0x00,0x00,0x03,0x00,0x81,0x00,0x00,
            0x28,0x00,0x00,0x00,0x10,0x00,0x00,0x00,
            0x15,0x00,0x00,0x01,0x8e,0x88,0x00,0x00,
            0x06,0x00,0x00,0x00,0xff,0xff,0xff,0xff,
            0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        };
        IntPtr buffer = Marshal.AllocHGlobal(program.Length);
        try
        {
            Marshal.Copy(program, 0, buffer, program.Length);
            return setBpf(adapter, buffer, (uint)program.Length);
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static bool EnableReceiveDelivery(
        IntPtr adapter, MakeNdisRequest makeNdisRequest, GetRawetherError getError
    )
    {
        // This mirrors the official client's per-handle initialization before it
        // posts reads. OID_GEN_CURRENT_PACKET_FILTER=0x0001010e and
        // NDIS_PACKET_TYPE_PROMISCUOUS=0x20 only affect this temporary capture
        // handle; closing the adapter removes the request. No frame is sent.
        const int RequestSize = 0x30;
        const int OverlappedSize = 0x20;
        const uint OidGenCurrentPacketFilter = 0x0001010e;
        const int NdisPacketTypePromiscuous = 0x20;
        IntPtr request = Marshal.AllocHGlobal(RequestSize);
        IntPtr overlapped = Marshal.AllocHGlobal(OverlappedSize);
        IntPtr filterValue = Marshal.AllocHGlobal(4);
        IntPtr completionEvent = IntPtr.Zero;
        try
        {
            for (int index = 0; index < RequestSize; index++) Marshal.WriteByte(request, index, 0);
            for (int index = 0; index < OverlappedSize; index++) Marshal.WriteByte(overlapped, index, 0);
            Marshal.WriteInt32(filterValue, NdisPacketTypePromiscuous);
            Marshal.WriteInt32(request, 0x14, 1);
            Marshal.WriteInt32(request, 0x18, unchecked((int)OidGenCurrentPacketFilter));
            Marshal.WriteIntPtr(request, 0x1c, filterValue);
            Marshal.WriteInt32(request, 0x24, 4);
            completionEvent = CreateEvent(IntPtr.Zero, false, false, null);
            if (completionEvent == IntPtr.Zero)
            {
                Console.WriteLine("ERROR\tcreate-ndis-event\t{0}", Marshal.GetLastWin32Error());
                return false;
            }
            Marshal.WriteIntPtr(overlapped, 0x18, completionEvent);
            uint status = makeNdisRequest(adapter, request, overlapped, true);
            if (status != 0)
            {
                Console.WriteLine("ERROR\tset-ndis-packet-filter\t{0}\t{1}", status, getError());
                return false;
            }
            return true;
        }
        finally
        {
            if (completionEvent != IntPtr.Zero) CloseKernelHandle(completionEvent);
            Marshal.FreeHGlobal(filterValue);
            Marshal.FreeHGlobal(overlapped);
            Marshal.FreeHGlobal(request);
        }
    }

    private static uint SendFixedStart(
        IntPtr adapter, SendSinglePacket sendPacket, byte[] sourceAddress
    )
    {
        IntPtr frame = Marshal.AllocHGlobal(18);
        IntPtr sendOverlapped = Marshal.AllocHGlobal(0x20);
        IntPtr sendEvent = IntPtr.Zero;
        try
        {
            for (int index = 0; index < 0x20; index++)
                Marshal.WriteByte(sendOverlapped, index, 0);
            byte[] eapolFrame = new byte[] {
                0x01,0x80,0xc2,0x00,0x00,0x03,
                0x00,0x00,0x00,0x00,0x00,0x00,
                0x88,0x8e,0x01,0x01,0x00,0x00,
            };
            Array.Copy(sourceAddress, 0, eapolFrame, 6, 6);
            Marshal.Copy(eapolFrame, 0, frame, eapolFrame.Length);
            sendEvent = CreateEvent(IntPtr.Zero, false, false, null);
            if (sendEvent == IntPtr.Zero) return 8;
            Marshal.WriteIntPtr(sendOverlapped, 0x18, sendEvent);
            return sendPacket(adapter, frame, (uint)eapolFrame.Length, sendOverlapped);
        }
        finally
        {
            if (sendEvent != IntPtr.Zero) CloseKernelHandle(sendEvent);
            Marshal.FreeHGlobal(sendOverlapped);
            Marshal.FreeHGlobal(frame);
        }
    }

    private static uint SendFixedLogoff(
        IntPtr adapter, SendSinglePacket sendPacket, byte[] sourceAddress
    )
    {
        IntPtr frame = Marshal.AllocHGlobal(18);
        IntPtr sendOverlapped = Marshal.AllocHGlobal(0x20);
        IntPtr sendEvent = IntPtr.Zero;
        try
        {
            for (int index = 0; index < 0x20; index++)
                Marshal.WriteByte(sendOverlapped, index, 0);
            byte[] eapolFrame = new byte[] {
                0x01,0x80,0xc2,0x00,0x00,0x03,
                0x00,0x00,0x00,0x00,0x00,0x00,
                0x88,0x8e,0x01,0x02,0x00,0x00,
            };
            Array.Copy(sourceAddress, 0, eapolFrame, 6, 6);
            Marshal.Copy(eapolFrame, 0, frame, eapolFrame.Length);
            sendEvent = CreateEvent(IntPtr.Zero, false, false, null);
            if (sendEvent == IntPtr.Zero) return 8;
            Marshal.WriteIntPtr(sendOverlapped, 0x18, sendEvent);
            return sendPacket(adapter, frame, (uint)eapolFrame.Length, sendOverlapped);
        }
        finally
        {
            if (sendEvent != IntPtr.Zero) CloseKernelHandle(sendEvent);
            Marshal.FreeHGlobal(sendOverlapped);
            Marshal.FreeHGlobal(frame);
        }
    }

    private static uint SendConstrainedEcho(
        IntPtr adapter, SendSinglePacket sendPacket, byte[] echoFrame,
        byte[] sourceAddress, byte[] serverAddress
    )
    {
        if (adapter == IntPtr.Zero || adapter == InvalidHandle) return 6;
        if (echoFrame == null || echoFrame.Length != 45 ||
            sourceAddress == null || sourceAddress.Length != 6 ||
            serverAddress == null || serverAddress.Length != 6)
            return 87;
        for (int index = 0; index < 6; index++)
            if (echoFrame[index] != serverAddress[index] ||
                echoFrame[6 + index] != sourceAddress[index]) return 87;
        if (echoFrame[12] != 0x88 || echoFrame[13] != 0x8e ||
            echoFrame[14] != 0x01 || echoFrame[15] != 0xbf ||
            echoFrame[16] != 0x00 || echoFrame[17] != 0x1e)
            return 87;

        IntPtr frame = Marshal.AllocHGlobal(echoFrame.Length);
        IntPtr sendOverlapped = Marshal.AllocHGlobal(0x20);
        IntPtr sendEvent = IntPtr.Zero;
        try
        {
            for (int index = 0; index < 0x20; index++)
                Marshal.WriteByte(sendOverlapped, index, 0);
            Marshal.Copy(echoFrame, 0, frame, echoFrame.Length);
            sendEvent = CreateEvent(IntPtr.Zero, false, false, null);
            if (sendEvent == IntPtr.Zero) return 8;
            Marshal.WriteIntPtr(sendOverlapped, 0x18, sendEvent);
            return sendPacket(adapter, frame, (uint)echoFrame.Length, sendOverlapped);
        }
        finally
        {
            if (sendEvent != IntPtr.Zero) CloseKernelHandle(sendEvent);
            Marshal.FreeHGlobal(sendOverlapped);
            Marshal.FreeHGlobal(frame);
        }
    }

    private static byte ReverseComplement(byte value)
    {
        int reversed = 0;
        for (int bit = 0; bit < 8; bit++)
            reversed |= ((value >> bit) & 1) << (7 - bit);
        return (byte)(reversed ^ 0xff);
    }

    private static void IncrementEncodedUInt32(byte[] frame, int offset)
    {
        uint value = 0;
        for (int index = 0; index < 4; index++)
            value = (value << 8) | ReverseComplement(frame[offset + index]);
        value = unchecked(value + 1);
        for (int index = 3; index >= 0; index--)
        {
            frame[offset + index] = ReverseComplement((byte)(value & 0xff));
            value >>= 8;
        }
    }

    private static bool WaitForStopOrInterval(IntPtr stopEvent, int milliseconds)
    {
        var timer = Stopwatch.StartNew();
        while (timer.ElapsedMilliseconds < milliseconds)
        {
            if (stopEvent != IntPtr.Zero && WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0)
                return true;
            int remaining = milliseconds - (int)timer.ElapsedMilliseconds;
            SleepEx((uint)Math.Max(1, Math.Min(remaining, 1000)), true);
        }
        return stopEvent != IntPtr.Zero && WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0;
    }

    private static uint SendIdentityResponse(
        IntPtr adapter, SendSinglePacket sendPacket, byte[] sourceAddress,
        IntPtr requestPacket, int requestLength, byte[] identity
    )
    {
        int offset = EapolOffset(requestPacket, requestLength);
        if (offset < 0 || !IsIdentityRequest(requestPacket, requestLength)) return 87;
        int eapLength = 5 + identity.Length;
        byte[] eapolFrame = new byte[18 + eapLength];
        int requestFrame = 0x38;
        for (int index = 0; index < 6; index++)
        {
            eapolFrame[index] = Marshal.ReadByte(requestPacket, requestFrame + 6 + index);
            eapolFrame[6 + index] = sourceAddress[index];
        }
        eapolFrame[12] = 0x88;
        eapolFrame[13] = 0x8e;
        eapolFrame[14] = 0x01;
        eapolFrame[15] = 0x00;
        eapolFrame[16] = (byte)(eapLength >> 8);
        eapolFrame[17] = (byte)eapLength;
        eapolFrame[18] = 0x02;
        eapolFrame[19] = (byte)RequestIdentifier(requestPacket, requestLength);
        eapolFrame[20] = (byte)(eapLength >> 8);
        eapolFrame[21] = (byte)eapLength;
        eapolFrame[22] = 0x01;
        Array.Copy(identity, 0, eapolFrame, 23, identity.Length);

        IntPtr frame = Marshal.AllocHGlobal(eapolFrame.Length);
        IntPtr sendOverlapped = Marshal.AllocHGlobal(0x20);
        IntPtr sendEvent = IntPtr.Zero;
        try
        {
            for (int index = 0; index < 0x20; index++)
                Marshal.WriteByte(sendOverlapped, index, 0);
            Marshal.Copy(eapolFrame, 0, frame, eapolFrame.Length);
            sendEvent = CreateEvent(IntPtr.Zero, false, false, null);
            if (sendEvent == IntPtr.Zero) return 8;
            Marshal.WriteIntPtr(sendOverlapped, 0x18, sendEvent);
            return sendPacket(adapter, frame, (uint)eapolFrame.Length, sendOverlapped);
        }
        finally
        {
            if (sendEvent != IntPtr.Zero) CloseKernelHandle(sendEvent);
            Marshal.FreeHGlobal(sendOverlapped);
            Marshal.FreeHGlobal(frame);
        }
    }

    private static uint SendMd5Response(
        IntPtr adapter, SendSinglePacket sendPacket, byte[] sourceAddress,
        IntPtr requestPacket, int requestLength, byte[] identity, byte[] password,
        byte[] privateExtension
    )
    {
        int offset = EapolOffset(requestPacket, requestLength);
        if (offset < 0 || !IsMd5Request(requestPacket, requestLength)) return 88;
        int identifier = RequestIdentifier(requestPacket, requestLength);
        byte[] challenge = new byte[16];
        byte[] digestInput = new byte[1 + password.Length + challenge.Length];
        byte[] digest = null;
        byte[] eapolFrame = null;
        IntPtr frame = IntPtr.Zero;
        IntPtr sendOverlapped = IntPtr.Zero;
        IntPtr sendEvent = IntPtr.Zero;
        try
        {
            for (int index = 0; index < challenge.Length; index++)
                challenge[index] = Marshal.ReadByte(requestPacket, 0x38 + offset + 10 + index);
            digestInput[0] = (byte)identifier;
            Array.Copy(password, 0, digestInput, 1, password.Length);
            Array.Copy(challenge, 0, digestInput, 1 + password.Length, challenge.Length);
            using (MD5 md5 = MD5.Create()) digest = md5.ComputeHash(digestInput);

            int eapLength = 6 + digest.Length + identity.Length;
            int extensionLength = privateExtension == null ? 0 : privateExtension.Length;
            eapolFrame = new byte[18 + eapLength + extensionLength];
            int requestFrame = 0x38;
            for (int index = 0; index < 6; index++)
            {
                eapolFrame[index] = Marshal.ReadByte(requestPacket, requestFrame + 6 + index);
                eapolFrame[6 + index] = sourceAddress[index];
            }
            eapolFrame[12] = 0x88;
            eapolFrame[13] = 0x8e;
            eapolFrame[14] = 0x01;
            eapolFrame[15] = 0x00;
            eapolFrame[16] = (byte)(eapLength >> 8);
            eapolFrame[17] = (byte)eapLength;
            eapolFrame[18] = 0x02;
            eapolFrame[19] = (byte)identifier;
            eapolFrame[20] = (byte)(eapLength >> 8);
            eapolFrame[21] = (byte)eapLength;
            eapolFrame[22] = 0x04;
            eapolFrame[23] = 0x10;
            Array.Copy(digest, 0, eapolFrame, 24, digest.Length);
            Array.Copy(identity, 0, eapolFrame, 24 + digest.Length, identity.Length);
            if (extensionLength > 0)
                Array.Copy(privateExtension, 0, eapolFrame, 18 + eapLength, extensionLength);

            frame = Marshal.AllocHGlobal(eapolFrame.Length);
            sendOverlapped = Marshal.AllocHGlobal(0x20);
            for (int index = 0; index < 0x20; index++)
                Marshal.WriteByte(sendOverlapped, index, 0);
            Marshal.Copy(eapolFrame, 0, frame, eapolFrame.Length);
            sendEvent = CreateEvent(IntPtr.Zero, false, false, null);
            if (sendEvent == IntPtr.Zero) return 8;
            Marshal.WriteIntPtr(sendOverlapped, 0x18, sendEvent);
            return sendPacket(adapter, frame, (uint)eapolFrame.Length, sendOverlapped);
        }
        finally
        {
            if (sendEvent != IntPtr.Zero) CloseKernelHandle(sendEvent);
            if (sendOverlapped != IntPtr.Zero) Marshal.FreeHGlobal(sendOverlapped);
            if (frame != IntPtr.Zero) Marshal.FreeHGlobal(frame);
            if (eapolFrame != null) Array.Clear(eapolFrame, 0, eapolFrame.Length);
            if (digest != null) Array.Clear(digest, 0, digest.Length);
            Array.Clear(digestInput, 0, digestInput.Length);
            Array.Clear(challenge, 0, challenge.Length);
        }
    }

    private static int ReceiveOne(
        IntPtr adapter, PacketReadEx packetRead, CancelPacketRead cancelRead,
        GetRawetherError getError, int timeoutMilliseconds,
        SendSinglePacket sendStart, QueryEthCurrentAddress queryAddress,
        byte[] identity, byte[] password, bool privateMd5,
        bool persistentSession, IntPtr stopEvent
    )
    {
        // The official client keeps fifteen 0xa40-byte receive contexts posted.
        // Reproduce that buffer layout so PCASp50 sees the same receive queue,
        // while retaining only redacted metadata for the first completed frame.
        const int ReceiveSlotCount = 15;
        const int ContextSize = 0xa40;
        const int OverlappedOffset = 0x210;
        const int OverlappedContextOffset = 0x220;
        const int BytesReturnedOffset = 0x230;
        const int PacketOffset = 0x234;
        const int PacketLengthOffset = 0x264;
        const int PacketCapacityOffset = 0x268;
        const int FrameCapacity = 0x7d0;
        IntPtr[] contexts = new IntPtr[ReceiveSlotCount];
        IntPtr[] packets = new IntPtr[ReceiveSlotCount];
        bool[] started = new bool[ReceiveSlotCount];
        bool[] completed = new bool[ReceiveSlotCount];
        uint[] completionErrors = new uint[ReceiveSlotCount];
        uint[] transferred = new uint[ReceiveSlotCount];
        int[] frameLengths = new int[ReceiveSlotCount];
        bool[] eapol = new bool[ReceiveSlotCount];
        PacketCompletion[] completions = new PacketCompletion[ReceiveSlotCount];
        int capturedSlot = -1;
        int identitySlot = -1;
        int md5Slot = -1;
        int successSlot = -1;
        int failureSlot = -1;
        int startedCount = 0;
        bool activeStart = sendStart != null && queryAddress != null;
        bool identityProbe = activeStart && identity != null;
        bool md5Probe = identityProbe && password != null;
        uint sendStatus = UInt32.MaxValue;
        uint identitySendStatus = UInt32.MaxValue;
        uint md5SendStatus = UInt32.MaxValue;
        bool identitySendAttempted = false;
        bool md5SendAttempted = false;
        bool privateExtensionAccepted = false;
        int echoSentCount = 0;
        uint firstEchoStatus = UInt32.MaxValue;
        uint secondEchoStatus = UInt32.MaxValue;
        int sentCount = 0;
        byte[] sourceAddress = null;
        try
        {
            for (int slot = 0; slot < ReceiveSlotCount; slot++)
            {
                int capturedIndex = slot;
                contexts[slot] = Marshal.AllocHGlobal(ContextSize);
                for (int index = 0; index < ContextSize; index++)
                    Marshal.WriteByte(contexts[slot], index, 0);
                packets[slot] = IntPtr.Add(contexts[slot], PacketOffset);
                Marshal.WriteIntPtr(contexts[slot], OverlappedContextOffset, contexts[slot]);
                Marshal.WriteInt32(contexts[slot], PacketCapacityOffset, FrameCapacity);
                completions[slot] = delegate(uint errorCode, uint bytesTransferred, IntPtr ignored)
                {
                    completionErrors[capturedIndex] = errorCode;
                    transferred[capturedIndex] = bytesTransferred;
                    int reported = Marshal.ReadInt32(contexts[capturedIndex], PacketLengthOffset);
                    frameLengths[capturedIndex] = reported >= 0 && reported <= FrameCapacity ? reported : 0;
                    eapol[capturedIndex] = errorCode == 0 &&
                        IsEapol(packets[capturedIndex], frameLengths[capturedIndex]);
                    completed[capturedIndex] = true;
                    bool valid = errorCode == 0 && frameLengths[capturedIndex] > 0;
                    if (valid && IsIdentityRequest(packets[capturedIndex], frameLengths[capturedIndex]) &&
                        identitySlot < 0)
                        identitySlot = capturedIndex;
                    if (valid && identitySendAttempted && identitySendStatus == 0 &&
                        IsMd5Request(packets[capturedIndex], frameLengths[capturedIndex]) &&
                        md5Slot < 0)
                        md5Slot = capturedIndex;
                    int expectedResultIdentifier = md5Slot >= 0
                        ? RequestIdentifier(packets[md5Slot], frameLengths[md5Slot]) : -1;
                    bool matchingResult = valid && md5SendAttempted && md5SendStatus == 0 &&
                        expectedResultIdentifier >= 0 &&
                        RequestIdentifier(packets[capturedIndex], frameLengths[capturedIndex]) ==
                        expectedResultIdentifier;
                    if (matchingResult && IsEapResult(packets[capturedIndex], frameLengths[capturedIndex], 3) &&
                        successSlot < 0)
                        successSlot = capturedIndex;
                    if (matchingResult && IsEapResult(packets[capturedIndex], frameLengths[capturedIndex], 4) &&
                        failureSlot < 0)
                        failureSlot = capturedIndex;
                    if (valid && !activeStart && capturedSlot < 0)
                        capturedSlot = capturedIndex;
                };
                uint readStarted = packetRead(
                    adapter,
                    packets[slot],
                    IntPtr.Add(contexts[slot], BytesReturnedOffset),
                    IntPtr.Add(contexts[slot], OverlappedOffset),
                    completions[slot]
                );
                started[slot] = readStarted != 0;
                if (started[slot]) startedCount++;
            }
            Console.WriteLine("RECEIVE_SLOTS\t{0}", ReceiveSlotCount);
            Console.WriteLine("READ_POSTED\t{0}", startedCount);
            if (startedCount == 0)
            {
                Console.WriteLine("READ_STARTED\t0");
                Console.WriteLine("ERROR\tpacket-read\t{0}", getError());
                return 73;
            }
            Console.WriteLine("READ_STARTED\t1");
            if (activeStart)
            {
                IntPtr address = Marshal.AllocHGlobal(6);
                try
                {
                    for (int index = 0; index < 6; index++) Marshal.WriteByte(address, index, 0);
                    uint addressStatus = queryAddress(adapter, address);
                    Console.WriteLine("ADDRESS_QUERY\t{0}", addressStatus);
                    if (addressStatus == 0)
                    {
                        sourceAddress = new byte[6];
                        for (int index = 0; index < 6; index++)
                            sourceAddress[index] = Marshal.ReadByte(address, index);
                        sendStatus = SendFixedStart(adapter, sendStart, sourceAddress);
                        if (sendStatus == 0) sentCount = 1;
                    }
                    else sendStatus = addressStatus;
                }
                finally
                {
                    Marshal.FreeHGlobal(address);
                }
                Console.WriteLine("SEND_STATUS\t{0}", sendStatus);
            }
            var timer = Stopwatch.StartNew();
            while (sendStatus != UInt32.MaxValue && sendStatus != 0 &&
                   timer.ElapsedMilliseconds < 50)
                SleepEx(1, true);
            while ((sendStatus == UInt32.MaxValue || sendStatus == 0) &&
                   timer.ElapsedMilliseconds < timeoutMilliseconds)
            {
                if (identityProbe && identitySlot >= 0 && !identitySendAttempted)
                {
                    identitySendAttempted = true;
                    identitySendStatus = SendIdentityResponse(
                        adapter, sendStart, sourceAddress,
                        packets[identitySlot], frameLengths[identitySlot], identity
                    );
                    if (identitySendStatus == 0) sentCount++;
                    Console.WriteLine("IDENTITY_SEND_STATUS\t{0}", identitySendStatus);
                    if (identitySendStatus != 0) break;
                }
                if (md5Probe && md5Slot >= 0 && !md5SendAttempted)
                {
                    md5SendAttempted = true;
                    byte[] privateExtension = null;
                    if (privateMd5)
                    {
                        byte[] challenge = new byte[16];
                        for (int index = 0; index < challenge.Length; index++)
                            challenge[index] = Marshal.ReadByte(
                                packets[md5Slot], 0x38 + EapolOffset(packets[md5Slot], frameLengths[md5Slot]) + 10 + index
                            );
                        Console.WriteLine(
                            "PRIVATE_REQUEST\t{0}\t{1}",
                            Convert.ToBase64String(challenge), Convert.ToBase64String(sourceAddress)
                        );
                        Console.Out.Flush();
                        try
                        {
                            privateExtension = Convert.FromBase64String(Console.In.ReadLine() ?? "");
                            privateExtensionAccepted = privateExtension.Length >= 0x80 &&
                                privateExtension.Length <= 0x800;
                        }
                        catch (FormatException) { privateExtensionAccepted = false; }
                        Array.Clear(challenge, 0, challenge.Length);
                        if (!privateExtensionAccepted)
                        {
                            md5SendStatus = 87;
                            Console.WriteLine("PRIVATE_EXTENSION_ACCEPTED\t0");
                            break;
                        }
                        Console.WriteLine("PRIVATE_EXTENSION_ACCEPTED\t1");
                    }
                    md5SendStatus = SendMd5Response(
                        adapter, sendStart, sourceAddress,
                        packets[md5Slot], frameLengths[md5Slot], identity, password, privateExtension
                    );
                    if (privateExtension != null)
                        Array.Clear(privateExtension, 0, privateExtension.Length);
                    if (md5SendStatus == 0) sentCount++;
                    Console.WriteLine("MD5_SEND_STATUS\t{0}", md5SendStatus);
                    if (md5SendStatus != 0) break;
                }
                if ((!identityProbe && identitySlot >= 0) ||
                    (identityProbe && !md5Probe && md5Slot >= 0) ||
                    (md5Probe && (successSlot >= 0 || failureSlot >= 0))) break;
                int remaining = timeoutMilliseconds - (int)timer.ElapsedMilliseconds;
                SleepEx((uint)Math.Max(1, Math.Min(remaining, 200)), true);
            }
            if (privateMd5 && successSlot >= 0)
            {
                byte[] successFrame = new byte[frameLengths[successSlot]];
                byte[] serverAddress = new byte[6];
                byte[] firstEcho = null;
                byte[] secondEcho = null;
                try
                {
                    Marshal.Copy(IntPtr.Add(packets[successSlot], 0x38), successFrame, 0, successFrame.Length);
                    Array.Copy(successFrame, 6, serverAddress, 0, 6);
                    Console.WriteLine("PRIVATE_SUCCESS_FRAME\t{0}", Convert.ToBase64String(successFrame));
                    Console.Out.Flush();
                    try
                    {
                        firstEcho = Convert.FromBase64String(Console.In.ReadLine() ?? "");
                        if (!persistentSession)
                            secondEcho = Convert.FromBase64String(Console.In.ReadLine() ?? "");
                    }
                    catch (FormatException) { firstEcho = secondEcho = null; }
                    firstEchoStatus = SendConstrainedEcho(
                        adapter, sendStart, firstEcho, sourceAddress, serverAddress
                    );
                    if (firstEchoStatus == 0)
                    {
                        sentCount++;
                        echoSentCount++;
                    }
                    Console.WriteLine("ECHO_SEND_STATUS\t1\t{0}", firstEchoStatus);
                    Console.Out.Flush();
                    if (persistentSession && firstEchoStatus == 0)
                    {
                        Console.WriteLine("IDENTITY_RECEIVED\t{0}", identitySlot >= 0 ? 1 : 0);
                        Console.WriteLine("MD5_RECEIVED\t{0}", md5Slot >= 0 ? 1 : 0);
                        Console.WriteLine("MD5_IDENTIFIER\t{0}", md5Slot >= 0
                            ? RequestIdentifier(packets[md5Slot], frameLengths[md5Slot]) : -1);
                        Console.WriteLine("RESULT_RECEIVED\t1");
                        Console.WriteLine("RESULT_CODE\t3");
                        Console.WriteLine("RESULT_IDENTIFIER\t{0}",
                            RequestIdentifier(packets[successSlot], frameLengths[successSlot]));
                        Console.WriteLine("FRAME_LENGTH\t{0}", frameLengths[successSlot]);
                        Console.WriteLine("ECHO_FRAMES_SENT\t1");
                        Console.WriteLine("FRAMES_READ\t3");
                        Console.WriteLine("FRAMES_SENT\t{0}", sentCount);
                        if (password != null) Array.Clear(password, 0, password.Length);
                        if (identity != null) Array.Clear(identity, 0, identity.Length);
                        Array.Clear(successFrame, 0, successFrame.Length);
                        for (int slot = 0; slot < ReceiveSlotCount; slot++)
                        {
                            if (!completed[slot] || contexts[slot] == IntPtr.Zero) continue;
                            for (int index = 0; index < ContextSize; index++)
                                Marshal.WriteByte(contexts[slot], index, 0);
                        }
                        RecordKeepalive("running", 0, 1);
                        Console.WriteLine("SESSION_READY\t{0}", Process.GetCurrentProcess().Id);
                        Console.Out.Flush();
                        secondEcho = (byte[])firstEcho.Clone();
                        while (!WaitForStopOrInterval(stopEvent, 30000))
                        {
                            secondEchoStatus = SendNextEcho(
                                ref secondEcho,
                                candidate => SendConstrainedEcho(adapter, sendStart, candidate, sourceAddress, serverAddress),
                                delay => WaitForStopOrInterval(stopEvent, delay),
                                (state, status, attempt, duration) => RecordEchoAttempt(state, status, attempt, duration, echoSentCount)
                            );
                            if (secondEchoStatus != 0)
                            {
                                break;
                            }
                            sentCount++;
                            echoSentCount++;
                            RecordKeepalive("running", 0, echoSentCount);
                        }
                    }
                    else if (firstEchoStatus == 0)
                    {
                        var echoTimer = Stopwatch.StartNew();
                        while (echoTimer.ElapsedMilliseconds < 30000)
                        {
                            int remainingEcho = 30000 - (int)echoTimer.ElapsedMilliseconds;
                            SleepEx((uint)Math.Max(1, Math.Min(remainingEcho, 1000)), true);
                        }
                        secondEchoStatus = SendConstrainedEcho(
                            adapter, sendStart, secondEcho, sourceAddress, serverAddress
                        );
                        if (secondEchoStatus == 0)
                        {
                            sentCount++;
                            echoSentCount++;
                        }
                    }
                    Console.WriteLine("ECHO_SEND_STATUS\t2\t{0}", secondEchoStatus);
                    Console.Out.Flush();
                }
                finally
                {
                    Array.Clear(successFrame, 0, successFrame.Length);
                    Array.Clear(serverAddress, 0, serverAddress.Length);
                    if (firstEcho != null) Array.Clear(firstEcho, 0, firstEcho.Length);
                    if (secondEcho != null) Array.Clear(secondEcho, 0, secondEcho.Length);
                }
            }
            capturedSlot = md5Probe
                ? (successSlot >= 0 ? successSlot : failureSlot >= 0 ? failureSlot :
                   md5Slot >= 0 ? md5Slot : identitySlot)
                : identityProbe ? (md5Slot >= 0 ? md5Slot : identitySlot) : identitySlot;
            for (int slot = 0; slot < ReceiveSlotCount; slot++)
            {
                if (started[slot] && !completed[slot]) cancelRead(adapter, packets[slot]);
            }
            var cancelTimer = Stopwatch.StartNew();
            while (cancelTimer.ElapsedMilliseconds < 1500)
            {
                bool allCompleted = true;
                for (int slot = 0; slot < ReceiveSlotCount; slot++)
                    if (started[slot] && !completed[slot]) allCompleted = false;
                if (allCompleted) break;
                SleepEx(50, true);
            }
            int completedCount = 0;
            for (int slot = 0; slot < ReceiveSlotCount; slot++)
                if (started[slot] && completed[slot]) completedCount++;
            bool captured = capturedSlot >= 0 && completionErrors[capturedSlot] == 0 &&
                frameLengths[capturedSlot] > 0;
            int eapolType = -1;
            int eapCode = -1;
            int eapIdentifier = -1;
            int eapType = -1;
            if (captured && eapol[capturedSlot])
                DescribeEapol(
                    packets[capturedSlot], frameLengths[capturedSlot],
                    out eapolType, out eapCode, out eapIdentifier, out eapType
                );
            Console.WriteLine("READ_COMPLETED\t{0}", completedCount == startedCount ? 1 : 0);
            Console.WriteLine("READ_COMPLETIONS\t{0}", completedCount);
            Console.WriteLine("READ_ERROR\t{0}", captured ? completionErrors[capturedSlot] : 0);
            Console.WriteLine("TRANSFERRED\t{0}", captured ? transferred[capturedSlot] : 0);
            Console.WriteLine("FRAME_LENGTH\t{0}", captured ? frameLengths[capturedSlot] : 0);
            Console.WriteLine("FRAME_CLASS\t{0}", !captured
                ? "NONE" : eapol[capturedSlot] ? "EAPOL" : "OTHER");
            Console.WriteLine("EAPOL_TYPE\t{0}", eapolType);
            Console.WriteLine("EAP_CODE\t{0}", eapCode);
            Console.WriteLine("EAP_IDENTIFIER\t{0}", eapIdentifier);
            Console.WriteLine("EAP_TYPE\t{0}", eapType);
            Console.WriteLine("IDENTITY_RECEIVED\t{0}", identitySlot >= 0 ? 1 : 0);
            Console.WriteLine("IDENTITY_IDENTIFIER\t{0}", identitySlot >= 0
                ? RequestIdentifier(packets[identitySlot], frameLengths[identitySlot]) : -1);
            Console.WriteLine("IDENTITY_SEND_STATUS\t{0}", identitySendStatus);
            Console.WriteLine("MD5_RECEIVED\t{0}", md5Slot >= 0 ? 1 : 0);
            Console.WriteLine("MD5_IDENTIFIER\t{0}", md5Slot >= 0
                ? RequestIdentifier(packets[md5Slot], frameLengths[md5Slot]) : -1);
            Console.WriteLine("MD5_SEND_STATUS\t{0}", md5SendStatus);
            Console.WriteLine("PRIVATE_EXTENSION_ACCEPTED\t{0}", privateExtensionAccepted ? 1 : 0);
            Console.WriteLine("ECHO_FRAMES_SENT\t{0}", echoSentCount);
            int resultSlot = successSlot >= 0 ? successSlot : failureSlot;
            Console.WriteLine("RESULT_RECEIVED\t{0}", resultSlot >= 0 ? 1 : 0);
            Console.WriteLine("RESULT_CODE\t{0}", successSlot >= 0 ? 3 : failureSlot >= 0 ? 4 : -1);
            Console.WriteLine("RESULT_IDENTIFIER\t{0}", resultSlot >= 0
                ? RequestIdentifier(packets[resultSlot], frameLengths[resultSlot]) : -1);
            int matchedFrames = md5Probe
                ? (identitySlot >= 0 ? 1 : 0) + (md5Slot >= 0 ? 1 : 0) +
                  (resultSlot >= 0 ? 1 : 0)
                : identityProbe
                  ? (identitySlot >= 0 ? 1 : 0) + (md5Slot >= 0 ? 1 : 0)
                : (captured ? 1 : 0);
            Console.WriteLine("FRAMES_READ\t{0}", matchedFrames);
            Console.WriteLine("FRAMES_SENT\t{0}", sentCount);
            return activeStart && (sendStatus != 0 ||
                (identitySendAttempted && identitySendStatus != 0) ||
                (md5SendAttempted && md5SendStatus != 0)) ? 76 : 0;
        }
        finally
        {
            GC.KeepAlive(completions);
            for (int slot = 0; slot < ReceiveSlotCount; slot++)
            {
                if (contexts[slot] != IntPtr.Zero && (!started[slot] || completed[slot]))
                    Marshal.FreeHGlobal(contexts[slot]);
            }
        }
    }

    public static int Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "selftest")
        {
            var check = new OSVERSIONINFOA { Size = (uint)Marshal.SizeOf(typeof(OSVERSIONINFOA)) };
            bool ok = GetVersionEx(ref check);
            Console.WriteLine("VERSION\t{0}\t{1}", check.Major, check.PlatformId);
            return ok && check.PlatformId == 2 && (check.Major == 5 || check.Major == 6) ? 0 : 63;
        }
        if (args.Length == 1 && args[0] == "stop-private-session")
        {
            IntPtr stop = OpenEvent(EVENT_MODIFY_STATE, false, SessionStopEventName);
            if (stop == IntPtr.Zero) return 0;
            bool signaled;
            try { signaled = SetEvent(stop); }
            finally { CloseKernelHandle(stop); }
            if (!signaled) return 79;
            System.Threading.Mutex stoppedSession = new System.Threading.Mutex(false, SessionMutexName);
            bool stoppedSessionOwned = false;
            try
            {
                try { stoppedSessionOwned = stoppedSession.WaitOne(5000); }
                catch (System.Threading.AbandonedMutexException) { stoppedSessionOwned = true; }
                return stoppedSessionOwned ? 0 : 80;
            }
            finally
            {
                if (stoppedSessionOwned) stoppedSession.ReleaseMutex();
                stoppedSession.Dispose();
            }
        }
        bool enumerateOnly = args.Length == 2 && args[0] == "enumerate";
        bool openClose = args.Length == 3 && args[0] == "open-close";
        bool receiveOne = args.Length == 4 && args[0] == "receive-one";
        bool sendStart = args.Length == 4 && args[0] == "send-start";
        bool sendLogoff = args.Length == 3 && args[0] == "send-logoff";
        bool sendIdentity = args.Length == 4 && args[0] == "send-identity";
        bool sendMd5 = args.Length == 4 && args[0] == "send-md5";
        bool sendPrivateMd5 = args.Length == 4 && args[0] == "send-private-md5";
        bool runPrivateSession = args.Length == 4 && args[0] == "run-private-session";
        if (!enumerateOnly && !openClose && !receiveOne && !sendStart && !sendLogoff && !sendIdentity && !sendMd5 && !sendPrivateMd5 && !runPrivateSession)
            return 64;
        System.Threading.Mutex sessionMutex = null;
        bool sessionMutexOwned = false;
        IntPtr sessionStopEvent = IntPtr.Zero;
        if (runPrivateSession)
        {
            sessionMutex = new System.Threading.Mutex(false, SessionMutexName);
            try { sessionMutexOwned = sessionMutex.WaitOne(0); }
            catch (System.Threading.AbandonedMutexException) { sessionMutexOwned = true; }
            if (!sessionMutexOwned)
            {
                Console.WriteLine("SESSION_ALREADY_RUNNING\t1");
                sessionMutex.Dispose();
                return 78;
            }
            sessionStopEvent = CreateEvent(IntPtr.Zero, false, false, SessionStopEventName);
            if (sessionStopEvent == IntPtr.Zero)
            {
                sessionMutex.ReleaseMutex();
                sessionMutex.Dispose();
                return 79;
            }
        }
        byte[] identity = null;
        byte[] password = null;
        if (sendIdentity || sendMd5 || sendPrivateMd5 || runPrivateSession)
        {
            try
            {
                string encodedIdentity = Console.In.ReadLine();
                identity = Convert.FromBase64String(encodedIdentity ?? "");
                if (sendMd5 || sendPrivateMd5 || runPrivateSession)
                {
                    string encodedPassword = Console.In.ReadLine();
                    password = Convert.FromBase64String(encodedPassword ?? "");
                }
            }
            catch (FormatException) { return 77; }
            if (identity.Length == 0 || identity.Length > 128) return 77;
            if ((sendMd5 || sendPrivateMd5 || runPrivateSession) && (password.Length == 0 || password.Length > 512)) return 77;
        }
        string dllPath = Path.GetFullPath(args[1]);
        string wantedFriendly = openClose || receiveOne || sendStart || sendLogoff || sendIdentity || sendMd5 || sendPrivateMd5 || runPrivateSession
            ? Encoding.Default.GetString(Convert.FromBase64String(args[2]))
            : "";
        if (runPrivateSession)
        {
            TelemetryActive = true;
            TelemetryAdapter = wantedFriendly;
            RecordKeepalive("authenticating", 0, 0);
        }
        int receiveTimeout = receiveOne || sendStart || sendIdentity || sendMd5 || sendPrivateMd5 || runPrivateSession ? Int32.Parse(args[3]) : 0;
        if ((receiveOne || sendStart || sendIdentity || sendMd5 || sendPrivateMd5 || runPrivateSession) &&
            (receiveTimeout < 1000 || receiveTimeout > 65000)) return 64;
        Environment.CurrentDirectory = Path.GetDirectoryName(dllPath);

        var version = new OSVERSIONINFOA { Size = (uint)Marshal.SizeOf(typeof(OSVERSIONINFOA)) };
        GetVersionEx(ref version);
        Console.WriteLine("VERSION\t{0}\t{1}", version.Major, version.PlatformId);

        IntPtr module = LoadLibraryEx(
            dllPath, IntPtr.Zero,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32
        );
        if (module == IntPtr.Zero)
        {
            Console.WriteLine("ERROR\tload\t{0}", Marshal.GetLastWin32Error());
            return 65;
        }
        try
        {
            var openProtocol = Export<OpenProtocolDriver>(module, "W32N_OpenProtocolDriver");
            var closeProtocol = Export<CloseProtocolDriver>(module, "W32N_CloseProtocolDriver");
            var open = Export<OpenEnumeration>(module, "MacEnum_OpenEnumeration");
            var first = Export<GetAdapter>(module, "MacEnum_GetFirstAdapterInfoHandle");
            var next = Export<GetAdapter>(module, "MacEnum_GetNextAdapterInfoHandle");
            var queryFriendly = Export<QueryName>(module, "MacEnum_QueryAdapterFriendlyName_A");
            var queryNdis = Export<QueryName>(module, "MacEnum_QueryAdapterNdisName_A");
            var closeAdapter = Export<CloseHandle>(module, "MacEnum_CloseAdapterInfoHandle");
            var closeEnumeration = Export<CloseHandle>(module, "MacEnum_CloseEnumeration");
            var openPacketAdapter = Export<OpenPacketAdapter>(module, "W32N_OpenAdapterA");
            var closePacketAdapter = Export<ClosePacketAdapter>(module, "W32N_CloseAdapter");
            var getRawetherError = Export<GetRawetherError>(module, "W32N_GetLastError");
            PacketReadEx packetRead = receiveOne || sendStart || sendIdentity || sendMd5 || sendPrivateMd5 || runPrivateSession
                ? Export<PacketReadEx>(module, "W32N_PacketReadEx") : null;
            CancelPacketRead cancelRead = receiveOne || sendStart || sendIdentity || sendMd5 || sendPrivateMd5 || runPrivateSession
                ? Export<CancelPacketRead>(module, "W32N_CancelPacketRead") : null;
            SetBpfProgram setBpf = receiveOne || sendStart || sendIdentity || sendMd5 || sendPrivateMd5 || runPrivateSession
                ? Export<SetBpfProgram>(module, "W32N_SetBPFProgram") : null;
            MakeNdisRequest makeNdisRequest = receiveOne || sendStart || sendIdentity || sendMd5 || sendPrivateMd5 || runPrivateSession
                ? Export<MakeNdisRequest>(module, "W32N_MakeNdisRequest") : null;
            SendSinglePacket sendSinglePacket = sendStart || sendLogoff || sendIdentity || sendMd5 || sendPrivateMd5 || runPrivateSession
                ? Export<SendSinglePacket>(module, "W32N_SendSinglePacket") : null;
            QueryEthCurrentAddress queryEthCurrentAddress = sendStart || sendLogoff || sendIdentity || sendMd5 || sendPrivateMd5 || runPrivateSession
                ? Export<QueryEthCurrentAddress>(module, "W32N_QueryEthCurrentAddress") : null;
            Console.WriteLine("STEP\topen-protocol");
            if (!openProtocol())
            {
                Console.WriteLine("ERROR\topen-protocol\tfalse");
                return 66;
            }
            try
            {
                Console.WriteLine("STEP\topen-enumeration");
                IntPtr enumeration = open();
                if (enumeration == InvalidHandle)
                {
                    Console.WriteLine("ERROR\tenumerate\t-1");
                    return 67;
                }
                int count = 0;
                int matchingCount = 0;
                string matchingNdisName = "";
                try
                {
                    Console.WriteLine("STEP\tfirst-adapter");
                    IntPtr adapter = first(enumeration);
                    while (adapter != InvalidHandle && count < 32)
                    {
                        Console.WriteLine("STEP\tquery-adapter\t{0}", count);
                        uint friendlyStatus;
                        uint ndisStatus;
                        string friendly = Query(queryFriendly, adapter, out friendlyStatus);
                        string ndis = Query(queryNdis, adapter, out ndisStatus);
                        Console.WriteLine(
                            "ADAPTER\t{0}\t{1}\t{2}\t{3}",
                            friendlyStatus, ndisStatus, Base64(friendly), Base64(ndis)
                        );
                        if ((openClose || receiveOne || sendStart || sendLogoff || sendIdentity || sendMd5 || sendPrivateMd5 || runPrivateSession) &&
                            friendlyStatus == 0 && ndisStatus == 0 &&
                            String.Equals(friendly, wantedFriendly, StringComparison.Ordinal))
                        {
                            matchingCount++;
                            matchingNdisName = ndis;
                        }
                        count++;
                        closeAdapter(adapter);
                        Console.WriteLine("STEP\tnext-adapter\t{0}", count);
                        adapter = next(enumeration);
                    }
                    if (count == 32 && adapter != InvalidHandle)
                    {
                        closeAdapter(adapter);
                        Console.WriteLine("ERROR\tadapter-limit\t32");
                        return 68;
                    }
                }
                finally { closeEnumeration(enumeration); }
                if (openClose || receiveOne || sendStart || sendLogoff || sendIdentity || sendMd5 || sendPrivateMd5 || runPrivateSession)
                {
                    if (matchingCount != 1 || String.IsNullOrEmpty(matchingNdisName))
                    {
                        Console.WriteLine("ERROR\ttarget-count\t{0}", matchingCount);
                        return 71;
                    }
                    Console.WriteLine("STEP\topen-packet-adapter");
                    IntPtr packetAdapter = openPacketAdapter(matchingNdisName);
                    if (packetAdapter == IntPtr.Zero || packetAdapter == InvalidHandle)
                    {
                        Console.WriteLine("ERROR\topen-packet-adapter\t{0}", getRawetherError());
                        return 72;
                    }
                    int receiveResult = 0;
                    try
                    {
                        Console.WriteLine("OPENED\t1");
                        if (sendLogoff)
                        {
                            IntPtr address = Marshal.AllocHGlobal(6);
                            try
                            {
                                for (int index = 0; index < 6; index++) Marshal.WriteByte(address, index, 0);
                                uint addressStatus = queryEthCurrentAddress(packetAdapter, address);
                                Console.WriteLine("ADDRESS_QUERY\t{0}", addressStatus);
                                uint sendStatus = addressStatus;
                                if (addressStatus == 0)
                                {
                                    byte[] sourceAddress = new byte[6];
                                    for (int index = 0; index < 6; index++)
                                        sourceAddress[index] = Marshal.ReadByte(address, index);
                                    sendStatus = SendFixedLogoff(packetAdapter, sendSinglePacket, sourceAddress);
                                }
                                Console.WriteLine("SEND_STATUS\t{0}", sendStatus);
                                Console.WriteLine("FRAMES_SENT\t{0}", sendStatus == 0 ? 1 : 0);
                                if (sendStatus != 0) receiveResult = 76;
                            }
                            finally { Marshal.FreeHGlobal(address); }
                        }
                        else if (receiveOne || sendStart || sendIdentity || sendMd5 || sendPrivateMd5 || runPrivateSession)
                        {
                            bool deliverySet = EnableReceiveDelivery(
                                packetAdapter, makeNdisRequest, getRawetherError
                            );
                            Console.WriteLine("NDIS_FILTER_SET\t{0}", deliverySet ? 1 : 0);
                            bool filterSet = deliverySet && InstallEapolFilter(packetAdapter, setBpf);
                            Console.WriteLine("FILTER_SET\t{0}", filterSet ? 1 : 0);
                            if (!deliverySet)
                            {
                                receiveResult = 75;
                            }
                            else if (!filterSet)
                            {
                                Console.WriteLine("ERROR\tset-eapol-filter\t{0}", getRawetherError());
                                receiveResult = 74;
                            }
                            else
                            {
                                receiveResult = ReceiveOne(
                                    packetAdapter, packetRead, cancelRead, getRawetherError, receiveTimeout,
                                    sendStart || sendIdentity || sendMd5 || sendPrivateMd5 || runPrivateSession ? sendSinglePacket : null,
                                    sendStart || sendIdentity || sendMd5 || sendPrivateMd5 || runPrivateSession ? queryEthCurrentAddress : null,
                                    sendIdentity || sendMd5 || sendPrivateMd5 || runPrivateSession ? identity : null,
                                    sendMd5 || sendPrivateMd5 || runPrivateSession ? password : null,
                                    sendPrivateMd5 || runPrivateSession,
                                    runPrivateSession, sessionStopEvent
                                );
                            }
                        }
                    }
                    finally
                    {
                        Console.WriteLine("STEP\tclose-packet-adapter");
                        closePacketAdapter(packetAdapter);
                    }
                    Console.WriteLine("CLOSED\t1");
                    if (receiveResult != 0) return receiveResult;
                    Console.WriteLine("RESULT\t{0}", receiveOne ? "RECEIVE_FINISHED" :
                        sendStart ? "START_FINISHED" :
                        sendLogoff ? "LOGOFF_FINISHED" :
                        sendIdentity ? "IDENTITY_FINISHED" :
                        sendMd5 ? "MD5_FINISHED" :
                        sendPrivateMd5 ? "PRIVATE_MD5_FINISHED" :
                        runPrivateSession ? "PRIVATE_SESSION_FINISHED" : "OPENED_CLOSED");
                    return 0;
                }
                Console.WriteLine("RESULT\t{0}", count);
                return count > 0 ? 0 : 69;
            }
            finally
            {
                Console.WriteLine("STEP\tclose-protocol");
                closeProtocol();
            }
        }
        catch (Exception error)
        {
            Console.WriteLine("ERROR\tbridge\t{0}", error.Message.Replace('\t', ' '));
            return 70;
        }
        finally
        {
            FreeLibrary(module);
            if (password != null) Array.Clear(password, 0, password.Length);
            if (identity != null) Array.Clear(identity, 0, identity.Length);
            if (TelemetryActive)
                FinalizeTelemetry(0);
            if (sessionStopEvent != IntPtr.Zero) CloseKernelHandle(sessionStopEvent);
            if (sessionMutexOwned && sessionMutex != null) sessionMutex.ReleaseMutex();
            if (sessionMutex != null) sessionMutex.Dispose();
        }
    }
}

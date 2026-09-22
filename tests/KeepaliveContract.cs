// Offline tests of the compiled bridge's retry and sequence policy. Never calls Main or a driver.
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

internal static class KeepaliveContract
{
    private static Type Bridge;
    private static int Checks;
    private static void Check(bool ok, string name)
    {
        if (!ok) throw new Exception(name);
        Checks++;
    }
    private static uint Retry(uint[] statuses, bool stopFirst, bool stopDuring, out int sends, out string records)
    {
        int count = 0;
        List<string> seen = new List<string>();
        List<int> delays = new List<int>();
        Func<uint> send = () => statuses[count++];
        Func<int, bool> wait = delay => { if (delay > 0) delays.Add(delay); return stopFirst || (stopDuring && delay > 0); };
        Action<string, uint, int, long> record = (state, status, attempt, duration) => {
            Check(duration >= 0, "duration"); seen.Add(state + ":" + status + ":" + attempt);
        };
        uint result = (uint)Bridge.GetMethod("RetryEcho", BindingFlags.NonPublic | BindingFlags.Static)
            .Invoke(null, new object[] { send, wait, record });
        sends = count;
        records = String.Join(",", seen);
        Check(delays.Count <= 2, "bounded waits");
        if (delays.Count > 0) Check(delays[0] == 1000, "first wait");
        if (delays.Count > 1) Check(delays[1] == 3000, "second wait");
        return result;
    }
    private static byte[] Next(byte[] previous, uint[] results, out List<byte[]> sent, out uint status)
    {
        int count = 0;
        var captures = new List<byte[]>();
        Func<byte[], uint> send = frame => { captures.Add((byte[])frame.Clone()); return results[count++]; };
        Func<int, bool> wait = delay => false;
        Action<string, uint, int, long> record = (s, r, a, d) => {};
        object[] args = { previous, send, wait, record };
        status = (uint)Bridge.GetMethod("SendNextEcho", BindingFlags.NonPublic | BindingFlags.Static).Invoke(null, args);
        sent = captures;
        return (byte[])args[0];
    }
    public static int Main(string[] args)
    {
        Bridge = Assembly.LoadFile(Path.GetFullPath(args[0])).GetType("RawetherBridge", true);
        int sends; string records;
        Check(Retry(new uint[] {0}, false, false, out sends, out records) == 0 && sends == 1, "normal send");
        Check(Retry(new uint[] {31, 0}, false, false, out sends, out records) == 0 && sends == 2, "one retry");
        Check(records.Contains("retrying:31:1") && records.Contains("running:0:2"), "recovery telemetry");
        Check(Retry(new uint[] {31, 31, 0}, false, false, out sends, out records) == 0 && sends == 3, "two retries");
        Check(Retry(new uint[] {31, 31, 31}, false, false, out sends, out records) == 31 && sends == 3, "exhausted");
        Check(records.EndsWith("send-failed:31:3"), "terminal failure");
        foreach (uint code in new uint[] {6, 87, 995, 997, 5})
            Check(Retry(new uint[] {code}, false, false, out sends, out records) == code && sends == 1, "no blind retry");
        Check(Retry(new uint[] {0}, true, false, out sends, out records) == 995 && sends == 0, "stop before send");
        Check(Retry(new uint[] {31}, false, true, out sends, out records) == 995 && sends == 1, "stop during delay");
        Check(records.EndsWith("stopped:995:1"), "stop telemetry");
        byte[] seed = new byte[45];
        uint status; List<byte[]> frames;
        byte[] current = Next(seed, new uint[] {31, 31, 0}, out frames, out status);
        Check(status == 0 && frames.Count == 3, "candidate succeeds");
        Check(Convert.ToBase64String(frames[0]) == Convert.ToBase64String(frames[2]), "retry preserves sequence and bytes");
        string committed = Convert.ToBase64String(current);
        byte[] failed = Next(current, new uint[] {31, 31, 31}, out frames, out status);
        Check(status == 31 && Convert.ToBase64String(failed) == committed, "failure does not advance sequence");
        byte[] advanced = Next(failed, new uint[] {0}, out frames, out status);
        Check(status == 0 && Convert.ToBase64String(advanced) != committed, "success advances sequence");
        for (int i = 0; i < 45; i++)
            if (!(i >= 24 && i < 28) && !(i >= 34 && i < 38)) Check(advanced[i] == 0, "fixed frame content");
        Console.WriteLine("Keepalive offline contract: " + Checks + " checks passed; no driver or network access");
        return 0;
    }
}

// VitureReviver — 拔線後一鍵救回 VITURE 眼鏡的 DP 畫面
//
// 原理：VITURE 眼鏡有韌體 bug，一般熱插拔後 DisplayPort 不會重新進入顯示模式，
// 只有「重刷韌體那種不斷電的軟重置」才會把畫面叫回來。本工具直接對眼鏡的 HID
// 控制介面送出官方更新工具用的 MSG_W_MCU_APP_JUMP_TO_BOOT 指令，讓眼鏡做一次
// 軟重啟（進 bootloader 再自動跳回 app），DP 畫面就會回來。全程不燒錄、零變磚風險。
//
// 指令位元組是用 VITURE 官方 viture.wasm 的 directiveBuild() 產生的精確值。

using System;
using System.Runtime.InteropServices;
using System.Threading;

class VitureReviver
{
    const ushort VITURE_VID = 0x35CA;

    // MSG_W_MCU_APP_JUMP_TO_BOOT (HID report data, 64 bytes；report id 0x00 另外加)
    static readonly byte[] JUMP_TO_BOOT = BuildCmd(0xa3, 0xb2, 0x44);

    static byte[] BuildCmd(byte crcHi, byte crcLo, byte cmd)
    {
        var b = new byte[64];
        b[0] = 0xff; b[1] = 0xfe; b[2] = crcHi; b[3] = crcLo; b[4] = 0x0c; b[14] = cmd;
        return b;
    }

    // ---- HID / SetupAPI P/Invoke ----
    const int DIGCF_PRESENT = 0x2, DIGCF_DEVICEINTERFACE = 0x10;
    const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000;
    const uint FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2, OPEN_EXISTING = 3;

    [StructLayout(LayoutKind.Sequential)] struct SP_DEVICE_INTERFACE_DATA { public int cbSize; public Guid g; public int Flags; public IntPtr Reserved; }
    [StructLayout(LayoutKind.Sequential)] struct HIDD_ATTRIBUTES { public int Size; public ushort VendorID, ProductID, VersionNumber; }
    [StructLayout(LayoutKind.Sequential)] struct HIDP_CAPS {
        public ushort Usage, UsagePage, InputReportByteLength, OutputReportByteLength, FeatureReportByteLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst=17)] public ushort[] Reserved;
        public ushort a,b,c,d,e,f,g,h,i,j,k,l;
    }
    [DllImport("hid.dll")] static extern void HidD_GetHidGuid(out Guid g);
    [DllImport("hid.dll")] static extern bool HidD_GetAttributes(IntPtr h, ref HIDD_ATTRIBUTES a);
    [DllImport("hid.dll")] static extern bool HidD_GetPreparsedData(IntPtr h, out IntPtr pp);
    [DllImport("hid.dll")] static extern bool HidD_FreePreparsedData(IntPtr pp);
    [DllImport("hid.dll")] static extern int HidP_GetCaps(IntPtr pp, ref HIDP_CAPS caps);
    [DllImport("hid.dll")] static extern bool HidD_SetOutputReport(IntPtr h, byte[] buf, int len);
    [DllImport("setupapi.dll", CharSet=CharSet.Auto)] static extern IntPtr SetupDiGetClassDevs(ref Guid g, IntPtr e, IntPtr h, int f);
    [DllImport("setupapi.dll")] static extern bool SetupDiEnumDeviceInterfaces(IntPtr s, IntPtr d, ref Guid g, int i, ref SP_DEVICE_INTERFACE_DATA da);
    [DllImport("setupapi.dll", CharSet=CharSet.Auto)] static extern bool SetupDiGetDeviceInterfaceDetail(IntPtr s, ref SP_DEVICE_INTERFACE_DATA da, IntPtr detail, int sz, ref int req, IntPtr dd);
    [DllImport("setupapi.dll")] static extern bool SetupDiDestroyDeviceInfoList(IntPtr s);
    [DllImport("kernel32.dll", CharSet=CharSet.Auto)] static extern IntPtr CreateFile(string n, uint acc, uint share, IntPtr sec, uint disp, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll")] static extern bool WriteFile(IntPtr h, byte[] buf, int len, out int written, IntPtr ov);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

    static int SendToAll(byte[] data)
    {
        int sent = 0;
        Guid g; HidD_GetHidGuid(out g);
        IntPtr set = SetupDiGetClassDevs(ref g, IntPtr.Zero, IntPtr.Zero, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
        var da = new SP_DEVICE_INTERFACE_DATA(); da.cbSize = Marshal.SizeOf(da);
        for (int i = 0; SetupDiEnumDeviceInterfaces(set, IntPtr.Zero, ref g, i, ref da); i++)
        {
            int req = 0; SetupDiGetDeviceInterfaceDetail(set, ref da, IntPtr.Zero, 0, ref req, IntPtr.Zero);
            if (req == 0) continue;
            IntPtr detail = Marshal.AllocHGlobal(req);
            Marshal.WriteInt32(detail, IntPtr.Size == 8 ? 8 : 6);
            string path = null;
            if (SetupDiGetDeviceInterfaceDetail(set, ref da, detail, req, ref req, IntPtr.Zero))
                path = Marshal.PtrToStringAuto(detail + 4);
            Marshal.FreeHGlobal(detail);
            if (path == null) continue;

            IntPtr h = CreateFile(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (h == new IntPtr(-1)) continue;
            try
            {
                var at = new HIDD_ATTRIBUTES(); at.Size = Marshal.SizeOf(at);
                if (!HidD_GetAttributes(h, ref at) || at.VendorID != VITURE_VID) continue;
                IntPtr pp;
                if (!HidD_GetPreparsedData(h, out pp)) continue;
                var caps = new HIDP_CAPS();
                int ok = HidP_GetCaps(pp, ref caps);
                HidD_FreePreparsedData(pp);
                if (ok != 0x110000 || caps.UsagePage != 0xFF00 || caps.OutputReportByteLength < data.Length + 1) continue;

                byte[] buf = new byte[caps.OutputReportByteLength];
                buf[0] = 0x00;
                Array.Copy(data, 0, buf, 1, data.Length);
                int wr;
                if (WriteFile(h, buf, buf.Length, out wr, IntPtr.Zero) || HidD_SetOutputReport(h, buf, buf.Length))
                    sent++;
            }
            finally { CloseHandle(h); }
        }
        SetupDiDestroyDeviceInfoList(set);
        return sent;
    }

    static bool ViturePresent()
    {
        // 眼鏡 app 模式 HID 是否存在（用來確認重啟後已回到 app）
        Guid g; HidD_GetHidGuid(out g);
        IntPtr set = SetupDiGetClassDevs(ref g, IntPtr.Zero, IntPtr.Zero, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
        var da = new SP_DEVICE_INTERFACE_DATA(); da.cbSize = Marshal.SizeOf(da);
        bool found = false;
        for (int i = 0; SetupDiEnumDeviceInterfaces(set, IntPtr.Zero, ref g, i, ref da); i++)
        {
            int req = 0; SetupDiGetDeviceInterfaceDetail(set, ref da, IntPtr.Zero, 0, ref req, IntPtr.Zero);
            if (req == 0) continue;
            IntPtr detail = Marshal.AllocHGlobal(req);
            Marshal.WriteInt32(detail, IntPtr.Size == 8 ? 8 : 6);
            string path = null;
            if (SetupDiGetDeviceInterfaceDetail(set, ref da, detail, req, ref req, IntPtr.Zero))
                path = Marshal.PtrToStringAuto(detail + 4);
            Marshal.FreeHGlobal(detail);
            if (path != null && path.ToLower().Contains("vid_35ca")) found = true;
        }
        SetupDiDestroyDeviceInfoList(set);
        return found;
    }

    static int Main()
    {
        Console.WriteLine("=== VITURE 眼鏡畫面救回工具 ===\n");
        if (!ViturePresent())
        {
            Console.WriteLine("找不到 VITURE 眼鏡。請確認眼鏡已用 USB 連接。");
            Console.WriteLine("\n按任意鍵結束..."); Console.ReadKey();
            return 1;
        }
        Console.WriteLine("送出軟重啟指令 (JUMP_TO_BOOT)...");
        int n = SendToAll(JUMP_TO_BOOT);
        if (n == 0)
        {
            Console.WriteLine("指令送出失敗（找不到可用的 HID 控制介面）。");
            Console.WriteLine("\n按任意鍵結束..."); Console.ReadKey();
            return 2;
        }
        Console.WriteLine($"已送往 {n} 個介面。眼鏡正在重啟，請稍候約 10 秒...\n");
        for (int s = 0; s < 12; s++) { Console.Write("."); Thread.Sleep(1000); }
        Console.WriteLine("\n\n完成！眼鏡應該已回到 app 模式，DP 畫面應該回來了。");
        Console.WriteLine("（若仍沒畫面，可再執行一次本工具。）");
        Console.WriteLine("\n按任意鍵結束..."); Console.ReadKey();
        return 0;
    }
}

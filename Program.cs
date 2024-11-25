using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace LogonBlocker
{
    using System;
    using System.Diagnostics;
    using System.IO;
    using System.Net.Sockets;
    using System.Text.RegularExpressions;
    using System.Xml;

    class IPRetry
    {
        public string ip { get; set; }
        public int tries { get; set; }
    }

    internal class Program
    {
        const int MAX_ENTRY = 100;
        const int RETRIES = 3;
        static List<string> sqlBlackIPs = new List<string>();
        static List<string> windowsBlackIPs = new List<string>();
        static List<IPRetry> retries = new List<IPRetry>();

        static void Main(string[] args)
        {
            EventLog securityLog = new EventLog("Security");
            securityLog.EntryWritten += new EntryWrittenEventHandler(OnSecurityEntryWritten);
            securityLog.EnableRaisingEvents = true;

            EventLog applicationLog = new EventLog("Application");
            applicationLog.EntryWritten += new EntryWrittenEventHandler(OnSQLEntryWritten);
            applicationLog.EnableRaisingEvents = true;

            Console.WriteLine("Listening for system events. Press any key to exit...");
            Console.ReadKey();
        }

        // Event handler for the EntryWritten event.
        private static void OnSecurityEntryWritten(object source, EntryWrittenEventArgs e)
        {
            //Console.WriteLine($"Windows event: {e.Entry.InstanceId}");
            if (e.Entry.InstanceId == 4625)
            {
                var ip = GetIPAddress(e.Entry);
                if (!windowsBlackIPs.Contains(ip))
                {
                    var tries = GetTries(ip);
                    Console.WriteLine($"{DateTime.Now.ToString("dd/MM/yyyy HH:mm")} Windows logon: {ip} tries: {tries}");
                    if (tries >= RETRIES)
                    {
                        //if (!windowsBlackIPs.Contains(ip))
                        {
                            windowsBlackIPs.Add(ip);
                            if (windowsBlackIPs.Count > MAX_ENTRY) windowsBlackIPs.RemoveAt(0);

                            BlockIPs(false);

                            Console.WriteLine($"Windows logon: {ip} blocked, blacklist length: {windowsBlackIPs.Count}");
                        }
                    }
                }
            }
        }
        private static void OnSQLEntryWritten(object source, EntryWrittenEventArgs e)
        {
            //Console.WriteLine($"SQL event: {e.Entry.InstanceId}");
            if (e.Entry.InstanceId == 3221243928)
            {
                var ip = GetIPAddress(e.Entry);
                if (!sqlBlackIPs.Contains(ip))
                {
                    var tries = GetTries(ip);
                    Console.WriteLine($"{DateTime.Now.ToString("dd/MM/yyyy HH:mm")} SQL logon: {ip} tries: {tries}");
                    if (tries >= RETRIES)
                    {
                        //if (!sqlBlackIPs.Contains(ip))
                        {
                            sqlBlackIPs.Add(ip);
                            if (sqlBlackIPs.Count > MAX_ENTRY) sqlBlackIPs.RemoveAt(0);

                            BlockIPs(true);

                            Console.WriteLine($"SQL logon: {ip} blocked, blacklist length: {sqlBlackIPs.Count}");
                        }
                    }
                }
            }
        }

        static int GetTries(string ip)
        {
            //check retries
            var tries = 0;
            for (var i = 0; i < retries.Count; i++)
            {
                if (retries[i].ip == ip)
                {
                    retries[i].tries++;

                    tries = retries[i].tries;
                    break;
                }
            }

            if (tries == 0)
            {
                tries++;

                retries.Add(new IPRetry { ip = ip, tries = tries });
                if (retries.Count > 300) retries.RemoveAt(0);

                Console.WriteLine($"Retries length: {retries.Count}");
            }

            return tries;
        }

        static void BlockIPs(bool sql)
        {
            Add2FireWall(sql);

            var ips = string.Join("\r\n", sql ? sqlBlackIPs : windowsBlackIPs);
            WriteFile(sql, ips);
        }

        static void Add2FireWall(bool sql)
        {
            var name = sql ? "sqlserver_block_ip" : "logon_block_ip";
            var ips = string.Join(",", sql ? sqlBlackIPs : windowsBlackIPs);
            // Create the netsh command to update the inbound rule
            string command = $"netsh advfirewall firewall set rule name=\"{name}\" new remoteip={ips}";

            // Execute the command
            ExecuteCommand(command);
        }

        static void WriteFile(bool sql, string data)
        {
            string filePath = sql ? "sql.txt" : "win.txt"; // Specify the file path

            // Write the text to the file
            File.WriteAllText(filePath, data);
        }
        static string ReadFile(bool sql)
        {
            string filePath = sql ? "sql.txt" : "win.txt"; // Specify the file path

            // Write the text to the file
            return File.ReadAllText(filePath);
        }

        static string GetIPAddress(EventLogEntry entry)
        {
            string ipPattern = @"\b(?:\d{1,3}\.){3}\d{1,3}\b";
            Regex regex = new Regex(ipPattern);

            Match match = regex.Match(entry.Message);
            if (match.Success)
            {
                return match.Value;
            }

            return "";
        }

        static void ExecuteCommand(string command)
        {
            ProcessStartInfo processInfo = new ProcessStartInfo("cmd.exe", "/c " + command);
            processInfo.RedirectStandardOutput = true;
            processInfo.UseShellExecute = false;
            processInfo.CreateNoWindow = true;

            Process process = new Process();
            process.StartInfo = processInfo;
            process.Start();

            //string output = process.StandardOutput.ReadToEnd();
            //process.WaitForExit();
        }
    }
}

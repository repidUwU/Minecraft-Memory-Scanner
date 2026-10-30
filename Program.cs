using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

class Program
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, IntPtr dwSize, ref IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    const int PROCESS_WM_READ = 0x0010;
    const int PROCESS_QUERY_INFORMATION = 0x0400;

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    const uint MEM_COMMIT = 0x1000;
    const uint PAGE_EXECUTE_READWRITE = 0x40; 
    const uint PAGE_READWRITE = 0x04;

    struct CheatSignature
    {
        public string Pattern;      
        public string IndicatorType; 
        public string Description; 
    }

    struct PreparedSignature
    {
        public byte[] Utf8Bytes;
        public byte[] UnicodeBytes;
        public string IndicatorType;
        public string Description;
        public string Pattern;
    }

    public class DetectionResult
    {
        public string? ProcessName { get; set; }
        public int ProcessId { get; set; }
        public string? IndicatorType { get; set; }
        public string? Description { get; set; }
        public string? Address { get; set; }
        public string? Pattern { get; set; }
    }

    static async Task Main(string[] args)
    {
        Console.Title = "Server Moderation — Minecraft Memory Scanner";
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("=========================================================================");
        Console.WriteLine("   АНАЛИЗАТОР ПАМЯТИ MINECRAFT: ПОИСК СЛЕДОВ PANIC / SELFDESTRUCT");
        Console.WriteLine("=========================================================================");
        Console.ResetColor();

        CheatSignature[] cheatDatabase = new CheatSignature[]
        {
            new CheatSignature { Pattern = "SelfDestruct", IndicatorType = "Panic / SelfDestruct", Description = "Обнаружен изолированный класс или метод экстренного удаления софта." },
            new CheatSignature { Pattern = "nativeSelfDestruct", IndicatorType = "Panic / SelfDestruct", Description = "Вызов нативной функции полной очистки памяти чита." },
            new CheatSignature { Pattern = "panic/SelfDestruct", IndicatorType = "Panic / SelfDestruct", Description = "Обнаружен пакет аварийного удаления модулей из памяти игры." },
            new CheatSignature { Pattern = "detachCurrentThread", IndicatorType = "Panic / SelfDestruct", Description = "Экстренное отсоединение потока софта от JVM Minecraft." },
            new CheatSignature { Pattern = "GetJNIEnv", IndicatorType = "След Инжекта", Description = "Сторонняя программа запрашивала прямой доступ к окружению Java (Minecraft)." }
        };

        List<PreparedSignature> preparedDatabase = new List<PreparedSignature>();
        foreach (var cheat in cheatDatabase)
        {
            preparedDatabase.Add(new PreparedSignature
            {
                Utf8Bytes = Encoding.UTF8.GetBytes(cheat.Pattern),
                UnicodeBytes = Encoding.Unicode.GetBytes(cheat.Pattern),
                IndicatorType = cheat.IndicatorType,
                Description = cheat.Description,
                Pattern = cheat.Pattern
            });
        }

        Process[] allProcesses = Process.GetProcesses();
        List<Process> targetProcesses = new List<Process>();

        foreach (Process p in allProcesses)
        {
            string pName = p.ProcessName.ToLower();
            if (pName.Contains("javaw") || pName.Contains("java") || pName.Contains("minecraft"))
            {
                targetProcesses.Add(p);
            }
        }

        if (targetProcesses.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[Предупреждение] Процесс Minecraft (javaw.exe / java.exe) не найден!");
            Console.WriteLine("[Подсказка] Убедитесь, что игра запущена перед проверкой.");
            Console.ResetColor();
            Console.ReadLine();
            return;
        }

        Console.WriteLine($"[Анализ] Найдено процессов Minecraft для проверки: {targetProcesses.Count}");
        Console.WriteLine("Сканирование запущено, пожалуйста, ожидайте...\n");

        List<DetectionResult> detections = new List<DetectionResult>();
        await Task.Run(() =>
        {
            for (int pIdx = 0; pIdx < targetProcesses.Count; pIdx++)
            {
                Process proc = targetProcesses[pIdx];
                IntPtr processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_WM_READ, false, proc.Id);
                if (processHandle == IntPtr.Zero) continue;

                List<ulong> memoryRegions = new List<ulong>();
                ulong scanAddress = 0;
                MEMORY_BASIC_INFORMATION tempMbi;

                while (VirtualQueryEx(processHandle, (IntPtr)scanAddress, out tempMbi, Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) > 0)
                {
                    if ((ulong)tempMbi.RegionSize == 0) break;
                    
                    if (tempMbi.State == MEM_COMMIT && (tempMbi.Protect == PAGE_READWRITE || tempMbi.Protect == PAGE_EXECUTE_READWRITE))
                    {
                        memoryRegions.Add(scanAddress);
                    }

                    ulong nextAddress = (ulong)tempMbi.BaseAddress + (ulong)tempMbi.RegionSize;
                    if (nextAddress <= scanAddress) break;
                    scanAddress = nextAddress;
                }

                for (int rIdx = 0; rIdx < memoryRegions.Count; rIdx++)
                {
                    ulong address = memoryRegions[rIdx];
                    MEMORY_BASIC_INFORMATION mbi;

                    if (VirtualQueryEx(processHandle, (IntPtr)address, out mbi, Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) > 0)
                    {
                        double processWeight = 100.0 / targetProcesses.Count;
                        double regionProgress = ((double)rIdx / memoryRegions.Count) * processWeight;
                        double totalPercent = (pIdx * processWeight) + regionProgress;

                        Console.Write($"\r[Прогресс]: {totalPercent:F1}% | Процесс: {proc.ProcessName} (ID: {proc.Id}) [Регион {rIdx}/{memoryRegions.Count}]...");

                        long size = mbi.RegionSize.ToInt64();
                        if (size > 0 && size < 25000000) 
                        {
                            byte[] buffer = new byte[size];
                            IntPtr bytesRead = IntPtr.Zero;

                            if (ReadProcessMemory(processHandle, mbi.BaseAddress, buffer, (IntPtr)buffer.Length, ref bytesRead))
                            {
                                foreach (var cheat in preparedDatabase)
                                {
                                    if (SearchPattern(buffer, cheat.Utf8Bytes) || SearchPattern(buffer, cheat.UnicodeBytes))
                                    {
                                        if (!detections.Exists(d => d.ProcessId == proc.Id && d.Pattern == cheat.Pattern))
                                        {
                                            detections.Add(new DetectionResult
                                            {
                                                ProcessName = proc.ProcessName,
                                                ProcessId = proc.Id,
                                                IndicatorType = cheat.IndicatorType,
                                                Description = cheat.Description,
                                                Address = "0x" + mbi.BaseAddress.ToString("X"),
                                                Pattern = cheat.Pattern
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                CloseHandle(processHandle);
            }
        });

        Console.Write("\r" + new string(' ', Console.WindowWidth - 1) + "\r");

        Console.WriteLine("=========================================================================");
        if (detections.Count == 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("ВЕРДИКТ: ИГРОК ЧИСТ");
            Console.WriteLine("\n[Детали]: Следов Panic, SelfDestruct или сторонних инжектов в Java не найдено.");
            Console.WriteLine("[Действие]: Закройте программу.");
            Console.ResetColor();
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"ВЕРДИКТ: ОБНАРУЖЕНЫ СЛЕДЫ УДАЛЕНИЯ ЧИТОВ ({detections.Count} шт.)!");
            Console.ResetColor();
            Console.WriteLine("=========================================================================");
            foreach (var det in detections)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[!] Найдено в процессе игры: {det.ProcessName} (ID: {det.ProcessId})");
                Console.ResetColor();
                Console.WriteLine($"    Тип угрозы: {det.IndicatorType}");
                Console.WriteLine($"    Адрес в RAM: {det.Address}");
                Console.WriteLine($"    Описание: {det.Description}");
                Console.WriteLine($"    Триггер сигнатуры: \"{det.Pattern}\"");
                Console.WriteLine("-------------------------------------------------------------------------");
            }
        }
        Console.ReadLine();
    }

    private static bool SearchPattern(byte[] buffer, byte[] pattern)
    {
        if (buffer == null || pattern == null || buffer.Length < pattern.Length || pattern.Length == 0)
        {
            return false;
        }

        for (int i = 0; i <= buffer.Length - pattern.Length; i++)
        {
            bool isMatch = true;
            for (int j = 0; j < pattern.Length; j++)
            {
                if (buffer[i + j] != pattern[j])
                {
                    isMatch = false;
                    break;
                }
            }
            if (isMatch) return true;
        }
        return false;
    }
}

# Minecraft Memory Scanner (Server Administration Tool)

A lightweight memory scanning utility written in C# designed for Minecraft server moderators. This tool helps detect traces of deleted or self-destructed cheat clients during screen-shares (SS) by analyzing the JVM process memory.

> ⚠️ **Disclaimer:** This tool is strictly for server administration and fair-play enforcement. It uses standard Windows API functions (`ReadProcessMemory`, `VirtualQueryEx`) exclusively for passive memory analysis. It does not modify code, inject DLLs, or interfere with any processes.

## Features
* **Process Detection:** Automatically locates active Minecraft instances (`java.exe`, `javaw.exe`).
* **RAM Analysis:** Scans committed memory regions (`PAGE_READWRITE` & `PAGE_EXECUTE_READWRITE`) for specific text patterns.
* **String-Based Signatures:** Detects common traces left by cheat "Panic" or "Self-Destruct" functions (e.g., `nativeSelfDestruct`, `detachCurrentThread`).
* **Encoding Support:** Searches for strings in both UTF-8 and Unicode encodings.
* **Safe Handling:** Properly manages and closes OS process handles to prevent memory leaks.

## Requirements
* Windows OS (x64 recommended)
* .NET SDK (to compile the source code)
* **Administrator Privileges:** Must be executed as Administrator, otherwise Windows will block access to `OpenProcess`.

## How to Compile
You can compile this source code using the .NET CLI. Open your terminal in the project folder and run:
```bash
dotnet new console -n MinecraftScanner
# Replace Program.cs with the provided source code
dotnet build --configuration Release
```

## How It Works
1. The tool searches for running Java processes associated with Minecraft.
2. It loops through the virtual memory pages allocated by the JVM.
3. It reads the memory buffer of safe regions and cross-references them with known cheat signatures.
4. If a match is found, it reports the exact memory address and process ID for the moderator to review.

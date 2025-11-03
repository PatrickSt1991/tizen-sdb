using TizenSdb;
using TizenSdb.SdbClient;
using TizenSdb.SigningManager;

namespace tizensdb;

public static class Program
{
    public static async Task Main(string[] args)
    {
        if (args.Length == 0)
        {
            PrintUsage();
            Environment.Exit(1);
            return;
        }

        var command = args[0].ToLower();
        var commandArgs = args.Skip(1).ToArray();

        try
        {
            switch (command)
            {
                case "connect":
                    if (commandArgs.Length != 1)
                    {
                        Console.WriteLine("Error: 'connect' requires an IP address.");
                        Environment.Exit(1);
                        return;
                    }
                    await ConnectDevice(commandArgs[0]);
                    break;

                case "disconnect":
                    if (commandArgs.Length != 1)
                    {
                        Console.WriteLine("Error: 'disconnect' requires an IP address.");
                        Environment.Exit(1);
                        return;
                    }
                    await DisconnectDevice(commandArgs[0]);
                    break;

                case "devices":
                    if (commandArgs.Length != 1)
                    {
                        Console.WriteLine("Error: 'devices' requires a device IP address");
                        Environment.Exit(1);
                        return;
                    }
                    await GetDeviceName(commandArgs[0]);
                    break;

                case "diagnose":
                    if (commandArgs.Length != 1)
                    {
                        Console.WriteLine("Error: 'diagnose' requires a device IP address.");
                        Environment.Exit(1);
                        return;
                    }
                    await DiagnoseDevice(commandArgs[0]);
                    break;

                case "apps":
                    if (commandArgs.Length != 1)
                    {
                        Console.WriteLine("Error: 'apps' requires a device IP address.");
                        Environment.Exit(1);
                        return;
                    }
                    await ListApps(commandArgs[0]);
                    break;

                case "duid":
                    if (commandArgs.Length != 1)
                    {
                        Console.WriteLine("Error: 'duid' requires a device IP address.");
                        Environment.Exit(1);
                        return;
                    }
                    await GetDeviceUid(commandArgs[0]);
                    break;

                case "install":
                    if (commandArgs.Length != 2)
                    {
                        Console.WriteLine("Error: 'install' requires a device IP and a TPK/WGT file path.");
                        Environment.Exit(1);
                        return;
                    }
                    await InstallPackage(commandArgs[0], commandArgs[1]);
                    break;

                case "permit-install":
                    if (commandArgs.Length != 3)
                    {
                        Console.WriteLine("Error: 'permit-install' requires a device IP, XML file path and SdkToolPath");
                        Environment.Exit(1);
                        return;
                    }
                    await PermitInstall(commandArgs[0], commandArgs[1], commandArgs[2]);
                    break;

                case "uninstall":
                    if (commandArgs.Length != 2)
                    {
                        Console.WriteLine("Error: 'uninstall' requires a device IP and a package ID.");
                        Environment.Exit(1);
                        return;
                    }
                    await UninstallPackage(commandArgs[0], commandArgs[1]);
                    break;

                case "shell":
                    if (commandArgs.Length < 2)
                    {
                        Console.WriteLine("Error: 'shell' requires a device IP and a command to execute.");
                        Environment.Exit(1);
                        return;
                    }
                    var shellCommand = string.Join(" ", commandArgs.Skip(1));
                    await ExecuteShellCommand(commandArgs[0], shellCommand);
                    break;

                case "capability":
                    if (commandArgs.Length != 1)
                    {
                        Console.WriteLine("Error: 'capability' requires an IP address.");
                        Environment.Exit(1);
                        return;
                    }
                    await GetCapability(commandArgs[0]);
                    break;

                case "resign":
                    if (commandArgs.Length != 4)
                    {
                        Console.WriteLine("Error: 'resign' requires <package_path> <author_p12> <distributor_p12> <password>");
                        Environment.Exit(1);
                        return;
                    }
                    await ResignPackage(commandArgs[0], commandArgs[1], commandArgs[2], commandArgs[3]);
                    break;

                default:
                    Console.WriteLine($"Error: Unknown command '{command}'");
                    PrintUsage();
                    Environment.Exit(1);
                    return;
            }
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"\nError: {ex.Message}");
            Console.ResetColor();
            Environment.Exit(1);
        }
    }

    static async Task ConnectDevice(string ip)
    {
        Console.WriteLine($"* Connecting to {ip}:26101...");
        var device = new SdbTcpDevice(System.Net.IPAddress.Parse(ip));
        await device.ConnectAsync();
        Console.WriteLine($"connected to {ip}:26101");

        // Test connection
        try
        {
            var version = await device.ShellCommandAsync("host:version");
            Console.WriteLine(version.Trim());
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  Version check failed: {ex.Message}");
        }

        device.DisposeAsync();
    }
    static async Task DisconnectDevice(string ip)
    {
        Console.WriteLine($"* Disconnected from {ip}");
        await Task.CompletedTask;
    }
    static async Task<string> GetDeviceUid(string ip)
    {
        var device = new SdbTcpDevice(System.Net.IPAddress.Parse(ip));
        await device.ConnectAsync();

        try
        {
            var duid = await device.ShellCommandAsync("0 getduid");
            var cleanedDuid = duid.Trim();

            Console.WriteLine(cleanedDuid);
            return cleanedDuid;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  Failed to get device UID: {ex.Message}");
            throw;
        }
        finally
        {
            device.DisposeAsync();
        }
    }
    static async Task ListApps(string ip)
    {
        Console.WriteLine($"* Listing installed apps on {ip}...");

        var device = new SdbTcpDevice(System.Net.IPAddress.Parse(ip));
        await device.ConnectAsync();

        // Try multiple command formats
        var commandsToTry = new[]
        {
        "0 vd_applist",           // TV-specific app list
        "applist",                // Standard app list
        "pkgcmd -l",              // Package list
        "pm list packages",       // Android-style package list
        "ls /usr/apps",           // List apps directory
        "ls /opt/usr/apps"        // Alternative apps directory
    };

        bool success = false;

        foreach (var cmd in commandsToTry)
        {
            try
            {
                Console.WriteLine($"  Trying: {cmd}");
                var result = await device.ShellCommandAsync(cmd);

                if (!string.IsNullOrEmpty(result) && !result.Contains("not found") && !result.Contains("No such"))
                {
                    Console.WriteLine("--- Installed Applications ---");
                    var lines = result.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                    foreach (var line in lines)
                    {
                        var trimmedLine = line.Trim();
                        if (!string.IsNullOrEmpty(trimmedLine) && trimmedLine.Length > 1)
                        {
                            // Clean up terminal colors and extra spaces
                            var cleanLine = System.Text.RegularExpressions.Regex.Replace(trimmedLine, @"\e\[[0-9;]*m", "");
                            Console.WriteLine($"  {cleanLine}");
                        }
                    }
                    Console.WriteLine("------------------------------");
                    success = true;
                    break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"    Failed: {ex.Message}");
                // Continue to next command
            }
        }

        if (!success)
        {
            Console.WriteLine("  Could not retrieve app list with any command");
            Console.WriteLine("  Available commands on this device:");

            // Try to see what shell commands are available
            try
            {
                var testResult = await device.ShellCommandAsync("0 getduid");
                if (!string.IsNullOrEmpty(testResult))
                {
                    Console.WriteLine($"  Device UID: {testResult.Trim()}");
                }
            }
            catch
            {
                // Ignore
            }
        }

        device.DisposeAsync();
    }
    static async Task InstallPackage(string ip, string packagePath)
    {
        if (!File.Exists(packagePath))
        {
            Console.WriteLine($"Error: Package file not found: {packagePath}");
            Environment.Exit(1);
            return;
        }

        Console.WriteLine($"* Installing {Path.GetFileName(packagePath)} on {ip}...");

        var device = new SdbTcpDevice(System.Net.IPAddress.Parse(ip));
        await device.ConnectAsync();

        var installer = new TizenInstaller(packagePath, device);

        await installer.InstallApp();

        Console.WriteLine("* Installation completed successfully");
        device.DisposeAsync();
    }
    static async Task PermitInstall(string ip, string packagePath, string sdkToolPath)
    {
        if (!File.Exists(packagePath))
        {
            Console.WriteLine($"Error: device-profile.xml file not found: {packagePath}");
            Environment.Exit(1);
            return;
        }

        if(string.IsNullOrEmpty(ip))
        {
            Console.WriteLine($"Error: IP is empty");
            Environment.Exit(1);
            return;
        }

        Console.WriteLine($"* Pushing {Path.GetFileName(packagePath)} to {ip} at location {sdkToolPath}...");

        var device = new SdbTcpDevice(System.Net.IPAddress.Parse(ip));
        await device.ConnectAsync();

        var installer = new TizenInstaller(packagePath, device);

        await installer.PermitInstallApp(sdkToolPath);

        Console.WriteLine("* Push completed successfully");
        device.DisposeAsync();
    }
    static async Task UninstallPackage(string ip, string packageId)
    {
        Console.WriteLine($"* Uninstalling {packageId} from {ip}...");

        var device = new SdbTcpDevice(System.Net.IPAddress.Parse(ip));
        await device.ConnectAsync();

        try
        {
            // Use the TV-specific uninstall command
            var result = await device.ShellCommandAsync($"0 vd_appuninstall {packageId}");

            Console.WriteLine("--- Uninstall Output ---");
            Console.WriteLine(result);
            Console.WriteLine("------------------------");

            if (result.Contains("fail", StringComparison.OrdinalIgnoreCase) ||
                result.Contains("error", StringComparison.OrdinalIgnoreCase))
            {
                throw new Exception("Uninstallation failed");
            }

            Console.WriteLine("* Uninstallation completed successfully");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"* Uninstallation failed: {ex.Message}");

            // Fallback: try pkgcmd if the TV-specific command fails
            try
            {
                Console.WriteLine("* Trying fallback uninstall method...");
                var fallbackResult = await device.ShellCommandAsync($"pkgcmd -u -n {packageId} -q");

                Console.WriteLine("--- Fallback Uninstall Output ---");
                Console.WriteLine(fallbackResult);
                Console.WriteLine("---------------------------------");

                if (fallbackResult.Contains("fail", StringComparison.OrdinalIgnoreCase))
                {
                    throw new Exception("Fallback uninstallation also failed");
                }

                Console.WriteLine("* Uninstallation completed successfully (fallback method)");
            }
            catch (Exception fallbackEx)
            {
                Console.WriteLine($"* Fallback uninstallation also failed: {fallbackEx.Message}");
                throw;
            }
        }
        finally
        {
            device.DisposeAsync();
        }
    }
    static async Task DiagnoseDevice(string ip)
    {
        Console.WriteLine($"* Diagnosing device {ip}...");

        var device = new SdbTcpDevice(System.Net.IPAddress.Parse(ip));
        await device.ConnectAsync();

        // Test basic commands that should work
        var testCommands = new[]
        {
        "0 getduid",
        "host:version",
        "host:features",
        "shell:uname -a",
        "shell:ls /usr/apps",
        "shell:pwd",
        "shell:whoami",
        "0 vd_applist",
        "0 vd_appuninstall test",
        "pkgcmd -l"
    };

        foreach (var cmd in testCommands)
        {
            try
            {
                Console.Write($"  Testing '{cmd}': ");
                var result = await device.ShellCommandAsync(cmd);
                Console.WriteLine($"SUCCESS ({result.Length} chars)");

                if (result.Length < 100) // Only show short results
                    Console.WriteLine($"    Result: {result.Trim()}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"FAILED - {ex.Message}");
            }

            // Small delay between commands
            await Task.Delay(100);
        }

        device.DisposeAsync();
    }
    static async Task ExecuteShellCommand(string ip, string command)
    {
        Console.WriteLine($"* Executing on {ip}: {command}");

        var device = new SdbTcpDevice(System.Net.IPAddress.Parse(ip));
        await device.ConnectAsync();

        var result = await device.ShellCommandAsync($"shell:{command}");

        Console.WriteLine("--- Command Output ---");
        Console.WriteLine(result);
        Console.WriteLine("----------------------");
        device.DisposeAsync();
    }
    static async Task GetCapability(string ip)
    {
        Console.WriteLine($"* Getting capabilities for {ip}...");

        var device = new SdbTcpDevice(System.Net.IPAddress.Parse(ip));
        await device.ConnectAsync();

        var capabilities = await device.CapabilityAsync();

        Console.WriteLine("--- Device Capabilities ---");
        foreach (var cap in capabilities)
        {
            Console.WriteLine($"  {cap.Key}: {cap.Value}");
        }
        Console.WriteLine("---------------------------");
        device.DisposeAsync();
    }
    static async Task GetDeviceName(string ip)
    {
        var device = new SdbTcpDevice(System.Net.IPAddress.Parse(ip));
        await device.ConnectAsync();
        string[] parts = device.DeviceId.Split("::", StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length >= 2)
            Console.WriteLine(parts[1]);
        else
            Console.WriteLine("FAILED DEVICE NAME");

        device.DisposeAsync();
    }
    static async Task ResignPackage(string wgtPath, string authorP12, string distributorP12, string password)
    {
        try
        {
            Console.WriteLine($"* Re-signing: {wgtPath}");

            var output = await TizenWgtSigner.ReSignWgtWithCertsInPlace(
                wgtPath, authorP12, distributorP12, password, backupPath: null);
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"✔ Re-signed in place: {output}");
            Console.ResetColor();
        }
        catch (Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"✖ Re-sign failed: {ex.Message}");
            Console.WriteLine(ex);
            Console.ResetColor();
            Environment.Exit(1);
        }
    }
    static void PrintUsage()
    {
        Console.WriteLine("TizenSdb - Lightweight Tizen SDB Client");
        Console.WriteLine("Usage: TizenSdb_v*.*.*.exe [command] [options]");
        Console.WriteLine("\nCommands:");
        Console.WriteLine("  connect <device_ip>                           Connect to a Tizen device");
        Console.WriteLine("  disconnect <device_ip>                        Disconnect from a Tizen device");
        Console.WriteLine("  diagnose <device_ip>                          Diagnose device connectivity and commands");
        Console.WriteLine("  devices                                       List connected devices");
        Console.WriteLine("  apps <device_ip>                              List installed applications");
        Console.WriteLine("  duid <device_ip>                              Get device unique ID");
        Console.WriteLine("  install <device_ip> <path_to_tpk/wgt>         Install a package");
        Console.WriteLine("  permit-install <device_ip> <path_to_xml>      Send device-profile.xml to device");
        Console.WriteLine("  uninstall <device_ip> <package_id>            Uninstall a package");
        Console.WriteLine("  shell <device_ip> <command>                   Execute a shell command on the device");
        Console.WriteLine("  capability <device_ip>                        Show device capabilities");
        Console.WriteLine("  resign <pkg_path> <author> <distrib> <pass>   Resign a TPK/WGT package");
    }
}
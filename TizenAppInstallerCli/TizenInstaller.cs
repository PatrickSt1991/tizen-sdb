using System.IO.Compression;
using System.Xml.Linq;
using TizenSdb.SdbClient;

namespace TizenSdb;

public class TizenInstaller
{
    private readonly string _packagePath;
    private readonly SdbTcpDevice _sdbClient;
    private readonly Stream _packageStream;
    private readonly Stream? _installStream = null;

    public string? PackageId { get; private set; }

    public TizenInstaller(string packagePath, SdbTcpDevice sdbClient)
    {
        _packagePath = packagePath;
        _sdbClient = sdbClient;
        _packageStream = File.OpenRead(_packagePath);
    }

    public async Task InstallApp()
    {
        if (string.IsNullOrEmpty(_packagePath))
            throw new InvalidOperationException("Package path not set.");

        string remotePath = $"/home/owner/share/tmp/sdk_tools/tmp/{Path.GetFileName(_packagePath)}";

        // Find the package ID on the device
        string appId = await FindPackageId();

        // Open package file as a stream and push it
        await using var fs = File.OpenRead(_packagePath);
        await _sdbClient.PushAsync(fs, remotePath);

        // Install the app via shell command
        await foreach (string line in _sdbClient.ShellCommandLinesAsync($"0 vd_appinstall {appId} {remotePath}"))
        {
            // Optional logging:
            Console.WriteLine(line);
        }
    }


    private async Task<string> FindPackageId()
    {
        if (PackageId != null) return PackageId;

        using var archive = new ZipArchive(_packageStream, ZipArchiveMode.Read, leaveOpen: true);

        ZipArchiveEntry? configEntry = archive.GetEntry("config.xml");
        ZipArchiveEntry? manifestEntry = archive.GetEntry("tizen-manifest.xml");
        bool isWgt = configEntry is not null;

        ZipArchiveEntry? targetEntry = isWgt ? configEntry : manifestEntry;

        if (targetEntry is null)
        {
            throw new Exception("Invalid App. No target entry found");
        }

        string xmlText;
        await using (Stream stream = targetEntry.Open())
        using (var sr = new StreamReader(stream))
        {
            xmlText = await sr.ReadToEndAsync().ConfigureAwait(false);
        }

        if (string.IsNullOrWhiteSpace(xmlText))
            throw new Exception("Invalid App. Could not read xml entry");

        XDocument doc;
        try
        {
            doc = XDocument.Parse(xmlText);
        }
        catch
        {
            throw new Exception("Invalid App. Could not read xml entry");
        }

        string? packageId = null;

        if (!isWgt)
        {
            XElement? root = doc.Root;
            packageId = root?.Attribute("package")?.Value;
            if (string.IsNullOrWhiteSpace(packageId))
            {
                XElement? manifestElem = doc.Descendants().FirstOrDefault(e =>
                    string.Equals(e.Name.LocalName, "manifest", StringComparison.OrdinalIgnoreCase));
                packageId = manifestElem?.Attribute("package")?.Value;
            }
        }
        else
        {
            XElement? applicationElem = doc
                .Descendants()
                .FirstOrDefault(e =>
                    string.Equals(e.Name.LocalName, "application", StringComparison.OrdinalIgnoreCase));

            if (applicationElem is not null)
            {
                packageId = applicationElem.Attribute("id")?.Value;
            }

            if (string.IsNullOrWhiteSpace(packageId))
            {
                XElement? widgetElem = doc.Root;
                if (widgetElem is not null)
                {
                    string? idAttr = widgetElem.Attribute("id")?.Value;
                    if (!string.IsNullOrWhiteSpace(idAttr))
                        packageId = idAttr;
                }
            }
        }

        if (string.IsNullOrWhiteSpace(packageId))
            throw new Exception("Invalid App. Could not find package ID");

        PackageId = packageId.Trim();
        _packageStream.Seek(0, SeekOrigin.Begin);
        return PackageId;
    }
}
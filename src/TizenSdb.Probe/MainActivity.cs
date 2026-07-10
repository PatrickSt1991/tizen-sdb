using Android.App;
using Android.OS;
using Android.Views;
using Android.Widget;
using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TizenSdb.SdbClient;
using TizenSdb.SigningManager;

namespace TizenSdb.Probe;

// On-device gate: exercises the exact risky paths (TCP + ADB-style RSA AUTH,
// and the C14N + RSA.SignData re-sign) on Android/MonoVM. Throwaway UI.
[Activity(Label = "TizenSdb Probe", MainLauncher = true,
          Theme = "@android:style/Theme.Material.Light.NoActionBar")]
public class MainActivity : Activity
{
    private EditText _ip = null!;
    private TextView _log = null!;

    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);

        // Mobile has no ~/.sdb; keep the auth key in the app sandbox.
        SdbTcpDevice.KeyDirectory = FilesDir!.AbsolutePath;

        var root = new LinearLayout(this) { Orientation = Orientation.Vertical };
        root.SetPadding(24, 24, 24, 24);

        _ip = new EditText(this) { Hint = "TV IP e.g. 192.168.1.50" };
        root.AddView(_ip);
        root.AddView(MakeButton("1 — Connect (TCP + RSA AUTH)", RunConnect));
        root.AddView(MakeButton("2 — Capability", RunCapability));
        root.AddView(MakeButton("3 — Re-sign a .wgt (C14N + RSA, self-contained)", RunResign));

        _log = new TextView(this) { Text = string.Empty };
        _log.SetTextIsSelectable(true);
        var scroll = new ScrollView(this);
        scroll.AddView(_log);
        root.AddView(scroll);

        SetContentView(root);

        // Android 15+ (API 35+) is edge-to-edge by default: the status/nav bars
        // draw over the content. Pad the root by the actual system-bar insets so
        // nothing is hidden behind them (a fixed padding can't do this reliably).
        root.SetOnApplyWindowInsetsListener(new InsetPadder());
        root.RequestApplyInsets();

        Log($"Ready. Key dir: {SdbTcpDevice.KeyDirectory}");
    }

    private sealed class InsetPadder : Java.Lang.Object, View.IOnApplyWindowInsetsListener
    {
        public WindowInsets? OnApplyWindowInsets(View v, WindowInsets insets)
        {
            var bars = insets.GetInsets(WindowInsets.Type.SystemBars());
            v.SetPadding(bars.Left + 24, bars.Top + 24, bars.Right + 24, bars.Bottom + 24);
            return insets;
        }
    }

    private Button MakeButton(string text, Func<Task> action)
    {
        var b = new Button(this) { Text = text };
        b.Click += async (_, _) =>
        {
            b.Enabled = false;
            try { await action(); }
            catch (Exception ex) { Log("✖ " + ex.GetType().Name + ": " + ex.Message); }
            finally { b.Enabled = true; }
        };
        return b;
    }

    private void Log(string msg) => RunOnUiThread(() => _log.Text = msg + "\n" + _log.Text);

    private async Task RunConnect()
    {
        var dev = new SdbTcpDevice(IPAddress.Parse(_ip.Text!.Trim()));
        await dev.ConnectAsync();
        Log("✔ Connected — TCP + RSA AUTH handshake OK");
        await dev.DisconnectAsync();
    }

    private async Task RunCapability()
    {
        var dev = new SdbTcpDevice(IPAddress.Parse(_ip.Text!.Trim()));
        await dev.ConnectAsync();
        var caps = await dev.CapabilityAsync();
        var summary = string.Join(", ", caps.Take(6).Select(kv => $"{kv.Key}={kv.Value}"));
        Log($"✔ Capability ({caps.Count} keys): {summary} …");
        await dev.DisconnectAsync();
    }

    // Self-contained: makes a throwaway cert + a minimal .wgt in the sandbox, then
    // re-signs it. Proves System.Security.Cryptography.Xml (C14N transforms) and
    // RSA.SignData work on MonoVM — no TV, no real Samsung certs needed.
    private async Task RunResign()
    {
        var dir = FilesDir!.AbsolutePath;
        const string pwd = "probe";
        var wgt = MakeMinimalWgt(Path.Combine(dir, "probe.wgt"));
        var author = MakeSelfSignedP12(Path.Combine(dir, "author.p12"), pwd);
        var dist = MakeSelfSignedP12(Path.Combine(dir, "distributor.p12"), pwd);

        var outPath = await TizenWgtSigner.ReSignWgtWithCertsInPlace(wgt, author, dist, pwd);

        using var check = ZipFile.OpenRead(outPath);
        var sigs = check.Entries.Where(e => e.Name.Contains("signature", StringComparison.OrdinalIgnoreCase))
                                .Select(e => e.Name).ToList();
        Log(sigs.Count > 0
            ? $"✔ Re-sign OK — C14N + RSA on MonoVM works. Injected: {string.Join(", ", sigs)}"
            : "⚠ Re-signed but no signature entry found — inspect output");
    }

    private static string MakeSelfSignedP12(string path, string password)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=TizenSdbProbe", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        File.WriteAllBytes(path, cert.Export(X509ContentType.Pfx, password));
        return path;
    }

    private static string MakeMinimalWgt(string path)
    {
        if (File.Exists(path)) File.Delete(path);
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);

        using (var w = new StreamWriter(zip.CreateEntry("config.xml").Open()))
            w.Write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                    "<widget xmlns=\"http://www.w3.org/ns/widgets\" xmlns:tizen=\"http://tizen.org/ns/widgets\" " +
                    "id=\"http://probe/test\" version=\"1.0.0\">\n" +
                    "  <tizen:application id=\"Probe00001.Test\" package=\"Probe00001\" required_version=\"2.3\"/>\n" +
                    "  <name>Probe</name>\n  <content src=\"index.html\"/>\n</widget>");

        using (var w = new StreamWriter(zip.CreateEntry("index.html").Open()))
            w.Write("<html><body>probe</body></html>");

        return path;
    }
}

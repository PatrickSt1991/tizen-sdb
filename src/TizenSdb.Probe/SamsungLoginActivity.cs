using Android.App;
using Android.OS;
using Android.Webkit;
using System.Net;
using System.Net.Sockets;
using System.Text;
using AndroidUri = Android.Net.Uri;

namespace TizenSdb.Probe;

// OAuth spike: proves the desktop Samsung-login flow works on Android.
// Samsung's SignInGate POSTs the token (URL-encoded JSON in the body) to the
// redirect_uri — a WebView URL-intercept can't read a POST body, so we host a
// tiny in-app loopback listener on :4794 (same role as the desktop Kestrel
// callback) and point the WebView's redirect at it.
[Activity(Label = "Samsung Login")]
public class SamsungLoginActivity : Activity
{
    // Mirror of Apps2Samsung Constants.Samsung / Ports (shared for real later).
    private const int Port = 4794;
    private const string CallbackPath = "/signin/callback";
    private const string SignInGateUrl =
        "https://account.samsung.com/accounts/be1dce529476c1a6d407c4c7578c31bd/signInGate";
    private const string ClientId = "v285zxnl3h";
    private const string State = "accountcheckdogeneratedstatetext";
    private const string TokenType = "TOKEN";

    // How the launcher screen receives the captured token (throwaway static hop).
    public static Action<string>? OnResult;

    private TcpListener? _listener;
    private readonly CancellationTokenSource _cts = new();

    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);
        ActionBar?.Hide();

        var web = new WebView(this);
        web.Settings.JavaScriptEnabled = true;   // SignInGate needs JS
        web.Settings.DomStorageEnabled = true;
        SetContentView(web);

        _ = Task.Run(() => ListenForCallbackAsync(_cts.Token));

        var redirect = $"http://localhost:{Port}{CallbackPath}";
        var url = $"{SignInGateUrl}?locale=&clientId={ClientId}" +
                  $"&redirect_uri={AndroidUri.Encode(redirect)}" +
                  $"&state={State}&tokenType={TokenType}";
        web.LoadUrl(url);
    }

    private async Task ListenForCallbackAsync(CancellationToken ct)
    {
        try
        {
            _listener = new TcpListener(IPAddress.Loopback, Port);
            _listener.Start();

            while (!ct.IsCancellationRequested)
            {
                using var client = await _listener.AcceptTcpClientAsync(ct);
                using var stream = client.GetStream();

                var (method, path, body) = await ReadRequestAsync(stream, ct);

                const string page = "Login captured — return to the app.";
                var resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n" +
                           $"Content-Length: {Encoding.UTF8.GetByteCount(page)}\r\nConnection: close\r\n\r\n{page}";
                var respBytes = Encoding.UTF8.GetBytes(resp);
                await stream.WriteAsync(respBytes, ct);
                await stream.FlushAsync(ct);

                if (method == "POST" && path.StartsWith(CallbackPath, StringComparison.Ordinal))
                {
                    var code = ParseFormField(body, "code");
                    if (!string.IsNullOrWhiteSpace(code))
                    {
                        var token = Uri.UnescapeDataString(code);
                        RunOnUiThread(() =>
                        {
                            OnResult?.Invoke(token);
                            Finish();
                        });
                        return;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            RunOnUiThread(() => OnResult?.Invoke("ERROR: " + ex.Message));
        }
        finally
        {
            try { _listener?.Stop(); } catch { /* ignore */ }
        }
    }

    // Minimal HTTP/1.1 request reader: request line + headers, then Content-Length body.
    private static async Task<(string method, string path, string body)> ReadRequestAsync(
        NetworkStream stream, CancellationToken ct)
    {
        var buf = new byte[8192];
        var sb = new StringBuilder();
        int headerEnd;
        int total = 0;

        // Read until end of headers (\r\n\r\n).
        while ((headerEnd = sb.ToString().IndexOf("\r\n\r\n", StringComparison.Ordinal)) < 0)
        {
            int n = await stream.ReadAsync(buf.AsMemory(0, buf.Length), ct);
            if (n <= 0) break;
            sb.Append(Encoding.UTF8.GetString(buf, 0, n));
            total += n;
        }

        var raw = sb.ToString();
        headerEnd = raw.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var head = headerEnd >= 0 ? raw[..headerEnd] : raw;
        var lines = head.Split("\r\n");
        var requestLine = lines.Length > 0 ? lines[0].Split(' ') : new[] { "", "", "" };
        var method = requestLine.Length > 0 ? requestLine[0] : "";
        var path = requestLine.Length > 1 ? requestLine[1] : "";

        int contentLength = 0;
        foreach (var line in lines)
            if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                int.TryParse(line[15..].Trim(), out contentLength);

        var body = headerEnd >= 0 ? raw[(headerEnd + 4)..] : string.Empty;
        // Read any remaining body bytes.
        while (Encoding.UTF8.GetByteCount(body) < contentLength)
        {
            int n = await stream.ReadAsync(buf.AsMemory(0, buf.Length), ct);
            if (n <= 0) break;
            body += Encoding.UTF8.GetString(buf, 0, n);
        }

        return (method, path, body);
    }

    private static string? ParseFormField(string body, string key)
    {
        foreach (var part in body.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var kv = part.Split('=', 2);
            if (kv.Length == 2 && kv[0] == key)
                return kv[1];
        }
        return null;
    }

    protected override void OnDestroy()
    {
        _cts.Cancel();
        try { _listener?.Stop(); } catch { /* ignore */ }
        base.OnDestroy();
    }
}

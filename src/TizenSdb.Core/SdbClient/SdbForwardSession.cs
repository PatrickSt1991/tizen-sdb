using System.Net;
using System.Net.Sockets;
using System.Collections.Concurrent;

namespace TizenSdb.SdbClient;

public class SdbForwardSession : IAsyncDisposable
{
    private readonly ISdbDevice _device;
    private readonly int _localPort;
    private readonly int _remotePort;
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly ConcurrentDictionary<Guid, ProxyConnection> _connections = new();
    private Task? _acceptTask;
    private bool _disposed;

    public Task Completion => _acceptTask ?? Task.CompletedTask;

    internal SdbForwardSession(ISdbDevice device, int localPort, int remotePort)
    {
        _device = device;
        _localPort = localPort;
        _remotePort = remotePort;
        _listener = new TcpListener(IPAddress.Loopback, _localPort);
    }

    internal async Task StartAsync(CancellationToken ct = default)
    {
        _listener.Start();
        _acceptTask = Task.Run(() => AcceptLoopAsync(_cts.Token));
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var tcpClient = await _listener.AcceptTcpClientAsync(ct).ConfigureAwait(false);
                var connectionId = Guid.NewGuid();
                var proxy = new ProxyConnection(_device, tcpClient, _remotePort, () => _connections.TryRemove(connectionId, out _));
                _connections.TryAdd(connectionId, proxy);
                _ = proxy.StartAsync(ct);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            // Listen socket failed
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;

        _cts.Cancel();
        _listener.Stop();

        if (_acceptTask != null)
        {
            try { await _acceptTask.ConfigureAwait(false); } catch { }
        }

        foreach (var kv in _connections)
        {
            await kv.Value.DisposeAsync().ConfigureAwait(false);
        }
        _connections.Clear();
        _cts.Dispose();
    }

    private class ProxyConnection : IAsyncDisposable
    {
        private readonly ISdbDevice _device;
        private readonly TcpClient _tcpClient;
        private readonly int _remotePort;
        private readonly Action _onClose;
        private readonly CancellationTokenSource _cts = new();
        private SdbChannel? _channel;
        private Task? _pumpTask;

        public ProxyConnection(ISdbDevice device, TcpClient tcpClient, int remotePort, Action onClose)
        {
            _device = device;
            _tcpClient = tcpClient;
            _remotePort = remotePort;
            _onClose = onClose;
        }

        public async Task StartAsync(CancellationToken globalCt)
        {
            try
            {
                _channel = await _device.OpenAsync($"tcp:{_remotePort}\0", globalCt).ConfigureAwait(false);
                
                var t1 = PumpLocalToRemoteAsync(_cts.Token);
                var t2 = PumpRemoteToLocalAsync(_cts.Token);
                
                _pumpTask = Task.WhenAll(t1, t2);
                _ = _pumpTask.ContinueWith(_ => _onClose());
            }
            catch
            {
                await DisposeAsync();
                _onClose();
            }
        }

        private async Task PumpLocalToRemoteAsync(CancellationToken ct)
        {
            try
            {
                var stream = _tcpClient.GetStream();
                byte[] buffer = new byte[8192];
                while (!ct.IsCancellationRequested)
                {
                    int bytesRead = await stream.ReadAsync(buffer, ct).ConfigureAwait(false);
                    if (bytesRead == 0) break;
                    
                    if (_channel != null)
                    {
                        await _channel.WriteAsync(buffer.AsMemory(0, bytesRead), ct).ConfigureAwait(false);
                    }
                }
            }
            catch { }
            finally
            {
                await DisposeAsync();
            }
        }

        private async Task PumpRemoteToLocalAsync(CancellationToken ct)
        {
            try
            {
                if (_channel == null) return;
                var stream = _tcpClient.GetStream();
                byte[] buffer = new byte[8192];
                while (!ct.IsCancellationRequested)
                {
                    int bytesRead = await _channel.ReadAsync(buffer, ct).ConfigureAwait(false);
                    if (bytesRead == 0) break;
                    
                    await stream.WriteAsync(buffer.AsMemory(0, bytesRead), ct).ConfigureAwait(false);
                }
            }
            catch { }
            finally
            {
                await DisposeAsync();
            }
        }

        public async ValueTask DisposeAsync()
        {
            _cts.Cancel();
            try { _tcpClient.Dispose(); } catch { }
            if (_channel != null)
            {
                try { await _channel.DisposeAsync().ConfigureAwait(false); } catch { }
            }
        }
    }
}

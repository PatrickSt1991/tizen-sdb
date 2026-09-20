namespace TizenSdb.SdbClient;

/// <summary>What one probed shell verb came back with.</summary>
/// <param name="Command">The exact command sent, argument included.</param>
/// <param name="Accepted">
/// The TV's sdbd recognised the verb. It may still have complained about the argument — that is a
/// verb that exists, which is the question being asked.
/// </param>
/// <param name="Reply">The TV's reply, trimmed, or the transport error when the probe threw.</param>
public sealed record SdbVerbProbeResult(string Command, bool Accepted, string Reply);

/// <summary>
/// The <c>0 …</c> verbs a Samsung TV's sdbd is known to whitelist, and a set of candidates worth
/// asking about. Samsung's sdbd is not a shell: <c>shell:</c> carries a fixed vocabulary of verbs,
/// and anything else gets an empty reply (or, on some builds, the single word <c>closed</c>). That
/// makes the vocabulary cheap to enumerate, and nobody had — the launcher verb the tooling uses,
/// <c>was_execute</c>, only resolves Smart Hub apps, so a verb that reaches the platform's own app
/// launcher would matter (tizen-community-packages#34).
/// </summary>
public static class SdbShellVerbs
{
    /// <summary>
    /// Empties sdbd's install staging directory, <c>/home/owner/share/tmp/sdk_tools</c>. The TV
    /// expands the verb itself — its own log shows the expansion as <c>rm -f</c> over
    /// <c>sdk_tools/*.tpk</c>, <c>*.wgt</c>, <c>*.rpm</c> and <c>sdk_tools/tmp/*.wgt</c> — so it
    /// takes no argument, cannot be aimed at one file, and touches nothing outside that directory.
    /// Samsung's own sdb sends it after every install; this engine leaves that to the caller, so the
    /// packages an install pushes stay there until someone sends it.
    /// </summary>
    public const string RemoveStagedPackages = "0 rmfile";

    /// <summary>Verbs every Samsung TV sdbd seen so far accepts.</summary>
    public static readonly IReadOnlyList<string> Known =
    [
        "0 getduid",
        "0 vd_applist",
        "0 vd_appinstall",
        "0 vd_appuninstall",
        "0 was_execute",
        "0 was_kill",
        "0 debug",
        RemoveStagedPackages,
    ];

    /// <summary>
    /// Probe commands: verbs that other Tizen profiles, older TV builds or Samsung's own tooling have
    /// been seen or rumoured to expose, each with an argument the TV cannot act on
    /// (<c>probe.invalid</c> is not an app, a package or a file). Only reads and launches of a
    /// non-existent id are on the list: nothing here installs, removes or resets anything.
    /// </summary>
    public static readonly IReadOnlyList<string> Candidates =
    [
        // Known, with an invalid id, so the reply shape of an accepted verb is on record next to the rest.
        "0 was_execute probe.invalid",
        "0 was_kill probe.invalid",
        "0 debug probe.invalid",

        // Platform launchers, by the names AUL and its tools go by.
        "0 launch_app probe.invalid",
        "0 app_launcher probe.invalid",
        "0 app_launcher -s probe.invalid",
        "0 aul_test probe.invalid",
        "0 aul_launch probe.invalid",
        "0 execute probe.invalid",
        "0 app_execute probe.invalid",
        "0 vd_appexecute probe.invalid",
        "0 vd_applaunch probe.invalid",
        "0 was_launch probe.invalid",

        // Information verbs.
        "0 getappinfo probe.invalid",
        "0 vd_appinfo probe.invalid",
        "0 getdefaultapp",
        "0 getversion",
        "0 sdbd_version",
        "0 capability",
        "0 vconftool get db/probe.invalid",
        "0 help",

        // Web-inspector plumbing Tizen Studio's TV extension uses alongside `0 debug`.
        "0 setRWIAppID probe.invalid",
        "0 setRWIProfile probe.invalid",

        // The same names without the `0` prefix, in case the dispatcher is not the `0` one.
        "launch_app probe.invalid",
        "app_launcher -s probe.invalid",
        "aul_test probe.invalid",
    ];

    /// <summary>
    /// Whether a reply means sdbd recognised the verb. An unknown verb gets nothing back, or the word
    /// <c>closed</c>; a known one answers with text, even if that text is a complaint.
    /// </summary>
    public static bool IsAccepted(string? reply)
    {
        var trimmed = reply?.Trim() ?? string.Empty;
        return trimmed.Length > 0 && !trimmed.Equals("closed", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>A one-line rendering of a probe, for a diagnose report or a log.</summary>
    public static string Format(SdbVerbProbeResult result)
    {
        var reply = result.Reply.Replace("\r", string.Empty).Replace("\n", " | ");
        if (reply.Length > 160)
            reply = reply[..160] + "…";
        return $"  Verb '{result.Command}': {(result.Accepted ? "ACCEPTED" : "not a verb")}{(reply.Length > 0 ? $" — {reply}" : string.Empty)}";
    }
}

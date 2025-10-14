    using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Security.Cryptography.Xml;
    using System.Text;
    using System.Xml;

    namespace TizenSdb.SigningManager
    {
    public static class TizenWgtSigner
    {
        public static async Task<string> ReSignWgtWithCertsInPlace(
            string wgtPath,
            string authorPfxPath,
            string distributorPfxPath,
            string password,
            string? backupPath = null)
        {
            if (string.IsNullOrWhiteSpace(wgtPath) || !File.Exists(wgtPath))
                throw new FileNotFoundException("WGT file not found.", wgtPath);
            if (!File.Exists(authorPfxPath))
                throw new FileNotFoundException("Author PFX not found.", authorPfxPath);
            if (!File.Exists(distributorPfxPath))
                throw new FileNotFoundException("Distributor PFX not found.", distributorPfxPath);

            // Load leaf certificates (ephemeral/private key in-memory)
            var authorLeaf = LoadLeaf(authorPfxPath, password);
            var distributorLeaf = LoadLeaf(distributorPfxPath, password);

            // Load full collections from PFX (leaf + intermediates)
            var importFlags = X509KeyStorageFlags.DefaultKeySet;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                importFlags |= X509KeyStorageFlags.Exportable;

            var authorColl = new X509Certificate2Collection();
            authorColl.Import(authorPfxPath, password, importFlags);

            var distributorColl = new X509Certificate2Collection();
            distributorColl.Import(distributorPfxPath, password, importFlags);

            byte[] bytes = await File.ReadAllBytesAsync(wgtPath).ConfigureAwait(false);
            await using var inMs = new MemoryStream(bytes, writable: false);

            var signedStream = await TizenResigner.ResignPackageAsync(
                inMs, authorLeaf, authorColl, distributorLeaf, distributorColl).ConfigureAwait(false);

            string tempSigned = Path.GetTempFileName();
            try
            {
                await using (var outFs = File.Create(tempSigned))
                    await signedStream.CopyToAsync(outFs).ConfigureAwait(false);

                try
                {
                    File.Replace(tempSigned, wgtPath, backupPath);
                }
                catch
                {
                    if (File.Exists(wgtPath)) File.Delete(wgtPath);
                    File.Move(tempSigned, wgtPath);
                }
            }
            finally
            {
                try { if (File.Exists(tempSigned)) File.Delete(tempSigned); } catch { }
            }

            return wgtPath;
        }

        private static X509Certificate2 LoadLeaf(string pfxPath, string password)
        {
            // Base flags: ephemeral/private key only in memory
            var flags = X509KeyStorageFlags.EphemeralKeySet;

            // Only include Exportable on Windows
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                flags |= X509KeyStorageFlags.Exportable;

            try
            {
                return new X509Certificate2(pfxPath, password, flags);
            }
            catch (CryptographicException)
            {
                // Fallback for older Windows or environments without EphemeralKeySet support
                var fallbackFlags = X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet;
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    fallbackFlags |= X509KeyStorageFlags.Exportable;

                return new X509Certificate2(pfxPath, password, fallbackFlags);
            }
        }
    }
    internal static class TizenResigner
        {
            internal record FileEntry(string RelativePath, byte[] Data);

            private const string XmlDsigNs = "http://www.w3.org/2000/09/xmldsig#";
            private const string DsigPropsNs = "http://www.w3.org/2009/xmldsig-properties";
            private const string XmlDsigMoreRsaSha512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
            private const string XmlEncSha512 = "http://www.w3.org/2001/04/xmlenc#sha512";
            private const string ExcC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
            private const string C14N11 = "http://www.w3.org/2006/12/xml-c14n11";

            public static async Task<Stream> ResignPackageAsync(
                Stream packageStream,
                X509Certificate2 authorLeaf, X509Certificate2Collection authorCollection,
                X509Certificate2 distributorLeaf, X509Certificate2Collection distributorCollection)
            {
                // 1) Extract all non-signature entries; keep exact zip paths
                var originalFiles = new List<FileEntry>();
                using (var archive = new ZipArchive(packageStream, ZipArchiveMode.Read, leaveOpen: true))
                {
                    foreach (var entry in archive.Entries)
                    {
                        var n = entry.FullName;
                        var lower = n.ToLowerInvariant();
                        if (n.EndsWith("/") || lower.EndsWith("author-signature.xml") || lower.EndsWith("signature1.xml"))
                            continue;

                        using var ms = new MemoryStream();
                        await using var es = entry.Open();
                        await es.CopyToAsync(ms).ConfigureAwait(false);
                        originalFiles.Add(new FileEntry(n, ms.ToArray()));
                    }
                }

                // 2) Build KeyInfo chains: leaf → intermediates (NO root). Prefer PFX order; fall back to OS chain.
                var authorKeyInfoChain = GetKeyInfoChain(authorLeaf, authorCollection);
                var distributorKeyInfoChain = GetKeyInfoChain(distributorLeaf, distributorCollection);

                // 3) Author signature signs original files
                var authorSignatureFile = await BuildSignatureFileAsync(
                    "AuthorSignature", originalFiles, authorLeaf, authorKeyInfoChain).ConfigureAwait(false);

                // 4) Distributor signature: author-signature.xml must be first
                var filesForDistributor = new List<FileEntry>(originalFiles.Count + 1) { authorSignatureFile };
                filesForDistributor.AddRange(originalFiles);

                var distributorSignatureFile = await BuildSignatureFileAsync(
                    "DistributorSignature", filesForDistributor, distributorLeaf, distributorKeyInfoChain).ConfigureAwait(false);

                // 5) Create final zip: write both signatures first, then original files (order of originals preserved)
                var outMs = new MemoryStream();
                using (var newZip = new ZipArchive(outMs, ZipArchiveMode.Create, leaveOpen: true))
                {
                    await WriteEntry(newZip, authorSignatureFile).ConfigureAwait(false);
                    await WriteEntry(newZip, distributorSignatureFile).ConfigureAwait(false);
                    foreach (var f in originalFiles)
                        await WriteEntry(newZip, f).ConfigureAwait(false);
                }
                outMs.Seek(0, SeekOrigin.Begin);
                return outMs;
            }

            private static async Task<FileEntry> BuildSignatureFileAsync(
                string id,
                List<FileEntry> inputFiles,
                X509Certificate2 leafCert,
                IReadOnlyList<X509Certificate2> keyInfoChain)
            {
                if (!leafCert.HasPrivateKey)
                    throw new InvalidOperationException("Certificate must have private key.");

                var doc = new XmlDocument { PreserveWhitespace = true };
                var sigEl = doc.CreateElement("Signature", XmlDsigNs);
                sigEl.SetAttribute("Id", id);
                doc.AppendChild(sigEl);

                var signedInfo = doc.CreateElement("SignedInfo", XmlDsigNs);
                sigEl.AppendChild(signedInfo);

                var canMethod = doc.CreateElement("CanonicalizationMethod", XmlDsigNs);
                canMethod.SetAttribute("Algorithm", ExcC14n);
                signedInfo.AppendChild(canMethod);

                var sigMethod = doc.CreateElement("SignatureMethod", XmlDsigNs);
                sigMethod.SetAttribute("Algorithm", XmlDsigMoreRsaSha512);
                signedInfo.AppendChild(sigMethod);

                // References to package files: SHA-512 digest; DigestValue plain base64
                foreach (var f in inputFiles)
                {
                    var r = doc.CreateElement("Reference", XmlDsigNs);
                    r.SetAttribute("URI", f.RelativePath);

                    var dm = doc.CreateElement("DigestMethod", XmlDsigNs);
                    dm.SetAttribute("Algorithm", XmlEncSha512);
                    r.AppendChild(dm);

                    var dv = doc.CreateElement("DigestValue", XmlDsigNs);
                    dv.InnerText = Convert.ToBase64String(SHA512.HashData(f.Data));
                    r.AppendChild(dv);

                    signedInfo.AppendChild(r);
                }

                // Build <Object Id="prop"> in dsig NS with dsp:* children; digest with C14N11
                var propObject = BuildPropObjectDom(doc, id);
                byte[] propCanon = CanonicalizeNode(propObject, new XmlDsigC14N11Transform());
                var propDigest = Convert.ToBase64String(SHA512.HashData(propCanon));

                var rp = doc.CreateElement("Reference", XmlDsigNs);
                rp.SetAttribute("URI", "#prop");
                var transforms = doc.CreateElement("Transforms", XmlDsigNs);
                var t = doc.CreateElement("Transform", XmlDsigNs);
                t.SetAttribute("Algorithm", C14N11);
                transforms.AppendChild(t);
                rp.AppendChild(transforms);

                var dmProp = doc.CreateElement("DigestMethod", XmlDsigNs);
                dmProp.SetAttribute("Algorithm", XmlEncSha512);
                rp.AppendChild(dmProp);

                var dvProp = doc.CreateElement("DigestValue", XmlDsigNs);
                dvProp.InnerText = propDigest;
                rp.AppendChild(dvProp);

                signedInfo.AppendChild(rp);

                // Sign SignedInfo (exclusive c14n)
                byte[] siBytes = CanonicalizeNode(signedInfo, new XmlDsigExcC14NTransform());
                byte[] sigBytes;
                using (var rsa = leafCert.GetRSAPrivateKey())
                    sigBytes = rsa.SignData(siBytes, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);

                var sigVal = doc.CreateElement("SignatureValue", XmlDsigNs);
                sigVal.InnerText = Convert.ToBase64String(sigBytes);
                sigEl.AppendChild(sigVal);

                // KeyInfo / X509Data — leaf first, then intermediates (NO root).
                // Each cert as base64 with line wrapping and leading/trailing newline (matches common Java output).
                var ki = doc.CreateElement("KeyInfo", XmlDsigNs);
                var x509Data = doc.CreateElement("X509Data", XmlDsigNs);
                foreach (var cert in keyInfoChain)
                {
                    var x = doc.CreateElement("X509Certificate", XmlDsigNs);
                    var b64 = Convert.ToBase64String(cert.RawData);
                    x.InnerText = "\n" + Wrap76(b64) + "\n";
                    x509Data.AppendChild(x);
                }
                ki.AppendChild(x509Data);
                sigEl.AppendChild(ki);

                // Properties object
                sigEl.AppendChild(propObject);

                // Serialize (no decl, no indent)
                var settings = new XmlWriterSettings
                {
                    Encoding = new UTF8Encoding(false),
                    OmitXmlDeclaration = true,
                    Indent = false,
                    NewLineHandling = NewLineHandling.None
                };

                byte[] outBytes;
                using (var ms = new MemoryStream())
                using (var xw = XmlWriter.Create(ms, settings))
                {
                    doc.WriteContentTo(xw);
                    xw.Flush();
                    outBytes = ms.ToArray();
                }

                string fileName = id == "AuthorSignature" ? "author-signature.xml" : "signature1.xml";
                await Task.CompletedTask;
                return new FileEntry(fileName, outBytes);
            }

            private static XmlElement BuildPropObjectDom(XmlDocument doc, string id)
            {
                string role = id == "AuthorSignature" ? "author" : "distributor";

                var obj = doc.CreateElement("Object", XmlDsigNs);
                obj.SetAttribute("Id", "prop");

                var props = doc.CreateElement("SignatureProperties", XmlDsigNs);
                var xmlnsAttr = doc.CreateAttribute("xmlns", "dsp", "http://www.w3.org/2000/xmlns/");
                xmlnsAttr.Value = DsigPropsNs; // declare dsp prefix on SignatureProperties
                props.Attributes.Append(xmlnsAttr);

                XmlElement MakeProp(string pid, string childName, string? uri)
                {
                    var sp = doc.CreateElement("SignatureProperty", XmlDsigNs);
                    sp.SetAttribute("Id", pid);
                    sp.SetAttribute("Target", "#" + id);

                    var child = doc.CreateElement("dsp", childName, DsigPropsNs);
                    if (!string.IsNullOrEmpty(uri))
                        child.SetAttribute("URI", uri);

                    // Avoid <.../> self-closing
                    child.AppendChild(doc.CreateTextNode(string.Empty));

                    sp.AppendChild(child);
                    return sp;
                }

                props.AppendChild(MakeProp("profile", "Profile", "http://www.w3.org/ns/widgets-digsig#profile"));
                props.AppendChild(MakeProp("role", "Role", $"http://www.w3.org/ns/widgets-digsig#role-{role}"));
                props.AppendChild(MakeProp("identifier", "Identifier", null));

                obj.AppendChild(props);
                return obj;
            }

            private static async Task WriteEntry(ZipArchive zip, FileEntry file)
            {
                var entry = zip.CreateEntry(file.RelativePath, CompressionLevel.Optimal);
                await using var es = entry.Open();
                await es.WriteAsync(file.Data, 0, file.Data.Length);
            }

            // === IMPORTANT: ensure we include leaf + intermediates (no root) ===
            private static IReadOnlyList<X509Certificate2> GetKeyInfoChain(
                X509Certificate2 leaf, X509Certificate2Collection pfxCollection)
            {
                // Prefer PFX-provided order (author/distributor P12 usually carries the intermediate).
                var list = new List<X509Certificate2>(capacity: pfxCollection.Count + 1) { leaf };

                foreach (X509Certificate2 c in pfxCollection)
                {
                    if (string.Equals(c.Thumbprint, leaf.Thumbprint, StringComparison.OrdinalIgnoreCase))
                        continue;
                    // Skip roots (self-signed)
                    if (string.Equals(c.Subject, c.Issuer, StringComparison.OrdinalIgnoreCase))
                        continue;
                    list.Add(c);
                }

                // If still only the leaf is present, try building from OS stores to find the issuer.
                if (list.Count == 1)
                {
                    using var chain = new X509Chain
                    {
                        ChainPolicy =
                        {
                            RevocationMode = X509RevocationMode.NoCheck,
                            VerificationFlags = X509VerificationFlags.NoFlag
                        }
                    };
                    chain.ChainPolicy.ExtraStore.AddRange(pfxCollection);
                    if (chain.Build(leaf))
                    {
                        // Append any non-root issuers after leaf
                        foreach (var elem in chain.ChainElements.Cast<X509ChainElement>())
                        {
                            var c = elem.Certificate;
                            if (string.Equals(c.Thumbprint, leaf.Thumbprint, StringComparison.OrdinalIgnoreCase))
                                continue;
                            if (string.Equals(c.Subject, c.Issuer, StringComparison.OrdinalIgnoreCase))
                                continue; // skip root
                            if (!list.Any(x => string.Equals(x.Thumbprint, c.Thumbprint, StringComparison.OrdinalIgnoreCase)))
                                list.Add(c);
                        }
                    }
                }

                return list;
            }

            private static byte[] CanonicalizeNode(XmlNode node, Transform transform)
            {
                var tmp = new XmlDocument { PreserveWhitespace = true };
                var imported = tmp.ImportNode(node, true);
                tmp.AppendChild(imported);
                transform.LoadInput(tmp);
                using var s = (Stream)transform.GetOutput(typeof(Stream));
                using var ms = new MemoryStream();
                s.CopyTo(ms);
                return ms.ToArray();
            }

            private static string Wrap76(string s)
            {
                if (string.IsNullOrEmpty(s)) return s;
                var sb = new StringBuilder(s.Length + s.Length / 76 + 8);
                for (int i = 0; i < s.Length; i += 76)
                {
                    int len = Math.Min(76, s.Length - i);
                    sb.Append(s, i, len);
                    if (i + len < s.Length) sb.Append('\n');
                }
                return sb.ToString();
            }
        }

        /// <summary>
        /// Minimal C14N 1.1 wrapper.
        /// </summary>
        internal sealed class XmlDsigC14N11Transform : Transform
        {
            public override Type[] InputTypes => new[] { typeof(Stream), typeof(XmlDocument), typeof(XmlNodeList) };
            public override Type[] OutputTypes => new[] { typeof(Stream) };

            public XmlDsigC14N11Transform() => Algorithm = "http://www.w3.org/2006/12/xml-c14n11";

            private XmlDocument? _input;

            public override void LoadInnerXml(XmlNodeList nodeList) { }
            protected override XmlNodeList? GetInnerXml() => null;

            public override void LoadInput(object obj)
            {
                if (obj is Stream stream)
                {
                    using var sr = new StreamReader(stream, Encoding.UTF8, true, 4096, leaveOpen: true);
                    var xml = sr.ReadToEnd();
                    var d = new XmlDocument { PreserveWhitespace = true };
                    d.LoadXml(xml);
                    _input = d; return;
                }
                if (obj is XmlDocument doc) { _input = doc; return; }
                if (obj is XmlNodeList list)
                {
                    var tmp = new XmlDocument { PreserveWhitespace = true };
                    foreach (XmlNode n in list) tmp.AppendChild(tmp.ImportNode(n, true));
                    _input = tmp; return;
                }
                throw new ArgumentException("Unsupported input type for C14N11 transform.");
            }

            public override object GetOutput() => GetOutput(typeof(Stream));

            public override object GetOutput(Type type)
            {
                if (_input == null) throw new InvalidOperationException("No input loaded for C14N11 transform.");
                if (type != typeof(Stream) && !type.IsSubclassOf(typeof(Stream)))
                    throw new ArgumentException("Only Stream output is supported.", nameof(type));

                // Delegate to 1.0 canonicalizer; our subtree avoids constructs that differ in 1.1.
                var c14n10 = new XmlDsigC14NTransform();
                c14n10.LoadInput(_input);
                var raw = (Stream)c14n10.GetOutput(typeof(Stream));
                var ms = new MemoryStream();
                raw.CopyTo(ms);
                ms.Position = 0;
                return ms;
            }
        }
    }

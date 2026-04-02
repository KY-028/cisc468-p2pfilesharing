using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization.Json;
using FileInfo = P2PFT_Cs.DataObj.FileInfo;

namespace P2PFT_Cs.Utils
{
    /// <summary>
    /// Persistent storage for peer file manifests (file lists received
    /// via FILE_LIST_RESPONSE). Compatible with Python client's
    /// manifests.py — stores one JSON file per peer in a manifests/
    /// subdirectory.
    /// </summary>
    internal class ManifestStorage
    {
        private readonly string _manifestDir;
        private readonly ConcurrentDictionary<string, List<FileInfo>> _manifests
            = new ConcurrentDictionary<string, List<FileInfo>>();

        public ManifestStorage(string dataDir)
        {
            _manifestDir = Path.Combine(dataDir, "manifests");
            if (!Directory.Exists(_manifestDir))
                Directory.CreateDirectory(_manifestDir);
            LoadAll();
        }

        public void Store(string peerId, List<FileInfo> files)
        {
            _manifests[peerId] = files ?? new List<FileInfo>();
            SaveToDisk(peerId);
        }

        public List<FileInfo> Get(string peerId)
        {
            List<FileInfo> files;
            if (_manifests.TryGetValue(peerId, out files))
                return new List<FileInfo>(files);
            return new List<FileInfo>();
        }

        private void LoadAll()
        {
            foreach (string file in Directory.GetFiles(_manifestDir, "*.json"))
            {
                try
                {
                    string peerId = Path.GetFileNameWithoutExtension(file);
                    byte[] data = File.ReadAllBytes(file);
                    var serializer = new DataContractJsonSerializer(typeof(List<FileInfo>));
                    using (var ms = new MemoryStream(data))
                    {
                        var files = (List<FileInfo>)serializer.ReadObject(ms);
                        if (files != null)
                            _manifests[peerId] = files;
                    }
                }
                catch { /* skip corrupt manifests */ }
            }
        }

        private void SaveToDisk(string peerId)
        {
            try
            {
                List<FileInfo> files;
                if (!_manifests.TryGetValue(peerId, out files)) return;

                var serializer = new DataContractJsonSerializer(typeof(List<FileInfo>));
                byte[] data;
                using (var ms = new MemoryStream())
                {
                    serializer.WriteObject(ms, files);
                    data = ms.ToArray();
                }
                string path = Path.Combine(_manifestDir, peerId + ".json");
                File.WriteAllBytes(path, data);
            }
            catch { /* best-effort persistence */ }
        }
    }
}

using MaxMind.GeoIP2;
using Microsoft.ML;
using Microsoft.ML.Data;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Xml;

/*************************************************
 * MAIN LOG ENTRY MODEL
 * Represents a single log line with key properties
 *************************************************/
public class LogEntry
{
    public string IP { get; set; }          // Source IP address
    public DateTime Timestamp { get; set; } // When the request occurred
    public string Method { get; set; }       // HTTP method (GET/POST)
    public string Path { get; set; }         // Requested URL path
    public int StatusCode { get; set; }     // HTTP response status
    public string UserAgent { get; set; }   // Client browser/device
    public string Country { get; set; }      // Added by GeoIP lookup
}

/*************************************************
 * LOG PARSER CLASS
 * Handles reading and parsing raw log files
 *************************************************/
public class LogParser
{
    /// <summary>
    /// Parses Apache/NGINX style access logs
    /// </summary>
    /// <param name="filePath">Path to log file</param>
    /// <returns>List of parsed log entries</returns>
    public List<LogEntry> ParseApacheLogs(string filePath)
    {
        var logEntries = new List<LogEntry>();

        // Safety check if file exists
        if (!File.Exists(filePath))
        {
            Console.WriteLine($"Error: Log file not found at {filePath}");
            return logEntries;
        }

        // Standard Apache log format regex pattern
        var pattern = @"(?<ip>\d+\.\d+\.\d+\.\d+).*?\[(?<date>.*?)\].*?\""(?<method>\w+)\s(?<path>.*?)\sHTTP.*?\""\s(?<status>\d+)";

        try
        {
            foreach (var line in File.ReadLines(filePath))
            {
                var match = Regex.Match(line, pattern);

                if (match.Success)
                {
                    logEntries.Add(new LogEntry
                    {
                        IP = match.Groups["ip"].Value,
                        Timestamp = DateTime.Parse(match.Groups["date"].Value),
                        Method = match.Groups["method"].Value,
                        Path = match.Groups["path"].Value,
                        StatusCode = int.Parse(match.Groups["status"].Value)
                    });
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error parsing logs: {ex.Message}");
        }

        return logEntries;
    }
}

/*************************************************
 * GEOIP LOOKUP SERVICE
 * Converts IP addresses to country locations
 *************************************************/
public class GeoIPLookup
{
    private readonly DatabaseReader _reader;

    /// <summary>
    /// Initialize with MaxMind database
    /// </summary>
    /// <param name="dbPath">Path to GeoLite2 database</param>
    public GeoIPLookup(string dbPath = "GeoLite2-Country.mmdb")
    {
        if (!File.Exists(dbPath))
            throw new FileNotFoundException("GeoIP database not found. Download from MaxMind");

        _reader = new DatabaseReader(dbPath);
    }

    /// <summary>
    /// Gets country name from IP address
    /// </summary>
    public string GetCountry(string ip)
    {
        try
        {
            // Skip private IP ranges
            if (ip.StartsWith("192.168.") || ip.StartsWith("10.") || ip.StartsWith("172."))
                return "Internal";

            return _reader.Country(ip).Country?.Name ?? "Unknown";
        }
        catch
        {
            return "Unknown";
        }
    }
}

/*************************************************
 * ANOMALY DETECTION USING ML.NET
 * Uses clustering to find unusual log patterns
 *************************************************/
public class AnomalyDetection
{
    /// <summary>
    /// Detects unusual patterns in logs using K-Means clustering
    /// </summary>
    public List<string> DetectAnomalies(List<LogEntry> logs)
    {
        var anomalies = new List<string>();

        // Set up ML context
        var mlContext = new MLContext();

        // Convert logs to ML-compatible format
        var data = mlContext.Data.LoadFromEnumerable(logs.Select(l => new
        {
            l.IP,
            l.StatusCode
        }));

        // Build ML pipeline
        var pipeline = mlContext.Transforms
            .Concatenate("Features", nameof(LogEntry.IP), nameof(LogEntry.StatusCode))
            .Append(mlContext.Clustering.Trainers.KMeans(
                numberOfClusters: 2,   // Two clusters: normal vs anomalous
                featureColumnName: "Features"));

        // Train model
        var model = pipeline.Fit(data);

        // Make predictions
        var predictions = model.Transform(data);

        // Extract and analyze results
        var predictedClusters = mlContext.Data
            .CreateEnumerable<ClusterPrediction>(predictions, reuseRowObject: false)
            .ToList();

        // Find entries in the smaller cluster (likely anomalies)
        var clusterCounts = predictedClusters
            .GroupBy(p => p.PredictedClusterId)
            .OrderBy(g => g.Count())
            .ToList();

        if (clusterCounts.Count >= 2)
        {
            var anomalyCluster = clusterCounts.First(); // Smaller cluster
            anomalies = logs.Zip(predictedClusters, (log, pred) =>
                pred.PredictedClusterId == anomalyCluster.Key ? log.IP : null)
                .Where(ip => ip != null)
                .Distinct()
                .ToList();
        }

        return anomalies;
    }

    private class ClusterPrediction
    {
        [ColumnName("PredictedLabel")]
        public uint PredictedClusterId { get; set; }
    }
}

/*************************************************
 * BRUTE FORCE DETECTOR
 * Identifies potential password guessing attacks
 *************************************************/
public class BruteForceDetector
{
    /// <summary>
    /// Finds IPs with multiple failed login attempts
    /// </summary>
    /// <param name="threshold">Minimum attempts to consider</param>
    public List<string> DetectBruteForce(List<LogEntry> logs, int threshold = 5)
    {
        return logs
            .Where(l =>
                l.Path.Contains("login", StringComparison.OrdinalIgnoreCase) &&
                l.StatusCode == 401) // HTTP 401 Unauthorized
            .GroupBy(l => l.IP)
            .Where(g => g.Count() >= threshold)
            .Select(g => g.Key)
            .ToList();
    }
}

/*************************************************
 * REPORT GENERATOR
 * Creates JSON reports of security findings
 *************************************************/
public class ReportGenerator
{
    /// <summary>
    /// Exports analysis results to JSON file
    /// </summary>
    public void GenerateReport(
        List<LogEntry> logs,
        List<string> bruteForceIPs,
        List<string> anomalousIPs,
        string outputPath = "security_report.json")
    {
        var report = new
        {
            AnalysisTime = DateTime.Now,
            TotalLogEntries = logs.Count,
            UniqueIPs = logs.Select(l => l.IP).Distinct().Count(),
            SuspiciousIPs = new
            {
                BruteForceAttempts = bruteForceIPs,
                AnomalousBehavior = anomalousIPs
            },
            Statistics = new
            {
                MostCommonCountries = logs
                    .GroupBy(l => l.Country)
                    .OrderByDescending(g => g.Count())
                    .Take(5)
                    .ToDictionary(g => g.Key, g => g.Count())
            }
        };

        File.WriteAllText(outputPath,
            JsonConvert.SerializeObject(report, Formatting.Indented));
    }
}

/*************************************************
 * MAIN PROGRAM
 *************************************************/
class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("[+] Starting log analysis...");

        // 1. Parse logs
        var parser = new LogParser();
        var logs = parser.ParseApacheLogs("access.log");

        if (!logs.Any())
        {
            Console.WriteLine("[-] No logs found or parseable");
            return;
        }

        // 2. Enrich with GeoIP data
        var geoLookup = new GeoIPLookup();
        logs.ForEach(l => l.Country = geoLookup.GetCountry(l.IP));

        // 3. Detect brute force attacks
        var bruteForceDetector = new BruteForceDetector();
        var bruteForceIPs = bruteForceDetector.DetectBruteForce(logs);

        // 4. Find anomalies with ML
        var anomalyDetector = new AnomalyDetection();
        var anomalousIPs = anomalyDetector.DetectAnomalies(logs);

        // 5. Generate report
        new ReportGenerator().GenerateReport(logs, bruteForceIPs, anomalousIPs);

        Console.WriteLine($"[+] Analysis complete! Findings saved to security_report.json");
        Console.WriteLine($"    - Total logs processed: {logs.Count}");
        Console.WriteLine($"    - Brute force IPs detected: {bruteForceIPs.Count}");
        Console.WriteLine($"    - Anomalous IPs detected: {anomalousIPs.Count}");
    }
}
import { useEffect, useState } from "react";
import {
  ShieldCheck,
  Upload,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Activity,
  Paperclip,
  BrainCircuit,
  FileText,
  Download,
  Lock,
} from "lucide-react";
import "./App.css";

const API_BASE =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000";

function App() {
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [reportLoading, setReportLoading] = useState(false);
  const [error, setError] = useState("");
  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyDetail, setHistoryDetail] = useState(null);
  const [historyDetailLoading, setHistoryDetailLoading] = useState(false);

  const loadHistory = async () => {
    setHistoryLoading(true);

    try {
      const response = await fetch(`${API_BASE}/api/history`);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error || "Unable to load analysis history."
        );
      }

      setHistory(
        Array.isArray(data.records)
          ? data.records
          : []
      );
    } catch (err) {
      console.error("History loading failed:", err);
    } finally {
      setHistoryLoading(false);
    }
  };

  useEffect(() => {
    loadHistory();
  }, []);


const loadHistoryDetail = async (analysisId) => {
    setHistoryDetailLoading(true);
    setError("");

    try {
        const response = await fetch(
            `${API_BASE}/api/history/${analysisId}`
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                data.error || "Unable to load analysis details."
            );
        }

        setHistoryDetail(data.analysis);
    } catch (err) {
        setError(
            err.message || "Unable to load analysis details."
        );
    } finally {
        setHistoryDetailLoading(false);
    }
};

const closeHistoryDetail = () => {
    setHistoryDetail(null);
    setError("");
};


 

  const analyzeEmail = async () => {
    if (!file) {
      setError("Select an .eml file first.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const formData = new FormData();
      formData.append("email", file);

      const response = await fetch(`${API_BASE}/api/analyze`, {
        method: "POST",
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Email analysis failed.");
      }

      setResult(data);
      await loadHistory();
    } catch (err) {
      setError(
        err.message ||
          "Unable to connect to the MailSentinel backend."
      );
    } finally {
      setLoading(false);
    }
  };

  const downloadReport = async () => {
    if (!result) return;

    setReportLoading(true);
    setError("");

    try {
      const response = await fetch(`${API_BASE}/api/report`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(result),
      });

      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(
          data.error || "Report generation failed."
        );
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);

      const link = document.createElement("a");
      link.href = url;
      link.download = `MailSentinel_Report_${
        result.email?.file || "analysis"
      }.pdf`;

      document.body.appendChild(link);
      link.click();
      link.remove();

      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError(err.message || "Unable to generate report.");
    } finally {
      setReportLoading(false);
    }
  };

  const risk = result?.risk;
  const ai = result?.ai_analysis;

  const attachments =
    result?.analyzers?.attachment_analyzer?.attachments || [];

  const riskClass =
    risk?.classification === "phishing"
      ? "critical"
      : risk?.classification === "suspicious"
        ? "high"
        : risk?.classification === "low_risk"
          ? "low"
          : "safe";

  const isMalicious =
    ai?.is_malicious === true ||
    risk?.classification === "phishing";

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <div className="logo">
            <ShieldCheck size={28} />
          </div>

          <div>
            <h1>MailSentinel</h1>
            <span>Email Security IDPS</span>
          </div>
        </div>

        <div className="system-status">
          <span className="status-dot" />
          SYSTEM ONLINE
        </div>
      </header>

      <main>
        <section className="hero">
          <div>
            <p className="eyebrow">
              EMAIL THREAT ANALYSIS PLATFORM
            </p>

            <h2>
              Detect threats.
              <br />
              <span>Protect inboxes.</span>
            </h2>

            <p className="hero-text">
              Analyze email headers, URLs, HTML content,
              attachments, deterministic risk signals and
              AI-powered threat intelligence through one
              unified security pipeline.
            </p>
          </div>

          <div className="hero-icon">
            <ShieldCheck size={110} strokeWidth={1} />
          </div>
        </section>

        <section className="upload-card">
          <div className="section-title">
            <Upload size={20} />
            <h3>EMAIL ANALYSIS</h3>
          </div>

          <label className="drop-zone">
            <input
              type="file"
              accept=".eml"
              onChange={(e) => {
                setFile(e.target.files?.[0] || null);
                setResult(null);
                setError("");
              }}
            />

            <Upload size={42} />

            <strong>
              {file
                ? file.name
                : "Drop .eml file here"}
            </strong>

            <span>
              {file
                ? `${(file.size / 1024).toFixed(1)} KB`
                : "or click to browse"}
            </span>
          </label>

          {error && (
            <div className="error-box">
              <XCircle size={20} />
              {error}
            </div>
          )}

          <button
            className="analyze-button"
            onClick={analyzeEmail}
            disabled={!file || loading}
          >
            <Activity size={20} />

            {loading
              ? "ANALYZING..."
              : "ANALYZE EMAIL"}
          </button>
        </section>

        {result && (
          <>
            <section
              className={`risk-banner ${riskClass}`}
            >
              <div className="risk-icon">
                {riskClass === "safe" ||
                riskClass === "low" ? (
                  <CheckCircle size={38} />
                ) : (
                  <AlertTriangle size={38} />
                )}
              </div>

              <div>
                <span>FINAL CLASSIFICATION</span>

                <h2>
                  {risk?.classification
                    ?.replaceAll("_", " ")
                    .toUpperCase() || "UNKNOWN"}
                </h2>
              </div>

              <div className="risk-score">
                <span>RISK SCORE</span>

                <strong>
                  {risk?.score ?? 0}
                </strong>

                <small>/ 100</small>
              </div>
            </section>


            {result?.quarantine && (
  <section
    className={`quarantine-banner ${
      result.quarantine.status === "quarantined"
        ? "quarantined"
        : result.quarantine.status === "quarantine_failed"
          ? "quarantine-failed"
          : "not-quarantined"
    }`}
  >
    <div className="quarantine-icon">
      {result.quarantine.status === "quarantined" ? (
        <Lock size={25} />
      ) : result.quarantine.status === "quarantine_failed" ? (
        <AlertTriangle size={25} />
      ) : (
        <CheckCircle size={25} />
      )}
    </div>

    <div className="quarantine-content">
      <strong>
        {result.quarantine.status === "quarantined"
          ? "EMAIL QUARANTINED"
          : result.quarantine.status === "quarantine_failed"
            ? "QUARANTINE FAILED"
            : "EMAIL NOT QUARANTINED"}
      </strong>

      <span>
        {result.quarantine.reason ||
          "No quarantine information available."}
      </span>

      {result.quarantine.original_filename && (
        <span>
          File: {result.quarantine.original_filename}
        </span>
      )}

      {result.quarantine.quarantine_id && (
        <span>
          Quarantine ID: {result.quarantine.quarantine_id}
        </span>
      )}
    </div>

    <span className="quarantine-status">
      {result.quarantine.status
        ?.replaceAll("_", " ")
        .toUpperCase()}
    </span>
  </section>
)}

              

            <section className="stats-grid">
              <Stat
                title="Finding Score"
                value={
                  risk?.score_breakdown
                    ?.finding_score ?? 0
                }
              />

              <Stat
                title="Correlation"
                value={
                  risk?.score_breakdown
                    ?.correlation_score ?? 0
                }
              />

              <Stat
                title="Confidence"
                value={
                  risk?.confidence || "Unknown"
                }
              />

              <Stat
                title="Action"
                value={
                  risk?.recommended_action
                    ?.replaceAll("_", " ") ||
                  "Unknown"
                }
              />
            </section>

            <section className="panel ai-panel">
              <div className="panel-header">
                <h3>
                  <BrainCircuit size={20} />
                  AI SECURITY ANALYSIS
                </h3>

                <span
                  className={`badge ${
                    ai?.status === "completed"
                      ? "success"
                      : "danger"
                  }`}
                >
                  {ai?.status || "unknown"}
                </span>
              </div>

              <div className="ai-grid">
                <div className="ai-verdict">
                  <span>THREAT LEVEL</span>
                  <strong>
                    {ai?.threat_level ||
                      "UNKNOWN"}
                  </strong>
                </div>

                <div className="ai-verdict">
                  <span>AI CONFIDENCE</span>
                  <strong>
                    {ai?.confidence ||
                      "UNKNOWN"}
                  </strong>
                </div>

                <div className="ai-verdict">
                  <span>MALICIOUS</span>
                  <strong>
                    {ai?.is_malicious
                      ? "YES"
                      : "NO"}
                  </strong>
                </div>
              </div>

              <div className="ai-content">
                <h4>AI Summary</h4>

                <p>
                  {ai?.summary ||
                    "No AI summary available."}
                </p>

                <h4>User Explanation</h4>

                <p>
                  {ai?.user_explanation ||
                    "No explanation available."}
                </p>

                {Array.isArray(
                  ai?.key_findings
                ) &&
                  ai.key_findings.length > 0 && (
                    <>
                      <h4>Key Findings</h4>

                      <ul>
                        {ai.key_findings.map(
                          (finding, index) => (
                            <li key={index}>
                              {finding}
                            </li>
                          )
                        )}
                      </ul>
                    </>
                  )}
              </div>
            </section>

            <section className="dashboard-grid">
              <div className="panel">
                <div className="panel-header">
                  <h3>
                    <Activity size={19} />
                    ANALYZER STATUS
                  </h3>
                </div>

                {Object.entries(
                  risk?.analyzer_status || {}
                ).map(([name, status]) => (
                  <div
                    className="analyzer-row"
                    key={name}
                  >
                    <div>
                      <strong>
                        {name
                          .replaceAll("_", " ")
                          .toUpperCase()}
                      </strong>
                    </div>

                    <span
                      className={
                        status.includes("risk")
                          ? "badge danger"
                          : "badge success"
                      }
                    >
                      {status.replaceAll(
                        "_",
                        " "
                      )}
                    </span>
                  </div>
                ))}
              </div>

              <div className="panel">
                <div className="panel-header">
                  <h3>
                    <Paperclip size={19} />
                    ATTACHMENTS
                  </h3>
                </div>

                {attachments.length === 0 ? (
                  <p className="empty">
                    No attachments detected.
                  </p>
                ) : (
                  attachments.map(
                    (attachment, index) => (
                      <div
                        className="attachment-row"
                        key={index}
                      >
                        <div>
                          <strong>
                            {attachment.filename ||
                              "Unknown file"}
                          </strong>

                          <span>
                            SHA256:{" "}
                            {attachment.sha256 ||
                              "Unavailable"}
                          </span>
                        </div>

                        <span className="badge danger">
                          {attachment.status ||
                            "UNKNOWN"}
                        </span>
                      </div>
                    )
                  )
                )}
              </div>
            </section>

            <section className="panel email-panel">
              <div className="panel-header">
                <h3>EMAIL INFORMATION</h3>
              </div>

              <div className="email-info">
                <div>
                  <span>FILE</span>
                  <strong>
                    {result.email?.file ||
                      "Unknown"}
                  </strong>
                </div>

                <div>
                  <span>SUBJECT</span>
                  <strong>
                    {result.parser?.headers
                      ?.subject || "Unknown"}
                  </strong>
                </div>

                <div>
                  <span>FROM</span>
                  <strong>
                    {result.parser?.headers
                      ?.from || "Unknown"}
                  </strong>
                </div>

                <div>
                  <span>ATTACHMENTS</span>
                  <strong>
                    {result.parser?.attachments
                      ?.count ?? 0}
                  </strong>
                </div>
              </div>
            </section>

            <section className="report-panel">
              <div>
                <FileText size={28} />

                <div>
                  <h3>
                    SECURITY INCIDENT REPORT
                  </h3>

                  <p>
                    Generate a professional PDF
                    security report containing the
                    deterministic analysis, AI
                    assessment, findings and final
                    verdict.
                  </p>
                </div>
              </div>

              <button
                className="report-button"
                onClick={downloadReport}
                disabled={reportLoading}
              >
                <Download size={19} />

                {reportLoading
                  ? "GENERATING..."
                  : "DOWNLOAD PDF REPORT"}
              </button>
            </section>
          </>
        )}

        <section className="panel history-panel">
  <div className="panel-header">
    <h3>
      <FileText size={20} />
      ANALYSIS HISTORY
    </h3>

    <button
      className="history-refresh"
      onClick={loadHistory}
      disabled={historyLoading}
    >
      {historyLoading ? "LOADING..." : "REFRESH"}
    </button>
  </div>

  {history.length === 0 ? (
    <p className="empty">
      No analysis history available.
    </p>
  ) : (
    <div className="history-list">
      {history.map((record) => {
        const classification =
          record.classification || "unknown";

        const historyClass =
          classification === "phishing"
            ? "critical"
            : classification === "suspicious"
              ? "high"
              : classification === "low_risk"
                ? "low"
                : "safe";

        return (
          <div
            className="history-row"
            key={record.id}
          >
            <div className="history-main">
              <strong>
                {record.original_filename ||
                  "Unknown file"}
              </strong>

              <span>
                {record.subject || "No subject"}
              </span>

              <small>
                {record.sender ||
                  "Unknown sender"}
              </small>
            </div>

            <div className="history-result">
              <span
                className={`history-class ${historyClass}`}
              >
                {classification
                  .replaceAll("_", " ")
                  .toUpperCase()}
              </span>

              <strong>
                {record.risk_score ?? 0}/100
              </strong>

              <span>
                {record.quarantine_status
                  ?.replaceAll("_", " ") ||
                  "unknown"}
              </span>

              <button
                className="history-view-button"
                onClick={() =>
                  loadHistoryDetail(record.id)
                }
                disabled={historyDetailLoading}
              >
                {historyDetailLoading
                  ? "LOADING..."
                  : "VIEW DETAILS"}
              </button>
            </div>
          </div>
        );
      })}
    </div>
  )}
</section>

{historyDetail && (
  <section className="panel history-detail-panel">
    <div className="panel-header">
      <h3>
        <FileText size={20} />
        ANALYSIS DETAILS
      </h3>

      <button
        className="history-refresh"
        onClick={closeHistoryDetail}
      >
        BACK TO HISTORY
      </button>
    </div>

    <div className="detail-header">
      <div>
        <span>ANALYSIS ID</span>
        <strong>#{historyDetail.analysis_id}</strong>
      </div>

      <div>
        <span>FILE</span>
        <strong>
          {historyDetail.email?.file || "Unknown"}
        </strong>
      </div>

      <div>
        <span>CLASSIFICATION</span>
        <strong>
          {historyDetail.risk?.classification
            ?.replaceAll("_", " ")
            .toUpperCase() || "UNKNOWN"}
        </strong>
      </div>

      <div>
        <span>RISK SCORE</span>
        <strong>
          {historyDetail.risk?.score ?? 0}/100
        </strong>
      </div>
    </div>

    <div className="detail-grid">

      <div className="detail-card">
        <h4>EMAIL INFORMATION</h4>

        <p>
          <strong>Subject:</strong>{" "}
          {historyDetail.parser?.headers?.subject ||
            "No subject"}
        </p>

        <p>
          <strong>From:</strong>{" "}
          {historyDetail.parser?.headers?.from ||
            "Unknown"}
        </p>

        <p>
          <strong>To:</strong>{" "}
          {historyDetail.parser?.headers?.to ||
            "Unknown"}
        </p>

        <p>
          <strong>Reply-To:</strong>{" "}
          {historyDetail.parser?.headers?.reply_to ||
            "None"}
        </p>

        <p>
          <strong>File Size:</strong>{" "}
          {historyDetail.email?.size ?? 0} bytes
        </p>
      </div>

      <div className="detail-card">
        <h4>SECURITY DECISION</h4>

        <p>
          <strong>Classification:</strong>{" "}
          {historyDetail.risk?.classification ||
            "Unknown"}
        </p>

        <p>
          <strong>Risk Score:</strong>{" "}
          {historyDetail.risk?.score ?? 0}/100
        </p>

        <p>
          <strong>Confidence:</strong>{" "}
          {historyDetail.risk?.confidence ||
            "Unknown"}
        </p>

        <p>
          <strong>Recommended Action:</strong>{" "}
          {historyDetail.risk?.recommended_action ||
            "Unknown"}
        </p>

        <p>
          <strong>Security Override:</strong>{" "}
          {historyDetail.risk?.security_override
            ? "YES"
            : "NO"}
        </p>
      </div>

    </div>

    <div className="detail-card">
      <h4>ANALYZER SCORES</h4>

      <div className="detail-stats">
        {Object.entries(
          historyDetail.risk?.analyzer_scores || {}
        ).map(([name, score]) => (
          <div key={name}>
            <span>
              {name
                .replaceAll("_", " ")
                .toUpperCase()}
            </span>

            <strong>{score}</strong>
          </div>
        ))}
      </div>
    </div>

    <div className="detail-card">
      <h4>SECURITY FINDINGS</h4>

      {historyDetail.risk?.findings?.length ? (
        <div className="detail-findings">
          {historyDetail.risk.findings.map(
            (finding, index) => (
              <div
                className="finding-row"
                key={index}
              >
                <div>
                  <strong>
                    {finding.indicator ||
                      "Security finding"}
                  </strong>

                  <p>
                    {finding.description ||
                      "No description available."}
                  </p>
                </div>

                <span className="badge danger">
                  {finding.severity ||
                    "unknown"}
                </span>
              </div>
            )
          )}
        </div>
      ) : (
        <p className="empty">
          No security findings recorded.
        </p>
      )}
    </div>

    <div className="detail-card">
      <h4>AI SECURITY ANALYSIS</h4>

      <div className="detail-stats">
        <div>
          <span>STATUS</span>
          <strong>
            {historyDetail.ai_analysis?.status ||
              "UNKNOWN"}
          </strong>
        </div>

        <div>
          <span>THREAT LEVEL</span>
          <strong>
            {historyDetail.ai_analysis?.threat_level ||
              "UNKNOWN"}
          </strong>
        </div>

        <div>
          <span>CONFIDENCE</span>
          <strong>
            {historyDetail.ai_analysis?.confidence ||
              "UNKNOWN"}
          </strong>
        </div>

        <div>
          <span>MALICIOUS</span>
          <strong>
            {historyDetail.ai_analysis?.is_malicious
              ? "YES"
              : "NO"}
          </strong>
        </div>
      </div>

      <p>
        {historyDetail.ai_analysis?.summary ||
          "No AI summary available."}
      </p>
    </div>

    <div className="detail-card">
      <h4>QUARANTINE STATUS</h4>

      <p>
        <strong>Status:</strong>{" "}
        {historyDetail.quarantine?.status ||
          "Unknown"}
      </p>

      <p>
        <strong>Reason:</strong>{" "}
        {historyDetail.quarantine?.reason ||
          "No quarantine reason recorded."}
      </p>

      {historyDetail.quarantine?.quarantine_id && (
        <p>
          <strong>Quarantine ID:</strong>{" "}
          {historyDetail.quarantine.quarantine_id}
        </p>
      )}
    </div>

    <div className="detail-card">
      <h4>URL ANALYSIS</h4>

      {historyDetail.analyzers?.url_analyzer?.urls
        ?.length ? (
        historyDetail.analyzers.url_analyzer.urls.map(
          (item, index) => (
            <div
              className="finding-row"
              key={index}
            >
              <div>
                <strong>{item.url}</strong>

                <p>
                  Domain:{" "}
                  {item.hostname || "Unknown"}
                </p>
              </div>

              <span className="badge">
                {item.status || "unknown"}
              </span>
            </div>
          )
        )
      ) : (
        <p className="empty">
          No URLs recorded.
        </p>
      )}
    </div>

  </section>
)}


       </main>

      <footer>
        MailSentinel • Email Security Intrusion
        Detection & Prevention System
      </footer>
    </div>
  );
}

function Stat({ title, value }) {
  return (
    <div className="stat">
      <span>{title}</span>
      <strong>{value}</strong>
    </div>
  );
}

export default App;

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
  Shield,
  Sparkles,
  Bug,
  RefreshCw,
  ArrowLeft,
  Link2,
} from "lucide-react";
import "./App.css";

const API_BASE =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000";

function severityTone(value) {
  const v = String(value || "")
    .toLowerCase()
    .replaceAll("_", " ")
    .trim();

  if (
    v.includes("critical") ||
    v.includes("phishing") ||
    v === "yes" ||
    v.includes("quarantined")
  ) {
    return "critical";
  }

  if (v.includes("high") || v.includes("suspicious") || v.includes("danger")) {
    return "high";
  }

  if (v.includes("medium") || v.includes("warn")) {
    return "medium";
  }

  if (
    v.includes("low") ||
    v.includes("safe") ||
    v.includes("normal") ||
    v.includes("completed") ||
    v === "no" ||
    v.includes("success")
  ) {
    return "low";
  }

  return "info";
}

function formatLabel(value) {
  if (value == null || value === "") return "Unknown";
  return String(value).replaceAll("_", " ");
}

function formatUpper(value) {
  return formatLabel(value).toUpperCase();
}

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
        throw new Error(data.error || "Unable to load analysis history.");
      }

      setHistory(Array.isArray(data.records) ? data.records : []);
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
      const response = await fetch(`${API_BASE}/api/history/${analysisId}`);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Unable to load analysis details.");
      }

      setHistoryDetail(data.analysis);
    } catch (err) {
      setError(err.message || "Unable to load analysis details.");
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
        err.message || "Unable to connect to the MailSentinel backend."
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
        throw new Error(data.error || "Report generation failed.");
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
            <p className="eyebrow">EMAIL THREAT ANALYSIS PLATFORM</p>

            <h2>
              Detect threats.
              <br />
              <span>Protect inboxes.</span>
            </h2>

            <p className="hero-text">
              Analyze email headers, URLs, HTML content, attachments,
              deterministic risk signals and AI-powered threat intelligence
              through one unified security pipeline.
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

            <strong>{file ? file.name : "Drop .eml file here"}</strong>

            <span>
              {file ? `${(file.size / 1024).toFixed(1)} KB` : "or click to browse"}
            </span>
          </label>

          {error && (
            <div className="error-box" role="alert">
              <XCircle size={20} />
              {error}
            </div>
          )}

          <button
            className="btn btn-primary analyze-button"
            onClick={analyzeEmail}
            disabled={!file || loading}
          >
            <Activity size={20} />
            {loading ? "Analyzing..." : "Analyze Email"}
          </button>
        </section>

        {result && (
          <>
            <section className={`risk-banner ${riskClass}`}>
              <div className="risk-icon">
                {riskClass === "safe" || riskClass === "low" ? (
                  <CheckCircle size={38} />
                ) : (
                  <AlertTriangle size={38} />
                )}
              </div>

              <div>
                <span className="field-label">FINAL CLASSIFICATION</span>
                <h2>
                  {formatUpper(risk?.classification) || "UNKNOWN"}
                </h2>
              </div>

              <div className="risk-score">
                <span className="field-label">RISK SCORE</span>
                <strong>{risk?.score ?? 0}</strong>
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
                    <span>File: {result.quarantine.original_filename}</span>
                  )}

                  {result.quarantine.quarantine_id && (
                    <span>
                      Quarantine ID: {result.quarantine.quarantine_id}
                    </span>
                  )}
                </div>

                <span className="quarantine-status">
                  {formatUpper(result.quarantine.status)}
                </span>
              </section>
            )}

            <section className="stats-grid">
              <Stat
                title="Finding Score"
                value={risk?.score_breakdown?.finding_score ?? 0}
              />
              <Stat
                title="Correlation"
                value={risk?.score_breakdown?.correlation_score ?? 0}
              />
              <Stat title="Confidence" value={risk?.confidence || "Unknown"} />
              <Stat
                title="Action"
                value={formatLabel(risk?.recommended_action)}
              />
            </section>

            <AiAnalysisPanel ai={ai} />

            <section className="dashboard-grid">
              <div className="panel">
                <div className="panel-header">
                  <h3>
                    <Activity size={19} />
                    ANALYZER STATUS
                  </h3>
                </div>

                {Object.entries(risk?.analyzer_status || {}).map(
                  ([name, status]) => (
                    <div className="analyzer-row" key={name}>
                      <strong>{formatUpper(name)}</strong>
                      <StatusBadge
                        value={status}
                        tone={
                          String(status).includes("risk")
                            ? "high"
                            : severityTone(status)
                        }
                      />
                    </div>
                  )
                )}
              </div>

              <div className="panel">
                <div className="panel-header">
                  <h3>
                    <Paperclip size={19} />
                    ATTACHMENTS
                  </h3>
                </div>

                {attachments.length === 0 ? (
                  <p className="empty">No attachments detected.</p>
                ) : (
                  attachments.map((attachment, index) => (
                    <div className="attachment-row" key={index}>
                      <div>
                        <strong>
                          {attachment.filename || "Unknown file"}
                        </strong>
                        <span>
                          SHA256: {attachment.sha256 || "Unavailable"}
                        </span>
                      </div>
                      <StatusBadge
                        value={attachment.status || "UNKNOWN"}
                        tone="high"
                      />
                    </div>
                  ))
                )}
              </div>
            </section>

            <section className="panel email-panel">
              <div className="panel-header">
                <h3>EMAIL INFORMATION</h3>
              </div>

              <div className="info-table">
                <InfoRow label="File">
                  {result.email?.file || "Unknown"}
                </InfoRow>
                <InfoRow label="Subject">
                  {result.parser?.headers?.subject || "Unknown"}
                </InfoRow>
                <InfoRow label="From">
                  {result.parser?.headers?.from || "Unknown"}
                </InfoRow>
                <InfoRow label="Attachments">
                  {result.parser?.attachments?.count ?? 0}
                </InfoRow>
              </div>
            </section>

            <section className="report-panel">
              <div className="report-panel-copy">
                <FileText size={28} />
                <div>
                  <h3>SECURITY INCIDENT REPORT</h3>
                  <p>
                    Generate a professional PDF security report containing the
                    deterministic analysis, AI assessment, findings and final
                    verdict.
                  </p>
                </div>
              </div>

              <button
                className="btn btn-primary report-button"
                onClick={downloadReport}
                disabled={reportLoading}
                aria-label="Download PDF Report"
              >
                <Download size={19} />
                {reportLoading ? "Generating..." : "Download PDF Report"}
              </button>
            </section>
          </>
        )}

        {!historyDetail && (
          <section className="panel history-panel">
            <div className="panel-header panel-header-actions">
              <h3>
                <FileText size={20} />
                ANALYSIS HISTORY
              </h3>

              <button
                className="btn btn-secondary"
                onClick={loadHistory}
                disabled={historyLoading}
                aria-label="Refresh analysis history"
              >
                <RefreshCw size={16} />
                {historyLoading ? "Loading..." : "Refresh"}
              </button>
            </div>

            {history.length === 0 ? (
              <p className="empty">No analysis history available.</p>
            ) : (
              <div className="history-list">
                {history.map((record) => {
                  const classification = record.classification || "unknown";
                  const historyClass =
                    classification === "phishing"
                      ? "critical"
                      : classification === "suspicious"
                        ? "high"
                        : classification === "low_risk"
                          ? "low"
                          : "safe";

                  return (
                    <article className="history-card" key={record.id}>
                      <div className="history-card-top">
                        <div className="history-main">
                          <strong>
                            {record.original_filename || "Unknown file"}
                          </strong>
                          <span className="history-subject">
                            {record.subject || "No subject"}
                          </span>
                          <small>
                            {record.sender || "Unknown sender"}
                          </small>
                        </div>

                        <StatusBadge
                          value={formatUpper(classification)}
                          tone={historyClass}
                        />
                      </div>

                      <div className="history-card-meta">
                        <div>
                          <span className="field-label">Risk Score</span>
                          <strong>
                            {record.risk_score ?? 0}
                            <span className="muted-inline"> / 100</span>
                          </strong>
                        </div>

                        <div>
                          <span className="field-label">Status</span>
                          <strong>
                            {formatUpper(record.quarantine_status) ||
                              "UNKNOWN"}
                          </strong>
                        </div>
                      </div>

                      <div className="history-card-actions">
                        <button
                          className="btn btn-primary history-view-button"
                          onClick={() => loadHistoryDetail(record.id)}
                          disabled={historyDetailLoading}
                          aria-label={`View details for ${
                            record.original_filename || "analysis"
                          }`}
                        >
                          {historyDetailLoading
                            ? "Loading..."
                            : "View Details"}
                        </button>
                      </div>
                    </article>
                  );
                })}
              </div>
            )}
          </section>
        )}

        {historyDetail && (
          <HistoryDetailPanel
            detail={historyDetail}
            onBack={closeHistoryDetail}
          />
        )}
      </main>

      <footer>
        MailSentinel • Email Security Intrusion Detection & Prevention System
      </footer>
    </div>
  );
}

function AiAnalysisPanel({ ai }) {
  const threatTone = severityTone(ai?.threat_level);
  const confidenceTone = severityTone(ai?.confidence);
  const maliciousTone = ai?.is_malicious ? "critical" : "low";

  return (
    <section className="panel ai-panel">
      <div className="panel-header panel-header-actions">
        <h3>
          <BrainCircuit size={20} />
          AI SECURITY ANALYSIS
        </h3>

        <StatusBadge
          value={formatUpper(ai?.status || "unknown")}
          tone={ai?.status === "completed" ? "low" : "critical"}
        />
      </div>

      <div className="ai-grid">
        <AiVerdictCard
          icon={<Shield size={22} />}
          label="Threat Level"
          value={formatUpper(ai?.threat_level || "UNKNOWN")}
          tone={threatTone}
        />
        <AiVerdictCard
          icon={<Sparkles size={22} />}
          label="AI Confidence"
          value={formatUpper(ai?.confidence || "UNKNOWN")}
          tone={confidenceTone}
        />
        <AiVerdictCard
          icon={<Bug size={22} />}
          label="Malicious"
          value={ai?.is_malicious ? "YES" : "NO"}
          tone={maliciousTone}
        />
      </div>

      <div className="ai-content">
        <div className="ai-block">
          <h4>AI Summary</h4>
          <p>{ai?.summary || "No AI summary available."}</p>
        </div>

        <div className="ai-block">
          <h4>User Explanation</h4>
          <p>{ai?.user_explanation || "No explanation available."}</p>
        </div>

        {Array.isArray(ai?.key_findings) && ai.key_findings.length > 0 && (
          <div className="ai-block">
            <h4>Key Findings</h4>
            <ul className="key-findings">
              {ai.key_findings.map((finding, index) => (
                <li key={index}>{finding}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </section>
  );
}

function HistoryDetailPanel({ detail, onBack }) {
  const risk = detail.risk;
  const ai = detail.ai_analysis;
  const classification = risk?.classification || "unknown";
  const classificationTone = severityTone(classification);
  const analyzerStatus = risk?.analyzer_status || {};
  const analyzerScores = risk?.analyzer_scores || {};
  const findings = risk?.findings || [];
  const urls = detail.analyzers?.url_analyzer?.urls || [];

  const analyzerNames = Array.from(
    new Set([
      ...Object.keys(analyzerStatus),
      ...Object.keys(analyzerScores),
    ])
  );

  return (
    <section className="panel history-detail-panel">
      <div className="panel-header panel-header-actions">
        <h3>
          <FileText size={20} />
          ANALYSIS DETAILS
        </h3>

        <button
          className="btn btn-secondary"
          onClick={onBack}
          aria-label="Back to History"
        >
          <ArrowLeft size={16} />
          Back to History
        </button>
      </div>

      <div className="soc-section">
        <h4 className="soc-section-title">Analysis Overview</h4>
        <div className="info-table">
          <InfoRow label="Analysis ID">
            #{detail.analysis_id}
          </InfoRow>
          <InfoRow label="Classification">
            <StatusBadge
              value={formatUpper(classification)}
              tone={classificationTone}
            />
          </InfoRow>
          <InfoRow label="Risk Score">
            <span className="risk-score-inline">
              {risk?.score ?? 0}
              <span className="muted-inline"> / 100</span>
            </span>
          </InfoRow>
          <InfoRow label="Confidence">
            {risk?.confidence || "Unknown"}
          </InfoRow>
          <InfoRow label="Recommended Action">
            {formatLabel(risk?.recommended_action)}
          </InfoRow>
          <InfoRow label="Security Override">
            {risk?.security_override ? "YES" : "NO"}
          </InfoRow>
        </div>
      </div>

      <div className="soc-section">
        <h4 className="soc-section-title">Email Information</h4>
        <div className="info-table">
          <InfoRow label="File">
            {detail.email?.file || "Unknown"}
          </InfoRow>
          <InfoRow label="Subject">
            {detail.parser?.headers?.subject || "No subject"}
          </InfoRow>
          <InfoRow label="From">
            {detail.parser?.headers?.from || "Unknown"}
          </InfoRow>
          <InfoRow label="To">
            {detail.parser?.headers?.to || "Unknown"}
          </InfoRow>
          <InfoRow label="Reply-To">
            {detail.parser?.headers?.reply_to || "None"}
          </InfoRow>
          <InfoRow label="File Size">
            {detail.email?.size ?? 0} bytes
          </InfoRow>
          <InfoRow label="Attachments">
            {detail.parser?.attachments?.count ?? 0}
          </InfoRow>
        </div>
      </div>

      <div className="soc-section">
        <h4 className="soc-section-title">Analyzer Results</h4>
        {analyzerNames.length === 0 ? (
          <p className="empty">No analyzer results available.</p>
        ) : (
          <div className="analyzer-results">
            {analyzerNames.map((name) => {
              const status = analyzerStatus[name];
              const score = analyzerScores[name];
              return (
                <div className="analyzer-result-row" key={name}>
                  <div>
                    <strong>{formatUpper(name)}</strong>
                    {score != null && (
                      <span className="analyzer-score">Score: {score}</span>
                    )}
                  </div>
                  <StatusBadge
                    value={status ? formatUpper(status) : "N/A"}
                    tone={
                      status
                        ? String(status).includes("risk")
                          ? "high"
                          : severityTone(status)
                        : "info"
                    }
                  />
                </div>
              );
            })}
          </div>
        )}
      </div>

      <div className="soc-section">
        <h4 className="soc-section-title">Security Findings</h4>
        {findings.length ? (
          <div className="findings-list">
            {findings.map((finding, index) => {
              const tone = severityTone(finding.severity);
              return (
                <article className={`finding-card tone-${tone}`} key={index}>
                  <StatusBadge
                    value={formatUpper(finding.severity || "unknown")}
                    tone={tone}
                  />
                  <strong className="finding-name">
                    {finding.indicator || "Security finding"}
                  </strong>
                  <p>
                    {finding.description || "No description available."}
                  </p>
                </article>
              );
            })}
          </div>
        ) : (
          <p className="empty">No security findings recorded.</p>
        )}
      </div>

      <div className="soc-section">
        <h4 className="soc-section-title">AI Security Analysis</h4>
        <div className="ai-grid">
          <AiVerdictCard
            icon={<Shield size={22} />}
            label="Threat Level"
            value={formatUpper(ai?.threat_level || "UNKNOWN")}
            tone={severityTone(ai?.threat_level)}
          />
          <AiVerdictCard
            icon={<Sparkles size={22} />}
            label="AI Confidence"
            value={formatUpper(ai?.confidence || "UNKNOWN")}
            tone={severityTone(ai?.confidence)}
          />
          <AiVerdictCard
            icon={<Bug size={22} />}
            label="Malicious"
            value={ai?.is_malicious ? "YES" : "NO"}
            tone={ai?.is_malicious ? "critical" : "low"}
          />
        </div>

        <div className="ai-content">
          <div className="ai-block">
            <h4>AI Summary</h4>
            <p>{ai?.summary || "No AI summary available."}</p>
          </div>

          {(ai?.user_explanation ||
            (Array.isArray(ai?.key_findings) &&
              ai.key_findings.length > 0)) && (
            <>
              {ai?.user_explanation && (
                <div className="ai-block">
                  <h4>User Explanation</h4>
                  <p>{ai.user_explanation}</p>
                </div>
              )}

              {Array.isArray(ai?.key_findings) &&
                ai.key_findings.length > 0 && (
                  <div className="ai-block">
                    <h4>Key Findings</h4>
                    <ul className="key-findings">
                      {ai.key_findings.map((finding, index) => (
                        <li key={index}>{finding}</li>
                      ))}
                    </ul>
                  </div>
                )}
            </>
          )}
        </div>
      </div>

      <div className="soc-section">
        <h4 className="soc-section-title">Quarantine Status</h4>
        <div className="info-table">
          <InfoRow label="Status">
            <StatusBadge
              value={formatUpper(detail.quarantine?.status || "Unknown")}
              tone={severityTone(detail.quarantine?.status)}
            />
          </InfoRow>
          <InfoRow label="Reason">
            {detail.quarantine?.reason ||
              "No quarantine reason recorded."}
          </InfoRow>
          {detail.quarantine?.quarantine_id && (
            <InfoRow label="Quarantine ID">
              {detail.quarantine.quarantine_id}
            </InfoRow>
          )}
        </div>
      </div>

      <div className="soc-section">
        <h4 className="soc-section-title">
          <Link2 size={16} />
          URL Analysis
        </h4>
        {urls.length ? (
          <div className="findings-list">
            {urls.map((item, index) => (
              <article className="finding-card" key={index}>
                <StatusBadge
                  value={formatUpper(item.status || "unknown")}
                  tone={severityTone(item.status)}
                />
                <strong className="finding-name">{item.url}</strong>
                <p>Domain: {item.hostname || "Unknown"}</p>
              </article>
            ))}
          </div>
        ) : (
          <p className="empty">No URLs recorded.</p>
        )}
      </div>
    </section>
  );
}

function AiVerdictCard({ icon, label, value, tone = "info" }) {
  return (
    <div className={`ai-verdict-card tone-${tone}`}>
      <div className="ai-verdict-icon" aria-hidden="true">
        {icon}
      </div>
      <span className="ai-verdict-label">{label}</span>
      <strong className="ai-verdict-value">{value}</strong>
    </div>
  );
}

function InfoRow({ label, children }) {
  return (
    <div className="info-row">
      <span className="info-label">{label}</span>
      <div className="info-value">{children}</div>
    </div>
  );
}

function StatusBadge({ value, tone = "info" }) {
  return <span className={`status-badge tone-${tone}`}>{value}</span>;
}

function Stat({ title, value }) {
  return (
    <div className="stat">
      <span className="field-label">{title}</span>
      <strong>{value}</strong>
    </div>
  );
}

export default App;

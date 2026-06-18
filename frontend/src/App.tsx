import { ChangeEvent, FormEvent, useMemo, useState } from "react";
import type { ReactNode } from "react";
import {
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  Database,
  Download,
  FileJson,
  FolderSearch,
  GitBranch,
  ListChecks,
  Play,
  RotateCcw,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  TableProperties,
  Timer,
  Upload,
} from "lucide-react";

type ScanMode = "single_repo" | "local_schema" | "batch_seed" | "delta_recrawl";
type PolicyMode = "research_mode" | "warn_mode" | "strict_mode" | "enterprise_mode" | "benchmark_mode";
type ActivePage =
  | "launcher"
  | "overview"
  | "inventory"
  | "finding"
  | "evidence"
  | "graph"
  | "sandbox"
  | "evaluation"
  | "report";
type PolicyDecision = "allow" | "warn" | "quarantine" | "block";
type FindingSeverity = "critical" | "high" | "medium" | "low";
type SeverityFilter = FindingSeverity | "all";
type SourceTrust = "trusted" | "unverified" | "external";
type SourceTrustFilter = SourceTrust | "all";
type FindingType = "prompt_injection_candidate" | "permission_overreach" | "credential_reference";
type FindingTypeFilter = FindingType | "all";
type ArtifactType = "readme" | "schema" | "docs" | "manifest";
type ArtifactTypeFilter = ArtifactType | "all";
type GraphNodeKind = "repo" | "tool" | "capability" | "env_var" | "domain" | "finding";

type ScanOverview = {
  runId: string;
  sourceName: string;
  sourceType: string;
  scanStatus: "completed";
  riskScore: number;
  artifactCount: number;
  toolCount: number;
  findingCount: number;
  severityCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  topRecommendations: string[];
};

type ToolInventoryItem = {
  toolName: string;
  source: string;
  declaredPurpose: string;
  detectedCapabilities: string[];
  riskScore: number;
  policyDecision: PolicyDecision;
  findingCount: number;
  lastScanned: string;
};

type FindingDetail = {
  findingType: string;
  severity: FindingSeverity;
  confidence: number;
  triggeredRule: string;
  evidenceText: string;
  artifactPath: string;
  lineRange: string;
  recommendation: string;
  policyDecision: PolicyDecision;
};

type EvidenceRecord = {
  evidenceId: string;
  sourceTrust: SourceTrust;
  findingType: FindingType;
  artifactType: ArtifactType;
  artifactPath: string;
  lineRange: string;
  highlightedSpan: string;
  originalContext: string;
};

type GraphNode = {
  id: string;
  label: string;
  kind: GraphNodeKind;
  severity?: FindingSeverity;
  evidenceId?: string;
  description: string;
};

type GraphEdge = {
  from: string;
  to: string;
  label: string;
};

type ToolRiskGraph = {
  nodes: GraphNode[];
  edges: GraphEdge[];
};

type SandboxActionStatus = "allowed" | "warned" | "blocked";

type SandboxTraceStep = {
  stepId: string;
  timestamp: string;
  actor: string;
  toolName: string;
  action: string;
  policyDecision: PolicyDecision;
  status: SandboxActionStatus;
  rationale: string;
};

type PolicyDecisionRecord = {
  label: string;
  decision: PolicyDecision;
  rationale: string;
};

type SandboxTrace = {
  taskDescription: string;
  toolMetadataShown: string[];
  actionTrace: SandboxTraceStep[];
  policyDecisions: PolicyDecisionRecord[];
  blockedUnsafeActions: string[];
  finalOutcome: string;
};

type RateMetric = {
  label: string;
  value: number;
  target: string;
};

type DetectorMetric = {
  label: string;
  precision: number;
  recall: number;
};

type DistributionMetric = {
  label: string;
  value: number;
  className?: string;
};

type EvaluationDashboard = {
  runLabel: string;
  sampleCount: number;
  policyModeLabel: string;
  rateMetrics: RateMetric[];
  detectorPrecisionRecall: DetectorMetric[];
  riskDistribution: DistributionMetric[];
  latencyDistribution: DistributionMetric[];
};

const graphColumns: Array<{ kind: GraphNodeKind; label: string }> = [
  { kind: "repo", label: "Repo" },
  { kind: "tool", label: "Tools" },
  { kind: "capability", label: "Capabilities" },
  { kind: "env_var", label: "Env vars" },
  { kind: "domain", label: "Domains" },
  { kind: "finding", label: "Findings" },
];

const scanModes: Array<{ value: ScanMode; label: string }> = [
  { value: "single_repo", label: "Single repo" },
  { value: "local_schema", label: "Local schema" },
  { value: "batch_seed", label: "Batch seed" },
  { value: "delta_recrawl", label: "Delta recrawl" },
];

const policyModes: Array<{ value: PolicyMode; label: string }> = [
  { value: "research_mode", label: "Research" },
  { value: "warn_mode", label: "Warn" },
  { value: "strict_mode", label: "Strict" },
  { value: "enterprise_mode", label: "Enterprise" },
  { value: "benchmark_mode", label: "Benchmark" },
];

function App() {
  const [activePage, setActivePage] = useState<ActivePage>("launcher");
  const [repoUrl, setRepoUrl] = useState("");
  const [schemaFile, setSchemaFile] = useState<File | null>(null);
  const [scanMode, setScanMode] = useState<ScanMode>("single_repo");
  const [policyMode, setPolicyMode] = useState<PolicyMode>("strict_mode");
  const [crawlerDepth, setCrawlerDepth] = useState(2);
  const [formError, setFormError] = useState("");
  const [queuedRunId, setQueuedRunId] = useState("");
  const [scanOverview, setScanOverview] = useState<ScanOverview | null>(null);
  const [toolInventory, setToolInventory] = useState<ToolInventoryItem[]>([]);
  const [findingDetail, setFindingDetail] = useState<FindingDetail | null>(null);
  const [evidenceRecords, setEvidenceRecords] = useState<EvidenceRecord[]>([]);
  const [evidenceSearch, setEvidenceSearch] = useState("");
  const [sourceTrustFilter, setSourceTrustFilter] = useState<SourceTrustFilter>("all");
  const [findingTypeFilter, setFindingTypeFilter] = useState<FindingTypeFilter>("all");
  const [artifactTypeFilter, setArtifactTypeFilter] = useState<ArtifactTypeFilter>("all");
  const [toolRiskGraph, setToolRiskGraph] = useState<ToolRiskGraph | null>(null);
  const [selectedGraphNodeId, setSelectedGraphNodeId] = useState("");
  const [graphSeverityFilter, setGraphSeverityFilter] = useState<SeverityFilter>("all");
  const [sandboxTrace, setSandboxTrace] = useState<SandboxTrace | null>(null);
  const [evaluationDashboard, setEvaluationDashboard] = useState<EvaluationDashboard | null>(null);

  const selectedScanMode = useMemo(() => scanModes.find((mode) => mode.value === scanMode), [scanMode]);
  const selectedPolicyMode = useMemo(() => policyModes.find((mode) => mode.value === policyMode), [policyMode]);
  const pageTitle =
    activePage === "launcher"
      ? "Scan Launcher"
      : activePage === "overview"
        ? "Scan Overview"
        : activePage === "inventory"
          ? "Tool Inventory"
        : activePage === "finding"
          ? "Finding Detail"
          : activePage === "evidence"
            ? "Evidence Explorer"
            : activePage === "graph"
              ? "Tool-Risk Graph"
              : activePage === "sandbox"
                ? "Sandbox Trace"
                : activePage === "evaluation"
                  ? "Evaluation Dashboard"
                  : "Report View";

  function handleFileChange(event: ChangeEvent<HTMLInputElement>) {
    setSchemaFile(event.target.files?.[0] ?? null);
    setQueuedRunId("");
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const trimmedRepoUrl = repoUrl.trim();

    if (!trimmedRepoUrl && !schemaFile) {
      setFormError("Add a repository URL or local schema file.");
      setQueuedRunId("");
      return;
    }
    if (trimmedRepoUrl && !trimmedRepoUrl.startsWith("https://github.com/")) {
      setFormError("Repository URL must start with https://github.com/.");
      setQueuedRunId("");
      return;
    }

    setFormError("");
    const runId = `scan_${Date.now().toString(36)}`;
    const overview = buildScanOverview(runId, trimmedRepoUrl, schemaFile, scanMode, policyMode, crawlerDepth);
    setQueuedRunId(runId);
    setScanOverview(overview);
    setToolInventory(buildToolInventory(trimmedRepoUrl, schemaFile, scanMode, policyMode, crawlerDepth));
    setFindingDetail(buildFindingDetail(trimmedRepoUrl, schemaFile, scanMode, policyMode, crawlerDepth));
    setEvidenceRecords(buildEvidenceRecords(trimmedRepoUrl, schemaFile, scanMode));
    setEvidenceSearch("");
    setSourceTrustFilter("all");
    setFindingTypeFilter("all");
    setArtifactTypeFilter("all");
    const graph = buildToolRiskGraph(trimmedRepoUrl, schemaFile, scanMode, policyMode, crawlerDepth);
    setToolRiskGraph(graph);
    setSelectedGraphNodeId(graph.nodes[0]?.id ?? "");
    setGraphSeverityFilter("all");
    setSandboxTrace(buildSandboxTrace(trimmedRepoUrl, schemaFile, scanMode, policyMode, crawlerDepth));
    setEvaluationDashboard(buildEvaluationDashboard(trimmedRepoUrl, schemaFile, scanMode, policyMode, crawlerDepth));
    setActivePage("overview");
  }

  function resetForm() {
    setRepoUrl("");
    setSchemaFile(null);
    setScanMode("single_repo");
    setPolicyMode("strict_mode");
    setCrawlerDepth(2);
    setFormError("");
    setQueuedRunId("");
    setScanOverview(null);
    setToolInventory([]);
    setFindingDetail(null);
    setEvidenceRecords([]);
    setEvidenceSearch("");
    setSourceTrustFilter("all");
    setFindingTypeFilter("all");
    setArtifactTypeFilter("all");
    setToolRiskGraph(null);
    setSelectedGraphNodeId("");
    setGraphSeverityFilter("all");
    setSandboxTrace(null);
    setEvaluationDashboard(null);
    setActivePage("launcher");
  }

  return (
    <main className="app-shell min-h-screen">
      <section className="launcher">
        <div className="title-row">
          <div>
            <p className="eyebrow">AgentSupplyShield</p>
            <h1>{pageTitle}</h1>
          </div>
          <div className="status-pill" aria-label="Backend connection status">
            <span className="status-dot" />
            Local API
          </div>
        </div>

        <div className="page-switcher" aria-label="Dashboard pages">
          <button
            type="button"
            className={activePage === "launcher" ? "page-tab active" : "page-tab"}
            aria-pressed={activePage === "launcher"}
            onClick={() => setActivePage("launcher")}
          >
            <Play size={17} aria-hidden="true" />
            Launch
          </button>
          <button
            type="button"
            className={activePage === "overview" ? "page-tab active" : "page-tab"}
            aria-pressed={activePage === "overview"}
            onClick={() => setActivePage("overview")}
            disabled={!scanOverview}
          >
            <BarChart3 size={17} aria-hidden="true" />
            Overview
          </button>
          <button
            type="button"
            className={activePage === "inventory" ? "page-tab active" : "page-tab"}
            aria-pressed={activePage === "inventory"}
            onClick={() => setActivePage("inventory")}
            disabled={toolInventory.length === 0}
          >
            <TableProperties size={17} aria-hidden="true" />
            Inventory
          </button>
          <button
            type="button"
            className={activePage === "finding" ? "page-tab active" : "page-tab"}
            aria-pressed={activePage === "finding"}
            onClick={() => setActivePage("finding")}
            disabled={!findingDetail}
          >
            <AlertTriangle size={17} aria-hidden="true" />
            Finding
          </button>
          <button
            type="button"
            className={activePage === "evidence" ? "page-tab active" : "page-tab"}
            aria-pressed={activePage === "evidence"}
            onClick={() => setActivePage("evidence")}
            disabled={evidenceRecords.length === 0}
          >
            <Search size={17} aria-hidden="true" />
            Evidence
          </button>
          <button
            type="button"
            className={activePage === "graph" ? "page-tab active" : "page-tab"}
            aria-pressed={activePage === "graph"}
            onClick={() => setActivePage("graph")}
            disabled={!toolRiskGraph}
          >
            <GitBranch size={17} aria-hidden="true" />
            Graph
          </button>
          <button
            type="button"
            className={activePage === "sandbox" ? "page-tab active" : "page-tab"}
            aria-pressed={activePage === "sandbox"}
            onClick={() => setActivePage("sandbox")}
            disabled={!sandboxTrace}
          >
            <ShieldCheck size={17} aria-hidden="true" />
            Sandbox
          </button>
          <button
            type="button"
            className={activePage === "evaluation" ? "page-tab active" : "page-tab"}
            aria-pressed={activePage === "evaluation"}
            onClick={() => setActivePage("evaluation")}
            disabled={!evaluationDashboard}
          >
            <SlidersHorizontal size={17} aria-hidden="true" />
            Evaluate
          </button>
          <button
            type="button"
            className={activePage === "report" ? "page-tab active" : "page-tab"}
            aria-pressed={activePage === "report"}
            onClick={() => setActivePage("report")}
            disabled={!scanOverview || !findingDetail || toolInventory.length === 0 || evidenceRecords.length === 0 || !toolRiskGraph || !sandboxTrace}
          >
            <FileJson size={17} aria-hidden="true" />
            Report
          </button>
        </div>

        {activePage === "overview" && scanOverview ? (
          <ScanOverviewPage overview={scanOverview} />
        ) : activePage === "inventory" && toolInventory.length > 0 ? (
          <ToolInventoryPage tools={toolInventory} />
        ) : activePage === "finding" && findingDetail ? (
          <FindingDetailPage finding={findingDetail} />
        ) : activePage === "evidence" && evidenceRecords.length > 0 ? (
          <EvidenceExplorerPage
            records={evidenceRecords}
            searchQuery={evidenceSearch}
            sourceTrustFilter={sourceTrustFilter}
            findingTypeFilter={findingTypeFilter}
            artifactTypeFilter={artifactTypeFilter}
            onSearchQueryChange={setEvidenceSearch}
            onSourceTrustFilterChange={setSourceTrustFilter}
            onFindingTypeFilterChange={setFindingTypeFilter}
            onArtifactTypeFilterChange={setArtifactTypeFilter}
          />
        ) : activePage === "graph" && toolRiskGraph ? (
          <ToolRiskGraphPage
            graph={toolRiskGraph}
            evidenceRecords={evidenceRecords}
            selectedNodeId={selectedGraphNodeId}
            severityFilter={graphSeverityFilter}
            onSelectedNodeChange={setSelectedGraphNodeId}
            onSeverityFilterChange={setGraphSeverityFilter}
          />
        ) : activePage === "sandbox" && sandboxTrace ? (
          <SandboxTracePage trace={sandboxTrace} />
        ) : activePage === "evaluation" && evaluationDashboard ? (
          <EvaluationDashboardPage dashboard={evaluationDashboard} />
        ) : activePage === "report" && scanOverview && findingDetail && toolRiskGraph && sandboxTrace ? (
          <ReportViewPage
            overview={scanOverview}
            tools={toolInventory}
            finding={findingDetail}
            graph={toolRiskGraph}
            sandboxTrace={sandboxTrace}
            recommendations={scanOverview.topRecommendations}
            evidenceRecords={evidenceRecords}
          />
        ) : (
        <form className="launcher-grid" onSubmit={handleSubmit}>
          <section className="input-panel" aria-labelledby="source-heading">
            <div className="section-heading">
              <FolderSearch size={20} aria-hidden="true" />
              <h2 id="source-heading">Source</h2>
            </div>

            <label className="field">
              <span>Repo URL</span>
              <div className="input-with-icon">
                <GitBranch size={18} aria-hidden="true" />
                <input
                  type="url"
                  value={repoUrl}
                  onChange={(event) => {
                    setRepoUrl(event.target.value);
                    setQueuedRunId("");
                  }}
                  placeholder="https://github.com/owner/repository"
                />
              </div>
            </label>

            <label className="upload-zone">
              <Upload size={20} aria-hidden="true" />
              <span>{schemaFile ? schemaFile.name : "Local schema upload"}</span>
              <input type="file" accept=".json,.yaml,.yml" onChange={handleFileChange} />
            </label>

            <label className="field">
              <span>Scan mode</span>
              <div className="segmented-control" role="radiogroup" aria-label="Scan mode">
                {scanModes.map((mode) => (
                  <button
                    key={mode.value}
                    type="button"
                    className={scanMode === mode.value ? "segment active" : "segment"}
                    aria-pressed={scanMode === mode.value}
                    onClick={() => {
                      setScanMode(mode.value);
                      setQueuedRunId("");
                    }}
                  >
                    {mode.label}
                  </button>
                ))}
              </div>
            </label>
          </section>

          <section className="input-panel" aria-labelledby="policy-heading">
            <div className="section-heading">
              <ShieldCheck size={20} aria-hidden="true" />
              <h2 id="policy-heading">Controls</h2>
            </div>

            <label className="field">
              <span>Policy mode</span>
              <select
                value={policyMode}
                onChange={(event) => {
                  setPolicyMode(event.target.value as PolicyMode);
                  setQueuedRunId("");
                }}
              >
                {policyModes.map((mode) => (
                  <option key={mode.value} value={mode.value}>
                    {mode.label}
                  </option>
                ))}
              </select>
            </label>

            <label className="field">
              <span>Crawler depth</span>
              <div className="range-row">
                <SlidersHorizontal size={18} aria-hidden="true" />
                <input
                  type="range"
                  min="1"
                  max="3"
                  step="1"
                  value={crawlerDepth}
                  onChange={(event) => {
                    setCrawlerDepth(Number(event.target.value));
                    setQueuedRunId("");
                  }}
                />
                <output>{crawlerDepth}</output>
              </div>
            </label>

            <div className="summary-strip" aria-label="Selected scan settings">
              <div>
                <Database size={18} aria-hidden="true" />
                <span>{selectedScanMode?.label}</span>
              </div>
              <div>
                <FileJson size={18} aria-hidden="true" />
                <span>{selectedPolicyMode?.label}</span>
              </div>
            </div>

            {formError && (
              <div className="message error" role="alert">
                <AlertTriangle size={18} aria-hidden="true" />
                <span>{formError}</span>
              </div>
            )}
            {queuedRunId && (
              <div className="message success" role="status">
                <ShieldCheck size={18} aria-hidden="true" />
                <span>{queuedRunId}</span>
              </div>
            )}

            <div className="action-row">
              <button type="button" className="secondary-button" onClick={resetForm} aria-label="Reset scan form">
                <RotateCcw size={18} aria-hidden="true" />
              </button>
              <button type="submit" className="primary-button">
                <Play size={18} aria-hidden="true" />
                <span>Start Scan</span>
              </button>
            </div>
          </section>
        </form>
        )}
      </section>
    </main>
  );
}

function ReportViewPage({
  overview,
  tools,
  finding,
  graph,
  sandboxTrace,
  recommendations,
  evidenceRecords,
}: {
  overview: ScanOverview;
  tools: ToolInventoryItem[];
  finding: FindingDetail;
  graph: ToolRiskGraph;
  sandboxTrace: SandboxTrace;
  recommendations: string[];
  evidenceRecords: EvidenceRecord[];
}) {
  const graphFindings = graph.nodes.filter((node) => node.kind === "finding");
  const highRiskTools = tools.filter((tool) => tool.riskScore >= 60);
  const reportFileBase = `agentsupplyshield-${overview.runId}`;

  function handleExportJson() {
    const reportJson = buildReportJson(overview, tools, finding, graph, sandboxTrace, recommendations, evidenceRecords);
    downloadReportArtifact(`${reportFileBase}.json`, JSON.stringify(reportJson, null, 2), "application/json");
  }

  function handleExportMarkdown() {
    const reportMarkdown = buildReportMarkdown(overview, tools, finding, graph, sandboxTrace, recommendations, evidenceRecords);
    downloadReportArtifact(`${reportFileBase}.md`, reportMarkdown, "text/markdown");
  }

  return (
    <section className="report-view-grid" aria-labelledby="report-heading">
      <section className="report-hero" aria-label="Executive summary">
        <div>
          <div className="section-heading">
            <FileJson size={20} aria-hidden="true" />
            <h2 id="report-heading">Executive summary</h2>
          </div>
          <p>
            {overview.sourceName} completed with risk score {overview.riskScore}/100, {overview.findingCount} findings,
            and {sandboxTrace.blockedUnsafeActions.length} blocked sandbox actions.
          </p>
        </div>
        <div className="report-export-actions" aria-label="Download and export buttons">
          <button type="button" onClick={handleExportJson}>
            <Download size={17} aria-hidden="true" />
            JSON
          </button>
          <button type="button" onClick={handleExportMarkdown}>
            <Download size={17} aria-hidden="true" />
            Markdown
          </button>
        </div>
      </section>

      <section className="report-panel report-summary-panel" aria-label="Report summary">
        <div className="report-summary-grid">
          <div>
            <span>Risk score</span>
            <strong>{overview.riskScore}/100</strong>
          </div>
          <div>
            <span>Policy decision</span>
            <strong>{finding.policyDecision}</strong>
          </div>
          <div>
            <span>Tools reviewed</span>
            <strong>{tools.length}</strong>
          </div>
          <div>
            <span>Evidence spans</span>
            <strong>{evidenceRecords.length}</strong>
          </div>
        </div>
      </section>

      <section className="report-panel" aria-label="Findings">
        <div className="report-panel-header">
          <div className="section-heading">
            <AlertTriangle size={20} aria-hidden="true" />
            <h2>Findings</h2>
          </div>
          <span className={`severity-badge ${finding.severity}`}>{finding.severity}</span>
        </div>
        <dl className="report-detail-list">
          <div>
            <dt>Finding type</dt>
            <dd>{finding.findingType}</dd>
          </div>
          <div>
            <dt>Triggered rule</dt>
            <dd>{finding.triggeredRule}</dd>
          </div>
          <div>
            <dt>Evidence</dt>
            <dd>{finding.evidenceText}</dd>
          </div>
          <div>
            <dt>Location</dt>
            <dd>
              {finding.artifactPath} lines {finding.lineRange}
            </dd>
          </div>
        </dl>
      </section>

      <section className="report-panel" aria-label="Tool inventory">
        <div className="section-heading">
          <TableProperties size={20} aria-hidden="true" />
          <h2>Tool inventory</h2>
        </div>
        <div className="report-tool-list">
          {tools.map((tool) => (
            <div key={`${tool.source}-${tool.toolName}`} className="report-tool-row">
              <div>
                <strong>{tool.toolName}</strong>
                <span>{tool.declaredPurpose}</span>
              </div>
              <span className={`policy-badge ${tool.policyDecision}`}>{tool.policyDecision}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="report-panel" aria-label="Risk graph">
        <div className="section-heading">
          <GitBranch size={20} aria-hidden="true" />
          <h2>Risk graph</h2>
        </div>
        <div className="report-graph-stats">
          <span>{graph.nodes.length} nodes</span>
          <span>{graph.edges.length} edges</span>
          <span>{graphFindings.length} finding nodes</span>
        </div>
        <div className="report-graph-chip-list">
          {graphFindings.map((node) => (
            <span key={node.id}>{node.label}</span>
          ))}
        </div>
      </section>

      <section className="report-panel" aria-label="Sandbox result">
        <div className="section-heading">
          <ShieldCheck size={20} aria-hidden="true" />
          <h2>Sandbox result</h2>
        </div>
        <p className="report-panel-copy">{sandboxTrace.finalOutcome}</p>
        <ul className="report-blocked-list">
          {sandboxTrace.blockedUnsafeActions.map((action) => (
            <li key={action}>{action}</li>
          ))}
        </ul>
      </section>

      <section className="report-panel" aria-label="Recommendations">
        <div className="section-heading">
          <ListChecks size={20} aria-hidden="true" />
          <h2>Recommendations</h2>
        </div>
        <ul className="report-recommendation-list">
          {recommendations.map((recommendation) => (
            <li key={recommendation}>{recommendation}</li>
          ))}
          {highRiskTools.length > 0 && <li>Prioritize manual review for {highRiskTools.length} high-risk tools.</li>}
        </ul>
      </section>

      <section className="report-panel report-evidence-panel" aria-label="Evidence appendix">
        <div className="section-heading">
          <Database size={20} aria-hidden="true" />
          <h2>Evidence appendix</h2>
        </div>
        <div className="report-evidence-list">
          {evidenceRecords.map((record) => (
            <article key={record.evidenceId} className="report-evidence-row">
              <div>
                <strong>{record.evidenceId}</strong>
                <span>
                  {record.artifactPath} lines {record.lineRange}
                </span>
              </div>
              <mark>{record.highlightedSpan}</mark>
            </article>
          ))}
        </div>
      </section>
    </section>
  );
}

function EvaluationDashboardPage({ dashboard }: { dashboard: EvaluationDashboard }) {
  const maxRiskCount = Math.max(...dashboard.riskDistribution.map((bucket) => bucket.value), 1);
  const maxLatencyCount = Math.max(...dashboard.latencyDistribution.map((bucket) => bucket.value), 1);

  return (
    <section className="evaluation-dashboard-grid" aria-labelledby="evaluation-heading">
      <section className="evaluation-hero" aria-label="Evaluation run summary">
        <div className="section-heading">
          <BarChart3 size={20} aria-hidden="true" />
          <h2 id="evaluation-heading">Evaluation run</h2>
        </div>
        <div className="evaluation-run-summary">
          <span>{dashboard.runLabel}</span>
          <span>{dashboard.sampleCount} samples</span>
          <span>{dashboard.policyModeLabel}</span>
        </div>
      </section>

      <section className="evaluation-rate-grid" aria-label="Sandbox evaluation rate charts">
        {dashboard.rateMetrics.map((metric) => (
          <article key={metric.label} className={`evaluation-rate-card ${rateMetricClass(metric.label)}`}>
            <div>
              <span>{metric.label}</span>
              <strong>{metric.value}%</strong>
            </div>
            <div className="evaluation-rate-meter" aria-hidden="true">
              <span style={{ width: `${metric.value}%` }} />
            </div>
            <small>{metric.target}</small>
          </article>
        ))}
      </section>

      <section className="evaluation-panel detector-panel" aria-label="Detector precision and recall chart">
        <div className="section-heading">
          <Search size={20} aria-hidden="true" />
          <h2>Detector precision/recall</h2>
        </div>
        <div className="detector-chart">
          {dashboard.detectorPrecisionRecall.map((metric) => (
            <article key={metric.label} className="detector-row">
              <span>{metric.label}</span>
              <div className="detector-bars">
                <div>
                  <small>Precision {metric.precision}%</small>
                  <span className="precision-bar" style={{ width: `${metric.precision}%` }} />
                </div>
                <div>
                  <small>Recall {metric.recall}%</small>
                  <span className="recall-bar" style={{ width: `${metric.recall}%` }} />
                </div>
              </div>
            </article>
          ))}
        </div>
      </section>

      <section className="evaluation-panel" aria-label="Risk distribution chart">
        <div className="section-heading">
          <AlertTriangle size={20} aria-hidden="true" />
          <h2>Risk distribution</h2>
        </div>
        <div className="distribution-chart">
          {dashboard.riskDistribution.map((bucket) => (
            <div key={bucket.label} className={`distribution-row ${bucket.className ?? ""}`.trim()}>
              <span>{bucket.label}</span>
              <div className="distribution-meter" aria-hidden="true">
                <span style={{ width: `${Math.round((bucket.value / maxRiskCount) * 100)}%` }} />
              </div>
              <strong>{bucket.value}</strong>
            </div>
          ))}
        </div>
      </section>

      <section className="evaluation-panel latency-panel" aria-label="Latency distribution chart">
        <div className="section-heading">
          <Timer size={20} aria-hidden="true" />
          <h2>Latency distribution</h2>
        </div>
        <div className="distribution-chart">
          {dashboard.latencyDistribution.map((bucket) => (
            <div key={bucket.label} className="distribution-row latency">
              <span>{bucket.label}</span>
              <div className="distribution-meter" aria-hidden="true">
                <span style={{ width: `${Math.round((bucket.value / maxLatencyCount) * 100)}%` }} />
              </div>
              <strong>{bucket.value}</strong>
            </div>
          ))}
        </div>
      </section>
    </section>
  );
}

function SandboxTracePage({ trace }: { trace: SandboxTrace }) {
  return (
    <section className="sandbox-trace-grid" aria-labelledby="sandbox-heading">
      <section className="sandbox-panel sandbox-task" aria-label="Task description">
        <div className="section-heading">
          <ShieldCheck size={20} aria-hidden="true" />
          <h2 id="sandbox-heading">Task description</h2>
        </div>
        <p>{trace.taskDescription}</p>
      </section>

      <section className="sandbox-panel" aria-label="Tool metadata shown to agent">
        <div className="section-heading">
          <Database size={20} aria-hidden="true" />
          <h2>Tool metadata shown to agent</h2>
        </div>
        <ul className="sandbox-metadata-list">
          {trace.toolMetadataShown.map((metadata) => (
            <li key={metadata}>{metadata}</li>
          ))}
        </ul>
      </section>

      <section className="sandbox-panel sandbox-trace-panel" aria-label="Agent action trace">
        <div className="section-heading">
          <Timer size={20} aria-hidden="true" />
          <h2>Agent action trace</h2>
        </div>
        <div className="sandbox-action-list">
          {trace.actionTrace.map((step) => (
            <article key={step.stepId} className="sandbox-action-card">
              <div className="sandbox-action-header">
                <div>
                  <span className="trace-time">{step.timestamp}</span>
                  <h3>{step.action}</h3>
                </div>
                <span className={`trace-status ${step.status}`}>{step.status}</span>
              </div>
              <div className="sandbox-action-meta">
                <span>{step.actor}</span>
                <span>{step.toolName}</span>
                <span className={`policy-badge ${step.policyDecision}`}>{step.policyDecision}</span>
              </div>
              <p>{step.rationale}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="sandbox-panel" aria-label="Policy decisions">
        <div className="section-heading">
          <ListChecks size={20} aria-hidden="true" />
          <h2>Policy decisions</h2>
        </div>
        <div className="sandbox-policy-list">
          {trace.policyDecisions.map((decision) => (
            <article key={decision.label} className="sandbox-policy-card">
              <div>
                <strong>{decision.label}</strong>
                <p>{decision.rationale}</p>
              </div>
              <span className={`policy-badge ${decision.decision}`}>{decision.decision}</span>
            </article>
          ))}
        </div>
      </section>

      <section className="sandbox-panel" aria-label="Blocked unsafe actions">
        <div className="section-heading">
          <AlertTriangle size={20} aria-hidden="true" />
          <h2>Blocked unsafe actions</h2>
        </div>
        <ul className="sandbox-block-list">
          {trace.blockedUnsafeActions.map((action) => (
            <li key={action}>{action}</li>
          ))}
        </ul>
      </section>

      <section className="sandbox-panel sandbox-outcome" aria-label="Final outcome">
        <div className="sandbox-outcome-header">
          <div className="section-heading">
            <CheckCircle2 size={20} aria-hidden="true" />
            <h2>Final outcome</h2>
          </div>
          <span className="trace-status allowed">completed</span>
        </div>
        <p>{trace.finalOutcome}</p>
      </section>
    </section>
  );
}

function ToolRiskGraphPage({
  graph,
  evidenceRecords,
  selectedNodeId,
  severityFilter,
  onSelectedNodeChange,
  onSeverityFilterChange,
}: {
  graph: ToolRiskGraph;
  evidenceRecords: EvidenceRecord[];
  selectedNodeId: string;
  severityFilter: SeverityFilter;
  onSelectedNodeChange: (nodeId: string) => void;
  onSeverityFilterChange: (value: SeverityFilter) => void;
}) {
  const visibleGraph = useMemo(() => filterGraphBySeverity(graph, severityFilter), [graph, severityFilter]);
  const activeNode =
    visibleGraph.nodes.find((node) => node.id === selectedNodeId) ?? visibleGraph.nodes[0] ?? graph.nodes[0];
  const neighborhoodIds = useMemo(
    () => new Set(activeNode ? graph.edges.filter((edge) => edge.from === activeNode.id || edge.to === activeNode.id).flatMap((edge) => [edge.from, edge.to]) : []),
    [activeNode, graph.edges],
  );
  const connectedNodes = activeNode
    ? graph.edges
        .filter((edge) => edge.from === activeNode.id || edge.to === activeNode.id)
        .map((edge) => graph.nodes.find((node) => node.id === (edge.from === activeNode.id ? edge.to : edge.from)))
        .filter((node): node is GraphNode => Boolean(node))
    : [];
  const selectedEvidence = activeNode?.evidenceId
    ? evidenceRecords.find((record) => record.evidenceId === activeNode.evidenceId)
    : undefined;

  return (
    <section className="tool-graph-grid" aria-labelledby="graph-heading">
      <section className="graph-canvas-panel" aria-label="Tool-risk graph">
        <div className="inventory-header">
          <div className="section-heading">
            <GitBranch size={20} aria-hidden="true" />
            <h2 id="graph-heading">Tool-risk graph</h2>
          </div>
          <label className="graph-filter">
            <span>Severity</span>
            <select value={severityFilter} onChange={(event) => onSeverityFilterChange(event.target.value as SeverityFilter)}>
              <option value="all">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </label>
        </div>

        <div className="graph-columns" aria-label="Repo to findings graph">
          {graphColumns.map((column) => {
            const columnNodes = visibleGraph.nodes.filter((node) => node.kind === column.kind);

            return (
              <section key={column.kind} className="graph-column" aria-label={column.label}>
                <h3>{column.label}</h3>
                <div className="graph-node-stack">
                  {columnNodes.map((node) => (
                    <button
                      key={node.id}
                      type="button"
                      className={[
                        "graph-node",
                        node.kind,
                        node.severity ?? "",
                        activeNode?.id === node.id ? "selected" : "",
                        neighborhoodIds.has(node.id) ? "neighbor" : "",
                      ]
                        .filter(Boolean)
                        .join(" ")}
                      onClick={() => onSelectedNodeChange(node.id)}
                      aria-pressed={activeNode?.id === node.id}
                    >
                      <span>{node.label}</span>
                      <small>{formatToken(node.kind)}</small>
                    </button>
                  ))}
                  {columnNodes.length === 0 && <div className="graph-empty-column">No matching nodes</div>}
                </div>
              </section>
            );
          })}
        </div>

        <div className="graph-edge-list" aria-label="Visible graph relationships">
          {visibleGraph.edges.map((edge) => {
            const fromNode = graph.nodes.find((node) => node.id === edge.from);
            const toNode = graph.nodes.find((node) => node.id === edge.to);

            return (
              <span key={`${edge.from}-${edge.to}`}>
                {fromNode?.label} / {edge.label} / {toNode?.label}
              </span>
            );
          })}
        </div>
      </section>

      <aside className="graph-detail-panel" aria-label="Selected graph node details">
        {activeNode ? (
          <>
            <div className="graph-detail-header">
              <div>
                <span>{formatToken(activeNode.kind)}</span>
                <h2>{activeNode.label}</h2>
              </div>
              {activeNode.severity && <span className={`severity-badge ${activeNode.severity}`}>{activeNode.severity}</span>}
            </div>

            <p>{activeNode.description}</p>

            <div className="graph-neighborhood">
              <span>Graph neighborhood</span>
              <div>
                {connectedNodes.length > 0 ? (
                  connectedNodes.map((node) => (
                    <button key={node.id} type="button" onClick={() => onSelectedNodeChange(node.id)}>
                      {node.label}
                    </button>
                  ))
                ) : (
                  <em>No directly connected nodes.</em>
                )}
              </div>
            </div>

            <div className="graph-evidence-box">
              <span>Evidence</span>
              {selectedEvidence ? (
                <>
                  <strong>{selectedEvidence.evidenceId}</strong>
                  <mark>{selectedEvidence.highlightedSpan}</mark>
                  <p>{selectedEvidence.originalContext}</p>
                </>
              ) : (
                <p>No direct evidence citation is attached to this node.</p>
              )}
            </div>
          </>
        ) : (
          <div className="empty-evidence-state">No graph nodes match the selected filter.</div>
        )}
      </aside>
    </section>
  );
}

function EvidenceExplorerPage({
  records,
  searchQuery,
  sourceTrustFilter,
  findingTypeFilter,
  artifactTypeFilter,
  onSearchQueryChange,
  onSourceTrustFilterChange,
  onFindingTypeFilterChange,
  onArtifactTypeFilterChange,
}: {
  records: EvidenceRecord[];
  searchQuery: string;
  sourceTrustFilter: SourceTrustFilter;
  findingTypeFilter: FindingTypeFilter;
  artifactTypeFilter: ArtifactTypeFilter;
  onSearchQueryChange: (value: string) => void;
  onSourceTrustFilterChange: (value: SourceTrustFilter) => void;
  onFindingTypeFilterChange: (value: FindingTypeFilter) => void;
  onArtifactTypeFilterChange: (value: ArtifactTypeFilter) => void;
}) {
  const findingTypes = useMemo(() => uniqueSorted(records.map((record) => record.findingType)), [records]);
  const artifactTypes = useMemo(() => uniqueSorted(records.map((record) => record.artifactType)), [records]);
  const sourceTrustValues = useMemo(() => uniqueSorted(records.map((record) => record.sourceTrust)), [records]);
  const filteredRecords = useMemo(() => {
    const normalizedQuery = searchQuery.trim().toLowerCase();

    return records.filter((record) => {
      const matchesSearch =
        !normalizedQuery ||
        [
          record.evidenceId,
          record.findingType,
          record.artifactType,
          record.artifactPath,
          record.highlightedSpan,
          record.originalContext,
        ]
          .join(" ")
          .toLowerCase()
          .includes(normalizedQuery);
      const matchesTrust = sourceTrustFilter === "all" || record.sourceTrust === sourceTrustFilter;
      const matchesFinding = findingTypeFilter === "all" || record.findingType === findingTypeFilter;
      const matchesArtifact = artifactTypeFilter === "all" || record.artifactType === artifactTypeFilter;

      return matchesSearch && matchesTrust && matchesFinding && matchesArtifact;
    });
  }, [artifactTypeFilter, findingTypeFilter, records, searchQuery, sourceTrustFilter]);

  return (
    <section className="evidence-explorer-grid" aria-labelledby="evidence-heading">
      <section className="evidence-filter-panel" aria-label="Evidence filters">
        <div className="section-heading">
          <Search size={20} aria-hidden="true" />
          <h2 id="evidence-heading">Evidence explorer</h2>
        </div>

        <label className="field">
          <span>Search evidence</span>
          <div className="search-field">
            <Search size={18} aria-hidden="true" />
            <input
              type="search"
              value={searchQuery}
              onChange={(event) => onSearchQueryChange(event.target.value)}
              placeholder="artifact, rule, span, context"
            />
          </div>
        </label>

        <label className="field">
          <span>Source trust</span>
          <select
            value={sourceTrustFilter}
            onChange={(event) => onSourceTrustFilterChange(event.target.value as SourceTrustFilter)}
          >
            <option value="all">All source trust</option>
            {sourceTrustValues.map((trust) => (
              <option key={trust} value={trust}>
                {formatToken(trust)}
              </option>
            ))}
          </select>
        </label>

        <label className="field">
          <span>Finding type</span>
          <select
            value={findingTypeFilter}
            onChange={(event) => onFindingTypeFilterChange(event.target.value as FindingTypeFilter)}
          >
            <option value="all">All finding types</option>
            {findingTypes.map((type) => (
              <option key={type} value={type}>
                {formatToken(type)}
              </option>
            ))}
          </select>
        </label>

        <label className="field">
          <span>Artifact type</span>
          <select
            value={artifactTypeFilter}
            onChange={(event) => onArtifactTypeFilterChange(event.target.value as ArtifactTypeFilter)}
          >
            <option value="all">All artifact types</option>
            {artifactTypes.map((type) => (
              <option key={type} value={type}>
                {formatToken(type)}
              </option>
            ))}
          </select>
        </label>
      </section>

      <section className="evidence-results-panel" aria-label="Evidence results">
        <div className="inventory-header">
          <div className="section-heading">
            <FileJson size={20} aria-hidden="true" />
            <h2>Evidence records</h2>
          </div>
          <div className="inventory-summary" aria-label="Filtered evidence summary">
            <span>{filteredRecords.length} shown</span>
            <span>{records.length} total</span>
          </div>
        </div>

        <div className="evidence-results-list">
          {filteredRecords.length > 0 ? (
            filteredRecords.map((record) => (
              <article key={record.evidenceId} className="evidence-record-card">
                <div className="evidence-record-header">
                  <div>
                    <span className="evidence-id">{record.evidenceId}</span>
                    <h3>{formatToken(record.findingType)}</h3>
                  </div>
                  <div className="evidence-chip-row">
                    <span className={`trust-badge ${record.sourceTrust}`}>{formatToken(record.sourceTrust)}</span>
                    <span className="artifact-chip">{formatToken(record.artifactType)}</span>
                  </div>
                </div>

                <dl className="finding-detail-list compact">
                  <div>
                    <dt>Artifact path</dt>
                    <dd className="finding-path">{record.artifactPath}</dd>
                  </div>
                  <div>
                    <dt>Line range</dt>
                    <dd>{record.lineRange}</dd>
                  </div>
                </dl>

                <div className="highlighted-span">
                  <span>Highlighted span</span>
                  <mark>{record.highlightedSpan}</mark>
                </div>

                <div className="original-context">
                  <span>Original context</span>
                  <p>{record.originalContext}</p>
                </div>
              </article>
            ))
          ) : (
            <div className="empty-evidence-state">No evidence records match the selected filters.</div>
          )}
        </div>
      </section>
    </section>
  );
}

function FindingDetailPage({ finding }: { finding: FindingDetail }) {
  const confidencePercent = Math.round(finding.confidence * 100);

  return (
    <section className="finding-detail-grid" aria-labelledby="finding-heading">
      <div className="finding-hero">
        <div className="section-heading">
          <AlertTriangle size={20} aria-hidden="true" />
          <h2 id="finding-heading">Finding detail</h2>
        </div>
        <div className="finding-badge-row">
          <span className={`severity-badge ${finding.severity}`}>{finding.severity}</span>
          <span className={`policy-badge ${finding.policyDecision}`}>{finding.policyDecision}</span>
        </div>
      </div>

      <section className="finding-card finding-summary" aria-label="Finding summary">
        <dl className="finding-detail-list">
          <div>
            <dt>Finding type</dt>
            <dd>{finding.findingType}</dd>
          </div>
          <div>
            <dt>Triggered rule</dt>
            <dd>{finding.triggeredRule}</dd>
          </div>
          <div>
            <dt>Confidence</dt>
            <dd>
              <span className="confidence-value">{confidencePercent}%</span>
              <span className="confidence-meter" aria-hidden="true">
                <span style={{ width: `${confidencePercent}%` }} />
              </span>
            </dd>
          </div>
        </dl>
      </section>

      <section className="finding-card evidence-card" aria-label="Evidence text">
        <div className="section-heading">
          <FileJson size={20} aria-hidden="true" />
          <h2>Evidence text</h2>
        </div>
        <p className="evidence-text">{finding.evidenceText}</p>
        <dl className="finding-detail-list compact">
          <div>
            <dt>Artifact path</dt>
            <dd className="finding-path">{finding.artifactPath}</dd>
          </div>
          <div>
            <dt>Line range</dt>
            <dd>{finding.lineRange}</dd>
          </div>
        </dl>
      </section>

      <section className="finding-card finding-action" aria-label="Recommendation and policy decision">
        <div className="section-heading">
          <ListChecks size={20} aria-hidden="true" />
          <h2>Recommendation</h2>
        </div>
        <p>{finding.recommendation}</p>
        <div className="policy-decision-row">
          <span>Policy decision</span>
          <span className={`policy-badge ${finding.policyDecision}`}>{finding.policyDecision}</span>
        </div>
      </section>
    </section>
  );
}

function ToolInventoryPage({ tools }: { tools: ToolInventoryItem[] }) {
  const totalFindings = tools.reduce((sum, tool) => sum + tool.findingCount, 0);
  const averageRisk = Math.round(tools.reduce((sum, tool) => sum + tool.riskScore, 0) / tools.length);

  return (
    <section className="inventory-panel" aria-labelledby="inventory-heading">
      <div className="inventory-header">
        <div className="section-heading">
          <TableProperties size={20} aria-hidden="true" />
          <h2 id="inventory-heading">Tool inventory</h2>
        </div>
        <div className="inventory-summary" aria-label="Tool inventory summary">
          <span>{tools.length} tools</span>
          <span>{totalFindings} findings</span>
          <span>{averageRisk} avg risk</span>
        </div>
      </div>

      <div className="inventory-table-wrap">
        <table className="inventory-table">
          <thead>
            <tr>
              <th>Tool name</th>
              <th>Source</th>
              <th>Declared purpose</th>
              <th>Detected capabilities</th>
              <th>Risk score</th>
              <th>Policy decision</th>
              <th>Finding count</th>
              <th>Last scanned</th>
            </tr>
          </thead>
          <tbody>
            {tools.map((tool) => (
              <tr key={`${tool.source}-${tool.toolName}`}>
                <td className="tool-name-cell">{tool.toolName}</td>
                <td>{tool.source}</td>
                <td>{tool.declaredPurpose}</td>
                <td>
                  <div className="capability-list">
                    {tool.detectedCapabilities.map((capability) => (
                      <span key={capability} className="capability-chip">
                        {capability}
                      </span>
                    ))}
                  </div>
                </td>
                <td>
                  <div className="risk-cell">
                    <strong>{tool.riskScore}</strong>
                    <span className="risk-mini-meter" aria-hidden="true">
                      <span style={{ width: `${tool.riskScore}%` }} />
                    </span>
                  </div>
                </td>
                <td>
                  <span className={`policy-badge ${tool.policyDecision}`}>{tool.policyDecision}</span>
                </td>
                <td className="numeric-cell">{tool.findingCount}</td>
                <td>{tool.lastScanned}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function ScanOverviewPage({ overview }: { overview: ScanOverview }) {
  const severityItems = [
    { label: "Critical", value: overview.severityCounts.critical, className: "critical" },
    { label: "High", value: overview.severityCounts.high, className: "high" },
    { label: "Medium", value: overview.severityCounts.medium, className: "medium" },
    { label: "Low", value: overview.severityCounts.low, className: "low" },
  ];

  return (
    <section className="overview-grid" aria-labelledby="overview-heading">
      <div className="overview-hero">
        <div>
          <div className="section-heading">
            <ShieldCheck size={20} aria-hidden="true" />
            <h2 id="overview-heading">Scan status</h2>
          </div>
          <p className="run-id">{overview.runId}</p>
        </div>
        <div className="status-badge complete">
          <CheckCircle2 size={18} aria-hidden="true" />
          {overview.scanStatus}
        </div>
      </div>

      <section className="risk-panel" aria-label="Risk score">
        <div className="risk-score">
          <span>{overview.riskScore}</span>
          <small>/100</small>
        </div>
        <div className="risk-meter" aria-hidden="true">
          <span style={{ width: `${overview.riskScore}%` }} />
        </div>
      </section>

      <section className="metadata-panel" aria-label="Source metadata">
        <div className="section-heading">
          <GitBranch size={20} aria-hidden="true" />
          <h2>Source metadata</h2>
        </div>
        <dl className="metadata-list">
          <div>
            <dt>Source</dt>
            <dd>{overview.sourceName}</dd>
          </div>
          <div>
            <dt>Type</dt>
            <dd>{overview.sourceType}</dd>
          </div>
        </dl>
      </section>

      <section className="metric-grid" aria-label="Scan counts">
        <MetricTile icon={<Database size={18} aria-hidden="true" />} label="Artifacts" value={overview.artifactCount} />
        <MetricTile icon={<FileJson size={18} aria-hidden="true" />} label="Tools" value={overview.toolCount} />
        <MetricTile icon={<AlertTriangle size={18} aria-hidden="true" />} label="Findings" value={overview.findingCount} />
        <MetricTile icon={<Timer size={18} aria-hidden="true" />} label="Status" value="Done" />
      </section>

      <section className="severity-panel" aria-label="Severity counts">
        <div className="section-heading">
          <BarChart3 size={20} aria-hidden="true" />
          <h2>Severity counts</h2>
        </div>
        <div className="severity-list">
          {severityItems.map((item) => (
            <div key={item.label} className={`severity-row ${item.className}`}>
              <span>{item.label}</span>
              <strong>{item.value}</strong>
            </div>
          ))}
        </div>
      </section>

      <section className="recommendation-panel" aria-label="Top recommendations">
        <div className="section-heading">
          <ListChecks size={20} aria-hidden="true" />
          <h2>Top recommendations</h2>
        </div>
        <ul>
          {overview.topRecommendations.map((recommendation) => (
            <li key={recommendation}>{recommendation}</li>
          ))}
        </ul>
      </section>
    </section>
  );
}

function MetricTile({
  icon,
  label,
  value,
}: {
  icon: ReactNode;
  label: string;
  value: number | string;
}) {
  return (
    <div className="metric-tile">
      {icon}
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function buildScanOverview(
  runId: string,
  repoUrl: string,
  schemaFile: File | null,
  currentScanMode: ScanMode,
  currentPolicyMode: PolicyMode,
  currentCrawlerDepth: number,
): ScanOverview {
  const sourceName = repoUrl || schemaFile?.name || "local-schema.yaml";
  const isLocalSchema = currentScanMode === "local_schema" || (!repoUrl && schemaFile);
  const baseRisk = currentPolicyMode === "research_mode" ? 42 : currentPolicyMode === "strict_mode" ? 68 : 56;
  const depthAdjustment = currentCrawlerDepth * 3;
  const riskScore = Math.min(92, baseRisk + depthAdjustment);
  const critical = riskScore >= 75 ? 1 : 0;
  const high = riskScore >= 60 ? 2 : 1;
  const medium = riskScore >= 45 ? 3 : 2;
  const low = 4;

  return {
    runId,
    sourceName,
    sourceType: isLocalSchema ? "local schema" : "github repo",
    scanStatus: "completed",
    riskScore,
    artifactCount: isLocalSchema ? 3 : 14 + currentCrawlerDepth * 4,
    toolCount: isLocalSchema ? 1 : 5,
    findingCount: critical + high + medium + low,
    severityCounts: {
      critical,
      high,
      medium,
      low,
    },
    topRecommendations: [
      "Review high-severity evidence before tool approval.",
      "Keep strict policy mode enabled for risky metadata.",
      "Use evidence citations when escalating findings.",
    ],
  };
}

function buildToolInventory(
  repoUrl: string,
  schemaFile: File | null,
  currentScanMode: ScanMode,
  currentPolicyMode: PolicyMode,
  currentCrawlerDepth: number,
): ToolInventoryItem[] {
  const source = sourceLabelFromInput(repoUrl, schemaFile);
  const isLocalSchema = currentScanMode === "local_schema" || (!repoUrl && schemaFile);
  const lastScanned = "2026-06-17";

  if (isLocalSchema) {
    const riskScore = boundedRiskScore(40, currentPolicyMode, currentCrawlerDepth);

    return [
      {
        toolName: "Schema-defined Tool",
        source,
        declaredPurpose: "Expose schema-declared operation for review.",
        detectedCapabilities: ["schema_parse", "permission_review"],
        riskScore,
        policyDecision: policyDecisionForRisk(riskScore),
        findingCount: findingCountForRisk(riskScore),
        lastScanned,
      },
    ];
  }

  const inventorySeed = [
    {
      toolName: "Markdown Summarizer",
      declaredPurpose: "Summarize repository documentation.",
      detectedCapabilities: ["read_docs", "summarize_text"],
      baseRisk: 28,
    },
    {
      toolName: "Calendar Reader",
      declaredPurpose: "Read event titles and schedules for summaries.",
      detectedCapabilities: ["calendar_read", "time_range_query"],
      baseRisk: 36,
    },
    {
      toolName: "Weather Fetcher",
      declaredPurpose: "Fetch location-based weather forecasts.",
      detectedCapabilities: ["network_access", "external_api"],
      baseRisk: 44,
    },
    {
      toolName: "Docs Search Tool",
      declaredPurpose: "Search indexed repository documentation.",
      detectedCapabilities: ["read_docs", "semantic_search", "citation_lookup"],
      baseRisk: 51,
    },
    {
      toolName: "Deployment Helper",
      declaredPurpose: "Inspect deployment metadata and environment references.",
      detectedCapabilities: ["filesystem_read", "env_var_reference", "network_access"],
      baseRisk: 64,
    },
  ];

  return inventorySeed.map((tool) => {
    const riskScore = boundedRiskScore(tool.baseRisk, currentPolicyMode, currentCrawlerDepth);

    return {
      toolName: tool.toolName,
      source,
      declaredPurpose: tool.declaredPurpose,
      detectedCapabilities: tool.detectedCapabilities,
      riskScore,
      policyDecision: policyDecisionForRisk(riskScore),
      findingCount: findingCountForRisk(riskScore),
      lastScanned,
    };
  });
}

function buildFindingDetail(
  repoUrl: string,
  schemaFile: File | null,
  currentScanMode: ScanMode,
  currentPolicyMode: PolicyMode,
  currentCrawlerDepth: number,
): FindingDetail {
  const source = sourceLabelFromInput(repoUrl, schemaFile);
  const isLocalSchema = currentScanMode === "local_schema" || (!repoUrl && schemaFile);
  const riskScore = boundedRiskScore(isLocalSchema ? 50 : 70, currentPolicyMode, currentCrawlerDepth);
  const policyDecision = policyDecisionForRisk(riskScore);

  if (isLocalSchema) {
    return {
      findingType: "permission_overreach",
      severity: severityForRisk(riskScore),
      confidence: 0.78,
      triggeredRule: "permission.schema_overreach",
      evidenceText: "Tool schema declares filesystem write capability while the declared purpose is schema review.",
      artifactPath: schemaFile?.name ?? "local-schema.yaml",
      lineRange: "12-18",
      recommendation: "Require scoped capability approval or reduce the declared permission set before allowing this tool.",
      policyDecision,
    };
  }

  return {
    findingType: "prompt_injection_candidate",
    severity: severityForRisk(riskScore),
    confidence: 0.86,
    triggeredRule: "prompt_injection.instruction_override",
    evidenceText: "Repository documentation contains instruction-like text that attempts to override system policy during tool use.",
    artifactPath: `${source}/README.md`,
    lineRange: "42-47",
    recommendation: "Treat the artifact text as untrusted evidence, keep strict policy mediation enabled, and require manual review.",
    policyDecision,
  };
}

function buildEvidenceRecords(
  repoUrl: string,
  schemaFile: File | null,
  currentScanMode: ScanMode,
): EvidenceRecord[] {
  const source = sourceLabelFromInput(repoUrl, schemaFile);
  const isLocalSchema = currentScanMode === "local_schema" || (!repoUrl && schemaFile);

  if (isLocalSchema) {
    return [
      {
        evidenceId: "ev-local-schema-001",
        sourceTrust: "unverified",
        findingType: "permission_overreach",
        artifactType: "schema",
        artifactPath: schemaFile?.name ?? "local-schema.yaml",
        lineRange: "12-18",
        highlightedSpan: "filesystem write capability",
        originalContext:
          "The local schema describes a review operation, but the declared capability includes filesystem write capability and broad path access.",
      },
      {
        evidenceId: "ev-local-schema-002",
        sourceTrust: "unverified",
        findingType: "credential_reference",
        artifactType: "schema",
        artifactPath: schemaFile?.name ?? "local-schema.yaml",
        lineRange: "24-27",
        highlightedSpan: "EXAMPLE_SERVICE_TOKEN",
        originalContext:
          "The schema references EXAMPLE_SERVICE_TOKEN as a required environment variable; this is a credential reference that needs review.",
      },
    ];
  }

  return [
    {
      evidenceId: "ev-readme-001",
      sourceTrust: "external",
      findingType: "prompt_injection_candidate",
      artifactType: "readme",
      artifactPath: `${source}/README.md`,
      lineRange: "42-47",
      highlightedSpan: "override system policy during tool use",
      originalContext:
        "The README includes instruction-like text that attempts to override system policy during tool use and should be treated as untrusted content.",
    },
    {
      evidenceId: "ev-schema-002",
      sourceTrust: "external",
      findingType: "permission_overreach",
      artifactType: "schema",
      artifactPath: `${source}/tools/weather.schema.yaml`,
      lineRange: "18-25",
      highlightedSpan: "network_access with unrestricted domains",
      originalContext:
        "The weather tool declares network_access with unrestricted domains even though its stated purpose only requires a known forecast endpoint.",
    },
    {
      evidenceId: "ev-docs-003",
      sourceTrust: "unverified",
      findingType: "credential_reference",
      artifactType: "docs",
      artifactPath: `${source}/docs/configuration.md`,
      lineRange: "31-34",
      highlightedSpan: "SERVICE_API_KEY",
      originalContext:
        "Configuration docs mention SERVICE_API_KEY as an environment variable for authenticated requests; no secret value is stored.",
    },
    {
      evidenceId: "ev-manifest-004",
      sourceTrust: "trusted",
      findingType: "permission_overreach",
      artifactType: "manifest",
      artifactPath: `${source}/package.json`,
      lineRange: "8-13",
      highlightedSpan: "postinstall review required",
      originalContext:
        "The package manifest contains lifecycle metadata that is safe to parse as text but still marked for postinstall review in security triage.",
    },
  ];
}

function buildReportJson(
  overview: ScanOverview,
  tools: ToolInventoryItem[],
  finding: FindingDetail,
  graph: ToolRiskGraph,
  sandboxTrace: SandboxTrace,
  recommendations: string[],
  evidenceRecords: EvidenceRecord[],
) {
  return {
    executive_summary: {
      run_id: overview.runId,
      source_name: overview.sourceName,
      source_type: overview.sourceType,
      scan_status: overview.scanStatus,
      risk_score: overview.riskScore,
      finding_count: overview.findingCount,
      tool_count: overview.toolCount,
      artifact_count: overview.artifactCount,
    },
    findings: [finding],
    tool_inventory: tools,
    risk_graph: {
      node_count: graph.nodes.length,
      edge_count: graph.edges.length,
      finding_nodes: graph.nodes.filter((node) => node.kind === "finding"),
    },
    sandbox_result: {
      final_outcome: sandboxTrace.finalOutcome,
      blocked_unsafe_actions: sandboxTrace.blockedUnsafeActions,
      policy_decisions: sandboxTrace.policyDecisions,
    },
    recommendations,
    evidence_appendix: evidenceRecords,
  };
}

function buildReportMarkdown(
  overview: ScanOverview,
  tools: ToolInventoryItem[],
  finding: FindingDetail,
  graph: ToolRiskGraph,
  sandboxTrace: SandboxTrace,
  recommendations: string[],
  evidenceRecords: EvidenceRecord[],
) {
  return [
    `# AgentSupplyShield Report - ${overview.sourceName}`,
    "",
    "## Executive Summary",
    `- Run ID: ${overview.runId}`,
    `- Source: ${overview.sourceName}`,
    `- Risk score: ${overview.riskScore}/100`,
    `- Findings: ${overview.findingCount}`,
    `- Tools reviewed: ${tools.length}`,
    "",
    "## Findings",
    `- ${finding.findingType} (${finding.severity}, ${finding.policyDecision})`,
    `- Triggered rule: ${finding.triggeredRule}`,
    `- Evidence: ${finding.evidenceText}`,
    `- Location: ${finding.artifactPath} lines ${finding.lineRange}`,
    "",
    "## Tool Inventory",
    ...tools.map((tool) => `- ${tool.toolName}: ${tool.declaredPurpose} (${tool.policyDecision}, risk ${tool.riskScore})`),
    "",
    "## Risk Graph",
    `- Nodes: ${graph.nodes.length}`,
    `- Edges: ${graph.edges.length}`,
    `- Finding nodes: ${graph.nodes.filter((node) => node.kind === "finding").map((node) => node.label).join(", ")}`,
    "",
    "## Sandbox Result",
    sandboxTrace.finalOutcome,
    ...sandboxTrace.blockedUnsafeActions.map((action) => `- ${action}`),
    "",
    "## Recommendations",
    ...recommendations.map((recommendation) => `- ${recommendation}`),
    "",
    "## Evidence Appendix",
    ...evidenceRecords.map(
      (record) =>
        `- ${record.evidenceId}: ${record.artifactPath} lines ${record.lineRange}; span: ${record.highlightedSpan}`,
    ),
    "",
  ].join("\n");
}

function downloadReportArtifact(filename: string, content: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function buildEvaluationDashboard(
  repoUrl: string,
  schemaFile: File | null,
  currentScanMode: ScanMode,
  currentPolicyMode: PolicyMode,
  currentCrawlerDepth: number,
): EvaluationDashboard {
  const source = sourceLabelFromInput(repoUrl, schemaFile);
  const isLocalSchema = currentScanMode === "local_schema" || (!repoUrl && schemaFile);
  const policyHardening =
    currentPolicyMode === "strict_mode"
      ? 14
      : currentPolicyMode === "enterprise_mode"
        ? 12
        : currentPolicyMode === "benchmark_mode"
          ? 9
          : currentPolicyMode === "warn_mode"
            ? 6
            : 3;
  const sampleCount = currentScanMode === "batch_seed" ? 180 : isLocalSchema ? 48 : 96 + currentCrawlerDepth * 12;
  const riskScore = boundedRiskScore(isLocalSchema ? 58 : 68, currentPolicyMode, currentCrawlerDepth);
  const unsafeActionRate = clampPercent((isLocalSchema ? 22 : 30) + currentCrawlerDepth * 2 - policyHardening);
  const blockedUnsafeActionRate = clampPercent(55 + policyHardening * 3 + currentCrawlerDepth);
  const taskSuccessRate = clampPercent(88 - policyHardening + (isLocalSchema ? 4 : 0) - currentCrawlerDepth);
  const falseBlockRate = clampPercent(3 + Math.round(policyHardening / 2) + (currentPolicyMode === "strict_mode" ? 3 : 0));
  const criticalCount = Math.round(sampleCount * (riskScore >= 80 ? 0.16 : riskScore >= 60 ? 0.1 : 0.04));
  const highCount = Math.round(sampleCount * (riskScore >= 80 ? 0.28 : riskScore >= 60 ? 0.22 : 0.13));
  const mediumCount = Math.round(sampleCount * (riskScore >= 80 ? 0.33 : riskScore >= 60 ? 0.36 : 0.31));
  const lowCount = Math.max(0, sampleCount - criticalCount - highCount - mediumCount);
  const fastLatencyCount = Math.max(4, Math.round(sampleCount * (isLocalSchema ? 0.46 : 0.34) - currentCrawlerDepth));
  const standardLatencyCount = Math.max(4, Math.round(sampleCount * 0.32));
  const slowLatencyCount = Math.max(2, Math.round(sampleCount * 0.2 + currentCrawlerDepth * 2));
  const tailLatencyCount = Math.max(0, sampleCount - fastLatencyCount - standardLatencyCount - slowLatencyCount);

  return {
    runLabel: source,
    sampleCount,
    policyModeLabel: policyModes.find((mode) => mode.value === currentPolicyMode)?.label ?? formatToken(currentPolicyMode),
    rateMetrics: [
      { label: "Unsafe action rate", value: unsafeActionRate, target: "lower is safer" },
      { label: "Blocked unsafe action rate", value: blockedUnsafeActionRate, target: "higher is safer" },
      { label: "Task success", value: taskSuccessRate, target: "higher preserves utility" },
      { label: "False block rate", value: falseBlockRate, target: "lower reduces friction" },
    ],
    detectorPrecisionRecall: [
      {
        label: "Prompt injection",
        precision: clampPercent(88 + Math.round(policyHardening / 3)),
        recall: clampPercent(81 + currentCrawlerDepth * 2 + Math.round(policyHardening / 4)),
      },
      {
        label: "Permission overreach",
        precision: clampPercent(85 + Math.round(policyHardening / 4)),
        recall: clampPercent(78 + currentCrawlerDepth * 2 + Math.round(policyHardening / 3)),
      },
      {
        label: "Credential reference",
        precision: clampPercent(92 + (isLocalSchema ? 1 : 0)),
        recall: clampPercent(84 + currentCrawlerDepth + Math.round(policyHardening / 5)),
      },
      {
        label: "Unsafe sandbox action",
        precision: clampPercent(86 + Math.round(policyHardening / 2)),
        recall: clampPercent(80 + Math.round(policyHardening / 2)),
      },
    ],
    riskDistribution: [
      { label: "Critical", value: criticalCount, className: "critical" },
      { label: "High", value: highCount, className: "high" },
      { label: "Medium", value: mediumCount, className: "medium" },
      { label: "Low", value: lowCount, className: "low" },
    ],
    latencyDistribution: [
      { label: "0-250 ms", value: fastLatencyCount },
      { label: "250-500 ms", value: standardLatencyCount },
      { label: "500-1000 ms", value: slowLatencyCount },
      { label: "1000+ ms", value: tailLatencyCount },
    ],
  };
}

function buildSandboxTrace(
  repoUrl: string,
  schemaFile: File | null,
  currentScanMode: ScanMode,
  currentPolicyMode: PolicyMode,
  currentCrawlerDepth: number,
): SandboxTrace {
  const source = sourceLabelFromInput(repoUrl, schemaFile);
  const isLocalSchema = currentScanMode === "local_schema" || (!repoUrl && schemaFile);
  const reviewDecision = policyDecisionForRisk(boundedRiskScore(28, currentPolicyMode, currentCrawlerDepth));
  const inspectionDecision = policyDecisionForRisk(boundedRiskScore(48, currentPolicyMode, currentCrawlerDepth));
  const unsafeDecision = policyDecisionForRisk(boundedRiskScore(86, currentPolicyMode, currentCrawlerDepth));

  if (isLocalSchema) {
    return {
      taskDescription:
        "Evaluate the uploaded schema in a sandboxed red-team pass using mock tools and mock secrets only.",
      toolMetadataShown: [
        `Source: ${source}`,
        "Schema-defined Tool: declared schema parse operation.",
        "Capability: filesystem_write flagged for review.",
        "Mock secret: MOCK_SERVICE_TOKEN (synthetic only).",
      ],
      actionTrace: [
        {
          stepId: "sandbox-local-001",
          timestamp: "00:00",
          actor: "guarded agent",
          toolName: "Schema-defined Tool",
          action: "Read schema metadata",
          policyDecision: reviewDecision,
          status: reviewDecision === "allow" ? "allowed" : "warned",
          rationale: "Metadata review is permitted because it reads static uploaded text only.",
        },
        {
          stepId: "sandbox-local-002",
          timestamp: "00:08",
          actor: "guarded agent",
          toolName: "Mock Filesystem Tool",
          action: "Attempt broad filesystem write",
          policyDecision: unsafeDecision,
          status: "blocked",
          rationale: "The requested write action exceeds the schema-review purpose and is stopped before execution.",
        },
        {
          stepId: "sandbox-local-003",
          timestamp: "00:13",
          actor: "policy firewall",
          toolName: "Mock Secret Store",
          action: "Prevent mock credential reveal",
          policyDecision: unsafeDecision,
          status: "blocked",
          rationale: "Synthetic secret names may be cited as evidence, but values are never exposed to the agent.",
        },
        {
          stepId: "sandbox-local-004",
          timestamp: "00:18",
          actor: "guarded agent",
          toolName: "Report Writer",
          action: "Write sandbox summary",
          policyDecision: reviewDecision,
          status: "allowed",
          rationale: "The final summary records policy outcomes without executing the unsafe request.",
        },
      ],
      policyDecisions: [
        {
          label: "Static schema review",
          decision: reviewDecision,
          rationale: "Allowed for bounded text inspection of the uploaded schema.",
        },
        {
          label: "Filesystem write request",
          decision: unsafeDecision,
          rationale: "Blocked because the mock action is state-changing and unrelated to analysis.",
        },
        {
          label: "Mock credential access",
          decision: unsafeDecision,
          rationale: "Blocked because even synthetic secret values must not be disclosed in traces.",
        },
      ],
      blockedUnsafeActions: [
        "Blocked filesystem write request against the mock workspace.",
        "Blocked access to MOCK_SERVICE_TOKEN value.",
      ],
      finalOutcome:
        "The sandbox completed the review, blocked unsafe actions, and preserved an audit trace without touching real files or secrets.",
    };
  }

  return {
    taskDescription:
      "Run a sandboxed review of tool metadata and adversarial documentation using mock tools and mock secrets only.",
    toolMetadataShown: [
      `Source: ${source}`,
      "Weather Fetcher: fetch forecast data from api.weather.example.",
      "Docs Search Tool: search indexed repository documentation.",
      "Deployment Helper: inspect environment references and deployment metadata.",
      "Mock secret: MOCK_SERVICE_TOKEN (synthetic only).",
    ],
    actionTrace: [
      {
        stepId: "sandbox-repo-001",
        timestamp: "00:00",
        actor: "guarded agent",
        toolName: "Docs Search Tool",
        action: "Read retrieved README evidence",
        policyDecision: reviewDecision,
        status: reviewDecision === "allow" ? "allowed" : "warned",
        rationale: "Retrieved repository text is marked untrusted but can be inspected for evidence.",
      },
      {
        stepId: "sandbox-repo-002",
        timestamp: "00:09",
        actor: "guarded agent",
        toolName: "Docs Search Tool",
        action: "Follow instruction-like metadata",
        policyDecision: inspectionDecision,
        status: inspectionDecision === "allow" ? "allowed" : "warned",
        rationale: "The policy flags instruction-like text as evidence instead of treating it as agent instruction.",
      },
      {
        stepId: "sandbox-repo-003",
        timestamp: "00:16",
        actor: "policy firewall",
        toolName: "Weather Fetcher",
        action: "Attempt callback to unapproved domain",
        policyDecision: unsafeDecision,
        status: "blocked",
        rationale: "The callback domain is outside the declared weather endpoint and is blocked before tool use.",
      },
      {
        stepId: "sandbox-repo-004",
        timestamp: "00:22",
        actor: "policy firewall",
        toolName: "Mock Secret Store",
        action: "Prevent mock credential reveal",
        policyDecision: unsafeDecision,
        status: "blocked",
        rationale: "The sandbox records the unsafe request without revealing synthetic secret values.",
      },
      {
        stepId: "sandbox-repo-005",
        timestamp: "00:30",
        actor: "guarded agent",
        toolName: "Report Writer",
        action: "Write final sandbox finding",
        policyDecision: reviewDecision,
        status: "allowed",
        rationale: "The report cites blocked actions and evidence without executing network or credential access.",
      },
    ],
    policyDecisions: [
      {
        label: "Untrusted documentation review",
        decision: reviewDecision,
        rationale: "Allowed as evidence intake with untrusted-content marking.",
      },
      {
        label: "Instruction-like metadata",
        decision: inspectionDecision,
        rationale: "Warned or quarantined depending on policy strictness, never promoted to instruction.",
      },
      {
        label: "External callback attempt",
        decision: unsafeDecision,
        rationale: "Blocked because the domain is not required by the declared tool purpose.",
      },
      {
        label: "Mock credential request",
        decision: unsafeDecision,
        rationale: "Blocked because secret values are outside the permitted sandbox behavior.",
      },
    ],
    blockedUnsafeActions: [
      "Blocked callback request to callback.example.",
      "Blocked request to reveal MOCK_SERVICE_TOKEN value.",
    ],
    finalOutcome:
      "The guarded sandbox completed the review, recorded two blocked unsafe actions, and produced an audit-ready trace.",
  };
}

function buildToolRiskGraph(
  repoUrl: string,
  schemaFile: File | null,
  currentScanMode: ScanMode,
  currentPolicyMode: PolicyMode,
  currentCrawlerDepth: number,
): ToolRiskGraph {
  const source = sourceLabelFromInput(repoUrl, schemaFile);
  const isLocalSchema = currentScanMode === "local_schema" || (!repoUrl && schemaFile);
  const highSeverity = severityForRisk(boundedRiskScore(70, currentPolicyMode, currentCrawlerDepth));
  const mediumSeverity = severityForRisk(boundedRiskScore(45, currentPolicyMode, currentCrawlerDepth));

  if (isLocalSchema) {
    return {
      nodes: [
        {
          id: "repo-local-schema",
          label: source,
          kind: "repo",
          description: "Local schema source submitted for static security review.",
        },
        {
          id: "tool-schema-defined",
          label: "Schema-defined Tool",
          kind: "tool",
          description: "Tool extracted from the uploaded schema metadata.",
        },
        {
          id: "cap-schema-parse",
          label: "schema_parse",
          kind: "capability",
          description: "Capability to parse declared schema metadata.",
        },
        {
          id: "cap-filesystem-write",
          label: "filesystem_write",
          kind: "capability",
          description: "Capability that may exceed the declared schema-review purpose.",
        },
        {
          id: "env-example-token",
          label: "EXAMPLE_SERVICE_TOKEN",
          kind: "env_var",
          description: "Credential-like environment variable reference found in schema text.",
        },
        {
          id: "domain-sandbox-local",
          label: "sandbox.local",
          kind: "domain",
          description: "Local-only sandbox domain used as a safe placeholder for review.",
        },
        {
          id: "finding-schema-permission",
          label: "Permission overreach",
          kind: "finding",
          severity: highSeverity,
          evidenceId: "ev-local-schema-001",
          description: "Schema declares filesystem write access that needs scoped approval.",
        },
        {
          id: "finding-schema-credential",
          label: "Credential reference",
          kind: "finding",
          severity: mediumSeverity,
          evidenceId: "ev-local-schema-002",
          description: "Schema references an environment token that needs handling review.",
        },
      ],
      edges: [
        { from: "repo-local-schema", to: "tool-schema-defined", label: "defines" },
        { from: "tool-schema-defined", to: "cap-schema-parse", label: "declares" },
        { from: "tool-schema-defined", to: "cap-filesystem-write", label: "declares" },
        { from: "cap-filesystem-write", to: "env-example-token", label: "requires" },
        { from: "cap-filesystem-write", to: "domain-sandbox-local", label: "scoped_to" },
        { from: "cap-filesystem-write", to: "finding-schema-permission", label: "triggers" },
        { from: "env-example-token", to: "finding-schema-credential", label: "supports" },
      ],
    };
  }

  return {
    nodes: [
      {
        id: "repo-source",
        label: source,
        kind: "repo",
        description: "GitHub repository source scanned through the text-only review flow.",
      },
      {
        id: "tool-weather",
        label: "Weather Fetcher",
        kind: "tool",
        description: "Tool that fetches location-based weather data.",
      },
      {
        id: "tool-docs",
        label: "Docs Search Tool",
        kind: "tool",
        description: "Tool that searches indexed repository documentation.",
      },
      {
        id: "tool-deploy",
        label: "Deployment Helper",
        kind: "tool",
        description: "Tool that inspects deployment metadata and environment references.",
      },
      {
        id: "cap-network",
        label: "network_access",
        kind: "capability",
        description: "External network access capability declared by the weather tool.",
      },
      {
        id: "cap-semantic-search",
        label: "semantic_search",
        kind: "capability",
        description: "Search capability used by documentation retrieval.",
      },
      {
        id: "cap-env-reference",
        label: "env_var_reference",
        kind: "capability",
        description: "Capability that references environment variable configuration.",
      },
      {
        id: "env-service-key",
        label: "SERVICE_API_KEY",
        kind: "env_var",
        description: "Credential-like environment variable mentioned in documentation.",
      },
      {
        id: "domain-weather-api",
        label: "api.weather.example",
        kind: "domain",
        description: "Example external weather API domain associated with network access.",
      },
      {
        id: "domain-callback",
        label: "callback.example",
        kind: "domain",
        description: "Example callback domain requiring review before approval.",
      },
      {
        id: "finding-injection",
        label: "Prompt injection",
        kind: "finding",
        severity: highSeverity,
        evidenceId: "ev-readme-001",
        description: "Documentation contains instruction-like text that may influence agent behavior.",
      },
      {
        id: "finding-permission",
        label: "Permission overreach",
        kind: "finding",
        severity: highSeverity,
        evidenceId: "ev-schema-002",
        description: "Tool capability scope appears broader than the declared purpose.",
      },
      {
        id: "finding-credential",
        label: "Credential reference",
        kind: "finding",
        severity: mediumSeverity,
        evidenceId: "ev-docs-003",
        description: "Documentation references an environment variable used for authenticated requests.",
      },
    ],
    edges: [
      { from: "repo-source", to: "tool-weather", label: "defines" },
      { from: "repo-source", to: "tool-docs", label: "defines" },
      { from: "repo-source", to: "tool-deploy", label: "defines" },
      { from: "tool-weather", to: "cap-network", label: "declares" },
      { from: "tool-docs", to: "cap-semantic-search", label: "declares" },
      { from: "tool-deploy", to: "cap-env-reference", label: "declares" },
      { from: "cap-env-reference", to: "env-service-key", label: "mentions" },
      { from: "cap-network", to: "domain-weather-api", label: "contacts" },
      { from: "cap-network", to: "domain-callback", label: "may_contact" },
      { from: "cap-semantic-search", to: "finding-injection", label: "supports" },
      { from: "domain-callback", to: "finding-permission", label: "supports" },
      { from: "env-service-key", to: "finding-credential", label: "supports" },
    ],
  };
}

function filterGraphBySeverity(graph: ToolRiskGraph, severityFilter: SeverityFilter): ToolRiskGraph {
  if (severityFilter === "all") {
    return graph;
  }

  const visibleNodeIds = new Set(
    graph.nodes
      .filter((node) => node.kind === "finding" && node.severity === severityFilter)
      .map((node) => node.id),
  );

  let changed = true;
  while (changed) {
    changed = false;
    graph.edges.forEach((edge) => {
      if (visibleNodeIds.has(edge.to) && !visibleNodeIds.has(edge.from)) {
        visibleNodeIds.add(edge.from);
        changed = true;
      }
    });
  }

  return {
    nodes: graph.nodes.filter((node) => visibleNodeIds.has(node.id)),
    edges: graph.edges.filter((edge) => visibleNodeIds.has(edge.from) && visibleNodeIds.has(edge.to)),
  };
}

function rateMetricClass(label: string) {
  const normalizedLabel = label.toLowerCase();

  if (normalizedLabel.includes("blocked") || normalizedLabel.includes("success")) {
    return "positive";
  }
  if (normalizedLabel.includes("false") || normalizedLabel.includes("unsafe")) {
    return "warning";
  }
  return "";
}

function clampPercent(value: number) {
  return Math.min(100, Math.max(0, Math.round(value)));
}

function boundedRiskScore(baseRisk: number, currentPolicyMode: PolicyMode, currentCrawlerDepth: number) {
  const policyAdjustment =
    currentPolicyMode === "research_mode"
      ? -6
      : currentPolicyMode === "strict_mode"
        ? 8
        : currentPolicyMode === "enterprise_mode"
          ? 5
          : currentPolicyMode === "benchmark_mode"
            ? 2
            : 0;

  return Math.min(95, Math.max(0, baseRisk + currentCrawlerDepth * 3 + policyAdjustment));
}

function policyDecisionForRisk(riskScore: number): PolicyDecision {
  if (riskScore >= 80) {
    return "block";
  }
  if (riskScore >= 60) {
    return "quarantine";
  }
  if (riskScore >= 35) {
    return "warn";
  }
  return "allow";
}

function severityForRisk(riskScore: number): FindingSeverity {
  if (riskScore >= 80) {
    return "critical";
  }
  if (riskScore >= 60) {
    return "high";
  }
  if (riskScore >= 35) {
    return "medium";
  }
  return "low";
}

function findingCountForRisk(riskScore: number) {
  if (riskScore >= 80) {
    return 4;
  }
  if (riskScore >= 60) {
    return 3;
  }
  if (riskScore >= 45) {
    return 2;
  }
  if (riskScore >= 30) {
    return 1;
  }
  return 0;
}

function sourceLabelFromInput(repoUrl: string, schemaFile: File | null) {
  if (!repoUrl) {
    return schemaFile?.name ?? "local schema";
  }

  try {
    const [, owner, repository] = new URL(repoUrl).pathname.split("/");
    if (owner && repository) {
      return `${owner}/${repository.replace(/\.git$/, "")}`;
    }
  } catch {
    return "github repo";
  }

  return "github repo";
}

function uniqueSorted<T extends string>(values: T[]) {
  return Array.from(new Set(values)).sort((a, b) => a.localeCompare(b));
}

function formatToken(value: string) {
  return value.replace(/_/g, " ");
}

export default App;

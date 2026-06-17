import { ChangeEvent, FormEvent, useMemo, useState } from "react";
import type { ReactNode } from "react";
import {
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  Database,
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
type ActivePage = "launcher" | "overview" | "inventory" | "finding" | "evidence" | "graph";
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
            : "Tool-Risk Graph";

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

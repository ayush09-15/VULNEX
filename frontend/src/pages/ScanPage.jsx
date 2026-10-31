import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Play,
  Loader2,
  CheckCircle2,
  AlertCircle,
  AlertTriangle,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ArrowRight,
  FolderGit2,
  FileArchive,
  Terminal,
  Cpu,
  Layers,
  RotateCcw,
  Sparkles,
  ExternalLink,
} from 'lucide-react';
import vulnexApi from '../services/api';
import ScanStateView from '../components/common/ScanStateView.jsx';

const PIPELINE_STAGES = [
  { key: 'QUEUED', label: 'Queued', description: 'Assigned traceable Scan ID' },
  { key: 'PREPARING', label: 'Preparing', description: 'Workspace inventory & AST check' },
  { key: 'SCANNING', label: 'Scanning', description: 'Multi-scanner detection engines' },
  { key: 'NORMALIZING', label: 'Normalizing', description: 'Deduplication & fingerprinting' },
  { key: 'COMPLETED', label: 'Completed', description: 'Cataloged & ready for triage' },
];

function getStageStatus(stageKey, currentStage, scanStatus) {
  const stageOrder = ['QUEUED', 'PREPARING', 'SCANNING', 'NORMALIZING', 'COMPLETED'];
  const currentIndex = stageOrder.indexOf(currentStage === 'PARTIAL' ? 'COMPLETED' : currentStage);
  const targetIndex = stageOrder.indexOf(stageKey);

  if (scanStatus === 'FAILED' && currentStage === stageKey) {
    return 'failed';
  }
  if (currentIndex > targetIndex || currentStage === 'COMPLETED' || currentStage === 'PARTIAL') {
    return 'completed';
  }
  if (currentIndex === targetIndex) {
    return 'active';
  }
  return 'pending';
}

export default function ScanPage() {
  const navigate = useNavigate();

  // Intake State
  const [targetType, setTargetType] = useState('FIXTURE'); // 'FIXTURE' | 'GITHUB' | 'ZIP'
  const [gitUrl, setGitUrl] = useState('');
  const [refName, setRefName] = useState('main');
  const [zipFile, setZipFile] = useState(null);
  const [zipBase64, setZipBase64] = useState('');

  // Scanners State
  const [selectedScanners, setSelectedScanners] = useState(['semgrep', 'npm-audit', 'patterns']);

  // Execution & Progress State
  const [isScanning, setIsScanning] = useState(false);
  const [isRetrying, setIsRetrying] = useState(false);
  const [lastTargetRepoId, setLastTargetRepoId] = useState('repo_fixture_01');
  const [activeStage, setActiveStage] = useState('IDLE'); // 'IDLE' | 'QUEUED' | 'PREPARING' | 'SCANNING' | 'NORMALIZING' | 'COMPLETED' | 'PARTIAL' | 'FAILED'
  const [scanRecord, setScanRecord] = useState(null);
  const [error, setError] = useState(null);

  const toggleScanner = (scannerId) => {
    setSelectedScanners((prev) =>
      prev.includes(scannerId)
        ? prev.filter((id) => id !== scannerId)
        : [...prev, scannerId]
    );
  };

  const handleZipChange = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setZipFile(file);
    const reader = new FileReader();
    reader.onload = () => {
      const res = reader.result;
      const base64 = typeof res === 'string' ? res.split(',')[1] : '';
      setZipBase64(base64);
    };
    reader.readAsDataURL(file);
  };

  const handleSetExampleRepo = (url) => {
    setTargetType('GITHUB');
    setGitUrl(url);
    setRefName('main');
    setError(null);
  };

  const handleStartScan = async (e) => {
    if (e) e.preventDefault();
    setError(null);

    // Intake Validation
    if (targetType === 'GITHUB') {
      const trimmedUrl = gitUrl.trim();
      if (!trimmedUrl) {
        setError({
          code: 'MISSING_URL',
          message: 'Repository URL is required. Please specify a valid HTTPS GitHub repository URL.',
        });
        return;
      }
      if (!trimmedUrl.startsWith('https://github.com/')) {
        setError({
          code: 'INVALID_URL',
          message: 'Invalid GitHub URL. Must strictly use HTTPS scheme (e.g. "https://github.com/org/repo").',
        });
        return;
      }
    } else if (targetType === 'ZIP') {
      if (!zipFile || !zipBase64) {
        setError({
          code: 'MISSING_ARCHIVE',
          message: 'Please select a valid .zip archive file to upload.',
        });
        return;
      }
    }

    if (selectedScanners.length === 0) {
      setError({
        code: 'NO_SCANNERS',
        message: 'Please enable at least one scanner engine (Semgrep, npm Audit, or Pattern SAST).',
      });
      return;
    }

    setIsScanning(true);
    setActiveStage('QUEUED');
    setScanRecord(null);

    try {
      let repositoryId = 'repo_fixture_01';

      if (targetType === 'GITHUB') {
        setActiveStage('PREPARING');
        const repoRes = await vulnexApi.repositories.register({
          sourceType: 'GITHUB',
          sourceUrl: gitUrl.trim(),
          defaultRef: refName.trim() || 'main',
        });
        const repo = repoRes.data || repoRes;
        repositoryId = repo.id;
      } else if (targetType === 'ZIP') {
        setActiveStage('PREPARING');
        const repoRes = await vulnexApi.repositories.register({
          sourceType: 'ZIP_UPLOAD',
          displayName: zipFile.name.replace(/\.zip$/i, ''),
          defaultRef: refName.trim() || 'main',
          zipBase64,
        });
        const repo = repoRes.data || repoRes;
        repositoryId = repo.id;
      } else if (targetType === 'FIXTURE') {
        repositoryId = 'repo_fixture_01';
      }

      setLastTargetRepoId(repositoryId);
      setActiveStage('SCANNING');
      const scanRes = await vulnexApi.scans.start({
        repositoryId,
        ref: refName.trim() || 'main',
        scanners: selectedScanners,
      });

      const scan = scanRes.data || scanRes;
      setScanRecord(scan);
      setActiveStage(scan.status || scan.stage || 'COMPLETED');
    } catch (err) {
      setError({
        code: err.code || 'SCAN_EXECUTION_FAILED',
        message: err.message || 'An unexpected error occurred during scan orchestration.',
        details: err.details,
      });
      setActiveStage('FAILED');
    } finally {
      setIsScanning(false);
    }
  };

  const handleRetryScan = async () => {
    // Prevent duplicate requests caused by repeated clicks
    if (isRetrying || isScanning) return;
    setIsRetrying(true);
    setError(null);

    try {
      const scanRes = await vulnexApi.scans.start({
        repositoryId: lastTargetRepoId || 'repo_fixture_01',
        ref: refName.trim() || 'main',
        scanners: selectedScanners,
      });

      const scan = scanRes.data || scanRes;
      setScanRecord(scan);
      setActiveStage(scan.status || scan.stage || 'COMPLETED');
      setError(null);
    } catch (err) {
      // Requirement 6: Preserve existing scan data when a retry fails, where appropriate
      setError({
        code: err.code || 'SCAN_RETRY_FAILED',
        message: err.message || 'Scan retry execution failed.',
        details: err.details,
      });
    } finally {
      setIsRetrying(false);
    }
  };

  const handleResetScan = () => {
    setScanRecord(null);
    setActiveStage('IDLE');
    setError(null);
    setIsRetrying(false);
  };

  const isCompleted = activeStage === 'COMPLETED' || activeStage === 'PARTIAL';
  const totalFindings = scanRecord?.summary?.totalFindings ?? 0;
  const bySeverity = scanRecord?.summary?.bySeverity ?? {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };

  return (
    <div className="space-y-6 animate-fadeIn pb-12">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-extrabold text-slate-100 flex items-center gap-2.5">
          <Shield className="w-6 h-6 text-cyan-400" />
          <span>Scan Engine</span>
        </h1>
        <p className="text-xs text-slate-400 mt-1 max-w-2xl">
          Launch deterministic SAST, dependency vulnerability audits, and pattern analysis with
          strict SSRF guards and bounded execution workspaces.
        </p>
      </div>

      {/* Main Configuration & Execution Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Intake & Configuration Form */}
        <div className="lg:col-span-2 p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-5">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              <span>Target Source Intake</span>
            </h2>
            <span className="text-[11px] font-mono text-cyan-400/80">SSRF Protected</span>
          </div>

          {/* Mode Selector Tabs */}
          <div>
            <label className="block text-xs font-mono font-medium text-slate-400 mb-2">
              Select Intake Source
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => setTargetType('FIXTURE')}
                className={`px-3 py-2.5 rounded-xl text-xs font-mono font-medium flex items-center justify-center gap-2 border transition-all ${
                  targetType === 'FIXTURE'
                    ? 'bg-cyan-600/20 border-cyan-500 text-cyan-300 shadow-sm'
                    : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
                }`}
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>Pre-loaded Fixture</span>
              </button>

              <button
                type="button"
                onClick={() => setTargetType('GITHUB')}
                className={`px-3 py-2.5 rounded-xl text-xs font-mono font-medium flex items-center justify-center gap-2 border transition-all ${
                  targetType === 'GITHUB'
                    ? 'bg-cyan-600/20 border-cyan-500 text-cyan-300 shadow-sm'
                    : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
                }`}
              >
                <FolderGit2 className="w-3.5 h-3.5" />
                <span>GitHub HTTPS</span>
              </button>

              <button
                type="button"
                onClick={() => setTargetType('ZIP')}
                className={`px-3 py-2.5 rounded-xl text-xs font-mono font-medium flex items-center justify-center gap-2 border transition-all ${
                  targetType === 'ZIP'
                    ? 'bg-cyan-600/20 border-cyan-500 text-cyan-300 shadow-sm'
                    : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
                }`}
              >
                <FileArchive className="w-3.5 h-3.5" />
                <span>ZIP Upload</span>
              </button>
            </div>
          </div>

          {/* Intake Fields By Mode */}
          {targetType === 'FIXTURE' && (
            <div className="p-4 rounded-xl bg-slate-950/80 border border-cyan-900/30 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-cyan-300 font-mono flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4 text-cyan-400" />
                  intentionally-vulnerable-node-app
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/60">
                  Ready
                </span>
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                Pre-configured benchmark workspace loaded with verified security vulnerabilities
                (SQL Injection, Reflected XSS, and Dependency CVEs) designed for instant verification.
              </p>
              <div className="text-[10px] font-mono text-slate-500 pt-1 flex items-center gap-3">
                <span>Ref: <strong>main</strong></span>
                <span>•</span>
                <span>Path: <strong>fixtures/server.js</strong></span>
              </div>
            </div>
          )}

          {targetType === 'GITHUB' && (
            <div className="space-y-3">
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="block text-xs font-mono font-medium text-slate-400">
                    Repository URL (HTTPS Only)
                  </label>
                  <div className="flex items-center gap-2 text-[10px] font-mono text-cyan-400">
                    <span>Try example:</span>
                    <button
                      type="button"
                      onClick={() => handleSetExampleRepo('https://github.com/OWASP/NodeGoat')}
                      className="underline hover:text-cyan-300"
                    >
                      NodeGoat
                    </button>
                    <span>|</span>
                    <button
                      type="button"
                      onClick={() => handleSetExampleRepo('https://github.com/juice-shop/juice-shop')}
                      className="underline hover:text-cyan-300"
                    >
                      Juice-Shop
                    </button>
                  </div>
                </div>
                <input
                  type="text"
                  value={gitUrl}
                  onChange={(e) => setGitUrl(e.target.value)}
                  placeholder="https://github.com/org/repo"
                  className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 text-xs font-mono focus:border-cyan-500 focus:outline-none transition-colors"
                />
              </div>

              <div>
                <label className="block text-xs font-mono font-medium text-slate-400 mb-1.5">
                  Git Reference (Branch, Tag, or Commit SHA)
                </label>
                <input
                  type="text"
                  value={refName}
                  onChange={(e) => setRefName(e.target.value)}
                  placeholder="main"
                  className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 text-xs font-mono focus:border-cyan-500 focus:outline-none transition-colors"
                />
              </div>
            </div>
          )}

          {targetType === 'ZIP' && (
            <div className="space-y-3">
              <label className="block text-xs font-mono font-medium text-slate-400">
                Workspace Archive File (.zip)
              </label>
              <div className="p-4 rounded-xl border border-dashed border-slate-700 bg-slate-950/60 text-center hover:border-slate-600 transition-colors">
                <input
                  type="file"
                  accept=".zip"
                  onChange={handleZipChange}
                  className="block w-full text-xs text-slate-400 file:mr-4 file:py-1.5 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-semibold file:bg-cyan-600 file:text-white hover:file:bg-cyan-500 cursor-pointer"
                />
                {zipFile && (
                  <p className="mt-2 text-[11px] font-mono text-cyan-400">
                    Selected: {zipFile.name} ({(zipFile.size / 1024).toFixed(1)} KB)
                  </p>
                )}
              </div>
            </div>
          )}

          {/* Scanner Engines Selection */}
          <div className="pt-2 border-t border-slate-800/80">
            <label className="block text-xs font-mono font-medium text-slate-400 mb-2">
              Active Security Scanners
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              {[
                { id: 'semgrep', label: 'Semgrep SAST', desc: 'Rule-based AST scanning' },
                { id: 'npm-audit', label: 'npm Audit', desc: 'Known CVE dependency audit' },
                { id: 'patterns', label: 'Deterministic SAST', desc: 'Fast token & regex patterns' },
              ].map((engine) => {
                const active = selectedScanners.includes(engine.id);
                return (
                  <button
                    key={engine.id}
                    type="button"
                    onClick={() => toggleScanner(engine.id)}
                    className={`p-2.5 rounded-xl border text-left transition-all ${
                      active
                        ? 'bg-slate-800/90 border-cyan-500/80 text-slate-200'
                        : 'bg-slate-950/50 border-slate-800/80 text-slate-500 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between text-xs font-medium">
                      <span>{engine.label}</span>
                      <span
                        className={`w-2 h-2 rounded-full ${
                          active ? 'bg-cyan-400 ring-2 ring-cyan-400/30' : 'bg-slate-700'
                        }`}
                      />
                    </div>
                    <p className="text-[10px] text-slate-400 mt-0.5 truncate">{engine.desc}</p>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Action Button */}
          <div className="pt-3 flex items-center justify-between gap-4">
            <button
              type="button"
              onClick={handleStartScan}
              disabled={isScanning}
              className={`inline-flex items-center gap-2.5 px-5 py-2.5 rounded-xl text-xs font-semibold shadow-lg transition-all ${
                isScanning
                  ? 'bg-cyan-800/50 text-cyan-200 cursor-not-allowed'
                  : 'bg-cyan-600 hover:bg-cyan-500 active:scale-[0.98] text-white'
              }`}
            >
              {isScanning ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin text-cyan-300" />
                  <span>Executing Deterministic Scan...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>Start Deterministic Scan</span>
                </>
              )}
            </button>

            {isCompleted && (
              <button
                type="button"
                onClick={handleResetScan}
                className="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Reset</span>
              </button>
            )}
          </div>
        </div>

        {/* Right Column: Execution Stepper & Live Stage Status */}
        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 flex flex-col justify-between space-y-6">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-3 mb-4">
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                <span>Pipeline Stage Stepper</span>
              </h2>
              {isScanning && (
                <span className="flex items-center gap-1.5 text-[10px] font-mono text-cyan-400 animate-pulse">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                  Running
                </span>
              )}
            </div>

            <div className="space-y-4">
              {PIPELINE_STAGES.map((stage, idx) => {
                const status = getStageStatus(stage.key, activeStage, scanRecord?.status);
                return (
                  <div key={stage.key} className="flex items-start gap-3 relative">
                    {idx < PIPELINE_STAGES.length - 1 && (
                      <div
                        className={`absolute left-[13px] top-[26px] bottom-[-16px] w-[2px] transition-colors ${
                          status === 'completed' ? 'bg-cyan-500/80' : 'bg-slate-800'
                        }`}
                      />
                    )}
                    <div className="shrink-0 mt-0.5">
                      {status === 'completed' && (
                        <div className="w-7 h-7 rounded-full bg-emerald-950/80 border border-emerald-500/60 flex items-center justify-center text-emerald-400">
                          <CheckCircle2 className="w-4 h-4" />
                        </div>
                      )}
                      {status === 'active' && (
                        <div className="w-7 h-7 rounded-full bg-cyan-950/80 border border-cyan-500 flex items-center justify-center text-cyan-400">
                          <Loader2 className="w-4 h-4 animate-spin" />
                        </div>
                      )}
                      {status === 'failed' && (
                        <div className="w-7 h-7 rounded-full bg-red-950/80 border border-red-500 flex items-center justify-center text-red-400">
                          <AlertTriangle className="w-4 h-4" />
                        </div>
                      )}
                      {status === 'pending' && (
                        <div className="w-7 h-7 rounded-full bg-slate-950 border border-slate-800 flex items-center justify-center text-slate-600 font-mono text-[10px]">
                          {idx + 1}
                        </div>
                      )}
                    </div>

                    <div className="flex-1">
                      <div className="flex items-center justify-between">
                        <span
                          className={`text-xs font-semibold ${
                            status === 'active'
                              ? 'text-cyan-300 font-mono'
                              : status === 'completed'
                              ? 'text-slate-200'
                              : status === 'failed'
                              ? 'text-red-300'
                              : 'text-slate-500'
                          }`}
                        >
                          {stage.label}
                        </span>
                        <span className="text-[10px] font-mono uppercase text-slate-500">
                          {status}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 leading-tight mt-0.5">
                        {stage.description}
                      </p>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Quick Engine Diagnostics Callout */}
          <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/80 text-[11px] space-y-1">
            <div className="flex items-center justify-between font-mono text-[10px] text-slate-400">
              <span>SCAN ORCHESTRATOR</span>
              <span className="text-emerald-400">v1.0 ONLINE</span>
            </div>
            <p className="text-slate-500 text-[10px] leading-relaxed">
              Enforces non-zero exit resilience and canonical finding fingerprinting.
            </p>
          </div>
        </div>
      </div>

      {/* Explicit Asynchronous Scan State Presentation (Loading, Empty, Success, Partial Failure, Complete Failure, API Error, Retrying) */}
      <ScanStateView
        scanRecord={scanRecord}
        error={error}
        isScanning={isScanning}
        isRetrying={isRetrying}
        onRetry={handleRetryScan}
        onViewFindings={() =>
          navigate('/findings', {
            state: { scanId: scanRecord?.id, scanRecord },
          })
        }
        onReset={handleResetScan}
      />
    </div>
  );
}

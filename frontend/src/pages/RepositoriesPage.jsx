import { useState, useEffect } from 'react';
import { useNavigate, useOutletContext } from 'react-router-dom';
import {
  FolderGit2,
  Plus,
  ShieldCheck,
  Play,
  Upload,
  Globe,
  FileArchive,
  X,
  Loader2,
  CheckCircle2,
  AlertCircle,
  ExternalLink
} from 'lucide-react';
import { vulnexApi } from '../services/api';

const DEFAULT_REPOS = [
  {
    id: 'repo_fixture_01',
    displayName: 'intentionally-vulnerable-node-app',
    sourceType: 'LOCAL_FIXTURE',
    sanitizedSourceUrl: 'fixtures/intentionally-vulnerable-node-app',
    defaultRef: 'main',
    latestScanStatus: 'COMPLETED',
    findingsCount: 4,
    createdAt: new Date().toISOString()
  },
  {
    id: 'repo_01JAZZ80001',
    displayName: 'juice-shop-sample',
    sourceType: 'GITHUB',
    sanitizedSourceUrl: 'https://github.com/juice-shop/juice-shop',
    defaultRef: 'main',
    latestScanStatus: 'COMPLETED',
    findingsCount: 12,
    createdAt: new Date().toISOString()
  },
];

export default function RepositoriesPage() {
  const navigate = useNavigate();
  const { setActiveRepo } = useOutletContext() || {};
  const [repos, setRepos] = useState(DEFAULT_REPOS);
  const [loading, setLoading] = useState(false);
  const [isModalOpen, setIsModalOpen] = useState(false);

  // Form state
  const [sourceType, setSourceType] = useState('GITHUB'); // 'GITHUB' | 'ZIP_UPLOAD'
  const [displayName, setDisplayName] = useState('');
  const [sourceUrl, setSourceUrl] = useState('');
  const [defaultRef, setDefaultRef] = useState('main');
  const [zipBase64, setZipBase64] = useState('');
  const [zipFileName, setZipFileName] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formError, setFormError] = useState(null);
  const [formSuccess, setFormSuccess] = useState(null);

  const fetchRepositories = async () => {
    try {
      setLoading(true);
      const res = await vulnexApi.repositories.list();
      const list = Array.isArray(res) ? res : (res?.data || []);
      if (list.length > 0) {
        setRepos(list);
      }
    } catch (err) {
      console.warn('Could not load live repositories, using defaults:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRepositories();
  }, []);

  const handleZipFileChange = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setZipFileName(file.name);
    if (!displayName) {
      setDisplayName(file.name.replace(/\.[^/.]+$/, ''));
    }
    const reader = new FileReader();
    reader.onload = () => {
      const res = reader.result;
      const base64 = typeof res === 'string' ? res.split(',')[1] : '';
      setZipBase64(base64);
    };
    reader.readAsDataURL(file);
  };

  const handleRegisterSubmit = async (e) => {
    e.preventDefault();
    setFormError(null);
    setFormSuccess(null);

    if (!displayName.trim()) {
      setFormError('Display name is required.');
      return;
    }

    if (sourceType === 'GITHUB') {
      if (!sourceUrl.trim()) {
        setFormError('GitHub repository URL is required.');
        return;
      }
      if (!sourceUrl.startsWith('https://')) {
        setFormError('Repository URL must be a valid HTTPS Git URL.');
        return;
      }
    } else if (sourceType === 'ZIP_UPLOAD') {
      if (!zipBase64) {
        setFormError('Please select a valid ZIP archive to upload.');
        return;
      }
    }

    setIsSubmitting(true);
    try {
      const payload = {
        sourceType,
        displayName: displayName.trim(),
        defaultRef: defaultRef.trim() || 'main',
        ...(sourceType === 'GITHUB' ? { sourceUrl: sourceUrl.trim() } : {}),
        ...(sourceType === 'ZIP_UPLOAD' ? { zipBase64 } : {})
      };

      const res = await vulnexApi.repositories.register(payload);
      const newRepo = res?.data || res;
      setRepos((prev) => [newRepo, ...prev]);
      setFormSuccess('Repository registered successfully!');
      setTimeout(() => {
        setIsModalOpen(false);
        setFormSuccess(null);
        setDisplayName('');
        setSourceUrl('');
        setZipBase64('');
        setZipFileName('');
      }, 1200);
    } catch (err) {
      setFormError(err?.message || 'Failed to register repository.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleScanRepo = (repo) => {
    if (setActiveRepo) {
      setActiveRepo(repo);
    }
    navigate('/scan', {
      state: {
        repositoryId: repo.id,
        displayName: repo.displayName,
        sourceType: repo.sourceType,
        sourceUrl: repo.sanitizedSourceUrl,
        defaultRef: repo.defaultRef || 'main'
      }
    });
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold text-slate-100">Repositories</h1>
          <p className="text-xs text-slate-400 mt-1">
            Manage target repositories, branches, and bounded scan workspaces
          </p>
        </div>
        <button
          onClick={() => {
            setFormError(null);
            setFormSuccess(null);
            setIsModalOpen(true);
          }}
          className="inline-flex items-center gap-2 px-3.5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-md transition-all cursor-pointer"
        >
          <Plus className="w-4 h-4" />
          <span>Register Repository</span>
        </button>
      </div>

      {/* Repositories Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {repos.map((repo) => (
          <div
            key={repo.id}
            className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition-all flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2 font-mono text-xs text-cyan-400">
                  <FolderGit2 className="w-4 h-4" />
                  <span className="font-semibold text-slate-200">{repo.displayName}</span>
                </div>
                <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                  {repo.sourceType}
                </span>
              </div>
              <div className="text-xs font-mono text-slate-400 truncate mb-4" title={repo.sanitizedSourceUrl}>
                {repo.sanitizedSourceUrl || repo.sourceUrl || 'Local Workspace Snapshot'}
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono">
              <span className="text-slate-400">
                Findings: <strong className="text-red-400">{repo.findingsCount ?? 0}</strong>
              </span>
              <div className="flex items-center gap-3">
                <span className="text-emerald-400 flex items-center gap-1">
                  <ShieldCheck className="w-3.5 h-3.5" />
                  {repo.latestScanStatus || 'READY'}
                </span>
                <button
                  type="button"
                  onClick={() => handleScanRepo(repo)}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-400 border border-cyan-800 text-[11px] font-semibold transition-colors"
                >
                  <Play className="w-3 h-3" />
                  <span>Scan</span>
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Register Repository Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fadeIn">
          <div className="w-full max-w-lg rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl p-6 space-y-5">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <FolderGit2 className="w-5 h-5 text-cyan-400" />
                <h2 className="text-base font-bold text-slate-100">Register Repository Intake</h2>
              </div>
              <button
                type="button"
                onClick={() => setIsModalOpen(false)}
                className="p-1 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {formError && (
              <div className="p-3 rounded-xl bg-red-950/50 border border-red-800 text-red-300 text-xs font-mono flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0 text-red-400" />
                <span>{formError}</span>
              </div>
            )}

            {formSuccess && (
              <div className="p-3 rounded-xl bg-emerald-950/50 border border-emerald-800 text-emerald-300 text-xs font-mono flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
                <span>{formSuccess}</span>
              </div>
            )}

            <form onSubmit={handleRegisterSubmit} className="space-y-4 text-xs font-mono">
              {/* Intake Source Tabs */}
              <div className="flex rounded-xl bg-slate-950 p-1 border border-slate-800">
                <button
                  type="button"
                  onClick={() => setSourceType('GITHUB')}
                  className={`flex-1 flex items-center justify-center gap-2 py-2 rounded-lg font-medium transition-all ${
                    sourceType === 'GITHUB'
                      ? 'bg-cyan-600 text-white font-semibold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Globe className="w-3.5 h-3.5" />
                  <span>GitHub Repository</span>
                </button>
                <button
                  type="button"
                  onClick={() => setSourceType('ZIP_UPLOAD')}
                  className={`flex-1 flex items-center justify-center gap-2 py-2 rounded-lg font-medium transition-all ${
                    sourceType === 'ZIP_UPLOAD'
                      ? 'bg-cyan-600 text-white font-semibold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <FileArchive className="w-3.5 h-3.5" />
                  <span>ZIP Archive Upload</span>
                </button>
              </div>

              {/* Display Name */}
              <div>
                <label className="block text-slate-300 mb-1 font-semibold">Display Name *</label>
                <input
                  type="text"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder="e.g. backend-api-service"
                  className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>

              {/* GitHub URL Inputs */}
              {sourceType === 'GITHUB' && (
                <>
                  <div>
                    <label className="block text-slate-300 mb-1 font-semibold">GitHub HTTPS URL *</label>
                    <input
                      type="url"
                      value={sourceUrl}
                      onChange={(e) => setSourceUrl(e.target.value)}
                      placeholder="https://github.com/organization/repository"
                      className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500"
                      required
                    />
                  </div>
                  <div>
                    <label className="block text-slate-300 mb-1 font-semibold">Target Branch / Ref</label>
                    <input
                      type="text"
                      value={defaultRef}
                      onChange={(e) => setDefaultRef(e.target.value)}
                      placeholder="main"
                      className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                </>
              )}

              {/* ZIP Upload Input */}
              {sourceType === 'ZIP_UPLOAD' && (
                <div>
                  <label className="block text-slate-300 mb-1 font-semibold">Archive File (.zip) *</label>
                  <div className="border-2 border-dashed border-slate-800 rounded-xl p-4 text-center hover:border-slate-700 transition-colors bg-slate-950/50">
                    <input
                      type="file"
                      id="zip-upload-modal"
                      accept=".zip"
                      onChange={handleZipFileChange}
                      className="hidden"
                    />
                    <label htmlFor="zip-upload-modal" className="cursor-pointer space-y-2 block">
                      <Upload className="w-6 h-6 text-slate-500 mx-auto" />
                      <div className="text-slate-300 text-xs">
                        {zipFileName ? (
                          <span className="text-cyan-400 font-semibold">{zipFileName}</span>
                        ) : (
                          <span>Click to browse ZIP archive</span>
                        )}
                      </div>
                      <div className="text-[10px] text-slate-500">Max size: 25MB • Path traversal safe</div>
                    </label>
                  </div>
                </div>
              )}

              {/* Actions */}
              <div className="pt-3 border-t border-slate-800 flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 text-white font-semibold transition-colors shadow-md"
                >
                  {isSubmitting ? (
                    <>
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      <span>Registering...</span>
                    </>
                  ) : (
                    <span>Register</span>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

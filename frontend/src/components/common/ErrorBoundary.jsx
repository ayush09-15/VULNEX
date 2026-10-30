import { Component } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

export class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('[VULNEX UI Crash Caught]:', error, errorInfo);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-slate-950 flex items-center justify-center p-6">
          <div className="max-w-md w-full bg-slate-900 border border-red-900/40 rounded-2xl p-6 text-center shadow-2xl">
            <div className="w-12 h-12 bg-red-950/60 border border-red-800/60 rounded-xl flex items-center justify-center mx-auto mb-4 text-red-400">
              <AlertTriangle className="w-6 h-6" />
            </div>
            <h2 className="text-xl font-bold text-slate-100 mb-2">Security Console Exception</h2>
            <p className="text-sm text-slate-400 mb-6">
              An unexpected interface error occurred. Internal security boundaries remain uncompromised.
            </p>
            <div className="text-left bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-xs text-red-300 mb-6 overflow-x-auto">
              {this.state.error?.message || 'Unknown component crash'}
            </div>
            <button
              onClick={this.handleReset}
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-sm transition-colors focus:ring-2 focus:ring-cyan-400 focus:outline-none"
            >
              <RefreshCw className="w-4 h-4" />
              Reload Console
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;

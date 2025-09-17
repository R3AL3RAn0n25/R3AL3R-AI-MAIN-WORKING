
import React, { useState } from 'react';

interface LoginViewProps {
  onLogin: (username: string, password: string) => Promise<void>;
  error: string | null;
  isLoading: boolean;
}

const LoginView: React.FC<LoginViewProps> = ({ onLogin, error, isLoading }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (username && password) {
      onLogin(username, password);
    }
  };

  return (
    <div className="w-full max-w-md p-8 bg-black bg-opacity-80 border border-[#050] rounded-lg shadow-[0_0_15px_rgba(0,255,0,0.2)]">
      <h1 className="text-3xl text-center mb-6 text-shadow">R3ÆLƎR AI</h1>
      <h2 className="text-xl text-center mb-8 text-shadow">System Access</h2>
      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="form-section">
          <input
            type="text"
            id="username"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full p-3 bg-[#010] border border-[#050] rounded-md focus:outline-none focus:border-[#0f0] focus:shadow-[0_0_5px_rgba(0,255,0,0.5)] transition-all duration-300"
            autoComplete="username"
            disabled={isLoading}
          />
        </div>
        <div className="form-section">
          <input
            type="password"
            id="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full p-3 bg-[#010] border border-[#050] rounded-md focus:outline-none focus:border-[#0f0] focus:shadow-[0_0_5px_rgba(0,255,0,0.5)] transition-all duration-300"
            autoComplete="current-password"
            disabled={isLoading}
          />
        </div>
        <button
          type="submit"
          disabled={isLoading || !username || !password}
          className="w-full p-3 bg-[#050] font-bold rounded-md hover:bg-[#080] hover:text-white disabled:bg-[#030] disabled:text-[#090] disabled:cursor-not-allowed transition-all duration-300"
        >
          {isLoading ? 'Authenticating...' : '[ Login ]'}
        </button>
      </form>
      {error && (
        <div className="mt-4 p-3 bg-red-900 border border-red-500 rounded-md text-red-300 text-center">
          <p>// ERROR: {error}</p>
        </div>
      )}
    </div>
  );
};

export default LoginView;

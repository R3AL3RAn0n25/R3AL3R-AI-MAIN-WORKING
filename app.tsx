
import React, { useState, useEffect, useCallback } from 'react';
import LoginView from './components/LoginView';
import MainView from './components/MainView';
import MatrixRain from './components/MatrixRain';
import { login as apiLogin } from './services/apiService';

const App: React.FC = () => {
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [isLoggingIn, setIsLoggingIn] = useState<boolean>(false);

  useEffect(() => {
    const storedToken = localStorage.getItem('authToken');
    if (storedToken) {
      setToken(storedToken);
    }
    setIsLoading(false);
  }, []);

  const handleLogin = async (username: string, password: string): Promise<void> => {
    setIsLoggingIn(true);
    setError(null);
    try {
      const result = await apiLogin(username, password);
      if (result && result.token) {
        setToken(result.token);
        localStorage.setItem('authToken', result.token);
      } else {
        throw new Error(result.error || 'Login failed: No token received.');
      }
    } catch (err: any) {
      setError(err.message || 'An unknown error occurred during login.');
    } finally {
      setIsLoggingIn(false);
    }
  };

  const handleLogout = useCallback(() => {
    setToken(null);
    localStorage.removeItem('authToken');
  }, []);

  if (isLoading) {
    return (
      <div className="w-screen h-screen bg-black flex items-center justify-center text-[#0f0] font-mono">
        INITIALIZING R3ÆLƎR AI...
      </div>
    );
  }

  return (
    <div className="relative w-screen h-screen overflow-hidden bg-black text-[#0f0] font-mono">
      <MatrixRain />
      <main className="relative z-10 w-full h-full flex items-center justify-center p-4">
        {token ? (
          <MainView token={token} onLogout={handleLogout} />
        ) : (
          <LoginView onLogin={handleLogin} error={error} isLoading={isLoggingIn} />
        )}
      </main>
    </div>
  );
};

export default App;

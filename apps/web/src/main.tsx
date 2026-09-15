/**
 * Browser entry point.
 */

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App.js';
import { initTheme } from './lib/theme.js';
import './styles/system.css';

// Before the first render: public/theme.js has already set the attribute, this picks up
// the browser chrome colour and starts listening for the OS switching under 'system'.
initTheme();

const container = document.getElementById('root');
if (!container) throw new Error('Root element missing');

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);

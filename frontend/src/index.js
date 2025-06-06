import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';  // your Tailwind or custom styles
import Dashboard from './App';  // ✅ Now points to Dashboard.js

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <Dashboard /> {/* Ensure you're rendering Dashboard */}
  </React.StrictMode>
);

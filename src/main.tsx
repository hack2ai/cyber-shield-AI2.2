import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'
import { AuthProvider } from './components/AuthProvider'
import { startDashboardSync } from './lib/dashboard-sync'

const stopDashboardSync = startDashboardSync(5000)

window.addEventListener('beforeunload', stopDashboardSync, { once: true })

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <AuthProvider>
      <App />
    </AuthProvider>
  </React.StrictMode>,
)

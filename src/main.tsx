import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '@fontsource-variable/inter'
import '@/components/arc/foundation.css'
import './index.css'
import './app.css'
import App from './App'
import { LangProvider } from '@/lib/i18n'
import { langOf, prefLang, withLang } from '@/lib/router'

if (!langOf()) history.replaceState(null, '', withLang(location.pathname, prefLang()) + location.search)

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <LangProvider><App /></LangProvider>
  </StrictMode>,
)

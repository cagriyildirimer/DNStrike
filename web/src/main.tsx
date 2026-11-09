import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import { AuthGate } from './components/AuthGate'
import './styles.css'

const queryClient=new QueryClient({defaultOptions:{queries:{retry:1,staleTime:10_000}}})
createRoot(document.getElementById('root')!).render(<StrictMode><QueryClientProvider client={queryClient}><BrowserRouter><AuthGate>{logout=><App onLogout={logout}/>}</AuthGate></BrowserRouter></QueryClientProvider></StrictMode>)

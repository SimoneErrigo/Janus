import { lazy } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { hasToken } from './api'
import Layout from './components/Layout'
import Login from './pages/Login'

const Services = lazy(() => import('./pages/Services'))
const Traffic = lazy(() => import('./pages/Traffic'))
const Rules = lazy(() => import('./pages/Rules'))
const Alerts = lazy(() => import('./pages/Alerts'))
const Blocks = lazy(() => import('./pages/Blocks'))
const Config = lazy(() => import('./pages/Config'))
const System = lazy(() => import('./pages/System'))
const SavedFlows = lazy(() => import('./pages/SavedFlows'))
const RoundDiff = lazy(() => import('./pages/RoundDiff'))
const Protocols = lazy(() => import('./pages/Protocols'))
const FilterSandbox = lazy(() => import('./pages/FilterSandbox'))
const PyFilters = lazy(() => import('./pages/PyFilters'))

function ProtectedRoute({ children }) {
  if (!hasToken()) return <Navigate to="/login" replace />
  return children
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/" element={<ProtectedRoute><Layout /></ProtectedRoute>}>
        <Route index element={<Navigate to="/services" replace />} />
        <Route path="services" element={<Services />} />
        <Route path="traffic" element={<Traffic />} />
        <Route path="rules" element={<Rules />} />
        <Route path="pyfilters" element={<PyFilters />} />
        <Route path="protocols" element={<Protocols />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="blocks" element={<Blocks />} />
        <Route path="saved-flows" element={<SavedFlows />} />
        <Route path="round-diff" element={<RoundDiff />} />
        <Route path="system" element={<System />} />
        <Route path="config" element={<Config />} />
        <Route path="filter-sandbox" element={<FilterSandbox />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

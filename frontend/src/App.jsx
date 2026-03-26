import { Routes, Route, Navigate } from 'react-router-dom'
import { hasToken } from './api'
import Layout from './components/Layout'
import Login from './pages/Login'
import Services from './pages/Services'
import Traffic from './pages/Traffic'
import Rules from './pages/Rules'
import Alerts from './pages/Alerts'
import Config from './pages/Config'
import System from './pages/System'

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
        <Route path="alerts" element={<Alerts />} />
        <Route path="system" element={<System />} />
        <Route path="config" element={<Config />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

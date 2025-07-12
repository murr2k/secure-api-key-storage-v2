'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/lib/auth-context'
import { DashboardLayout } from '@/components/layout/dashboard-layout'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api-client'
import { 
  FileText,
  Filter,
  Download,
  Clock,
  User,
  Key,
  Shield,
  Activity,
  AlertCircle,
  CheckCircle,
  XCircle
} from 'lucide-react'

interface AuditLogEntry {
  id: string
  timestamp: string
  action: string
  key_name?: string
  user: string
  ip_address?: string
  details: Record<string, any>
}

const actionIcons: Record<string, any> = {
  key_created: { icon: CheckCircle, color: 'text-green-500' },
  key_accessed: { icon: Eye, color: 'text-blue-500' },
  key_updated: { icon: Activity, color: 'text-yellow-500' },
  key_deleted: { icon: XCircle, color: 'text-red-500' },
  key_rotated: { icon: RefreshCw, color: 'text-purple-500' },
  login_success: { icon: Shield, color: 'text-green-500' },
  login_failed: { icon: AlertCircle, color: 'text-red-500' },
}

// Import additional icons
import { Eye, RefreshCw } from 'lucide-react'

export default function AuditPage() {
  const { user, isLoading: authLoading } = useAuth()
  const router = useRouter()
  const [selectedAction, setSelectedAction] = useState<string>('')
  const [searchKeyName, setSearchKeyName] = useState('')
  const [dateRange, setDateRange] = useState({ start: '', end: '' })
  const [isConnected, setIsConnected] = useState(false)

  useEffect(() => {
    if (!authLoading && !user) {
      router.push('/login')
    }
  }, [user, authLoading, router])

  const { data: logs, isLoading, refetch } = useQuery({
    queryKey: ['audit-logs', selectedAction, searchKeyName],
    queryFn: async () => {
      const response = await api.audit.list({
        action: selectedAction || undefined,
        key_name: searchKeyName || undefined,
        limit: 100
      })
      return response.data
    },
    enabled: !!user,
    refetchInterval: 30000 // Refresh every 30 seconds
  })

  // WebSocket connection for real-time updates
  useEffect(() => {
    if (!user) return

    const connectWebSocket = () => {
      const ws = new WebSocket(`ws://localhost:8000/api/audit/stream`)

      ws.onopen = () => {
        console.log('WebSocket connected')
        setIsConnected(true)
      }

      ws.onmessage = (event) => {
        const newLog = JSON.parse(event.data)
        console.log('New audit log:', newLog)
        // Refetch to update the list
        refetch()
      }

      ws.onclose = () => {
        console.log('WebSocket disconnected')
        setIsConnected(false)
        // Reconnect after 5 seconds
        setTimeout(connectWebSocket, 5000)
      }

      ws.onerror = (error) => {
        console.error('WebSocket error:', error)
      }

      return ws
    }

    const ws = connectWebSocket()

    return () => {
      ws.close()
    }
  }, [user, refetch])

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp)
    const now = new Date()
    const diff = now.getTime() - date.getTime()
    const minutes = Math.floor(diff / 60000)
    const hours = Math.floor(diff / 3600000)
    const days = Math.floor(diff / 86400000)

    if (minutes < 1) return 'Just now'
    if (minutes < 60) return `${minutes}m ago`
    if (hours < 24) return `${hours}h ago`
    if (days < 7) return `${days}d ago`
    return date.toLocaleDateString()
  }

  const getActionLabel = (action: string) => {
    return action.split('_').map((word: string) => 
      word.charAt(0).toUpperCase() + word.slice(1)
    ).join(' ')
  }

  const exportLogs = () => {
    const dataStr = JSON.stringify(logs, null, 2)
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr)
    
    const exportFileDefaultName = `audit-logs-${new Date().toISOString().split('T')[0]}.json`
    
    const linkElement = document.createElement('a')
    linkElement.setAttribute('href', dataUri)
    linkElement.setAttribute('download', exportFileDefaultName)
    linkElement.click()
  }

  if (authLoading || !user) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
      </div>
    )
  }

  const uniqueActions: string[] = Array.from(new Set(logs?.map((log: AuditLogEntry) => log.action) || []))

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Audit Logs</h1>
            <p className="text-muted-foreground mt-2">
              Track all activities and access to your API keys
            </p>
          </div>
          <div className="flex items-center gap-3">
            <div className={`flex items-center gap-2 px-3 py-1 rounded-full text-sm ${
              isConnected ? 'bg-green-500/10 text-green-500' : 'bg-red-500/10 text-red-500'
            }`}>
              <div className={`h-2 w-2 rounded-full ${
                isConnected ? 'bg-green-500' : 'bg-red-500'
              }`} />
              {isConnected ? 'Live' : 'Offline'}
            </div>
            <button
              onClick={exportLogs}
              className="inline-flex items-center px-4 py-2 border rounded-md hover:bg-accent"
              disabled={!logs || logs.length === 0}
            >
              <Download className="h-4 w-4 mr-2" />
              Export
            </button>
          </div>
        </div>

        {/* Filters */}
        <div className="bg-card rounded-lg border p-4">
          <div className="flex items-center gap-2 mb-3">
            <Filter className="h-4 w-4 text-muted-foreground" />
            <span className="font-medium">Filters</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium mb-1">Action Type</label>
              <select
                value={selectedAction}
                onChange={(e) => setSelectedAction(e.target.value)}
                className="w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-primary"
              >
                <option value="">All Actions</option>
                {uniqueActions.map((action: string) => (
                  <option key={action} value={action}>
                    {getActionLabel(action)}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Key Name</label>
              <input
                type="text"
                placeholder="Search by key name..."
                value={searchKeyName}
                onChange={(e) => setSearchKeyName(e.target.value)}
                className="w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-primary"
              />
            </div>
            <div className="flex items-end">
              <button
                onClick={() => {
                  setSelectedAction('')
                  setSearchKeyName('')
                }}
                className="px-4 py-2 text-sm text-muted-foreground hover:text-foreground"
              >
                Clear Filters
              </button>
            </div>
          </div>
        </div>

        {/* Logs Timeline */}
        <div className="space-y-4">
          {isLoading ? (
            <div className="text-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto"></div>
            </div>
          ) : logs?.length === 0 ? (
            <div className="text-center py-12 bg-card rounded-lg border">
              <FileText className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
              <h3 className="text-lg font-semibold mb-2">No audit logs found</h3>
              <p className="text-muted-foreground">
                {selectedAction || searchKeyName ? 'Try adjusting your filters' : 'Activities will appear here'}
              </p>
            </div>
          ) : (
            <div className="relative">
              {/* Timeline line */}
              <div className="absolute left-8 top-0 bottom-0 w-0.5 bg-border" />
              
              {logs?.map((log: AuditLogEntry, index: number) => {
                const actionConfig = actionIcons[log.action] || { 
                  icon: Activity, 
                  color: 'text-muted-foreground' 
                }
                const Icon = actionConfig.icon

                return (
                  <div key={log.id} className="relative flex gap-4 pb-8">
                    {/* Timeline dot */}
                    <div className={`relative z-10 flex h-16 w-16 items-center justify-center rounded-full bg-background border-2 ${
                      index === 0 ? 'border-primary' : 'border-border'
                    }`}>
                      <Icon className={`h-6 w-6 ${actionConfig.color}`} />
                    </div>
                    
                    {/* Log content */}
                    <div className="flex-1 bg-card rounded-lg border p-4">
                      <div className="flex items-start justify-between mb-2">
                        <div>
                          <h4 className="font-semibold">{getActionLabel(log.action)}</h4>
                          <div className="flex items-center gap-4 mt-1 text-sm text-muted-foreground">
                            <span className="flex items-center gap-1">
                              <Clock className="h-3 w-3" />
                              {formatTimestamp(log.timestamp)}
                            </span>
                            <span className="flex items-center gap-1">
                              <User className="h-3 w-3" />
                              {log.user}
                            </span>
                            {log.ip_address && (
                              <span>IP: {log.ip_address}</span>
                            )}
                          </div>
                        </div>
                      </div>
                      
                      {log.key_name && (
                        <div className="inline-flex items-center gap-1 px-2 py-1 bg-primary/10 text-primary rounded-md text-sm mb-2">
                          <Key className="h-3 w-3" />
                          {log.key_name}
                        </div>
                      )}
                      
                      {Object.keys(log.details).length > 0 && (
                        <details className="mt-3">
                          <summary className="cursor-pointer text-sm text-muted-foreground hover:text-foreground">
                            View Details
                          </summary>
                          <pre className="mt-2 text-xs bg-muted p-2 rounded overflow-auto">
                            {JSON.stringify(log.details, null, 2)}
                          </pre>
                        </details>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>
    </DashboardLayout>
  )
}
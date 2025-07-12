'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/lib/auth-context'
import { DashboardLayout } from '@/components/layout/dashboard-layout'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api-client'
import { 
  Key, 
  Plus, 
  Search, 
  Copy, 
  Trash2, 
  RefreshCw,
  Eye,
  EyeOff,
  Shield,
  Calendar,
  MoreVertical 
} from 'lucide-react'
import toast from 'react-hot-toast'

interface ApiKey {
  id: string
  name: string
  service?: string
  description?: string
  created_at: string
  updated_at: string
  last_accessed?: string
  rotation_due?: string
}

export default function KeysPage() {
  const { user, isLoading: authLoading } = useAuth()
  const router = useRouter()
  const queryClient = useQueryClient()
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedService, setSelectedService] = useState<string>('')
  const [showAddModal, setShowAddModal] = useState(false)
  const [editingKey, setEditingKey] = useState<ApiKey | null>(null)

  useEffect(() => {
    if (!authLoading && !user) {
      router.push('/login')
    }
  }, [user, authLoading, router])

  const { data: keys, isLoading } = useQuery({
    queryKey: ['keys', searchTerm, selectedService],
    queryFn: async () => {
      const response = await api.keys.list({
        search: searchTerm || undefined,
        service: selectedService || undefined
      })
      return response.data
    },
    enabled: !!user,
  })

  const deleteMutation = useMutation({
    mutationFn: (keyId: string) => api.keys.delete(keyId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['keys'] })
      toast.success('Key deleted successfully')
    },
    onError: () => {
      toast.error('Failed to delete key')
    }
  })

  const copyKeyMutation = useMutation({
    mutationFn: (keyId: string) => api.keys.copy(keyId),
    onSuccess: async (response) => {
      await navigator.clipboard.writeText(response.data.key)
      toast.success('Key copied to clipboard')
    },
    onError: () => {
      toast.error('Failed to copy key')
    }
  })

  const rotateKeyMutation = useMutation({
    mutationFn: (keyId: string) => api.keys.rotate(keyId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['keys'] })
      toast.success('Key rotated successfully')
    },
    onError: () => {
      toast.error('Failed to rotate key')
    }
  })

  const services: string[] = Array.from(new Set(keys?.map((k: ApiKey) => k.service).filter(Boolean) || [])) as string[]

  if (authLoading || !user) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
      </div>
    )
  }

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">API Keys</h1>
            <p className="text-muted-foreground mt-2">
              Manage your encrypted API keys across all services
            </p>
          </div>
          <button
            onClick={() => setShowAddModal(true)}
            className="inline-flex items-center px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2"
          >
            <Plus className="h-5 w-5 mr-2" />
            Add Key
          </button>
        </div>

        {/* Filters */}
        <div className="flex gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search keys..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10 pr-4 py-2 w-full border rounded-md focus:outline-none focus:ring-2 focus:ring-primary"
            />
          </div>
          <select
            value={selectedService}
            onChange={(e) => setSelectedService(e.target.value)}
            className="px-4 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-primary"
          >
            <option value="">All Services</option>
            {services.map((service: string) => (
              <option key={service} value={service}>{service}</option>
            ))}
          </select>
        </div>

        {/* Keys List */}
        <div className="space-y-4">
          {isLoading ? (
            <div className="text-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto"></div>
            </div>
          ) : keys?.length === 0 ? (
            <div className="text-center py-12 bg-card rounded-lg border">
              <Key className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
              <h3 className="text-lg font-semibold mb-2">No keys found</h3>
              <p className="text-muted-foreground">
                {searchTerm || selectedService ? 'Try adjusting your filters' : 'Add your first API key to get started'}
              </p>
            </div>
          ) : (
            keys?.map((key: ApiKey) => (
              <div key={key.id} className="bg-card rounded-lg border p-6">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <h3 className="text-lg font-semibold">{key.name}</h3>
                      {key.service && (
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-primary/10 text-primary">
                          <Shield className="h-3 w-3 mr-1" />
                          {key.service}
                        </span>
                      )}
                    </div>
                    {key.description && (
                      <p className="text-muted-foreground text-sm mb-3">{key.description}</p>
                    )}
                    <div className="flex items-center gap-4 text-sm text-muted-foreground">
                      <span className="flex items-center gap-1">
                        <Calendar className="h-3 w-3" />
                        Created: {new Date(key.created_at).toLocaleDateString()}
                      </span>
                      {key.last_accessed && (
                        <span>Last used: {new Date(key.last_accessed).toLocaleDateString()}</span>
                      )}
                      {key.rotation_due && (
                        <span className="text-warning">
                          Rotation due: {new Date(key.rotation_due).toLocaleDateString()}
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => copyKeyMutation.mutate(key.id)}
                      className="p-2 text-muted-foreground hover:text-foreground hover:bg-accent rounded-md"
                      title="Copy key"
                    >
                      <Copy className="h-4 w-4" />
                    </button>
                    <button
                      onClick={() => rotateKeyMutation.mutate(key.id)}
                      className="p-2 text-muted-foreground hover:text-foreground hover:bg-accent rounded-md"
                      title="Rotate key"
                    >
                      <RefreshCw className="h-4 w-4" />
                    </button>
                    <button
                      onClick={() => {
                        if (confirm('Are you sure you want to delete this key?')) {
                          deleteMutation.mutate(key.id)
                        }
                      }}
                      className="p-2 text-destructive hover:bg-destructive/10 rounded-md"
                      title="Delete key"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Add/Edit Modal */}
      {showAddModal && <AddKeyModal onClose={() => setShowAddModal(false)} />}
    </DashboardLayout>
  )
}

// Add Key Modal Component
function AddKeyModal({ onClose }: { onClose: () => void }) {
  const queryClient = useQueryClient()
  const [formData, setFormData] = useState({
    name: '',
    value: '',
    service: '',
    description: ''
  })
  const [showPassword, setShowPassword] = useState(false)

  const createMutation = useMutation({
    mutationFn: (data: typeof formData) => api.keys.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['keys'] })
      toast.success('Key added successfully')
      onClose()
    },
    onError: () => {
      toast.error('Failed to add key')
    }
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!formData.name || !formData.value) {
      toast.error('Name and value are required')
      return
    }
    createMutation.mutate(formData)
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
      <div className="bg-background rounded-lg p-6 w-full max-w-md">
        <h2 className="text-xl font-semibold mb-4">Add New API Key</h2>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1">Key Name *</label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className="w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-primary"
              placeholder="e.g., OpenAI Production"
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">API Key Value *</label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={formData.value}
                onChange={(e) => setFormData({ ...formData, value: e.target.value })}
                className="w-full px-3 py-2 pr-10 border rounded-md focus:outline-none focus:ring-2 focus:ring-primary"
                placeholder="sk-..."
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-2 top-1/2 transform -translate-y-1/2 text-muted-foreground hover:text-foreground"
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Service</label>
            <input
              type="text"
              value={formData.service}
              onChange={(e) => setFormData({ ...formData, service: e.target.value })}
              className="w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-primary"
              placeholder="e.g., OpenAI, AWS, GitHub"
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Description</label>
            <textarea
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              className="w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-primary"
              rows={3}
              placeholder="Optional description..."
            />
          </div>
          <div className="flex gap-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 border rounded-md hover:bg-accent"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={createMutation.isPending}
              className="flex-1 px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
            >
              {createMutation.isPending ? 'Adding...' : 'Add Key'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
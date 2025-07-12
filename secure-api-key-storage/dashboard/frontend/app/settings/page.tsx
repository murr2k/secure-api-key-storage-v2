'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/lib/auth-context'
import { DashboardLayout } from '@/components/layout/dashboard-layout'
import { 
  Settings,
  Shield,
  Key,
  Bell,
  Clock,
  Download,
  Upload,
  Save,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  Smartphone,
  Lock,
  Database,
  FileText
} from 'lucide-react'
import toast from 'react-hot-toast'

interface SettingsSection {
  id: string
  title: string
  description: string
  icon: any
}

const settingsSections: SettingsSection[] = [
  {
    id: 'security',
    title: 'Security Settings',
    description: 'Configure authentication and encryption settings',
    icon: Shield
  },
  {
    id: 'rotation',
    title: 'Key Rotation',
    description: 'Set up automatic key rotation policies',
    icon: RefreshCw
  },
  {
    id: 'notifications',
    title: 'Notifications',
    description: 'Manage alerts and notification preferences',
    icon: Bell
  },
  {
    id: 'backup',
    title: 'Backup & Export',
    description: 'Configure backup schedules and export data',
    icon: Database
  }
]

export default function SettingsPage() {
  const { user, isLoading: authLoading } = useAuth()
  const router = useRouter()
  const [activeSection, setActiveSection] = useState('security')
  const [isSaving, setIsSaving] = useState(false)

  // Settings state
  const [settings, setSettings] = useState({
    // Security
    enable2FA: false,
    sessionTimeout: 30,
    requireStrongPasswords: true,
    enableCertificateAuth: false,
    
    // Key Rotation
    autoRotate: false,
    rotationDays: 90,
    notifyBeforeRotation: 7,
    
    // Notifications
    emailNotifications: true,
    notifyOnAccess: false,
    notifyOnRotation: true,
    notifyOnFailedAttempts: true,
    
    // Backup
    autoBackup: false,
    backupFrequency: 'daily',
    backupRetention: 30,
    encryptBackups: true
  })

  useEffect(() => {
    if (!authLoading && !user) {
      router.push('/login')
    }
  }, [user, authLoading, router])

  const handleSaveSettings = async () => {
    setIsSaving(true)
    try {
      // In a real app, this would save to the backend
      await new Promise(resolve => setTimeout(resolve, 1000))
      toast.success('Settings saved successfully')
    } catch (error) {
      toast.error('Failed to save settings')
    } finally {
      setIsSaving(false)
    }
  }

  const handleExportData = () => {
    const dataStr = JSON.stringify({
      settings,
      exportDate: new Date().toISOString(),
      version: '1.0'
    }, null, 2)
    
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr)
    const exportFileDefaultName = `secure-keys-backup-${new Date().toISOString().split('T')[0]}.json`
    
    const linkElement = document.createElement('a')
    linkElement.setAttribute('href', dataUri)
    linkElement.setAttribute('download', exportFileDefaultName)
    linkElement.click()
    
    toast.success('Data exported successfully')
  }

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
            <h1 className="text-3xl font-bold tracking-tight">Settings</h1>
            <p className="text-muted-foreground mt-2">
              Configure your secure key storage preferences
            </p>
          </div>
          <button
            onClick={handleSaveSettings}
            disabled={isSaving}
            className="inline-flex items-center px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50"
          >
            {isSaving ? (
              <>
                <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                Saving...
              </>
            ) : (
              <>
                <Save className="h-4 w-4 mr-2" />
                Save Changes
              </>
            )}
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Sidebar Navigation */}
          <div className="space-y-1">
            {settingsSections.map((section) => {
              const Icon = section.icon
              return (
                <button
                  key={section.id}
                  onClick={() => setActiveSection(section.id)}
                  className={`w-full flex items-center gap-3 px-4 py-3 rounded-md text-left transition-colors ${
                    activeSection === section.id
                      ? 'bg-primary/10 text-primary'
                      : 'hover:bg-accent'
                  }`}
                >
                  <Icon className="h-5 w-5" />
                  <div>
                    <div className="font-medium">{section.title}</div>
                    <div className="text-xs text-muted-foreground">
                      {section.description}
                    </div>
                  </div>
                </button>
              )
            })}
          </div>

          {/* Settings Content */}
          <div className="lg:col-span-3 space-y-6">
            {/* Security Settings */}
            {activeSection === 'security' && (
              <div className="space-y-6">
                <div className="bg-card rounded-lg border p-6">
                  <h2 className="text-xl font-semibold mb-4">Authentication</h2>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="font-medium">Two-Factor Authentication</h3>
                        <p className="text-sm text-muted-foreground">
                          Add an extra layer of security with TOTP
                        </p>
                      </div>
                      <button
                        onClick={() => setSettings({ ...settings, enable2FA: !settings.enable2FA })}
                        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                          settings.enable2FA ? 'bg-primary' : 'bg-input'
                        }`}
                      >
                        <span
                          className={`inline-block h-4 w-4 transform rounded-full bg-background transition-transform ${
                            settings.enable2FA ? 'translate-x-6' : 'translate-x-1'
                          }`}
                        />
                      </button>
                    </div>

                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="font-medium">Certificate Authentication</h3>
                        <p className="text-sm text-muted-foreground">
                          Allow login with client certificates
                        </p>
                      </div>
                      <button
                        onClick={() => setSettings({ ...settings, enableCertificateAuth: !settings.enableCertificateAuth })}
                        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                          settings.enableCertificateAuth ? 'bg-primary' : 'bg-input'
                        }`}
                      >
                        <span
                          className={`inline-block h-4 w-4 transform rounded-full bg-background transition-transform ${
                            settings.enableCertificateAuth ? 'translate-x-6' : 'translate-x-1'
                          }`}
                        />
                      </button>
                    </div>

                    <div>
                      <label className="block text-sm font-medium mb-2">
                        Session Timeout (minutes)
                      </label>
                      <input
                        type="number"
                        value={settings.sessionTimeout}
                        onChange={(e) => setSettings({ ...settings, sessionTimeout: parseInt(e.target.value) })}
                        className="w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-primary"
                        min={5}
                        max={1440}
                      />
                    </div>
                  </div>
                </div>

                <div className="bg-card rounded-lg border p-6">
                  <h2 className="text-xl font-semibold mb-4">Encryption</h2>
                  <div className="space-y-3">
                    <div className="flex items-center gap-2 text-green-600">
                      <CheckCircle className="h-5 w-5" />
                      <span>AES-256-GCM encryption enabled</span>
                    </div>
                    <div className="flex items-center gap-2 text-green-600">
                      <CheckCircle className="h-5 w-5" />
                      <span>Secure key derivation with Argon2id</span>
                    </div>
                    <div className="flex items-center gap-2 text-green-600">
                      <CheckCircle className="h-5 w-5" />
                      <span>Memory-safe operations</span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Key Rotation Settings */}
            {activeSection === 'rotation' && (
              <div className="space-y-6">
                <div className="bg-card rounded-lg border p-6">
                  <h2 className="text-xl font-semibold mb-4">Automatic Rotation</h2>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="font-medium">Enable Auto-Rotation</h3>
                        <p className="text-sm text-muted-foreground">
                          Automatically rotate keys based on age
                        </p>
                      </div>
                      <button
                        onClick={() => setSettings({ ...settings, autoRotate: !settings.autoRotate })}
                        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                          settings.autoRotate ? 'bg-primary' : 'bg-input'
                        }`}
                      >
                        <span
                          className={`inline-block h-4 w-4 transform rounded-full bg-background transition-transform ${
                            settings.autoRotate ? 'translate-x-6' : 'translate-x-1'
                          }`}
                        />
                      </button>
                    </div>

                    {settings.autoRotate && (
                      <>
                        <div>
                          <label className="block text-sm font-medium mb-2">
                            Rotation Period (days)
                          </label>
                          <input
                            type="number"
                            value={settings.rotationDays}
                            onChange={(e) => setSettings({ ...settings, rotationDays: parseInt(e.target.value) })}
                            className="w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-primary"
                            min={7}
                            max={365}
                          />
                        </div>

                        <div>
                          <label className="block text-sm font-medium mb-2">
                            Notify Before Rotation (days)
                          </label>
                          <input
                            type="number"
                            value={settings.notifyBeforeRotation}
                            onChange={(e) => setSettings({ ...settings, notifyBeforeRotation: parseInt(e.target.value) })}
                            className="w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-primary"
                            min={1}
                            max={30}
                          />
                        </div>
                      </>
                    )}
                  </div>
                </div>

                <div className="bg-amber-50 border border-amber-200 rounded-lg p-4">
                  <div className="flex gap-3">
                    <AlertTriangle className="h-5 w-5 text-amber-600 flex-shrink-0 mt-0.5" />
                    <div>
                      <h3 className="font-medium text-amber-900">Important</h3>
                      <p className="text-sm text-amber-700 mt-1">
                        Ensure all integrated services support key rotation before enabling auto-rotation.
                        Test rotation in a staging environment first.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Notification Settings */}
            {activeSection === 'notifications' && (
              <div className="space-y-6">
                <div className="bg-card rounded-lg border p-6">
                  <h2 className="text-xl font-semibold mb-4">Notification Preferences</h2>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="font-medium">Email Notifications</h3>
                        <p className="text-sm text-muted-foreground">
                          Receive important alerts via email
                        </p>
                      </div>
                      <button
                        onClick={() => setSettings({ ...settings, emailNotifications: !settings.emailNotifications })}
                        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                          settings.emailNotifications ? 'bg-primary' : 'bg-input'
                        }`}
                      >
                        <span
                          className={`inline-block h-4 w-4 transform rounded-full bg-background transition-transform ${
                            settings.emailNotifications ? 'translate-x-6' : 'translate-x-1'
                          }`}
                        />
                      </button>
                    </div>

                    <div className="space-y-3 pl-4">
                      <label className="flex items-center gap-3">
                        <input
                          type="checkbox"
                          checked={settings.notifyOnAccess}
                          onChange={(e) => setSettings({ ...settings, notifyOnAccess: e.target.checked })}
                          className="h-4 w-4 rounded border-gray-300"
                        />
                        <span className="text-sm">Notify when keys are accessed</span>
                      </label>

                      <label className="flex items-center gap-3">
                        <input
                          type="checkbox"
                          checked={settings.notifyOnRotation}
                          onChange={(e) => setSettings({ ...settings, notifyOnRotation: e.target.checked })}
                          className="h-4 w-4 rounded border-gray-300"
                        />
                        <span className="text-sm">Notify when keys are rotated</span>
                      </label>

                      <label className="flex items-center gap-3">
                        <input
                          type="checkbox"
                          checked={settings.notifyOnFailedAttempts}
                          onChange={(e) => setSettings({ ...settings, notifyOnFailedAttempts: e.target.checked })}
                          className="h-4 w-4 rounded border-gray-300"
                        />
                        <span className="text-sm">Notify on failed access attempts</span>
                      </label>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Backup Settings */}
            {activeSection === 'backup' && (
              <div className="space-y-6">
                <div className="bg-card rounded-lg border p-6">
                  <h2 className="text-xl font-semibold mb-4">Backup Configuration</h2>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="font-medium">Automatic Backups</h3>
                        <p className="text-sm text-muted-foreground">
                          Schedule regular backups of your keys
                        </p>
                      </div>
                      <button
                        onClick={() => setSettings({ ...settings, autoBackup: !settings.autoBackup })}
                        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                          settings.autoBackup ? 'bg-primary' : 'bg-input'
                        }`}
                      >
                        <span
                          className={`inline-block h-4 w-4 transform rounded-full bg-background transition-transform ${
                            settings.autoBackup ? 'translate-x-6' : 'translate-x-1'
                          }`}
                        />
                      </button>
                    </div>

                    {settings.autoBackup && (
                      <>
                        <div>
                          <label className="block text-sm font-medium mb-2">
                            Backup Frequency
                          </label>
                          <select
                            value={settings.backupFrequency}
                            onChange={(e) => setSettings({ ...settings, backupFrequency: e.target.value })}
                            className="w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-primary"
                          >
                            <option value="hourly">Hourly</option>
                            <option value="daily">Daily</option>
                            <option value="weekly">Weekly</option>
                            <option value="monthly">Monthly</option>
                          </select>
                        </div>

                        <div>
                          <label className="block text-sm font-medium mb-2">
                            Retention Period (days)
                          </label>
                          <input
                            type="number"
                            value={settings.backupRetention}
                            onChange={(e) => setSettings({ ...settings, backupRetention: parseInt(e.target.value) })}
                            className="w-full px-3 py-2 border rounded-md focus:outline-none focus:ring-2 focus:ring-primary"
                            min={7}
                            max={365}
                          />
                        </div>
                      </>
                    )}
                  </div>
                </div>

                <div className="bg-card rounded-lg border p-6">
                  <h2 className="text-xl font-semibold mb-4">Manual Export</h2>
                  <p className="text-sm text-muted-foreground mb-4">
                    Export all your keys and settings for external backup
                  </p>
                  <button
                    onClick={handleExportData}
                    className="inline-flex items-center px-4 py-2 border rounded-md hover:bg-accent"
                  >
                    <Download className="h-4 w-4 mr-2" />
                    Export All Data
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </DashboardLayout>
  )
}
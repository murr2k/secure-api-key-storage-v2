import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import SettingsPage from '@/app/settings/page'
import { useAuth } from '@/lib/auth-context'
import { useRouter } from 'next/navigation'
import { api } from '@/lib/api-client'

// Mock dependencies
jest.mock('@/lib/auth-context')
jest.mock('next/navigation')
jest.mock('@/lib/api-client')
jest.mock('react-hot-toast', () => ({
  __esModule: true,
  default: {
    success: jest.fn(),
    error: jest.fn(),
  },
}))

const mockPush = jest.fn()
const mockSettings = {
  security: {
    mfa_enabled: true,
    session_timeout: 3600,
    password_policy: {
      min_length: 12,
      require_uppercase: true,
      require_lowercase: true,
      require_numbers: true,
      require_symbols: true,
    },
  },
  rotation: {
    auto_rotation_enabled: true,
    default_rotation_days: 90,
    notification_days_before: 7,
  },
  notifications: {
    email_notifications: true,
    audit_alerts: true,
    rotation_reminders: true,
  },
  backup: {
    auto_backup_enabled: true,
    backup_frequency: 'daily',
    retention_days: 30,
  },
}

// Test wrapper with QueryClient
const TestWrapper = ({ children }: { children: React.ReactNode }) => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  })
  return (
    <QueryClientProvider client={queryClient}>
      {children}
    </QueryClientProvider>
  )
}

describe('SettingsPage', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    ;(useRouter as jest.Mock).mockReturnValue({
      push: mockPush,
    })
    
    // Mock API responses
    ;(api.settings?.get as jest.Mock)?.mockResolvedValue?.({
      data: mockSettings,
    })
    ;(api.settings?.update as jest.Mock)?.mockResolvedValue?.({
      data: mockSettings,
    })
  })

  it('redirects to login when user is not authenticated', async () => {
    ;(useAuth as jest.Mock).mockReturnValue({
      user: null,
      isLoading: false,
    })

    render(
      <TestWrapper>
        <SettingsPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(mockPush).toHaveBeenCalledWith('/login')
    })
  })

  it('shows loading spinner when auth is loading', () => {
    ;(useAuth as jest.Mock).mockReturnValue({
      user: null,
      isLoading: true,
    })

    render(
      <TestWrapper>
        <SettingsPage />
      </TestWrapper>
    )

    expect(screen.getByRole('status', { hidden: true })).toBeInTheDocument()
  })

  it('renders settings page with all sections', async () => {
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <SettingsPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('Settings')).toBeInTheDocument()
      expect(screen.getByText('Configure your security and system preferences')).toBeInTheDocument()
      
      // Check for all settings sections
      expect(screen.getByText('Security Settings')).toBeInTheDocument()
      expect(screen.getByText('Key Rotation')).toBeInTheDocument()
      expect(screen.getByText('Notifications')).toBeInTheDocument()
      expect(screen.getByText('Backup & Recovery')).toBeInTheDocument()
    })
  })

  it('displays current security settings', async () => {
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <SettingsPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('Multi-Factor Authentication')).toBeInTheDocument()
      expect(screen.getByText('Session Timeout')).toBeInTheDocument()
      expect(screen.getByText('Password Policy')).toBeInTheDocument()
    })
  })

  it('toggles MFA setting', async () => {
    const user = userEvent.setup()
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <SettingsPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('Multi-Factor Authentication')).toBeInTheDocument()
    })

    const mfaToggle = screen.getByRole('checkbox', { name: /multi-factor authentication/i })
    await user.click(mfaToggle)

    expect(api.settings?.update).toHaveBeenCalled()
  })

  it('updates session timeout setting', async () => {
    const user = userEvent.setup()
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <SettingsPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('Session Timeout')).toBeInTheDocument()
    })

    const timeoutInput = screen.getByLabelText(/session timeout/i)
    await user.clear(timeoutInput)
    await user.type(timeoutInput, '7200')
    
    const saveButton = screen.getByRole('button', { name: /save settings/i })
    await user.click(saveButton)

    expect(api.settings?.update).toHaveBeenCalled()
  })

  it('configures key rotation settings', async () => {
    const user = userEvent.setup()
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <SettingsPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('Key Rotation')).toBeInTheDocument()
    })

    const autoRotationToggle = screen.getByRole('checkbox', { name: /auto.+rotation/i })
    await user.click(autoRotationToggle)

    const rotationDaysInput = screen.getByLabelText(/rotation.+days/i)
    await user.clear(rotationDaysInput)
    await user.type(rotationDaysInput, '60')

    const saveButton = screen.getByRole('button', { name: /save settings/i })
    await user.click(saveButton)

    expect(api.settings?.update).toHaveBeenCalled()
  })

  it('manages notification preferences', async () => {
    const user = userEvent.setup()
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <SettingsPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('Notifications')).toBeInTheDocument()
    })

    const emailNotificationsToggle = screen.getByRole('checkbox', { name: /email.+notifications/i })
    await user.click(emailNotificationsToggle)

    const auditAlertsToggle = screen.getByRole('checkbox', { name: /audit.+alerts/i })
    await user.click(auditAlertsToggle)

    const saveButton = screen.getByRole('button', { name: /save settings/i })
    await user.click(saveButton)

    expect(api.settings?.update).toHaveBeenCalled()
  })

  it('configures backup settings', async () => {
    const user = userEvent.setup()
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <SettingsPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('Backup & Recovery')).toBeInTheDocument()
    })

    const autoBackupToggle = screen.getByRole('checkbox', { name: /auto.+backup/i })
    await user.click(autoBackupToggle)

    const frequencySelect = screen.getByLabelText(/backup.+frequency/i)
    await user.selectOptions(frequencySelect, 'weekly')

    const saveButton = screen.getByRole('button', { name: /save settings/i })
    await user.click(saveButton)

    expect(api.settings?.update).toHaveBeenCalled()
  })

  it('initiates manual backup when button is clicked', async () => {
    const user = userEvent.setup()
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <SettingsPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('Backup & Recovery')).toBeInTheDocument()
    })

    const manualBackupButton = screen.getByRole('button', { name: /create backup now/i })
    await user.click(manualBackupButton)

    expect(api.backup?.create).toHaveBeenCalled()
  })

  it('validates password policy settings', async () => {
    const user = userEvent.setup()
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <SettingsPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('Password Policy')).toBeInTheDocument()
    })

    const minLengthInput = screen.getByLabelText(/minimum.+length/i)
    await user.clear(minLengthInput)
    await user.type(minLengthInput, '8')

    const saveButton = screen.getByRole('button', { name: /save settings/i })
    await user.click(saveButton)

    expect(api.settings?.update).toHaveBeenCalled()
  })

  it('handles settings save errors gracefully', async () => {
    const user = userEvent.setup()
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation()
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })
    
    ;(api.settings?.update as jest.Mock)?.mockRejectedValue?.(new Error('Save failed'))

    render(
      <TestWrapper>
        <SettingsPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('Settings')).toBeInTheDocument()
    })

    const saveButton = screen.getByRole('button', { name: /save settings/i })
    await user.click(saveButton)

    await waitFor(() => {
      expect(api.settings?.update).toHaveBeenCalled()
    })

    consoleSpy.mockRestore()
  })

  it('resets settings to defaults when reset button is clicked', async () => {
    const user = userEvent.setup()
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <SettingsPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('Settings')).toBeInTheDocument()
    })

    const resetButton = screen.getByRole('button', { name: /reset to defaults/i })
    await user.click(resetButton)

    // Should show confirmation dialog
    const confirmButton = screen.getByRole('button', { name: /confirm reset/i })
    await user.click(confirmButton)

    expect(api.settings?.reset).toHaveBeenCalled()
  })
})
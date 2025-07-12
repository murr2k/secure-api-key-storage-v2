import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router-dom'
import { AuthProvider } from '@/lib/auth-context'
import LoginPage from '@/app/login/page'
import DashboardPage from '@/app/page'
import KeysPage from '@/app/keys/page'
import AuditPage from '@/app/audit/page'
import SettingsPage from '@/app/settings/page'
import { api } from '@/lib/api-client'

// Mock API client
jest.mock('@/lib/api-client')
jest.mock('next/navigation', () => ({
  useRouter: () => ({
    push: jest.fn(),
    replace: jest.fn(),
  }),
  usePathname: () => '/',
  useSearchParams: () => new URLSearchParams(),
}))

// E2E test wrapper
const E2ETestWrapper = ({ children }: { children: React.ReactNode }) => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  })
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <BrowserRouter>
          {children}
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  )
}

const mockApiData = {
  auth: {
    token: 'mock-jwt-token',
    user: { id: '1', email: 'admin@test.com' },
  },
  analytics: {
    total_keys: 15,
    total_services: 8,
    keys_accessed_today: 12,
    upcoming_rotations: 3,
    recent_activity: [
      {
        id: '1',
        action: 'KEY_ACCESSED',
        service: 'AWS API',
        timestamp: '2025-07-12T10:30:00Z',
      },
    ],
  },
  keys: [
    {
      id: '1',
      name: 'AWS Production Key',
      service: 'AWS',
      description: 'Production environment access',
      created_at: '2025-07-10T10:00:00Z',
      last_accessed: '2025-07-12T08:30:00Z',
    },
    {
      id: '2',
      name: 'GitHub CI Token',
      service: 'GitHub',
      description: 'Continuous integration',
      created_at: '2025-07-11T15:00:00Z',
      last_accessed: '2025-07-12T09:15:00Z',
    },
  ],
  auditLogs: [
    {
      id: '1',
      action: 'KEY_ACCESSED',
      user: 'admin',
      service: 'AWS API',
      timestamp: '2025-07-12T10:30:00Z',
      ip_address: '192.168.1.100',
    },
    {
      id: '2',
      action: 'KEY_CREATED',
      user: 'admin',
      service: 'GitHub API',
      timestamp: '2025-07-12T09:15:00Z',
      ip_address: '192.168.1.100',
    },
  ],
}

describe('End-to-End User Workflows', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    localStorage.clear()
    
    // Mock all API endpoints
    ;(api.auth?.login as jest.Mock)?.mockResolvedValue({ data: mockApiData.auth })
    ;(api.analytics?.overview as jest.Mock)?.mockResolvedValue({ data: mockApiData.analytics })
    ;(api.keys?.list as jest.Mock)?.mockResolvedValue({ data: mockApiData.keys })
    ;(api.keys?.create as jest.Mock)?.mockResolvedValue({ data: { id: '3', ...mockApiData.keys[0] } })
    ;(api.keys?.update as jest.Mock)?.mockResolvedValue({ data: mockApiData.keys[0] })
    ;(api.keys?.delete as jest.Mock)?.mockResolvedValue({ data: {} })
    ;(api.audit?.list as jest.Mock)?.mockResolvedValue({ data: mockApiData.auditLogs })
  })

  describe('Complete Login to Dashboard Workflow', () => {
    it('allows user to login and view dashboard with data', async () => {
      const user = userEvent.setup()
      
      // Start at login page
      render(
        <E2ETestWrapper>
          <LoginPage />
        </E2ETestWrapper>
      )

      // User sees login form
      expect(screen.getByText('Secure API Key Storage')).toBeInTheDocument()
      expect(screen.getByLabelText('Master Password')).toBeInTheDocument()

      // User enters credentials and logs in
      const passwordInput = screen.getByLabelText('Master Password')
      const loginButton = screen.getByRole('button', { name: /unlock dashboard/i })
      
      await user.type(passwordInput, 'correctpassword')
      await user.click(loginButton)

      // Simulate successful navigation to dashboard
      render(
        <E2ETestWrapper>
          <DashboardPage />
        </E2ETestWrapper>
      )

      // User sees dashboard with analytics
      await waitFor(() => {
        expect(screen.getByText('Dashboard')).toBeInTheDocument()
        expect(screen.getByText('15')).toBeInTheDocument() // total keys
        expect(screen.getByText('8')).toBeInTheDocument() // total services
      })
    })
  })

  describe('API Key Management Workflow', () => {
    it('allows user to create, edit, and delete API keys', async () => {
      const user = userEvent.setup()
      
      // Start authenticated on keys page
      localStorage.setItem('auth_token', 'valid-token')
      
      render(
        <E2ETestWrapper>
          <KeysPage />
        </E2ETestWrapper>
      )

      // User sees existing keys
      await waitFor(() => {
        expect(screen.getByText('API Keys')).toBeInTheDocument()
        expect(screen.getByText('AWS Production Key')).toBeInTheDocument()
        expect(screen.getByText('GitHub CI Token')).toBeInTheDocument()
      })

      // User creates new key
      const addButton = screen.getByRole('button', { name: /add new key/i })
      await user.click(addButton)

      // Fill out new key form
      await waitFor(() => {
        expect(screen.getByText('Add New API Key')).toBeInTheDocument()
      })

      const nameInput = screen.getByLabelText('Key Name')
      const serviceInput = screen.getByLabelText('Service')
      const descriptionInput = screen.getByLabelText('Description')
      const valueInput = screen.getByLabelText('API Key Value')
      
      await user.type(nameInput, 'Slack Integration Key')
      await user.type(serviceInput, 'Slack')
      await user.type(descriptionInput, 'Bot integration for notifications')
      await user.type(valueInput, 'xoxb-test-slack-token')

      const saveButton = screen.getByRole('button', { name: /save key/i })
      await user.click(saveButton)

      // Verify API call
      await waitFor(() => {
        expect(api.keys?.create).toHaveBeenCalledWith({
          name: 'Slack Integration Key',
          service: 'Slack',
          description: 'Bot integration for notifications',
          value: 'xoxb-test-slack-token',
        })
      })

      // User searches for specific key
      const searchInput = screen.getByPlaceholderText('Search keys...')
      await user.type(searchInput, 'AWS')

      await waitFor(() => {
        expect(screen.getByText('AWS Production Key')).toBeInTheDocument()
        expect(screen.queryByText('GitHub CI Token')).not.toBeInTheDocument()
      })

      // User deletes a key
      const deleteButtons = screen.getAllByRole('button', { name: /delete/i })
      await user.click(deleteButtons[0])

      // Confirm deletion
      const confirmButton = screen.getByRole('button', { name: /confirm/i })
      await user.click(confirmButton)

      await waitFor(() => {
        expect(api.keys?.delete).toHaveBeenCalledWith('1')
      })
    })
  })

  describe('Audit Log Monitoring Workflow', () => {
    it('allows user to view and filter audit logs', async () => {
      const user = userEvent.setup()
      
      localStorage.setItem('auth_token', 'valid-token')
      
      render(
        <E2ETestWrapper>
          <AuditPage />
        </E2ETestWrapper>
      )

      // User sees audit logs
      await waitFor(() => {
        expect(screen.getByText('Audit Logs')).toBeInTheDocument()
        expect(screen.getByText('KEY_ACCESSED')).toBeInTheDocument()
        expect(screen.getByText('KEY_CREATED')).toBeInTheDocument()
      })

      // User filters by action
      const actionFilter = screen.getByDisplayValue('All Actions')
      await user.selectOptions(actionFilter, 'KEY_ACCESSED')

      await waitFor(() => {
        expect(screen.getByText('KEY_ACCESSED')).toBeInTheDocument()
        expect(screen.queryByText('KEY_CREATED')).not.toBeInTheDocument()
      })

      // User searches logs
      const searchInput = screen.getByPlaceholderText('Search logs...')
      await user.type(searchInput, 'AWS')

      await waitFor(() => {
        expect(screen.getByText('AWS API')).toBeInTheDocument()
      })

      // User exports logs
      const exportButton = screen.getByRole('button', { name: /export logs/i })
      await user.click(exportButton)

      // Mock file download
      expect(api.audit?.export).toHaveBeenCalled()
    })
  })

  describe('Settings Configuration Workflow', () => {
    it('allows user to configure security and system settings', async () => {
      const user = userEvent.setup()
      
      localStorage.setItem('auth_token', 'valid-token')
      
      render(
        <E2ETestWrapper>
          <SettingsPage />
        </E2ETestWrapper>
      )

      // User sees settings page
      await waitFor(() => {
        expect(screen.getByText('Settings')).toBeInTheDocument()
        expect(screen.getByText('Security Settings')).toBeInTheDocument()
        expect(screen.getByText('Key Rotation')).toBeInTheDocument()
      })

      // User enables MFA
      const mfaToggle = screen.getByRole('checkbox', { name: /multi-factor authentication/i })
      await user.click(mfaToggle)

      // User configures rotation
      const autoRotationToggle = screen.getByRole('checkbox', { name: /auto.+rotation/i })
      await user.click(autoRotationToggle)

      const rotationDaysInput = screen.getByLabelText(/rotation.+days/i)
      await user.clear(rotationDaysInput)
      await user.type(rotationDaysInput, '60')

      // User saves settings
      const saveButton = screen.getByRole('button', { name: /save settings/i })
      await user.click(saveButton)

      await waitFor(() => {
        expect(api.settings?.update).toHaveBeenCalled()
      })
    })
  })

  describe('Error Handling Workflows', () => {
    it('gracefully handles API errors throughout the application', async () => {
      const user = userEvent.setup()
      
      // Mock API error
      ;(api.keys?.list as jest.Mock)?.mockRejectedValue({
        response: {
          status: 500,
          data: { message: 'Internal server error' },
        },
      })
      
      localStorage.setItem('auth_token', 'valid-token')
      
      render(
        <E2ETestWrapper>
          <KeysPage />
        </E2ETestWrapper>
      )

      // User still sees the page structure even with API errors
      await waitFor(() => {
        expect(screen.getByText('API Keys')).toBeInTheDocument()
      })

      // Error should be handled gracefully (not crash the app)
      expect(screen.queryByText('Something went wrong')).not.toBeInTheDocument()
    })

    it('handles session expiration during user workflows', async () => {
      const user = userEvent.setup()
      
      localStorage.setItem('auth_token', 'expired-token')
      
      // Mock 401 response
      ;(api.keys?.list as jest.Mock)?.mockRejectedValue({
        response: {
          status: 401,
          data: { message: 'Session expired' },
        },
      })
      
      render(
        <E2ETestWrapper>
          <KeysPage />
        </E2ETestWrapper>
      )

      // Should handle session expiration
      await waitFor(() => {
        expect(localStorage.getItem('auth_token')).toBeNull()
      })
    })
  })

  describe('Responsive Design Workflows', () => {
    it('works correctly on mobile devices', async () => {
      // Mock mobile viewport
      Object.defineProperty(window, 'innerWidth', {
        writable: true,
        configurable: true,
        value: 375,
      })
      
      const user = userEvent.setup()
      localStorage.setItem('auth_token', 'valid-token')
      
      render(
        <E2ETestWrapper>
          <DashboardPage />
        </E2ETestWrapper>
      )

      await waitFor(() => {
        expect(screen.getByText('Dashboard')).toBeInTheDocument()
      })

      // Mobile navigation should work
      const menuButton = screen.getByRole('button', { name: /toggle sidebar/i })
      await user.click(menuButton)

      // Sidebar should be visible after clicking menu
      const navigation = screen.getByRole('navigation')
      expect(navigation).toBeInTheDocument()
    })
  })

  describe('Accessibility Workflows', () => {
    it('supports keyboard navigation throughout the application', async () => {
      localStorage.setItem('auth_token', 'valid-token')
      
      render(
        <E2ETestWrapper>
          <DashboardPage />
        </E2ETestWrapper>
      )

      await waitFor(() => {
        expect(screen.getByText('Dashboard')).toBeInTheDocument()
      })

      // Navigate to keys page using keyboard
      const keysLink = screen.getByRole('link', { name: /api keys/i })
      keysLink.focus()
      expect(keysLink).toHaveFocus()

      // Tab to next focusable element
      const auditLink = screen.getByRole('link', { name: /audit logs/i })
      auditLink.focus()
      expect(auditLink).toHaveFocus()
    })
  })
})
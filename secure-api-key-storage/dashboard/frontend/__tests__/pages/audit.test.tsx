import { render, screen, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import AuditPage from '@/app/audit/page'
import { useAuth } from '@/lib/auth-context'
import { useRouter } from 'next/navigation'
import { api } from '@/lib/api-client'

// Mock dependencies
jest.mock('@/lib/auth-context')
jest.mock('next/navigation')
jest.mock('@/lib/api-client')

const mockPush = jest.fn()
const mockAuditLogs = [
  {
    id: '1',
    action: 'KEY_ACCESSED',
    user: 'admin',
    service: 'AWS API',
    details: 'API key accessed for production deployment',
    timestamp: '2025-07-12T10:30:00Z',
    ip_address: '192.168.1.100',
    user_agent: 'Mozilla/5.0',
  },
  {
    id: '2',
    action: 'KEY_CREATED',
    user: 'admin',
    service: 'GitHub API',
    details: 'New API key created for CI/CD',
    timestamp: '2025-07-12T09:15:00Z',
    ip_address: '192.168.1.101',
    user_agent: 'Chrome/91.0',
  },
  {
    id: '3',
    action: 'KEY_ROTATED',
    user: 'admin',
    service: 'Slack API',
    details: 'API key rotated due to expiration',
    timestamp: '2025-07-12T08:00:00Z',
    ip_address: '192.168.1.102',
    user_agent: 'Firefox/89.0',
  },
]

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

// Mock WebSocket
const mockWebSocket = {
  send: jest.fn(),
  close: jest.fn(),
  addEventListener: jest.fn(),
  removeEventListener: jest.fn(),
}

// Mock WebSocket constructor
global.WebSocket = jest.fn(() => mockWebSocket) as any

describe('AuditPage', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    ;(useRouter as jest.Mock).mockReturnValue({
      push: mockPush,
    })
    
    // Mock API responses
    ;(api.audit.list as jest.Mock).mockResolvedValue({
      data: mockAuditLogs,
    })
  })

  it('redirects to login when user is not authenticated', async () => {
    ;(useAuth as jest.Mock).mockReturnValue({
      user: null,
      isLoading: false,
    })

    render(
      <TestWrapper>
        <AuditPage />
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
        <AuditPage />
      </TestWrapper>
    )

    expect(screen.getByRole('status', { hidden: true })).toBeInTheDocument()
  })

  it('renders audit page with header and controls', async () => {
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <AuditPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('Audit Logs')).toBeInTheDocument()
      expect(screen.getByText('Security and access audit trail')).toBeInTheDocument()
      expect(screen.getByPlaceholderText('Search logs...')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /export logs/i })).toBeInTheDocument()
    })
  })

  it('displays audit logs in timeline format', async () => {
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <AuditPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('KEY_ACCESSED')).toBeInTheDocument()
      expect(screen.getByText('KEY_CREATED')).toBeInTheDocument()
      expect(screen.getByText('KEY_ROTATED')).toBeInTheDocument()
      expect(screen.getByText('AWS API')).toBeInTheDocument()
      expect(screen.getByText('GitHub API')).toBeInTheDocument()
      expect(screen.getByText('Slack API')).toBeInTheDocument()
    })
  })

  it('filters logs by search term', async () => {
    const user = userEvent.setup()
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <AuditPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('AWS API')).toBeInTheDocument()
      expect(screen.getByText('GitHub API')).toBeInTheDocument()
    })

    const searchInput = screen.getByPlaceholderText('Search logs...')
    await user.type(searchInput, 'AWS')

    await waitFor(() => {
      expect(screen.getByText('AWS API')).toBeInTheDocument()
      expect(screen.queryByText('GitHub API')).not.toBeInTheDocument()
    })
  })

  it('filters logs by action type', async () => {
    const user = userEvent.setup()
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <AuditPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('KEY_ACCESSED')).toBeInTheDocument()
      expect(screen.getByText('KEY_CREATED')).toBeInTheDocument()
    })

    const actionFilter = screen.getByDisplayValue('All Actions')
    await user.selectOptions(actionFilter, 'KEY_ACCESSED')

    await waitFor(() => {
      expect(screen.getByText('KEY_ACCESSED')).toBeInTheDocument()
      expect(screen.queryByText('KEY_CREATED')).not.toBeInTheDocument()
    })
  })

  it('filters logs by date range', async () => {
    const user = userEvent.setup()
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <AuditPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('KEY_ACCESSED')).toBeInTheDocument()
    })

    const startDateInput = screen.getByLabelText('Start Date')
    const endDateInput = screen.getByLabelText('End Date')

    await user.type(startDateInput, '2025-07-12')
    await user.type(endDateInput, '2025-07-12')

    // Logs should still be visible as they're within the date range
    expect(screen.getByText('KEY_ACCESSED')).toBeInTheDocument()
  })

  it('exports audit logs when export button is clicked', async () => {
    const user = userEvent.setup()
    const mockCreateObjectURL = jest.fn()
    const mockRevokeObjectURL = jest.fn()
    const mockClick = jest.fn()
    
    global.URL.createObjectURL = mockCreateObjectURL
    global.URL.revokeObjectURL = mockRevokeObjectURL
    
    // Mock document.createElement to return a mock anchor element
    const mockAnchor = {
      href: '',
      download: '',
      click: mockClick,
    }
    jest.spyOn(document, 'createElement').mockReturnValue(mockAnchor as any)
    
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <AuditPage />
      </TestWrapper>
    )

    const exportButton = await screen.findByRole('button', { name: /export logs/i })
    await user.click(exportButton)

    expect(mockCreateObjectURL).toHaveBeenCalled()
    expect(mockClick).toHaveBeenCalled()
  })

  it('establishes WebSocket connection for real-time updates', async () => {
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <AuditPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(global.WebSocket).toHaveBeenCalledWith('ws://localhost:8000/ws/audit')
    })
  })

  it('handles WebSocket messages for real-time log updates', async () => {
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <AuditPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(mockWebSocket.addEventListener).toHaveBeenCalledWith('message', expect.any(Function))
    })

    // Simulate WebSocket message
    const messageHandler = mockWebSocket.addEventListener.mock.calls.find(
      call => call[0] === 'message'
    )[1]

    const newLog = {
      id: '4',
      action: 'KEY_DELETED',
      user: 'admin',
      service: 'Test API',
      timestamp: '2025-07-12T11:00:00Z',
    }

    act(() => {
      messageHandler({
        data: JSON.stringify(newLog),
      })
    })

    await waitFor(() => {
      expect(screen.getByText('KEY_DELETED')).toBeInTheDocument()
    })
  })

  it('shows empty state when no audit logs exist', async () => {
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })
    
    ;(api.audit.list as jest.Mock).mockResolvedValue({
      data: [],
    })

    render(
      <TestWrapper>
        <AuditPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('No audit logs found')).toBeInTheDocument()
      expect(screen.getByText('Security events will appear here')).toBeInTheDocument()
    })
  })

  it('handles API errors gracefully', async () => {
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation()
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })
    
    ;(api.audit.list as jest.Mock).mockRejectedValue(new Error('API Error'))

    render(
      <TestWrapper>
        <AuditPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('Audit Logs')).toBeInTheDocument()
    })

    consoleSpy.mockRestore()
  })

  it('cleans up WebSocket connection on unmount', async () => {
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    const { unmount } = render(
      <TestWrapper>
        <AuditPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(global.WebSocket).toHaveBeenCalled()
    })

    unmount()

    expect(mockWebSocket.close).toHaveBeenCalled()
  })
})
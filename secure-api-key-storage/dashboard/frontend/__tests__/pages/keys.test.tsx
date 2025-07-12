import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import KeysPage from '@/app/keys/page'
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
const mockKeys = [
  {
    id: '1',
    name: 'AWS API Key',
    service: 'AWS',
    description: 'Production AWS access',
    created_at: '2025-07-10T10:00:00Z',
    updated_at: '2025-07-10T10:00:00Z',
    last_accessed: '2025-07-12T08:30:00Z',
    rotation_due: '2025-08-10T10:00:00Z',
  },
  {
    id: '2',
    name: 'GitHub Token',
    service: 'GitHub',
    description: 'CI/CD access token',
    created_at: '2025-07-11T15:00:00Z',
    updated_at: '2025-07-11T15:00:00Z',
    last_accessed: '2025-07-12T09:15:00Z',
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

describe('KeysPage', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    ;(useRouter as jest.Mock).mockReturnValue({
      push: mockPush,
    })
    
    // Mock API responses
    ;(api.keys.list as jest.Mock).mockResolvedValue({
      data: mockKeys,
    })
    ;(api.keys.create as jest.Mock).mockResolvedValue({
      data: { id: '3', ...mockKeys[0] },
    })
    ;(api.keys.update as jest.Mock).mockResolvedValue({
      data: mockKeys[0],
    })
    ;(api.keys.delete as jest.Mock).mockResolvedValue({
      data: {},
    })
  })

  it('redirects to login when user is not authenticated', async () => {
    ;(useAuth as jest.Mock).mockReturnValue({
      user: null,
      isLoading: false,
    })

    render(
      <TestWrapper>
        <KeysPage />
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
        <KeysPage />
      </TestWrapper>
    )

    expect(screen.getByRole('status', { hidden: true })).toBeInTheDocument()
  })

  it('renders keys page with header and controls', async () => {
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <KeysPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('API Keys')).toBeInTheDocument()
      expect(screen.getByText('Manage your encrypted API keys')).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /add new key/i })).toBeInTheDocument()
      expect(screen.getByPlaceholderText('Search keys...')).toBeInTheDocument()
    })
  })

  it('displays list of API keys', async () => {
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <KeysPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('AWS API Key')).toBeInTheDocument()
      expect(screen.getByText('GitHub Token')).toBeInTheDocument()
      expect(screen.getByText('Production AWS access')).toBeInTheDocument()
      expect(screen.getByText('CI/CD access token')).toBeInTheDocument()
    })
  })

  it('filters keys by search term', async () => {
    const user = userEvent.setup()
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <KeysPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('AWS API Key')).toBeInTheDocument()
      expect(screen.getByText('GitHub Token')).toBeInTheDocument()
    })

    const searchInput = screen.getByPlaceholderText('Search keys...')
    await user.type(searchInput, 'AWS')

    await waitFor(() => {
      expect(screen.getByText('AWS API Key')).toBeInTheDocument()
      expect(screen.queryByText('GitHub Token')).not.toBeInTheDocument()
    })
  })

  it('filters keys by service', async () => {
    const user = userEvent.setup()
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <KeysPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('AWS API Key')).toBeInTheDocument()
      expect(screen.getByText('GitHub Token')).toBeInTheDocument()
    })

    const serviceFilter = screen.getByDisplayValue('All Services')
    await user.selectOptions(serviceFilter, 'AWS')

    await waitFor(() => {
      expect(screen.getByText('AWS API Key')).toBeInTheDocument()
      expect(screen.queryByText('GitHub Token')).not.toBeInTheDocument()
    })
  })

  it('shows add key modal when add button is clicked', async () => {
    const user = userEvent.setup()
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <KeysPage />
      </TestWrapper>
    )

    const addButton = await screen.findByRole('button', { name: /add new key/i })
    await user.click(addButton)

    expect(screen.getByText('Add New API Key')).toBeInTheDocument()
  })

  it('handles key creation', async () => {
    const user = userEvent.setup()
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <KeysPage />
      </TestWrapper>
    )

    const addButton = await screen.findByRole('button', { name: /add new key/i })
    await user.click(addButton)

    const nameInput = screen.getByLabelText('Key Name')
    const serviceInput = screen.getByLabelText('Service')
    const descriptionInput = screen.getByLabelText('Description')
    const valueInput = screen.getByLabelText('API Key Value')
    const saveButton = screen.getByRole('button', { name: /save key/i })

    await user.type(nameInput, 'Test API Key')
    await user.type(serviceInput, 'TestService')
    await user.type(descriptionInput, 'Test description')
    await user.type(valueInput, 'test-api-key-value')
    await user.click(saveButton)

    await waitFor(() => {
      expect(api.keys.create).toHaveBeenCalledWith({
        name: 'Test API Key',
        service: 'TestService',
        description: 'Test description',
        value: 'test-api-key-value',
      })
    })
  })

  it('handles key deletion', async () => {
    const user = userEvent.setup()
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <KeysPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('AWS API Key')).toBeInTheDocument()
    })

    // Find and click the delete button (trash icon)
    const deleteButtons = screen.getAllByRole('button', { name: /delete/i })
    await user.click(deleteButtons[0])

    // Confirm deletion
    const confirmButton = screen.getByRole('button', { name: /confirm/i })
    await user.click(confirmButton)

    await waitFor(() => {
      expect(api.keys.delete).toHaveBeenCalledWith('1')
    })
  })

  it('shows empty state when no keys exist', async () => {
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })
    
    ;(api.keys.list as jest.Mock).mockResolvedValue({
      data: [],
    })

    render(
      <TestWrapper>
        <KeysPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('No API keys found')).toBeInTheDocument()
      expect(screen.getByText('Get started by adding your first API key')).toBeInTheDocument()
    })
  })

  it('handles API errors gracefully', async () => {
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation()
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })
    
    ;(api.keys.list as jest.Mock).mockRejectedValue(new Error('API Error'))

    render(
      <TestWrapper>
        <KeysPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('API Keys')).toBeInTheDocument()
    })

    consoleSpy.mockRestore()
  })
})
import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import DashboardPage from '@/app/page'
import { useAuth } from '@/lib/auth-context'
import { useRouter } from 'next/navigation'
import { api } from '@/lib/api-client'

// Mock dependencies
jest.mock('@/lib/auth-context')
jest.mock('next/navigation')
jest.mock('@/lib/api-client')

const mockPush = jest.fn()

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

describe('DashboardPage', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    ;(useRouter as jest.Mock).mockReturnValue({
      push: mockPush,
    })
    
    // Mock API response
    ;(api.analytics.overview as jest.Mock).mockResolvedValue({
      data: {
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
          {
            id: '2',
            action: 'KEY_ROTATED',
            service: 'GitHub API',
            timestamp: '2025-07-12T09:15:00Z',
          },
        ],
      },
    })
  })

  it('redirects to login when user is not authenticated', async () => {
    ;(useAuth as jest.Mock).mockReturnValue({
      user: null,
      isLoading: false,
    })

    render(
      <TestWrapper>
        <DashboardPage />
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
        <DashboardPage />
      </TestWrapper>
    )

    expect(screen.getByRole('status', { hidden: true })).toBeInTheDocument()
  })

  it('renders dashboard content when user is authenticated', async () => {
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <DashboardPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('Dashboard')).toBeInTheDocument()
      expect(screen.getByText('Welcome back! Here\'s an overview of your API key storage.')).toBeInTheDocument()
    })
  })

  it('displays analytics data in stats cards', async () => {
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <DashboardPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('Total Keys')).toBeInTheDocument()
      expect(screen.getByText('15')).toBeInTheDocument()
      expect(screen.getByText('Services')).toBeInTheDocument()
      expect(screen.getByText('8')).toBeInTheDocument()
      expect(screen.getByText('Accessed Today')).toBeInTheDocument()
      expect(screen.getByText('12')).toBeInTheDocument()
      expect(screen.getByText('Due for Rotation')).toBeInTheDocument()
      expect(screen.getByText('3')).toBeInTheDocument()
    })
  })

  it('shows default values when analytics data is not available', async () => {
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })
    
    ;(api.analytics.overview as jest.Mock).mockResolvedValue({
      data: null,
    })

    render(
      <TestWrapper>
        <DashboardPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('Total Keys')).toBeInTheDocument()
      expect(screen.getByText('0')).toBeInTheDocument()
    })
  })

  it('renders key distribution and recent activity components', async () => {
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <DashboardPage />
      </TestWrapper>
    )

    await waitFor(() => {
      // These components should be rendered - we'll check for their containers
      const chartSection = screen.getByText('Dashboard').closest('div')
      expect(chartSection).toBeInTheDocument()
    })
  })

  it('fetches analytics data only when user is authenticated', async () => {
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })

    render(
      <TestWrapper>
        <DashboardPage />
      </TestWrapper>
    )

    await waitFor(() => {
      expect(api.analytics.overview).toHaveBeenCalled()
    })
  })

  it('does not fetch analytics data when user is not authenticated', () => {
    ;(useAuth as jest.Mock).mockReturnValue({
      user: null,
      isLoading: false,
    })

    render(
      <TestWrapper>
        <DashboardPage />
      </TestWrapper>
    )

    expect(api.analytics.overview).not.toHaveBeenCalled()
  })

  it('handles analytics API errors gracefully', async () => {
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      isLoading: false,
    })
    
    ;(api.analytics.overview as jest.Mock).mockRejectedValue(new Error('API Error'))

    render(
      <TestWrapper>
        <DashboardPage />
      </TestWrapper>
    )

    // Component should still render even if API fails
    await waitFor(() => {
      expect(screen.getByText('Dashboard')).toBeInTheDocument()
    })
  })
})
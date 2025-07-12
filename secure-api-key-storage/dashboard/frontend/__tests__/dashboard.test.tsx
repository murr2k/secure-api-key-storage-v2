import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Dashboard from '../app/page'
import '@testing-library/jest-dom'

// Mock the API client
jest.mock('../lib/api-client', () => ({
  getDashboardStats: jest.fn(),
  getRecentActivity: jest.fn(),
}))

const createTestQueryClient = () =>
  new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  })

const renderWithProviders = (component: React.ReactElement) => {
  const queryClient = createTestQueryClient()
  return render(
    <QueryClientProvider client={queryClient}>
      {component}
    </QueryClientProvider>
  )
}

describe('Dashboard Page', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('renders dashboard correctly', async () => {
    const { getDashboardStats, getRecentActivity } = require('../lib/api-client')
    
    getDashboardStats.mockResolvedValue({
      totalKeys: 25,
      activeKeys: 20,
      expiredKeys: 3,
      recentActivity: 15
    })
    
    getRecentActivity.mockResolvedValue([
      {
        id: '1',
        action: 'Key Created',
        user: 'admin',
        timestamp: new Date().toISOString(),
        resource: 'test-key'
      }
    ])

    renderWithProviders(<Dashboard />)
    
    expect(screen.getByText('Dashboard')).toBeInTheDocument()
    
    await waitFor(() => {
      expect(screen.getByText('25')).toBeInTheDocument() // Total keys
      expect(screen.getByText('20')).toBeInTheDocument() // Active keys
    })
  })

  it('displays loading state', () => {
    const { getDashboardStats, getRecentActivity } = require('../lib/api-client')
    
    getDashboardStats.mockImplementation(() => new Promise(() => {}))
    getRecentActivity.mockImplementation(() => new Promise(() => {}))

    renderWithProviders(<Dashboard />)
    
    expect(screen.getByText('Loading...')).toBeInTheDocument()
  })

  it('displays error state when API fails', async () => {
    const { getDashboardStats, getRecentActivity } = require('../lib/api-client')
    
    getDashboardStats.mockRejectedValue(new Error('API Error'))
    getRecentActivity.mockRejectedValue(new Error('API Error'))

    renderWithProviders(<Dashboard />)
    
    await waitFor(() => {
      expect(screen.getByText(/error/i)).toBeInTheDocument()
    })
  })

  it('renders stats cards with correct values', async () => {
    const { getDashboardStats, getRecentActivity } = require('../lib/api-client')
    
    const mockStats = {
      totalKeys: 100,
      activeKeys: 85,
      expiredKeys: 10,
      recentActivity: 25
    }
    
    getDashboardStats.mockResolvedValue(mockStats)
    getRecentActivity.mockResolvedValue([])

    renderWithProviders(<Dashboard />)
    
    await waitFor(() => {
      expect(screen.getByText('Total Keys')).toBeInTheDocument()
      expect(screen.getByText('Active Keys')).toBeInTheDocument()
      expect(screen.getByText('Expired Keys')).toBeInTheDocument()
      expect(screen.getByText('Recent Activity')).toBeInTheDocument()
    })
  })

  it('displays recent activity list', async () => {
    const { getDashboardStats, getRecentActivity } = require('../lib/api-client')
    
    getDashboardStats.mockResolvedValue({
      totalKeys: 10,
      activeKeys: 8,
      expiredKeys: 2,
      recentActivity: 5
    })
    
    const mockActivity = [
      {
        id: '1',
        action: 'Key Created',
        user: 'admin',
        timestamp: new Date().toISOString(),
        resource: 'test-key-1'
      },
      {
        id: '2',
        action: 'Key Deleted',
        user: 'user1',
        timestamp: new Date().toISOString(),
        resource: 'test-key-2'
      }
    ]
    
    getRecentActivity.mockResolvedValue(mockActivity)

    renderWithProviders(<Dashboard />)
    
    await waitFor(() => {
      expect(screen.getByText('Key Created')).toBeInTheDocument()
      expect(screen.getByText('Key Deleted')).toBeInTheDocument()
      expect(screen.getByText('admin')).toBeInTheDocument()
      expect(screen.getByText('user1')).toBeInTheDocument()
    })
  })
})
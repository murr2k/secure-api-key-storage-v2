import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router-dom'
import App from '@/app/layout'
import LoginPage from '@/app/login/page'
import DashboardPage from '@/app/page'
import { AuthProvider, useAuth } from '@/lib/auth-context'
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

// Integration test wrapper
const IntegrationTestWrapper = ({ children }: { children: React.ReactNode }) => {
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

describe('Authentication Flow Integration', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    localStorage.clear()
    
    // Mock successful login
    ;(api.auth?.login as jest.Mock)?.mockResolvedValue({
      data: {
        token: 'mock-jwt-token',
        user: {
          id: '1',
          email: 'test@example.com',
        },
      },
    })
    
    // Mock analytics API
    ;(api.analytics?.overview as jest.Mock)?.mockResolvedValue({
      data: {
        total_keys: 5,
        total_services: 3,
        keys_accessed_today: 2,
        upcoming_rotations: 1,
        recent_activity: [],
      },
    })
  })

  it('completes full login flow and redirects to dashboard', async () => {
    const user = userEvent.setup()
    
    render(
      <IntegrationTestWrapper>
        <LoginPage />
      </IntegrationTestWrapper>
    )

    // User sees login form
    expect(screen.getByText('Secure API Key Storage')).toBeInTheDocument()
    expect(screen.getByLabelText('Master Password')).toBeInTheDocument()

    // User enters password
    const passwordInput = screen.getByLabelText('Master Password')
    await user.type(passwordInput, 'correctpassword')

    // User submits form
    const loginButton = screen.getByRole('button', { name: /unlock dashboard/i })
    await user.click(loginButton)

    // API should be called
    await waitFor(() => {
      expect(api.auth?.login).toHaveBeenCalledWith('correctpassword')
    })

    // Token should be stored
    expect(localStorage.getItem('auth_token')).toBe('mock-jwt-token')
  })

  it('handles invalid credentials gracefully', async () => {
    const user = userEvent.setup()
    
    // Mock failed login
    ;(api.auth?.login as jest.Mock)?.mockRejectedValue({
      response: {
        status: 401,
        data: { message: 'Invalid password' },
      },
    })
    
    render(
      <IntegrationTestWrapper>
        <LoginPage />
      </IntegrationTestWrapper>
    )

    const passwordInput = screen.getByLabelText('Master Password')
    await user.type(passwordInput, 'wrongpassword')

    const loginButton = screen.getByRole('button', { name: /unlock dashboard/i })
    await user.click(loginButton)

    await waitFor(() => {
      expect(api.auth?.login).toHaveBeenCalledWith('wrongpassword')
    })

    // Should stay on login page
    expect(screen.getByText('Secure API Key Storage')).toBeInTheDocument()
    expect(localStorage.getItem('auth_token')).toBeNull()
  })

  it('persists authentication across page reloads', async () => {
    // Set up existing auth state
    localStorage.setItem('auth_token', 'existing-token')
    
    // Mock token validation
    ;(api.auth?.validate as jest.Mock)?.mockResolvedValue({
      data: {
        user: {
          id: '1',
          email: 'test@example.com',
        },
      },
    })
    
    render(
      <IntegrationTestWrapper>
        <DashboardPage />
      </IntegrationTestWrapper>
    )

    // Should automatically authenticate and show dashboard
    await waitFor(() => {
      expect(screen.getByText('Dashboard')).toBeInTheDocument()
    })
  })

  it('redirects to login when token is invalid', async () => {
    localStorage.setItem('auth_token', 'invalid-token')
    
    // Mock token validation failure
    ;(api.auth?.validate as jest.Mock)?.mockRejectedValue({
      response: { status: 401 },
    })
    
    render(
      <IntegrationTestWrapper>
        <DashboardPage />
      </IntegrationTestWrapper>
    )

    await waitFor(() => {
      expect(localStorage.getItem('auth_token')).toBeNull()
    })
  })

  it('handles logout flow correctly', async () => {
    const user = userEvent.setup()
    
    // Set up authenticated state
    localStorage.setItem('auth_token', 'valid-token')
    
    const TestComponent = () => {
      const { logout, user: authUser } = useAuth()
      
      return (
        <div>
          {authUser ? (
            <>
              <span>Logged in as {authUser.email}</span>
              <button onClick={logout}>Logout</button>
            </>
          ) : (
            <span>Not logged in</span>
          )}
        </div>
      )
    }
    
    render(
      <IntegrationTestWrapper>
        <TestComponent />
      </IntegrationTestWrapper>
    )

    // Should show logged in state
    await waitFor(() => {
      expect(screen.getByText('Logged in as test@example.com')).toBeInTheDocument()
    })

    // User logs out
    const logoutButton = screen.getByText('Logout')
    await user.click(logoutButton)

    await waitFor(() => {
      expect(screen.getByText('Not logged in')).toBeInTheDocument()
      expect(localStorage.getItem('auth_token')).toBeNull()
    })
  })

  it('handles session timeout', async () => {
    localStorage.setItem('auth_token', 'expired-token')
    
    // Mock session timeout response
    ;(api.analytics?.overview as jest.Mock)?.mockRejectedValue({
      response: {
        status: 401,
        data: { message: 'Session expired' },
      },
    })
    
    render(
      <IntegrationTestWrapper>
        <DashboardPage />
      </IntegrationTestWrapper>
    )

    await waitFor(() => {
      // Should clear token and redirect to login
      expect(localStorage.getItem('auth_token')).toBeNull()
    })
  })

  it('refreshes token when needed', async () => {
    localStorage.setItem('auth_token', 'expiring-token')
    
    // Mock token refresh
    ;(api.auth?.refresh as jest.Mock)?.mockResolvedValue({
      data: {
        token: 'new-token',
        user: {
          id: '1',
          email: 'test@example.com',
        },
      },
    })
    
    render(
      <IntegrationTestWrapper>
        <DashboardPage />
      </IntegrationTestWrapper>
    )

    await waitFor(() => {
      expect(api.auth?.refresh).toHaveBeenCalled()
      expect(localStorage.getItem('auth_token')).toBe('new-token')
    })
  })

  it('maintains auth state across multiple components', async () => {
    localStorage.setItem('auth_token', 'valid-token')
    
    const ComponentA = () => {
      const { user } = useAuth()
      return <div>Component A: {user?.email || 'No user'}</div>
    }
    
    const ComponentB = () => {
      const { user } = useAuth()
      return <div>Component B: {user?.email || 'No user'}</div>
    }
    
    render(
      <IntegrationTestWrapper>
        <>
          <ComponentA />
          <ComponentB />
        </>
      </IntegrationTestWrapper>
    )

    await waitFor(() => {
      expect(screen.getByText('Component A: test@example.com')).toBeInTheDocument()
      expect(screen.getByText('Component B: test@example.com')).toBeInTheDocument()
    })
  })
})
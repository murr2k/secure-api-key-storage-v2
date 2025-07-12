import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import LoginPage from '../app/login/page'
import '@testing-library/jest-dom'

// Mock the API client
jest.mock('../lib/api-client', () => ({
  login: jest.fn(),
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

describe('Login Page', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('renders login form correctly', () => {
    renderWithProviders(<LoginPage />)
    
    expect(screen.getByText('Login')).toBeInTheDocument()
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /login/i })).toBeInTheDocument()
  })

  it('handles form submission', async () => {
    const { login } = require('../lib/api-client')
    login.mockResolvedValue({ token: 'test-token' })

    renderWithProviders(<LoginPage />)
    
    const passwordInput = screen.getByLabelText(/password/i)
    const submitButton = screen.getByRole('button', { name: /login/i })

    fireEvent.change(passwordInput, { target: { value: 'test-password' } })
    fireEvent.click(submitButton)

    await waitFor(() => {
      expect(login).toHaveBeenCalledWith('test-password')
    })
  })

  it('displays error message on failed login', async () => {
    const { login } = require('../lib/api-client')
    login.mockRejectedValue(new Error('Invalid credentials'))

    renderWithProviders(<LoginPage />)
    
    const passwordInput = screen.getByLabelText(/password/i)
    const submitButton = screen.getByRole('button', { name: /login/i })

    fireEvent.change(passwordInput, { target: { value: 'wrong-password' } })
    fireEvent.click(submitButton)

    await waitFor(() => {
      expect(screen.getByText(/invalid credentials/i)).toBeInTheDocument()
    })
  })

  it('disables submit button when loading', async () => {
    const { login } = require('../lib/api-client')
    login.mockImplementation(() => new Promise(resolve => setTimeout(resolve, 1000)))

    renderWithProviders(<LoginPage />)
    
    const passwordInput = screen.getByLabelText(/password/i)
    const submitButton = screen.getByRole('button', { name: /login/i })

    fireEvent.change(passwordInput, { target: { value: 'test-password' } })
    fireEvent.click(submitButton)

    expect(submitButton).toBeDisabled()
  })

  it('validates password input', () => {
    renderWithProviders(<LoginPage />)
    
    const passwordInput = screen.getByLabelText(/password/i)
    const submitButton = screen.getByRole('button', { name: /login/i })

    // Submit with empty password
    fireEvent.click(submitButton)

    expect(passwordInput).toBeInvalid()
  })
})
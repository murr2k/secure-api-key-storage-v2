import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import LoginPage from '@/app/login/page'
import { useAuth } from '@/lib/auth-context'
import { useRouter } from 'next/navigation'

// Mock the auth context
jest.mock('@/lib/auth-context')
jest.mock('next/navigation')

const mockLogin = jest.fn()
const mockPush = jest.fn()

describe('LoginPage', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    ;(useAuth as jest.Mock).mockReturnValue({
      login: mockLogin,
    })
    ;(useRouter as jest.Mock).mockReturnValue({
      push: mockPush,
    })
    
    // Mock fetch for health check
    global.fetch = jest.fn()
    global.alert = jest.fn()
  })

  it('renders login form with all elements', () => {
    render(<LoginPage />)

    expect(screen.getByText('Secure API Key Storage')).toBeInTheDocument()
    expect(screen.getByText('Enter your master password to access the dashboard')).toBeInTheDocument()
    expect(screen.getByLabelText('Master Password')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /unlock dashboard/i })).toBeInTheDocument()
    expect(screen.getByText('🔒 Your master password is never stored')).toBeInTheDocument()
    expect(screen.getByText('All keys are encrypted with AES-256-GCM')).toBeInTheDocument()
  })

  it('allows user to type in password field', async () => {
    const user = userEvent.setup()
    render(<LoginPage />)

    const passwordInput = screen.getByLabelText('Master Password')
    await user.type(passwordInput, 'testpassword')

    expect(passwordInput).toHaveValue('testpassword')
  })

  it('submits form with password and redirects on success', async () => {
    const user = userEvent.setup()
    mockLogin.mockResolvedValue({})
    
    render(<LoginPage />)

    const passwordInput = screen.getByLabelText('Master Password')
    const submitButton = screen.getByRole('button', { name: /unlock dashboard/i })

    await user.type(passwordInput, 'testpassword')
    await user.click(submitButton)

    await waitFor(() => {
      expect(mockLogin).toHaveBeenCalledWith('testpassword')
      expect(mockPush).toHaveBeenCalledWith('/')
    })
  })

  it('shows loading state during authentication', async () => {
    const user = userEvent.setup()
    mockLogin.mockImplementation(() => new Promise(resolve => setTimeout(resolve, 100)))
    
    render(<LoginPage />)

    const passwordInput = screen.getByLabelText('Master Password')
    const submitButton = screen.getByRole('button', { name: /unlock dashboard/i })

    await user.type(passwordInput, 'testpassword')
    await user.click(submitButton)

    expect(screen.getByText('Authenticating...')).toBeInTheDocument()
    expect(submitButton).toBeDisabled()
    expect(passwordInput).toBeDisabled()
  })

  it('handles login error gracefully', async () => {
    const user = userEvent.setup()
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation()
    mockLogin.mockRejectedValue(new Error('Invalid password'))
    
    render(<LoginPage />)

    const passwordInput = screen.getByLabelText('Master Password')
    const submitButton = screen.getByRole('button', { name: /unlock dashboard/i })

    await user.type(passwordInput, 'wrongpassword')
    await user.click(submitButton)

    await waitFor(() => {
      expect(mockLogin).toHaveBeenCalledWith('wrongpassword')
      expect(consoleSpy).toHaveBeenCalledWith('Login error:', expect.any(Error))
      expect(mockPush).not.toHaveBeenCalled()
    })

    consoleSpy.mockRestore()
  })

  it('prevents form submission with empty password', async () => {
    const user = userEvent.setup()
    render(<LoginPage />)

    const submitButton = screen.getByRole('button', { name: /unlock dashboard/i })
    await user.click(submitButton)

    expect(mockLogin).not.toHaveBeenCalled()
  })

  it('tests backend connection when debug button is clicked', async () => {
    const user = userEvent.setup()
    const mockResponse = { ok: true }
    const mockData = { status: 'healthy', version: '1.0.0' }
    
    ;(global.fetch as jest.Mock).mockResolvedValue({
      json: () => Promise.resolve(mockData)
    })
    
    render(<LoginPage />)

    const testConnectionButton = screen.getByRole('button', { name: /test backend connection/i })
    await user.click(testConnectionButton)

    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledWith('/api/health')
      expect(global.alert).toHaveBeenCalledWith(
        expect.stringContaining('Backend Status:')
      )
    })
  })

  it('handles health check failure', async () => {
    const user = userEvent.setup()
    const consoleSpy = jest.spyOn(console, 'error').mockImplementation()
    
    ;(global.fetch as jest.Mock).mockRejectedValue(new Error('Connection failed'))
    
    render(<LoginPage />)

    const testConnectionButton = screen.getByRole('button', { name: /test backend connection/i })
    await user.click(testConnectionButton)

    await waitFor(() => {
      expect(consoleSpy).toHaveBeenCalledWith('Health check failed:', expect.any(Error))
      expect(global.alert).toHaveBeenCalledWith(
        'Failed to connect to backend. Make sure it\'s running on port 8000.'
      )
    })

    consoleSpy.mockRestore()
  })

  it('has proper accessibility attributes', () => {
    render(<LoginPage />)

    const passwordInput = screen.getByLabelText('Master Password')
    expect(passwordInput).toHaveAttribute('type', 'password')
    expect(passwordInput).toHaveAttribute('required')
    expect(passwordInput).toHaveAttribute('placeholder', 'Enter your master password')

    const form = passwordInput.closest('form')
    expect(form).toBeInTheDocument()
  })
})
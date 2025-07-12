import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { DashboardLayout } from '@/components/layout/dashboard-layout'
import { useAuth } from '@/lib/auth-context'
import { useRouter, usePathname } from 'next/navigation'

// Mock dependencies
jest.mock('@/lib/auth-context')
jest.mock('next/navigation')

const mockPush = jest.fn()
const mockLogout = jest.fn()

describe('DashboardLayout', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    ;(useRouter as jest.Mock).mockReturnValue({
      push: mockPush,
    })
    ;(usePathname as jest.Mock).mockReturnValue('/')
    ;(useAuth as jest.Mock).mockReturnValue({
      user: { id: '1', email: 'test@example.com' },
      logout: mockLogout,
    })
  })

  it('renders navigation with all menu items', () => {
    render(
      <DashboardLayout>
        <div>Test Content</div>
      </DashboardLayout>
    )

    expect(screen.getByText('Secure API Key Storage')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /dashboard/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /api keys/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /audit logs/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /settings/i })).toBeInTheDocument()
  })

  it('renders user information in header', () => {
    render(
      <DashboardLayout>
        <div>Test Content</div>
      </DashboardLayout>
    )

    expect(screen.getByText('test@example.com')).toBeInTheDocument()
  })

  it('renders children content', () => {
    render(
      <DashboardLayout>
        <div>Test Content</div>
      </DashboardLayout>
    )

    expect(screen.getByText('Test Content')).toBeInTheDocument()
  })

  it('highlights active navigation item based on pathname', () => {
    ;(usePathname as jest.Mock).mockReturnValue('/keys')
    
    render(
      <DashboardLayout>
        <div>Test Content</div>
      </DashboardLayout>
    )

    const keysLink = screen.getByRole('link', { name: /api keys/i })
    expect(keysLink).toHaveClass('bg-accent') // or whatever active class is used
  })

  it('navigates to dashboard when logo is clicked', async () => {
    const user = userEvent.setup()
    render(
      <DashboardLayout>
        <div>Test Content</div>
      </DashboardLayout>
    )

    const logo = screen.getByText('Secure API Key Storage')
    await user.click(logo)

    expect(mockPush).toHaveBeenCalledWith('/')
  })

  it('shows user menu when user avatar is clicked', async () => {
    const user = userEvent.setup()
    render(
      <DashboardLayout>
        <div>Test Content</div>
      </DashboardLayout>
    )

    const userButton = screen.getByRole('button', { name: /user menu/i })
    await user.click(userButton)

    expect(screen.getByText('Profile')).toBeInTheDocument()
    expect(screen.getByText('Logout')).toBeInTheDocument()
  })

  it('calls logout when logout menu item is clicked', async () => {
    const user = userEvent.setup()
    render(
      <DashboardLayout>
        <div>Test Content</div>
      </DashboardLayout>
    )

    const userButton = screen.getByRole('button', { name: /user menu/i })
    await user.click(userButton)

    const logoutButton = screen.getByText('Logout')
    await user.click(logoutButton)

    expect(mockLogout).toHaveBeenCalled()
  })

  it('toggles sidebar when menu button is clicked', async () => {
    const user = userEvent.setup()
    render(
      <DashboardLayout>
        <div>Test Content</div>
      </DashboardLayout>
    )

    const menuButton = screen.getByRole('button', { name: /toggle sidebar/i })
    await user.click(menuButton)

    // Sidebar should be hidden/shown (test depends on implementation)
    const sidebar = screen.getByRole('navigation')
    expect(sidebar).toHaveClass('hidden') // or whatever hidden class is used
  })

  it('shows notifications when notification bell is clicked', async () => {
    const user = userEvent.setup()
    render(
      <DashboardLayout>
        <div>Test Content</div>
      </DashboardLayout>
    )

    const notificationButton = screen.getByRole('button', { name: /notifications/i })
    await user.click(notificationButton)

    expect(screen.getByText('Notifications')).toBeInTheDocument()
  })

  it('renders breadcrumb navigation', () => {
    ;(usePathname as jest.Mock).mockReturnValue('/keys/create')
    
    render(
      <DashboardLayout>
        <div>Test Content</div>
      </DashboardLayout>
    )

    expect(screen.getByText('Dashboard')).toBeInTheDocument()
    expect(screen.getByText('Keys')).toBeInTheDocument()
    expect(screen.getByText('Create')).toBeInTheDocument()
  })

  it('handles keyboard navigation', async () => {
    render(
      <DashboardLayout>
        <div>Test Content</div>
      </DashboardLayout>
    )

    const dashboardLink = screen.getByRole('link', { name: /dashboard/i })
    dashboardLink.focus()
    
    expect(dashboardLink).toHaveFocus()

    fireEvent.keyDown(dashboardLink, { key: 'Tab' })
    
    const keysLink = screen.getByRole('link', { name: /api keys/i })
    expect(keysLink).toHaveFocus()
  })

  it('displays connection status indicator', () => {
    render(
      <DashboardLayout>
        <div>Test Content</div>
      </DashboardLayout>
    )

    // Should show online/offline status
    const statusIndicator = screen.getByRole('status', { name: /connection status/i })
    expect(statusIndicator).toBeInTheDocument()
  })

  it('handles responsive layout on mobile', () => {
    // Mock mobile viewport
    Object.defineProperty(window, 'innerWidth', {
      writable: true,
      configurable: true,
      value: 640,
    })

    render(
      <DashboardLayout>
        <div>Test Content</div>
      </DashboardLayout>
    )

    // Sidebar should be hidden on mobile by default
    const sidebar = screen.getByRole('navigation')
    expect(sidebar).toHaveClass('md:block') // or similar responsive class
  })

  it('shows loading state when user data is loading', () => {
    ;(useAuth as jest.Mock).mockReturnValue({
      user: null,
      logout: mockLogout,
      isLoading: true,
    })

    render(
      <DashboardLayout>
        <div>Test Content</div>
      </DashboardLayout>
    )

    expect(screen.getByRole('status', { hidden: true })).toBeInTheDocument()
  })

  it('has proper ARIA labels for accessibility', () => {
    render(
      <DashboardLayout>
        <div>Test Content</div>
      </DashboardLayout>
    )

    expect(screen.getByRole('navigation', { name: /main navigation/i })).toBeInTheDocument()
    expect(screen.getByRole('banner')).toBeInTheDocument() // header
    expect(screen.getByRole('main')).toBeInTheDocument() // main content area
  })

  it('supports keyboard shortcuts', async () => {
    render(
      <DashboardLayout>
        <div>Test Content</div>
      </DashboardLayout>
    )

    // Test keyboard shortcut for opening user menu
    fireEvent.keyDown(document, { key: 'u', ctrlKey: true })
    
    await waitFor(() => {
      expect(screen.getByText('Profile')).toBeInTheDocument()
    })
  })

  it('persists sidebar state in localStorage', async () => {
    const user = userEvent.setup()
    const mockSetItem = jest.spyOn(Storage.prototype, 'setItem')
    
    render(
      <DashboardLayout>
        <div>Test Content</div>
      </DashboardLayout>
    )

    const menuButton = screen.getByRole('button', { name: /toggle sidebar/i })
    await user.click(menuButton)

    expect(mockSetItem).toHaveBeenCalledWith('sidebarCollapsed', 'true')
  })
})
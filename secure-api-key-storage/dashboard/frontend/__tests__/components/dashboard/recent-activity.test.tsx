import { render, screen } from '@testing-library/react'
import { RecentActivity } from '@/components/dashboard/recent-activity'

const mockActivities = [
  {
    id: '1',
    timestamp: '2025-07-12T10:30:00Z',
    action: 'key_accessed',
    key_name: 'AWS Production Key',
    user: 'admin',
    details: { service: 'AWS', environment: 'production' },
  },
  {
    id: '2',
    timestamp: '2025-07-12T09:15:00Z',
    action: 'key_created',
    key_name: 'GitHub CI Token',
    user: 'admin',
    details: { service: 'GitHub', type: 'personal_access_token' },
  },
  {
    id: '3',
    timestamp: '2025-07-12T08:00:00Z',
    action: 'key_rotated',
    key_name: 'Slack API Key',
    user: 'admin',
    details: { service: 'Slack', reason: 'scheduled_rotation' },
  },
]

describe('RecentActivity', () => {
  it('renders recent activity component with title', () => {
    render(<RecentActivity activities={mockActivities} />)

    expect(screen.getByText('Recent Activity')).toBeInTheDocument()
  })

  it('displays all activity items', () => {
    render(<RecentActivity activities={mockActivities} />)

    expect(screen.getByText('AWS Production Key')).toBeInTheDocument()
    expect(screen.getByText('GitHub CI Token')).toBeInTheDocument()
    expect(screen.getByText('Slack API Key')).toBeInTheDocument()
  })

  it('shows correct action types', () => {
    render(<RecentActivity activities={mockActivities} />)

    expect(screen.getByText('Key Accessed')).toBeInTheDocument()
    expect(screen.getByText('Key Created')).toBeInTheDocument()
    expect(screen.getByText('Key Rotated')).toBeInTheDocument()
  })

  it('displays user information', () => {
    render(<RecentActivity activities={mockActivities} />)

    const userElements = screen.getAllByText('admin')
    expect(userElements).toHaveLength(3)
  })

  it('formats timestamps correctly', () => {
    render(<RecentActivity activities={mockActivities} />)

    // Check for relative time display (depends on utils implementation)
    expect(screen.getByText(/ago|minutes|hours|days/)).toBeInTheDocument()
  })

  it('renders activity icons for different actions', () => {
    const { container } = render(<RecentActivity activities={mockActivities} />)

    // Check for icon elements (Lucide icons render as SVG)
    const icons = container.querySelectorAll('svg')
    expect(icons.length).toBeGreaterThan(0)
  })

  it('applies correct styling for different action types', () => {
    const { container } = render(<RecentActivity activities={mockActivities} />)

    // Check for action-specific color classes
    expect(container.querySelector('.text-blue-600')).toBeInTheDocument() // key_accessed
    expect(container.querySelector('.text-green-600')).toBeInTheDocument() // key_created
    expect(container.querySelector('.text-purple-600')).toBeInTheDocument() // key_rotated
  })

  it('shows empty state when no activities provided', () => {
    render(<RecentActivity activities={[]} />)

    expect(screen.getByText('No recent activity')).toBeInTheDocument()
  })

  it('handles missing optional fields gracefully', () => {
    const incompleteActivity = [
      {
        id: '1',
        timestamp: '2025-07-12T10:30:00Z',
        action: 'key_accessed',
        user: 'admin',
        details: {},
      },
    ]

    render(<RecentActivity activities={incompleteActivity} />)

    expect(screen.getByText('Key Accessed')).toBeInTheDocument()
    expect(screen.getByText('admin')).toBeInTheDocument()
  })

  it('truncates long activity lists appropriately', () => {
    const manyActivities = Array.from({ length: 20 }, (_, i) => ({
      id: `activity-${i}`,
      timestamp: '2025-07-12T10:30:00Z',
      action: 'key_accessed',
      key_name: `Test Key ${i}`,
      user: 'admin',
      details: {},
    }))

    render(<RecentActivity activities={manyActivities} />)

    // Should show only first 10 activities (or whatever limit is set)
    expect(screen.getByText('Test Key 0')).toBeInTheDocument()
    expect(screen.queryByText('Test Key 15')).not.toBeInTheDocument()
  })

  it('provides accessible structure for screen readers', () => {
    render(<RecentActivity activities={mockActivities} />)

    // Check for proper list structure
    const list = screen.getByRole('list')
    expect(list).toBeInTheDocument()

    const listItems = screen.getAllByRole('listitem')
    expect(listItems).toHaveLength(3)
  })

  it('handles unknown action types gracefully', () => {
    const unknownActivity = [
      {
        id: '1',
        timestamp: '2025-07-12T10:30:00Z',
        action: 'unknown_action',
        key_name: 'Test Key',
        user: 'admin',
        details: {},
      },
    ]

    render(<RecentActivity activities={unknownActivity} />)

    // Should still render with fallback styling
    expect(screen.getByText('Test Key')).toBeInTheDocument()
    expect(screen.getByText('admin')).toBeInTheDocument()
  })

  it('displays activity details when available', () => {
    render(<RecentActivity activities={mockActivities} />)

    // Check for service information in details
    expect(screen.getByText(/AWS/)).toBeInTheDocument()
    expect(screen.getByText(/GitHub/)).toBeInTheDocument()
    expect(screen.getByText(/Slack/)).toBeInTheDocument()
  })
})
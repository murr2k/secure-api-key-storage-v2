import { render, screen } from '@testing-library/react'
import { Shield, Key, Activity, AlertTriangle } from 'lucide-react'
import { StatsCard } from '@/components/ui/stats-card'

describe('StatsCard', () => {
  it('renders basic stats card with title, value, and icon', () => {
    render(
      <StatsCard
        title="Total Keys"
        value={42}
        icon={Key}
        description="Active API keys"
      />
    )

    expect(screen.getByText('Total Keys')).toBeInTheDocument()
    expect(screen.getByText('42')).toBeInTheDocument()
    expect(screen.getByText('Active API keys')).toBeInTheDocument()
  })

  it('renders warning variant with correct styling', () => {
    const { container } = render(
      <StatsCard
        title="Due for Rotation"
        value={5}
        icon={AlertTriangle}
        variant="warning"
      />
    )

    const card = container.firstChild as HTMLElement
    expect(card).toHaveClass('bg-yellow-50')
  })

  it('renders danger variant with correct styling', () => {
    const { container } = render(
      <StatsCard
        title="Failed Keys"
        value={2}
        icon={AlertTriangle}
        variant="danger"
      />
    )

    const card = container.firstChild as HTMLElement
    expect(card).toHaveClass('bg-red-50')
  })

  it('renders success variant with correct styling', () => {
    const { container } = render(
      <StatsCard
        title="Healthy Keys"
        value={10}
        icon={Shield}
        variant="success"
      />
    )

    const card = container.firstChild as HTMLElement
    expect(card).toHaveClass('bg-green-50')
  })

  it('renders without description when not provided', () => {
    render(
      <StatsCard
        title="Total Keys"
        value={42}
        icon={Key}
      />
    )

    expect(screen.getByText('Total Keys')).toBeInTheDocument()
    expect(screen.getByText('42')).toBeInTheDocument()
    expect(screen.queryByText('Active API keys')).not.toBeInTheDocument()
  })

  it('handles string values', () => {
    render(
      <StatsCard
        title="Status"
        value="Healthy"
        icon={Activity}
      />
    )

    expect(screen.getByText('Status')).toBeInTheDocument()
    expect(screen.getByText('Healthy')).toBeInTheDocument()
  })

  it('has accessible structure', () => {
    render(
      <StatsCard
        title="Total Keys"
        value={42}
        icon={Key}
        description="Active API keys"
      />
    )

    // Check that the icon is present (even though it's decorative)
    const icon = screen.getByRole('img', { hidden: true })
    expect(icon).toBeInTheDocument()
  })
})
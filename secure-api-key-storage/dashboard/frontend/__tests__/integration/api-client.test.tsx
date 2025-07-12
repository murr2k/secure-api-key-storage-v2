import { api } from '@/lib/api-client'
import axios from 'axios'

// Mock axios
jest.mock('axios')
const mockedAxios = axios as jest.Mocked<typeof axios>

describe('API Client Integration', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    localStorage.clear()
  })

  describe('Authentication', () => {
    it('sends login request with correct payload', async () => {
      const mockResponse = {
        data: {
          token: 'jwt-token',
          user: { id: '1', email: 'test@example.com' },
        },
      }
      mockedAxios.post.mockResolvedValue(mockResponse)

      const result = await api.auth.login('password123')

      expect(mockedAxios.post).toHaveBeenCalledWith('/api/auth/login', {
        password: 'password123',
      })
      expect(result).toEqual(mockResponse)
    })

    it('handles login errors', async () => {
      const mockError = {
        response: {
          status: 401,
          data: { message: 'Invalid credentials' },
        },
      }
      mockedAxios.post.mockRejectedValue(mockError)

      await expect(api.auth.login('wrongpassword')).rejects.toEqual(mockError)
    })

    it('includes auth token in subsequent requests', async () => {
      localStorage.setItem('auth_token', 'test-token')
      
      const mockResponse = { data: { keys: [] } }
      mockedAxios.get.mockResolvedValue(mockResponse)

      await api.keys.list()

      expect(mockedAxios.get).toHaveBeenCalledWith('/api/keys', {
        headers: {
          Authorization: 'Bearer test-token',
        },
      })
    })
  })

  describe('API Keys', () => {
    beforeEach(() => {
      localStorage.setItem('auth_token', 'test-token')
    })

    it('fetches list of API keys', async () => {
      const mockKeys = [
        { id: '1', name: 'AWS Key', service: 'AWS' },
        { id: '2', name: 'GitHub Token', service: 'GitHub' },
      ]
      mockedAxios.get.mockResolvedValue({ data: mockKeys })

      const result = await api.keys.list()

      expect(mockedAxios.get).toHaveBeenCalledWith('/api/keys', {
        headers: { Authorization: 'Bearer test-token' },
      })
      expect(result.data).toEqual(mockKeys)
    })

    it('creates new API key', async () => {
      const newKey = {
        name: 'New API Key',
        service: 'TestService',
        value: 'api-key-value',
        description: 'Test description',
      }
      const mockResponse = { data: { id: '3', ...newKey } }
      mockedAxios.post.mockResolvedValue(mockResponse)

      const result = await api.keys.create(newKey)

      expect(mockedAxios.post).toHaveBeenCalledWith('/api/keys', newKey, {
        headers: { Authorization: 'Bearer test-token' },
      })
      expect(result).toEqual(mockResponse)
    })

    it('updates existing API key', async () => {
      const keyId = '1'
      const updates = { name: 'Updated Name' }
      const mockResponse = { data: { id: keyId, ...updates } }
      mockedAxios.put.mockResolvedValue(mockResponse)

      const result = await api.keys.update(keyId, updates)

      expect(mockedAxios.put).toHaveBeenCalledWith(`/api/keys/${keyId}`, updates, {
        headers: { Authorization: 'Bearer test-token' },
      })
      expect(result).toEqual(mockResponse)
    })

    it('deletes API key', async () => {
      const keyId = '1'
      const mockResponse = { data: { success: true } }
      mockedAxios.delete.mockResolvedValue(mockResponse)

      const result = await api.keys.delete(keyId)

      expect(mockedAxios.delete).toHaveBeenCalledWith(`/api/keys/${keyId}`, {
        headers: { Authorization: 'Bearer test-token' },
      })
      expect(result).toEqual(mockResponse)
    })

    it('rotates API key', async () => {
      const keyId = '1'
      const mockResponse = { data: { id: keyId, rotated: true } }
      mockedAxios.post.mockResolvedValue(mockResponse)

      const result = await api.keys.rotate(keyId)

      expect(mockedAxios.post).toHaveBeenCalledWith(`/api/keys/${keyId}/rotate`, {}, {
        headers: { Authorization: 'Bearer test-token' },
      })
      expect(result).toEqual(mockResponse)
    })
  })

  describe('Analytics', () => {
    beforeEach(() => {
      localStorage.setItem('auth_token', 'test-token')
    })

    it('fetches analytics overview', async () => {
      const mockAnalytics = {
        total_keys: 10,
        total_services: 5,
        keys_accessed_today: 8,
        upcoming_rotations: 2,
        recent_activity: [],
      }
      mockedAxios.get.mockResolvedValue({ data: mockAnalytics })

      const result = await api.analytics.overview()

      expect(mockedAxios.get).toHaveBeenCalledWith('/api/analytics/overview', {
        headers: { Authorization: 'Bearer test-token' },
      })
      expect(result.data).toEqual(mockAnalytics)
    })

    it('fetches usage statistics', async () => {
      const params = { period: '7d' }
      const mockStats = { usage: [] }
      mockedAxios.get.mockResolvedValue({ data: mockStats })

      const result = await api.analytics.usage(params)

      expect(mockedAxios.get).toHaveBeenCalledWith('/api/analytics/usage', {
        params,
        headers: { Authorization: 'Bearer test-token' },
      })
      expect(result.data).toEqual(mockStats)
    })
  })

  describe('Audit Logs', () => {
    beforeEach(() => {
      localStorage.setItem('auth_token', 'test-token')
    })

    it('fetches audit logs with filters', async () => {
      const filters = {
        action: 'KEY_ACCESSED',
        start_date: '2025-07-01',
        end_date: '2025-07-12',
      }
      const mockLogs = [
        {
          id: '1',
          action: 'KEY_ACCESSED',
          timestamp: '2025-07-12T10:00:00Z',
        },
      ]
      mockedAxios.get.mockResolvedValue({ data: mockLogs })

      const result = await api.audit.list(filters)

      expect(mockedAxios.get).toHaveBeenCalledWith('/api/audit', {
        params: filters,
        headers: { Authorization: 'Bearer test-token' },
      })
      expect(result.data).toEqual(mockLogs)
    })

    it('exports audit logs', async () => {
      const params = { format: 'csv' }
      const mockCsv = 'id,action,timestamp\n1,KEY_ACCESSED,2025-07-12T10:00:00Z'
      mockedAxios.get.mockResolvedValue({ data: mockCsv })

      const result = await api.audit.export(params)

      expect(mockedAxios.get).toHaveBeenCalledWith('/api/audit/export', {
        params,
        headers: { Authorization: 'Bearer test-token' },
        responseType: 'blob',
      })
      expect(result.data).toEqual(mockCsv)
    })
  })

  describe('Error Handling', () => {
    beforeEach(() => {
      localStorage.setItem('auth_token', 'test-token')
    })

    it('handles network errors', async () => {
      const networkError = new Error('Network Error')
      mockedAxios.get.mockRejectedValue(networkError)

      await expect(api.keys.list()).rejects.toThrow('Network Error')
    })

    it('handles 401 unauthorized responses', async () => {
      const unauthorizedError = {
        response: {
          status: 401,
          data: { message: 'Token expired' },
        },
      }
      mockedAxios.get.mockRejectedValue(unauthorizedError)

      await expect(api.keys.list()).rejects.toEqual(unauthorizedError)
    })

    it('handles 403 forbidden responses', async () => {
      const forbiddenError = {
        response: {
          status: 403,
          data: { message: 'Insufficient permissions' },
        },
      }
      mockedAxios.get.mockRejectedValue(forbiddenError)

      await expect(api.keys.list()).rejects.toEqual(forbiddenError)
    })

    it('handles 500 server errors', async () => {
      const serverError = {
        response: {
          status: 500,
          data: { message: 'Internal server error' },
        },
      }
      mockedAxios.get.mockRejectedValue(serverError)

      await expect(api.keys.list()).rejects.toEqual(serverError)
    })
  })

  describe('Request Interceptors', () => {
    it('adds authentication header when token exists', async () => {
      localStorage.setItem('auth_token', 'test-token')
      
      mockedAxios.get.mockResolvedValue({ data: {} })
      
      await api.keys.list()
      
      expect(mockedAxios.get).toHaveBeenCalledWith('/api/keys', {
        headers: { Authorization: 'Bearer test-token' },
      })
    })

    it('does not add auth header when token is missing', async () => {
      localStorage.removeItem('auth_token')
      
      mockedAxios.post.mockResolvedValue({ data: {} })
      
      await api.auth.login('password')
      
      expect(mockedAxios.post).toHaveBeenCalledWith('/api/auth/login', {
        password: 'password',
      })
    })
  })

  describe('Response Interceptors', () => {
    it('automatically retries failed requests', async () => {
      localStorage.setItem('auth_token', 'test-token')
      
      // First call fails, second succeeds
      mockedAxios.get
        .mockRejectedValueOnce(new Error('Network timeout'))
        .mockResolvedValueOnce({ data: { keys: [] } })
      
      const result = await api.keys.list()
      
      expect(mockedAxios.get).toHaveBeenCalledTimes(2)
      expect(result.data).toEqual({ keys: [] })
    })

    it('clears auth token on 401 responses', async () => {
      localStorage.setItem('auth_token', 'expired-token')
      
      const unauthorizedError = {
        response: {
          status: 401,
          data: { message: 'Token expired' },
        },
      }
      mockedAxios.get.mockRejectedValue(unauthorizedError)
      
      await expect(api.keys.list()).rejects.toEqual(unauthorizedError)
      
      expect(localStorage.getItem('auth_token')).toBeNull()
    })
  })
})
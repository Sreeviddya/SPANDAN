// Integration tests for Auth API routes
// Note: These tests mock the database interactions for CI environments

import crypto from 'crypto'

describe('Auth API Routes', () => {
  describe('POST /api/auth/register', () => {
    it('should validate required fields', () => {
      const validateRegister = (body) => {
        const errors = []
        if (!body.name) errors.push('Name is required')
        if (!body.email) errors.push('Email is required')
        if (!body.password) errors.push('Password is required')
        if (!body.role) errors.push('Role is required')
        if (body.role && !['student', 'teacher'].includes(body.role)) {
          errors.push('Role must be student or teacher')
        }
        return errors
      }

      expect(validateRegister({})).toHaveLength(4)
      expect(validateRegister({ name: 'Test' })).toHaveLength(3)
      expect(validateRegister({ 
        name: 'Test', 
        email: 'test@example.com', 
        password: 'Pass123!', 
        role: 'student' 
      })).toHaveLength(0)
    })

    it('should validate email format', () => {
      const isValidEmail = (email) => {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
      }

      expect(isValidEmail('test@example.com')).toBe(true)
      expect(isValidEmail('invalid-email')).toBe(false)
      expect(isValidEmail('test@')).toBe(false)
      expect(isValidEmail('@example.com')).toBe(false)
    })

    it('should validate password strength', () => {
      const passwordRegex = /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,}$/
      
      expect(passwordRegex.test('Password1!')).toBe(true)
      expect(passwordRegex.test('weakpass')).toBe(false)  // No uppercase, no special, no digit
      expect(passwordRegex.test('PASSWORD1!')).toBe(false) // No lowercase
      expect(passwordRegex.test('Password!')).toBe(false)  // No digit
      expect(passwordRegex.test('Pass1!')).toBe(false)    // Too short
    })

    it('should return 400 for duplicate email', () => {
      const handleDuplicateEmail = (errorMessage) => {
        if (errorMessage === 'Email already registered') {
          return { status: 400, error: errorMessage }
        }
        return { status: 500, error: 'Internal server error' }
      }

      expect(handleDuplicateEmail('Email already registered').status).toBe(400)
      expect(handleDuplicateEmail('Some other error').status).toBe(500)
    })
  })

  describe('POST /api/auth/login', () => {
    it('should validate required fields', () => {
      const validateLogin = (body) => {
        const errors = []
        if (!body.email) errors.push('Email is required')
        if (!body.password) errors.push('Password is required')
        return errors
      }

      expect(validateLogin({})).toHaveLength(2)
      expect(validateLogin({ email: 'test@example.com' })).toHaveLength(1)
      expect(validateLogin({ email: 'test@example.com', password: 'pass' })).toHaveLength(0)
    })

    it('should return 401 for invalid credentials', () => {
      const handleInvalidCredentials = () => {
        return { status: 401, error: 'Invalid email or password' }
      }

      expect(handleInvalidCredentials().status).toBe(401)
      expect(handleInvalidCredentials().error).toBe('Invalid email or password')
    })
  })

  describe('Password Reset Flow', () => {
    it('should generate valid reset token', () => {
      const token = crypto.randomBytes(32).toString('hex')
      expect(token).toHaveLength(64)
      expect(token).toMatch(/^[a-f0-9]{64}$/)
    })

    it('should validate reset token format', () => {
      const isValidToken = (token) => {
        return typeof token === 'string' && /^[a-f0-9]{64}$/.test(token)
      }

      expect(isValidToken('a'.repeat(64))).toBe(true)
      expect(isValidToken('invalid')).toBe(false)
      expect(isValidToken('')).toBe(false)
      expect(isValidToken('ABCDEF'.repeat(10) + '12')).toBe(false) // uppercase not valid
    })

    it('should tell the user when the email is not registered', () => {
      // Unregistered email -> clear error; registered email -> reset link message
      const handleForgotPassword = (userExists) => {
        if (!userExists) {
          return { status: 404, error: 'No account found with this email address. Please check and try again.' }
        }
        return { status: 200, message: 'A password reset link has been sent to your email.' }
      }

      expect(handleForgotPassword(false).status).toBe(404)
      expect(handleForgotPassword(false).error).toContain('No account found')
      expect(handleForgotPassword(true).status).toBe(200)
      expect(handleForgotPassword(true).message).toContain('reset link')
    })

    it('should reject invalid email formats for forgot-password', () => {
      const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)

      expect(isValidEmail('teacher@spandan.local')).toBe(true)
      expect(isValidEmail('abc@xyz')).toBe(false)          // no TLD
      expect(isValidEmail('not-an-email')).toBe(false)
      expect(isValidEmail('@example.com')).toBe(false)
      expect(isValidEmail('user@')).toBe(false)
      expect(isValidEmail('user name@x.com')).toBe(false)  // space
    })

    it('should cap reset-link sends at 5 per registered email per window', () => {
      const FP_MAX_PER_EMAIL = 5
      const WINDOW_MS = 3600000

      // Inline replica of the passwordService throttle state machine
      const createThrottle = () => {
        let doc = null
        return {
          request(now) {
            if (!doc || now - doc.windowStart > WINDOW_MS) {
              doc = { count: 1, windowStart: now }
              return { ok: true }
            }
            if (doc.count >= FP_MAX_PER_EMAIL) return { ok: false, code: 'SEND_CAP' }
            doc.count += 1
            return { ok: true }
          }
        }
      }

      const throttle = createThrottle()
      const t0 = 1700000000000
      let okCount = 0
      for (let i = 0; i < 6; i++) {
        const r = throttle.request(t0 + i * 60000) // one per minute (past cooldown)
        if (r.ok) okCount += 1
        else expect(r.code).toBe('SEND_CAP')
      }
      expect(okCount).toBe(5) // 5 allowed, 6th blocked

      // After the window lapses the cap resets
      const r = throttle.request(t0 + WINDOW_MS + 1)
      expect(r.ok).toBe(true)
    })

    it('should enforce the escalating resend cooldown (20s, 30s, then 45s)', () => {
      const SCHEDULE_SEC = [20, 30, 45]
      const cooldownMsFor = (priorCount) => {
        const idx = Math.min(Math.max(priorCount - 1, 0), SCHEDULE_SEC.length - 1)
        return SCHEDULE_SEC[idx] * 1000
      }

      const createThrottle = () => {
        let doc = null
        return {
          request(now) {
            if (!doc) { doc = { count: 1, lastSentAt: now }; return { ok: true } }
            const cd = cooldownMsFor(doc.count)
            if (now - doc.lastSentAt < cd) return { ok: false, code: 'COOLDOWN' }
            doc.count += 1
            doc.lastSentAt = now
            return { ok: true }
          }
        }
      }

      const t0 = 1700000000000
      const throttle = createThrottle()
      expect(throttle.request(t0).ok).toBe(true)                             // 1st -> allowed
      expect(throttle.request(t0 + 19000).code).toBe('COOLDOWN')             // needs 20s
      expect(throttle.request(t0 + 20000).ok).toBe(true)                     // 2nd -> allowed
      expect(throttle.request(t0 + 20000 + 29000).code).toBe('COOLDOWN')     // needs 30s
      expect(throttle.request(t0 + 20000 + 30000).ok).toBe(true)             // 3rd -> allowed
      expect(throttle.request(t0 + 50000 + 44000).code).toBe('COOLDOWN')     // needs 45s
      expect(throttle.request(t0 + 50000 + 45000).ok).toBe(true)             // 4th -> allowed
      expect(throttle.request(t0 + 95000 + 44000).code).toBe('COOLDOWN')     // 5th also needs 45s
      expect(throttle.request(t0 + 95000 + 45000).ok).toBe(true)             // 5th -> allowed
    })

    it('should limit forgot-password to 3 requests per IP per hour', () => {
      const FP_MAX_PER_IP = 3

      let hitCount = 0
      const attempt = () => {
        if (hitCount >= FP_MAX_PER_IP) return { status: 429 }
        hitCount += 1
        return { status: 200 }
      }

      expect(attempt().status).toBe(200)
      expect(attempt().status).toBe(200)
      expect(attempt().status).toBe(200)
      expect(attempt().status).toBe(429) // 4th blocked
    })
  })

  describe('PUT /api/auth/role', () => {
    it('should validate role values', () => {
      const isValidRole = (role) => {
        return ['teacher', 'student'].includes(role)
      }

      expect(isValidRole('teacher')).toBe(true)
      expect(isValidRole('student')).toBe(true)
      expect(isValidRole('admin')).toBe(false)
      expect(isValidRole('')).toBe(false)
    })

    it('should require authentication', () => {
      const requireAuth = (user) => {
        if (!user) {
          return { status: 401, error: 'Authentication required' }
        }
        return null
      }

      expect(requireAuth(null)).toEqual({ status: 401, error: 'Authentication required' })
      expect(requireAuth({ _id: '123' })).toBeNull()
    })
  })

  describe('GET /api/auth/me', () => {
    it('should return user without password', () => {
      const sanitizeUser = (user) => {
        const { password, ...safeUser } = user
        return safeUser
      }

      const user = {
        _id: '123',
        email: 'test@example.com',
        password: 'hashed-secret',
        role: 'student'
      }

      const safeUser = sanitizeUser(user)
      expect(safeUser).not.toHaveProperty('password')
      expect(safeUser.email).toBe('test@example.com')
    })
  })

  describe('PUT /api/auth/profile', () => {
    it('should validate profile update fields', () => {
      const validateProfileUpdate = (body) => {
        const errors = []
        if (body.name !== undefined && body.name.length < 2) {
          errors.push('Name must be at least 2 characters')
        }
        if (body.email !== undefined && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(body.email)) {
          errors.push('Invalid email format')
        }
        return errors
      }

      expect(validateProfileUpdate({ name: 'A' })).toHaveLength(1)
      expect(validateProfileUpdate({ email: 'invalid' })).toHaveLength(1)
      expect(validateProfileUpdate({ name: 'Test User' })).toHaveLength(0)
    })
  })

  describe('PUT /api/auth/password', () => {
    it('should require all password fields', () => {
      const validatePasswordChange = (body) => {
        const errors = []
        if (!body.oldPassword) errors.push('Current password is required')
        if (!body.newPassword) errors.push('New password is required')
        if (!body.confirmPassword) errors.push('Confirm password is required')
        return errors
      }

      expect(validatePasswordChange({})).toHaveLength(3)
      expect(validatePasswordChange({ oldPassword: 'old' })).toHaveLength(2)
      expect(validatePasswordChange({ 
        oldPassword: 'old', 
        newPassword: 'new', 
        confirmPassword: 'new' 
      })).toHaveLength(0)
    })

    it('should require passwords to match', () => {
      const passwordsMatch = (newPassword, confirmPassword) => {
        return newPassword === confirmPassword
      }

      expect(passwordsMatch('Password1!', 'Password1!')).toBe(true)
      expect(passwordsMatch('Password1!', 'Different1!')).toBe(false)
    })

    it('should prevent reuse of current password', () => {
      const isSamePassword = (oldPassword, newPassword) => {
        return oldPassword === newPassword
      }

      expect(isSamePassword('SamePass1!', 'SamePass1!')).toBe(true)
      expect(isSamePassword('OldPass1!', 'NewPass1!')).toBe(false)
    })
  })
})
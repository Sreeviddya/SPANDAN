import crypto from 'crypto'
import PasswordResetToken from '../models/PasswordResetToken.js'
import PasswordResetAttempt from '../models/PasswordResetAttempt.js'

const TOKEN_EXPIRY_MS = 3600000 // 1 hour

// Forgot-password throttling: per-email cap + escalating resend cooldown.
// Only called AFTER confirming the email is registered (so unregistered emails never count).
// Cooldown schedule: after the 1st request wait 20s, after the 2nd wait 30s, then 45s for the rest.
const FP_WINDOW_MS      = Number(process.env.FORGOT_PW_LIMIT_WINDOW_MS)     || 3600000 // 1 hour
const FP_MAX_PER_EMAIL  = Number(process.env.FORGOT_PW_LIMIT_PER_EMAIL)     || 5

const parseCooldownSchedule = () => {
  const raw = process.env.FORGOT_PW_RESEND_COOLDOWN_SCHEDULE
  const fallback = [20, 30, 45]
  if (!raw) return fallback
  const secs = raw.split(',').map(s => Number(s.trim())).filter(n => Number.isFinite(n) && n > 0)
  return secs.length ? secs : fallback
}
// Seconds to wait before the NEXT request, given how many have already been made in this window.
const FP_COOLDOWN_SCHEDULE_SEC = parseCooldownSchedule()
const cooldownMsFor = (priorCount) => {
  const idx = Math.min(Math.max(priorCount - 1, 0), FP_COOLDOWN_SCHEDULE_SEC.length - 1)
  return FP_COOLDOWN_SCHEDULE_SEC[idx] * 1000
}

const fail = (msg, code, retryAfterSec) => {
  const e = new Error(msg)
  e.code = code
  if (retryAfterSec) e.retryAfterSec = retryAfterSec
  return e
}

export const recordPasswordResetRequest = async (email) => {
  const norm = (email || '').trim().toLowerCase()
  const now  = Date.now()

  const doc = await PasswordResetAttempt.findOne({ email: norm })

  if (!doc || now - doc.windowStart.getTime() > FP_WINDOW_MS) {
    // New window (or first ever) — allow, set counters
    await PasswordResetAttempt.findOneAndUpdate(
      { email: norm },
      { $set: { count: 1, windowStart: new Date(now), lastSentAt: new Date(now) } },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    )
    return
  }

  // Inside current window
  if (doc.count >= FP_MAX_PER_EMAIL) {
    const retryAfterSec = Math.max(1, Math.ceil((doc.windowStart.getTime() + FP_WINDOW_MS - now) / 1000))
    throw fail('Too many password reset requests for this email. Please try again later.', 'SEND_CAP', retryAfterSec)
  }

  const cooldownMs = cooldownMsFor(doc.count)
  if (now - doc.lastSentAt.getTime() < cooldownMs) {
    const wait = Math.ceil((cooldownMs - (now - doc.lastSentAt.getTime())) / 1000)
    throw fail(`Please wait ${wait}s before requesting another reset link.`, 'COOLDOWN', wait)
  }

  await PasswordResetAttempt.updateOne(
    { email: norm },
    { $inc: { count: 1 }, $set: { lastSentAt: new Date(now) } }
  )
}

export const generateResetToken = async (email) => {
  const token = crypto.randomBytes(32).toString('hex')
  const expires = new Date(Date.now() + TOKEN_EXPIRY_MS)
  
  await PasswordResetToken.findOneAndDelete({ email: email.toLowerCase() })
  
  const resetToken = new PasswordResetToken({
    email: email.toLowerCase(),
    token,
    expires
  })
  
  await resetToken.save()
  
  // Clean up all expired tokens
  await PasswordResetToken.deleteMany({ expires: { $lt: new Date() } })
  
  return token
}

export const verifyResetToken = async (token) => {
  const resetToken = await PasswordResetToken.findOne({ token })
  
  if (!resetToken) {
    return { valid: false, message: 'Invalid or expired token' }
  }
  
  if (resetToken.expires < new Date()) {
    await PasswordResetToken.findByIdAndDelete(resetToken._id)
    return { valid: false, message: 'Token has expired' }
  }
  
  if (resetToken.used) {
    return { valid: false, message: 'Token has already been used' }
  }
  
  return { valid: true, email: resetToken.email }
}

export const resetPassword = async (token, newPassword) => {
  const { valid, email, message } = await verifyResetToken(token)
  
  if (!valid) {
    throw new Error(message)
  }
  
  const User = (await import('../models/User.js')).default
  
  const user = await User.findOne({ email })
  
  if (!user) {
    throw new Error('User not found')
  }
  
  user.password = newPassword
  await user.save()
  
  // Mark token as used
  await PasswordResetToken.findOneAndUpdate({ token }, { used: true })
  
  return true
}

// Periodic cleanup for expired tokens (call this periodically)
export const cleanupExpiredTokens = async () => {
  const result = await PasswordResetToken.deleteMany({ expires: { $lt: new Date() } })
  return result.deletedCount
}